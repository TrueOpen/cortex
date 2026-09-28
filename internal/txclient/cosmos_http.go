package txclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var (
	ErrTxNotFound      = errors.New("Cosmos transaction not found")
	ErrRetryableCosmos = errors.New("Cosmos request is retryable")
)

const maxCosmosResponseBytes = 4 << 20

type CosmosHTTPConfig struct {
	Endpoint   string
	HTTPClient *http.Client
	// Transport carries the node's TLS trust (node.tls) when HTTPClient is nil.
	// Nil means http.DefaultTransport and the system root CAs.
	Transport http.RoundTripper
}

type CosmosHTTPClient struct {
	endpoint string
	http     *http.Client
}

func NewCosmosHTTPClient(cfg CosmosHTTPConfig) *CosmosHTTPClient {
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second, Transport: cfg.Transport}
	}
	return &CosmosHTTPClient{endpoint: strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/"), http: httpClient}
}

func (c *CosmosHTTPClient) Account(ctx context.Context, address string) (Account, error) {
	if strings.TrimSpace(address) == "" || strings.TrimSpace(address) != address {
		return Account{}, fmt.Errorf("account address is required")
	}
	var response struct {
		Account json.RawMessage `json:"account"`
	}
	if err := c.get(ctx, "/cosmos/auth/v1beta1/accounts/"+url.PathEscape(address), &response); err != nil {
		return Account{}, err
	}
	var value any
	if err := json.Unmarshal(response.Account, &value); err != nil {
		return Account{}, fmt.Errorf("decode Cosmos account")
	}
	base, ok := findBaseAccount(value)
	if !ok {
		return Account{}, fmt.Errorf("Cosmos Auth response does not contain a base account")
	}
	accountNumber, err := parseJSONUint64(base["account_number"])
	if err != nil {
		return Account{}, fmt.Errorf("Cosmos account number: %w", err)
	}
	sequence, err := parseJSONUint64(base["sequence"])
	if err != nil {
		return Account{}, fmt.Errorf("Cosmos account sequence: %w", err)
	}
	gotAddress, _ := base["address"].(string)
	if gotAddress != address {
		return Account{}, fmt.Errorf("Cosmos Auth account address mismatch")
	}
	return Account{Address: gotAddress, AccountNumber: accountNumber, Sequence: sequence}, nil
}

func (c *CosmosHTTPClient) BroadcastTx(ctx context.Context, txRaw []byte) (BroadcastResult, error) {
	if len(txRaw) == 0 {
		return BroadcastResult{}, fmt.Errorf("signed TxRaw bytes are required")
	}
	request := struct {
		TxBytes string `json:"tx_bytes"`
		Mode    string `json:"mode"`
	}{TxBytes: base64.StdEncoding.EncodeToString(txRaw), Mode: "BROADCAST_MODE_SYNC"}
	var response struct {
		TxResponse cosmosTxResponse `json:"tx_response"`
	}
	if err := c.post(ctx, "/cosmos/tx/v1beta1/txs", request, &response); err != nil {
		return BroadcastResult{}, err
	}
	expectedHash := cosmosTxHash(txRaw)
	if !strings.EqualFold(strings.TrimSpace(response.TxResponse.TxHash), expectedHash) {
		return BroadcastResult{}, fmt.Errorf("BroadcastTx response transaction hash mismatch")
	}
	return BroadcastResult{Code: response.TxResponse.Code, TxHash: response.TxResponse.TxHash, Log: response.TxResponse.RawLog}, nil
}

func (c *CosmosHTTPClient) Tx(ctx context.Context, txHash string) (InclusionResult, error) {
	if strings.TrimSpace(txHash) == "" || strings.TrimSpace(txHash) != txHash {
		return InclusionResult{}, fmt.Errorf("tx hash is required")
	}
	var response struct {
		TxResponse cosmosTxResponse `json:"tx_response"`
	}
	if err := c.get(ctx, "/cosmos/tx/v1beta1/txs/"+url.PathEscape(txHash), &response); err != nil {
		return InclusionResult{}, err
	}
	height, err := strconv.ParseUint(response.TxResponse.Height, 10, 64)
	if err != nil || height == 0 {
		return InclusionResult{}, fmt.Errorf("Cosmos Tx response height is invalid")
	}
	if !strings.EqualFold(strings.TrimSpace(response.TxResponse.TxHash), txHash) {
		return InclusionResult{}, fmt.Errorf("Cosmos Tx response transaction hash mismatch")
	}
	return InclusionResult{Code: response.TxResponse.Code, Height: height, TxHash: response.TxResponse.TxHash, Log: response.TxResponse.RawLog}, nil
}

func cosmosTxHash(txRaw []byte) string {
	digest := sha256.Sum256(txRaw)
	return strings.ToUpper(hex.EncodeToString(digest[:]))
}

type cosmosTxResponse struct {
	Height string `json:"height"`
	Code   uint32 `json:"code"`
	TxHash string `json:"txhash"`
	RawLog string `json:"raw_log"`
}

func (c *CosmosHTTPClient) get(ctx context.Context, path string, output any) error {
	return c.do(ctx, http.MethodGet, path, nil, output)
}

func (c *CosmosHTTPClient) post(ctx context.Context, path string, input, output any) error {
	payload, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("encode Cosmos REST request")
	}
	return c.do(ctx, http.MethodPost, path, payload, output)
}

func (c *CosmosHTTPClient) do(ctx context.Context, method, path string, payload []byte, output any) error {
	parsed, err := url.Parse(c.endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil {
		return fmt.Errorf("Cosmos REST endpoint must be an HTTP(S) URL without credentials")
	}
	request, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create Cosmos REST request")
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%w: transport failure", ErrRetryableCosmos)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound && strings.HasPrefix(path, "/cosmos/tx/v1beta1/txs/") {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxCosmosResponseBytes))
		return ErrTxNotFound
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxCosmosResponseBytes))
		if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
			return fmt.Errorf("%w: HTTP status %d", ErrRetryableCosmos, response.StatusCode)
		}
		return fmt.Errorf("Cosmos REST HTTP status %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxCosmosResponseBytes))
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode Cosmos REST response")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("Cosmos REST response has trailing JSON")
	}
	return nil
}

func findBaseAccount(value any) (map[string]any, bool) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	if _, hasNumber := object["account_number"]; hasNumber {
		if _, hasSequence := object["sequence"]; hasSequence {
			return object, true
		}
	}
	for _, nested := range object {
		if base, ok := findBaseAccount(nested); ok {
			return base, true
		}
	}
	return nil, false
}

func parseJSONUint64(value any) (uint64, error) {
	encoded, ok := value.(string)
	if !ok {
		return 0, fmt.Errorf("must be a decimal string")
	}
	parsed, err := strconv.ParseUint(encoded, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != encoded {
		return 0, fmt.Errorf("must be a canonical decimal string")
	}
	return parsed, nil
}
