package signer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/denom"
)

var (
	ErrRetryable       = errors.New("signer request is retryable")
	ErrRejected        = errors.New("signer request was rejected")
	ErrInvalidResponse = errors.New("signer returned an invalid response")
)

const maxResponseBytes = 1 << 20

type ClientConfig struct {
	Endpoint   string
	HTTPClient *http.Client
}

type Client struct {
	endpoint string
	http     *http.Client
}

type DigestSigner interface {
	SignDigest(context.Context, DigestRequest) ([]byte, error)
}

type DigestSignerFunc func(context.Context, DigestRequest) ([]byte, error)

func (f DigestSignerFunc) SignDigest(ctx context.Context, req DigestRequest) ([]byte, error) {
	return f(ctx, req)
}

type DigestRequest struct {
	KeyRef                string     `json:"key_ref"`
	ExpectedSignerAddress string     `json:"expected_signer_address"`
	Digest                codec.Hash `json:"-"`
}

func (r DigestRequest) MarshalJSON() ([]byte, error) {
	type wire struct {
		KeyRef                string `json:"key_ref"`
		ExpectedSignerAddress string `json:"expected_signer_address"`
		Digest                string `json:"digest"`
	}
	return json.Marshal(wire{
		KeyRef: r.KeyRef, ExpectedSignerAddress: r.ExpectedSignerAddress,
		Digest: hex.EncodeToString(r.Digest[:]),
	})
}

func (r *DigestRequest) UnmarshalJSON(data []byte) error {
	var value struct {
		KeyRef                string `json:"key_ref"`
		ExpectedSignerAddress string `json:"expected_signer_address"`
		Digest                string `json:"digest"`
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	decoded, err := hex.DecodeString(value.Digest)
	if err != nil || len(decoded) != len(r.Digest) {
		return fmt.Errorf("invalid digest")
	}
	r.KeyRef = value.KeyRef
	r.ExpectedSignerAddress = value.ExpectedSignerAddress
	copy(r.Digest[:], decoded)
	return nil
}

type CosmosMessage struct {
	TypeURL string          `json:"type_url"`
	Value   json.RawMessage `json:"value"`
}

type CosmosTxRequest struct {
	KeyRef                string          `json:"key_ref"`
	ExpectedSignerAddress string          `json:"expected_signer_address"`
	ChainID               string          `json:"chain_id"`
	AccountNumber         uint64          `json:"account_number"`
	Sequence              uint64          `json:"sequence"`
	GasLimit              uint64          `json:"gas_limit"`
	FeeAmount             uint64          `json:"fee_amount"`
	FeeDenom              string          `json:"fee_denom"`
	FeePayer              string          `json:"fee_payer"`
	FeeGranter            string          `json:"fee_granter,omitempty"`
	Memo                  string          `json:"memo,omitempty"`
	TimeoutHeight         uint64          `json:"timeout_height,omitempty"`
	Messages              []CosmosMessage `json:"messages"`
}

type signResponse struct {
	Signature     string `json:"signature"`
	TxRaw         string `json:"tx_raw"`
	SignerAddress string `json:"signer_address"`
}

func NewClient(cfg ClientConfig) *Client {
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{endpoint: strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/"), http: httpClient}
}

func (c *Client) SignDigest(ctx context.Context, req DigestRequest) ([]byte, error) {
	if err := validateKey(req.KeyRef, req.ExpectedSignerAddress); err != nil {
		return nil, err
	}
	if req.Digest == (codec.Hash{}) {
		return nil, fmt.Errorf("digest is required")
	}
	var response signResponse
	if err := c.post(ctx, "/v1/sign/digest", req, &response); err != nil {
		return nil, err
	}
	if err := validateIdentityResponse(response, req.ExpectedSignerAddress); err != nil {
		return nil, err
	}
	return decodeSignature(response.Signature)
}

// CanSignCosmosTx is true: the remote service implements /v1/sign/cosmos-tx.
func (c *Client) CanSignCosmosTx() bool { return true }

func (c *Client) SignCosmosTx(ctx context.Context, req CosmosTxRequest) ([]byte, error) {
	if err := validateCosmosTxRequest(req); err != nil {
		return nil, err
	}
	var response signResponse
	if err := c.post(ctx, "/v1/sign/cosmos-tx", req, &response); err != nil {
		return nil, err
	}
	if err := validateIdentityResponse(response, req.ExpectedSignerAddress); err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(response.TxRaw)
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("%w: malformed tx raw bytes", ErrInvalidResponse)
	}
	return raw, nil
}

func (c *Client) post(ctx context.Context, path string, input any, output any) error {
	if err := validateEndpoint(c.endpoint); err != nil {
		return err
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("encode signer request")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create signer request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%w: transport failure", ErrRetryable)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return fmt.Errorf("%w: HTTP status %d", ErrRetryable, resp.StatusCode)
		}
		return fmt.Errorf("%w: HTTP status %d", ErrRejected, resp.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("%w: malformed JSON", ErrInvalidResponse)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing JSON", ErrInvalidResponse)
	}
	return nil
}

func validateEndpoint(endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil {
		return fmt.Errorf("signer endpoint must be an HTTP(S) URL without credentials")
	}
	return nil
}

func validateKey(keyRef string, expectedAddress string) error {
	if strings.TrimSpace(keyRef) == "" || strings.TrimSpace(keyRef) != keyRef {
		return fmt.Errorf("signer key reference is required")
	}
	if strings.TrimSpace(expectedAddress) == "" || strings.TrimSpace(expectedAddress) != expectedAddress {
		return fmt.Errorf("expected signer address is required")
	}
	return nil
}

func validateCosmosTxRequest(req CosmosTxRequest) error {
	if err := validateKey(req.KeyRef, req.ExpectedSignerAddress); err != nil {
		return err
	}
	if strings.TrimSpace(req.ChainID) == "" || req.GasLimit == 0 || req.FeeAmount == 0 || !denom.Valid(req.FeeDenom) || strings.TrimSpace(req.FeePayer) == "" || strings.TrimSpace(req.FeePayer) != req.FeePayer {
		return fmt.Errorf("Cosmos chain, gas, fee payer, and a valid fee denomination are required")
	}
	if len(req.Messages) == 0 {
		return fmt.Errorf("at least one Cosmos message is required")
	}
	for _, message := range req.Messages {
		if !strings.HasPrefix(message.TypeURL, "/") || len(message.Value) == 0 || !json.Valid(message.Value) {
			return fmt.Errorf("Cosmos message type URL and JSON value are required")
		}
	}
	return nil
}

func validateIdentityResponse(response signResponse, expectedAddress string) error {
	if response.SignerAddress != expectedAddress {
		return fmt.Errorf("%w: signer address mismatch", ErrInvalidResponse)
	}
	return nil
}

func decodeSignature(raw string) ([]byte, error) {
	if len(raw) != 128 || raw != strings.ToLower(raw) || strings.HasPrefix(raw, "0x") {
		return nil, fmt.Errorf("%w: signature must be 64-byte lowercase hex", ErrInvalidResponse)
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: signature must be 64-byte lowercase hex", ErrInvalidResponse)
	}
	allZero := true
	for _, value := range decoded {
		if value != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, fmt.Errorf("%w: signature must not be zero", ErrInvalidResponse)
	}
	return decoded, nil
}
