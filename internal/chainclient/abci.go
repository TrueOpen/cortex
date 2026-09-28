package chainclient

import (
	"context"
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

	"google.golang.org/protobuf/proto"
)

const keeperQueryTimeout = 10 * time.Second

// KeeperABCIClient reads Keeper state through CometBFT's protobuf ABCI query
// endpoint. Query identifiers are encoded in the request body, so values such
// as model IDs may safely contain URL path separators.
type KeeperABCIClient struct {
	rpcURL string
	http   *http.Client
}

// KeeperHTTPClient is retained as a source-compatible name for callers that
// have not yet adopted NewKeeperABCIClient. It now uses ABCI, not Keeper REST.
type KeeperHTTPClient = KeeperABCIClient

var ErrNotFound = errors.New("Keeper state not found")

// ErrFailedPrecondition is the application answering "not yet": the state the
// query names exists in the protocol but is not materialized at this height. It
// is a distinct sentinel from ErrNotFound because the two license different
// behaviour -- several Keeper reads sit on a clock the chain owns (a window
// header waiting for its Beacon, most of all) and their contract is to wait,
// not to report a fault.
var ErrFailedPrecondition = errors.New("Keeper state is not materialized yet")

func NewKeeperABCIClient(rpcURL string) *KeeperABCIClient {
	return NewKeeperABCIClientWithTransport(rpcURL, nil)
}

// NewKeeperABCIClientWithTransport is NewKeeperABCIClient over transport, which
// carries the node's TLS trust (node.tls). A nil transport means
// http.DefaultTransport and the system root CAs.
func NewKeeperABCIClientWithTransport(rpcURL string, transport http.RoundTripper) *KeeperABCIClient {
	return &KeeperABCIClient{
		rpcURL: strings.TrimRight(strings.TrimSpace(rpcURL), "/"),
		http:   &http.Client{Timeout: keeperQueryTimeout, Transport: transport},
	}
}

type cometRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   *struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	} `json:"error,omitempty"`
	Result json.RawMessage `json:"result"`
}

type abciQueryResult struct {
	Response struct {
		Code      uint32 `json:"code"`
		Log       string `json:"log"`
		Info      string `json:"info"`
		Value     string `json:"value"`
		Height    string `json:"height"`
		Codespace string `json:"codespace"`
	} `json:"response"`
}

// query issues an ABCI query and discards the height it was served at. Use it
// only where nothing downstream is bound to a height.
func (c *KeeperABCIClient) query(ctx context.Context, serviceMethod string, height uint64, request, response proto.Message) error {
	_, err := c.queryServed(ctx, serviceMethod, height, request, response)
	return err
}

// queryServed issues one ABCI query and reports the block height the response
// was served from.
//
// height 0 asks for the latest committed application state; any other value pins
// the read to that height. A pinned read is only legitimate when the height came
// from the application's own committed view (CommittedHeight), never from
// CometBFT's /status: the block store is written before the application commits,
// so /status can name a height the application cannot serve yet and the SDK
// rejects it as "cannot query with height in the future" (codespace "sdk" code
// 26).
//
// The Cosmos SDK echoes the requested height in the response, so for a pinned
// read this value confirms the node answered where we asked; a node that answers
// elsewhere is refused rather than trusted. A node that reports no height leaves
// the pinned height standing, which is the height its state was loaded at.
func (c *KeeperABCIClient) queryServed(ctx context.Context, serviceMethod string, height uint64, request, response proto.Message) (uint64, error) {
	requestBytes, err := proto.Marshal(request)
	if err != nil {
		return 0, fmt.Errorf("encode Keeper %s request: %w", serviceMethod, err)
	}
	values := url.Values{
		"path":  []string{strconv.Quote(serviceMethod)},
		"data":  []string{"0x" + hex.EncodeToString(requestBytes)},
		"prove": []string{"false"},
	}
	if height != 0 {
		values.Set("height", strconv.FormatUint(height, 10))
	}

	var rpc cometRPCResponse
	if err := c.getRPC(ctx, "/abci_query", values, &rpc); err != nil {
		return 0, err
	}
	if rpc.Error != nil {
		return 0, fmt.Errorf("Keeper %s RPC error %d: %s", serviceMethod, rpc.Error.Code, rpc.Error.Message)
	}
	var result abciQueryResult
	if err := json.Unmarshal(rpc.Result, &result); err != nil {
		return 0, fmt.Errorf("decode Keeper %s ABCI result: %w", serviceMethod, err)
	}
	if result.Response.Code != 0 {
		// Cosmos SDK maps gRPC NotFound into an ABCI response whose numeric code
		// is module/version dependent (the deployed Node currently returns 22).
		// The canonical gRPC status in the log is the stable discriminator.
		if result.Response.Code == uint32(5) || strings.Contains(result.Response.Log, "code = NotFound") {
			return 0, ErrNotFound
		}
		detail := strings.TrimSpace(result.Response.Log)
		if detail == "" {
			detail = strings.TrimSpace(result.Response.Info)
		}
		// FailedPrecondition is read the same way and for the same reason: the
		// numeric ABCI code is whatever the module registered (the deployed Node
		// returns 18, the SDK's ErrInvalidRequest), so the canonical gRPC status
		// the SDK writes into the log is the stable discriminator. The detail is
		// kept, because "not yet" still has to say what is not ready yet.
		if strings.Contains(result.Response.Log, "FailedPrecondition") {
			return 0, fmt.Errorf("%w: Keeper %s: %s", ErrFailedPrecondition, serviceMethod, detail)
		}
		return 0, fmt.Errorf("Keeper %s ABCI query failed (codespace %q code %d): %s", serviceMethod, result.Response.Codespace, result.Response.Code, detail)
	}
	served, err := result.servedHeight()
	if err != nil {
		return 0, fmt.Errorf("Keeper %s: %w", serviceMethod, err)
	}
	switch {
	case served == 0:
		served = height
	case height != 0 && served != height:
		return 0, fmt.Errorf("Keeper %s was queried at height %d and answered at height %d", serviceMethod, height, served)
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(result.Response.Value)
	if err != nil {
		return 0, fmt.Errorf("decode Keeper %s ABCI value: %w", serviceMethod, err)
	}
	if err := proto.Unmarshal(payload, response); err != nil {
		return 0, fmt.Errorf("decode Keeper %s protobuf response: %w", serviceMethod, err)
	}
	return served, nil
}

// servedHeight decodes the height CometBFT reported for the response. An absent
// or zero height means the node did not report one.
func (r abciQueryResult) servedHeight() (uint64, error) {
	raw := strings.TrimSpace(r.Response.Height)
	if raw == "" {
		return 0, nil
	}
	served, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("decode ABCI response height %q: %w", raw, err)
	}
	return served, nil
}

func (c *KeeperABCIClient) querySnapshot(ctx context.Context, serviceMethod string, height uint64, request, response proto.Message, snapshot any) error {
	_, err := c.querySnapshotServed(ctx, serviceMethod, height, request, response, snapshot)
	return err
}

// querySnapshotServed is querySnapshot for callers that must know which height
// the snapshot came from.
func (c *KeeperABCIClient) querySnapshotServed(ctx context.Context, serviceMethod string, height uint64, request, response proto.Message, snapshot any) (uint64, error) {
	served, err := c.queryServed(ctx, serviceMethod, height, request, response)
	if err != nil {
		return 0, err
	}
	encoded, err := restProtoJSON(response)
	if err != nil {
		return 0, fmt.Errorf("encode Keeper %s protobuf JSON: %w", serviceMethod, err)
	}
	if err := json.Unmarshal(encoded, snapshot); err != nil {
		return 0, fmt.Errorf("map Keeper %s response: %w", serviceMethod, err)
	}
	return served, nil
}

func (c *KeeperABCIClient) getRPC(ctx context.Context, path string, values url.Values, out any) error {
	requestURL := c.rpcURL + path
	if len(values) != 0 {
		requestURL += "?" + values.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return fmt.Errorf("create Keeper RPC request %s: %w", path, err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return keeperRequestError(path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := fmt.Errorf("Keeper RPC %s returned %s", path, resp.Status)
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return retryableError{err: err}
		}
		return err
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 8<<20))
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("decode Keeper RPC %s: %w", path, err)
	}
	return nil
}

func keeperRequestError(path string, err error) error {
	wrapped := fmt.Errorf("Keeper RPC %s request failed: %w", path, err)
	if !errors.Is(err, context.DeadlineExceeded) {
		var timeout interface{ Timeout() bool }
		if errors.As(err, &timeout) && timeout.Timeout() {
			wrapped = fmt.Errorf("%v: %w", wrapped, context.DeadlineExceeded)
		}
	}
	return retryableError{err: wrapped}
}
