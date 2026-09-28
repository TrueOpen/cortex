package chainclient

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type EventPosition struct {
	Height     uint64
	TxIndex    uint32
	MsgIndex   uint32
	EventIndex uint32
}

// CursorAheadOfChainError reports a durable event cursor above the chain tip.
// The local store therefore describes a chain the configured endpoint has never
// reached -- in practice a chain that was reset and restarted from height 1
// while keeping its chain id. It is deliberately not retryable: no amount of
// waiting brings a tip back up to a cursor recorded on a dead chain.
type CursorAheadOfChainError struct {
	ChainID      string
	CursorHeight uint64
	ChainHeight  uint64
}

func (e *CursorAheadOfChainError) Error() string {
	return fmt.Sprintf(
		"Keeper event cursor height %d is above chain %q tip %d: the local store describes a chain that no longer exists "+
			"(a chain reset keeps its chain id). Stop the node and move the store aside -- back up and remove the Pebble directory, "+
			"keeping config.yaml, keystore/, secrets/ and data/evidence/ -- so the cursor replays from height 0, "+
			"or repoint node.rpc_endpoint at the chain this store was populated against",
		e.CursorHeight, e.ChainID, e.ChainHeight)
}

// IsCursorAheadOfChain reports whether err is the cursor-above-tip refusal.
func IsCursorAheadOfChain(err error) bool {
	var target *CursorAheadOfChainError
	return errors.As(err, &target)
}

func BlockEndPosition(height uint64) EventPosition {
	return EventPosition{Height: height, TxIndex: ^uint32(0), MsgIndex: ^uint32(0), EventIndex: ^uint32(0)}
}

func (p EventPosition) String() string {
	return fmt.Sprintf("%d:%d:%d:%d", p.Height, p.TxIndex, p.MsgIndex, p.EventIndex)
}

func ParseEventPosition(raw string) (EventPosition, error) {
	parts := strings.Split(raw, ":")
	if len(parts) != 4 {
		return EventPosition{}, fmt.Errorf("event position must contain height, tx, message, and event indexes")
	}
	height, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return EventPosition{}, fmt.Errorf("invalid event position height: %w", err)
	}
	indexes := make([]uint32, 3)
	for i, part := range parts[1:] {
		value, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return EventPosition{}, fmt.Errorf("invalid event position index: %w", err)
		}
		indexes[i] = uint32(value)
	}
	return EventPosition{Height: height, TxIndex: indexes[0], MsgIndex: indexes[1], EventIndex: indexes[2]}, nil
}

type CometEventClientConfig struct {
	RPCURL        string
	ChainID       string
	FinalityDepth uint64
	HTTPClient    *http.Client
	// Transport carries the node's TLS trust (node.tls) when HTTPClient is nil.
	// Nil means http.DefaultTransport and the system root CAs.
	Transport http.RoundTripper
	// Identifier decides which protocol event each raw chain event is. Nil
	// selects released message names and the typed protocol event envelope.
	Identifier EventIdentifier
}

type CometEventClient struct {
	rpcURL        string
	chainID       string
	finalityDepth uint64
	http          *http.Client
	identifier    EventIdentifier
}

func NewCometEventClient(cfg CometEventClientConfig) *CometEventClient {
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second, Transport: cfg.Transport}
	}
	identifier := cfg.Identifier
	if identifier == nil {
		identifier = MessageNameEventIdentifier()
	}
	return &CometEventClient{
		rpcURL:        strings.TrimRight(strings.TrimSpace(cfg.RPCURL), "/"),
		chainID:       strings.TrimSpace(cfg.ChainID),
		finalityDepth: cfg.FinalityDepth,
		http:          httpClient,
		identifier:    identifier,
	}
}

func (c *CometEventClient) FinalizedEvents(ctx context.Context, after EventPosition) (KeeperEventsPage, error) {
	chainHeight, network, err := c.status(ctx)
	if err != nil {
		return KeeperEventsPage{}, err
	}
	if c.chainID == "" || network != c.chainID {
		return KeeperEventsPage{}, fmt.Errorf("CometBFT chain id %q does not match configured %q", network, c.chainID)
	}
	// A cursor above the tip cannot describe this chain. The chain id check
	// above does not catch it, because a chain reset keeps its chain id: the
	// node then reads an empty page forever, writes the same cursor back, and
	// reports zero lag because the cursor is at or above the tip. Refusing here
	// turns that silent idle into a diagnosable stop.
	if after.Height > chainHeight {
		return KeeperEventsPage{}, &CursorAheadOfChainError{
			ChainID:      network,
			CursorHeight: after.Height,
			ChainHeight:  chainHeight,
		}
	}
	finalizedHeight := chainHeight
	if c.finalityDepth >= finalizedHeight {
		finalizedHeight = 0
	} else {
		finalizedHeight -= c.finalityDepth
	}
	page := KeeperEventsPage{ChainHeight: chainHeight, FinalizedHeight: finalizedHeight, RangeComplete: true}
	if finalizedHeight == 0 || after.Height >= finalizedHeight {
		page.RangeEndHeight = finalizedHeight
		return page, nil
	}
	startHeight := after.Height + 1
	page.RangeStartHeight = startHeight
	page.RangeEndHeight = finalizedHeight
	for height := startHeight; height <= finalizedHeight; height++ {
		events, err := c.blockEvents(ctx, height)
		if err != nil {
			return KeeperEventsPage{}, err
		}
		page.Events = append(page.Events, events...)
		if len(events) > 0 {
			page.LastEventHeight = height
		}
	}
	page.LastPosition = BlockEndPosition(finalizedHeight)
	return page, nil
}

func (c *CometEventClient) ChainStatus(ctx context.Context) (uint64, string, error) {
	return c.status(ctx)
}

func (c *CometEventClient) status(ctx context.Context) (uint64, string, error) {
	var response struct {
		Result struct {
			NodeInfo struct {
				Network string `json:"network"`
			} `json:"node_info"`
			SyncInfo struct {
				LatestBlockHeight string `json:"latest_block_height"`
			} `json:"sync_info"`
		} `json:"result"`
	}
	if err := c.get(ctx, "/status", nil, &response); err != nil {
		return 0, "", err
	}
	height, err := strconv.ParseUint(response.Result.SyncInfo.LatestBlockHeight, 10, 64)
	if err != nil || height == 0 {
		return 0, "", fmt.Errorf("invalid CometBFT latest block height %q", response.Result.SyncInfo.LatestBlockHeight)
	}
	return height, strings.TrimSpace(response.Result.NodeInfo.Network), nil
}

type cometAttribute struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type cometEvent struct {
	Type       string           `json:"type"`
	Attributes []cometAttribute `json:"attributes"`
}

func (c *CometEventClient) blockEvents(ctx context.Context, height uint64) ([]KeeperEvent, error) {
	query := url.Values{"height": []string{strconv.FormatUint(height, 10)}}
	var resultsResponse struct {
		Result struct {
			Height     string `json:"height"`
			TxsResults []struct {
				Code   uint32       `json:"code"`
				Events []cometEvent `json:"events"`
			} `json:"txs_results"`
			FinalizeBlockEvents []cometEvent `json:"finalize_block_events"`
		} `json:"result"`
	}
	if err := c.get(ctx, "/block_results", query, &resultsResponse); err != nil {
		return nil, err
	}
	if resultsResponse.Result.Height != strconv.FormatUint(height, 10) {
		return nil, fmt.Errorf("CometBFT block results height %q does not match requested %d", resultsResponse.Result.Height, height)
	}

	var blockResponse struct {
		Result struct {
			Block struct {
				Header struct {
					ChainID string `json:"chain_id"`
					Height  string `json:"height"`
				} `json:"header"`
				Data struct {
					Txs []string `json:"txs"`
				} `json:"data"`
			} `json:"block"`
		} `json:"result"`
	}
	if err := c.get(ctx, "/block", query, &blockResponse); err != nil {
		return nil, err
	}
	if blockResponse.Result.Block.Header.ChainID != c.chainID || blockResponse.Result.Block.Header.Height != strconv.FormatUint(height, 10) {
		return nil, fmt.Errorf("CometBFT block identity does not match requested chain/height")
	}
	if len(blockResponse.Result.Block.Data.Txs) < len(resultsResponse.Result.TxsResults) {
		return nil, fmt.Errorf("CometBFT block has fewer transactions than block results")
	}

	var out []KeeperEvent
	for txIndex, result := range resultsResponse.Result.TxsResults {
		if result.Code != 0 {
			continue
		}
		txBytes, err := base64.StdEncoding.DecodeString(blockResponse.Result.Block.Data.Txs[txIndex])
		if err != nil {
			return nil, fmt.Errorf("decode CometBFT transaction %d: %w", txIndex, err)
		}
		txDigest := sha256.Sum256(txBytes)
		txHash := hex.EncodeToString(txDigest[:])
		events, err := parseCometEvents(c.identifier, c.chainID, height, uint32(txIndex), txHash, result.Events)
		if err != nil {
			return nil, err
		}
		out = append(out, events...)
	}
	if len(resultsResponse.Result.FinalizeBlockEvents) > 0 {
		events, err := parseCometEvents(c.identifier, c.chainID, height, ^uint32(0), "", resultsResponse.Result.FinalizeBlockEvents)
		if err != nil {
			return nil, err
		}
		out = append(out, events...)
	}
	return out, nil
}

// parseCometEvents turns raw ABCI events into KeeperEvents. It asks identifier
// which protocol event each one is and what it concerns, and never inspects the
// wire type itself beyond carrying it as RawType.
func parseCometEvents(identifier EventIdentifier, chainID string, height uint64, txIndex uint32, txHash string, rawEvents []cometEvent) ([]KeeperEvent, error) {
	var out []KeeperEvent
	var msgIndex uint32
	seenMessage := false
	for eventIndex, rawEvent := range rawEvents {
		attributes := decodeCometAttributes(rawEvent.Attributes)
		if rawEvent.Type == "message" {
			if seenMessage {
				msgIndex++
			}
			seenMessage = true
			continue
		}
		identity := identifier.Identify(RawChainEvent{ABCIType: rawEvent.Type, Attributes: attributes})
		if identity.Attributes != nil {
			attributes = identity.Attributes
		}
		event := KeeperEvent{
			Type:            identity.Type,
			ContractVersion: KeeperEventContractVersionV1,
			RawType:         rawEvent.Type,
			Known:           identity.Known,
			ChainID:         chainID,
			Height:          height,
			Position:        EventPosition{Height: height, TxIndex: txIndex, MsgIndex: msgIndex, EventIndex: uint32(eventIndex)},
			TxHash:          txHash,
			Attributes:      attributes,
			TaskID:          identity.TaskID,
			SessionID:       identity.SessionID,
			// Keeper names operator attributes <role>_operator_address --
			// worker_operator_address appears on six task events and
			// verifier_operator_address on four. Omitting them left Worker empty
			// on a real assignment_finalized, which Validate rejects, and the
			// poller treats that as terminal: every node died on the block
			// carrying the first genuine assignment.
			Worker:         firstAttribute(attributes, "worker_operator_address", "winner_worker", "worker", "worker_address", "operator_address", "operator"),
			Verifier:       firstAttribute(attributes, "verifier_operator_address", "verifier", "verifier_address"),
			ChallengeID:    attributes["challenge_id"],
			ModelID:        attributes["model_id"],
			ProfileVersion: attributes["profile_version"],
			Phase:          firstAttribute(attributes, "status", "phase"),
		}
		event.OrderSequence, _ = strconv.ParseUint(attributes["order_sequence"], 10, 64)
		event.WinnerConfirmHeight, _ = strconv.ParseUint(attributes["winner_confirm_height"], 10, 64)
		event.InferDeadlineHeight, _ = strconv.ParseUint(firstAttribute(attributes, "infer_deadline_height", "infer_deadline"), 10, 64)
		if identity.Known {
			if identity.Error != "" || identity.BlockHeight != 0 && identity.BlockHeight != height {
				event.Quarantined = true
				event.QuarantineReason = "invalid protocol event envelope: " + identity.Error
				if identity.BlockHeight != 0 && identity.BlockHeight != height {
					event.QuarantineReason += " block height mismatch"
				}
			}
			// A recognized event that fails validation is quarantined rather
			// than failing the page. The event is permanent chain history, so
			// rejecting the page only prevents the cursor from ever advancing
			// past it -- which turned one unmapped attribute name into every
			// node exiting on the same block, and exiting again on restart.
			if err := event.Validate(); err != nil {
				event.Quarantined = true
				event.QuarantineReason = fmt.Sprintf("invalid Keeper event %q at %s: %v", rawEvent.Type, event.Position.String(), err)
			}
			out = append(out, event)
			continue
		}
		if rawEvent.Type != "" {
			out = append(out, event)
		}
	}
	return out, nil
}

func decodeCometAttributes(raw []cometAttribute) map[string]string {
	out := make(map[string]string, len(raw))
	for _, attribute := range raw {
		key := decodeCometText(attribute.Key)
		if sensitiveEventAttribute(key) {
			continue
		}
		out[key] = normalizeTypedEventValue(decodeCometText(attribute.Value))
	}
	return out
}

// normalizeTypedEventValue converts a Cosmos SDK typed-event attribute value
// into the plain string the parser below expects. Typed events carry ProtoJSON
// fragments rather than an independent string schema: string and uint64 fields
// keep their JSON quoting, uint32 and bool fields do not, and repeated or
// nested fields arrive as JSON arrays/objects. Unquoting here keeps every
// downstream consumer working on plain scalars while leaving composite values
// as raw JSON for callers that want to decode them.
func normalizeTypedEventValue(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return raw
	}
	if trimmed[0] != '"' {
		// Numbers, booleans, arrays, objects and legacy plain text all pass
		// through unchanged. Only JSON strings carry quoting to strip.
		return trimmed
	}
	var decoded string
	if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
		return trimmed
	}
	return decoded
}

func decodeCometText(raw string) string {
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err == nil && utf8.Valid(decoded) {
		printable := true
		for _, r := range string(decoded) {
			if r < 0x20 || r == 0x7f {
				printable = false
				break
			}
		}
		if printable {
			return string(decoded)
		}
	}
	return raw
}

func sensitiveEventAttribute(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "prompt", "input", "output", "prompt_plaintext", "input_plaintext", "output_plaintext":
		return true
	default:
		return false
	}
}
func firstAttribute(attributes map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := attributes[key]; value != "" {
			return value
		}
	}
	return ""
}

func (c *CometEventClient) get(ctx context.Context, path string, query url.Values, out any) error {
	rawURL := c.rpcURL + path
	if len(query) > 0 {
		rawURL += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("create CometBFT request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return retryableError{err: fmt.Errorf("CometBFT %s request failed: %w", path, err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := fmt.Errorf("CometBFT %s returned %s", path, resp.Status)
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return retryableError{err: err}
		}
		return err
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode CometBFT %s response: %w", path, err)
	}
	return nil
}
