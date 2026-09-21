package chainclient

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestCometEventClientReadsFinalizedKeeperEventsWithStablePositions(t *testing.T) {
	txBytes := []byte("signed-tx")
	wantTxHashBytes := sha256.Sum256(txBytes)
	wantTxHash := hex.EncodeToString(wantTxHashBytes[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"node_info":{"network":"trueopen-devnet-1"},"sync_info":{"latest_block_height":"12"}}}`))
		case "/block_results":
			if got := r.URL.Query().Get("height"); got != "10" {
				t.Errorf("block_results height = %q, want 10", got)
			}
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"height":"10","txs_results":[{"code":0,"events":[{"type":"message","attributes":[{"key":"action","value":"/task.v1.MsgAssign","index":true}]},{"type":"task.v1.EventWorkerAssignmentFinalized","attributes":[{"key":"` + b64("session_id") + `","value":"` + b64("session-1") + `","index":true},{"key":"task_id","value":"task-1","index":true},{"key":"winner_worker","value":"trueopen1node","index":true},{"key":"winner_confirm_height","value":"9","index":true},{"key":"infer_deadline_height","value":"20","index":true},{"key":"prompt","value":"must-not-be-consumed","index":false}]},{"type":"custom_notice","attributes":[{"key":"status","value":"seen","index":true}]}]}],"finalize_block_events":[]}}`))
		case "/block":
			if got := r.URL.Query().Get("height"); got != "10" {
				t.Errorf("block height = %q, want 10", got)
			}
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"block":{"header":{"chain_id":"trueopen-devnet-1","height":"10"},"data":{"txs":["` + base64.StdEncoding.EncodeToString(txBytes) + `"]}}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewCometEventClient(CometEventClientConfig{
		RPCURL:        server.URL,
		ChainID:       "trueopen-devnet-1",
		FinalityDepth: 2,
	})
	page, err := client.FinalizedEvents(context.Background(), EventPosition{Height: 9})
	if err != nil {
		t.Fatalf("FinalizedEvents returned error: %v", err)
	}
	if page.ChainHeight != 12 || page.FinalizedHeight != 10 {
		t.Fatalf("page heights = chain %d finalized %d, want 12/10", page.ChainHeight, page.FinalizedHeight)
	}
	if page.RangeStartHeight != 10 || page.RangeEndHeight != 10 || !page.RangeComplete || page.NextPageToken != "" {
		t.Fatalf("page range = %#v, want explicit complete range 10-10", page)
	}
	if len(page.Events) != 2 {
		t.Fatalf("events = %#v, want recognized and unknown events", page.Events)
	}
	assignment := page.Events[0]
	if assignment.Type != KeeperEventAssignmentFinalized || assignment.RawType != "task.v1.EventWorkerAssignmentFinalized" {
		t.Fatalf("assignment type = %q raw=%q", assignment.Type, assignment.RawType)
	}
	if assignment.ContractVersion != KeeperEventContractVersionV1 {
		t.Fatalf("assignment contract version = %q", assignment.ContractVersion)
	}
	if assignment.ChainID != "trueopen-devnet-1" || assignment.Height != 10 || assignment.Position.TxIndex != 0 || assignment.Position.EventIndex != 1 {
		t.Fatalf("assignment position = %#v", assignment)
	}
	if assignment.SessionID != "session-1" || assignment.TaskID != "task-1" || assignment.Worker != "trueopen1node" || assignment.WinnerConfirmHeight != 9 {
		t.Fatalf("assignment attributes = %#v", assignment)
	}
	if assignment.TxHash != wantTxHash {
		t.Fatalf("tx hash = %q, want %q", assignment.TxHash, wantTxHash)
	}
	if _, ok := assignment.Attributes["prompt"]; ok {
		t.Fatalf("prompt leaked into retained event attributes: %#v", assignment.Attributes)
	}
	unknown := page.Events[1]
	if unknown.Known || unknown.RawType != "custom_notice" || unknown.Attributes["status"] != "seen" {
		t.Fatalf("unknown event = %#v", unknown)
	}
	if page.LastPosition != BlockEndPosition(10) {
		t.Fatalf("last position = %#v, want block-end position", page.LastPosition)
	}
	if assignment.Digest() == unknown.Digest() {
		t.Fatalf("event digests collide")
	}
}

func TestCometEventClientRejectsChainIDMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"node_info":{"network":"other-chain"},"sync_info":{"latest_block_height":"12"}}}`))
	}))
	defer server.Close()

	client := NewCometEventClient(CometEventClientConfig{RPCURL: server.URL, ChainID: "trueopen-devnet-1"})
	if _, err := client.FinalizedEvents(context.Background(), EventPosition{Height: 11}); err == nil {
		t.Fatalf("FinalizedEvents error = nil, want chain id mismatch")
	}
}

// The gpu-test devnet was reset and restarted from height 1 while keeping its
// chain id, so the chain id check above passed while the durable cursor sat
// roughly 20000 blocks above the new tip. FinalizedEvents returned an empty
// page, the poller wrote the same cursor back, and the node consumed nothing
// for as long as it stayed up without emitting a single log line.
func TestCometEventClientRefusesCursorAboveChainTip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			t.Errorf("unexpected request to %s: the refusal must happen before any block is read", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"node_info":{"network":"trueopen-localnet-1"},"sync_info":{"latest_block_height":"13134"}}}`))
	}))
	defer server.Close()

	client := NewCometEventClient(CometEventClientConfig{
		RPCURL:        server.URL,
		ChainID:       "trueopen-localnet-1",
		FinalityDepth: 2,
	})
	page, err := client.FinalizedEvents(context.Background(), EventPosition{Height: 33161})
	if err == nil {
		t.Fatalf("FinalizedEvents page = %#v, err = nil; want a refusal instead of a silent empty page", page)
	}
	if !IsCursorAheadOfChain(err) {
		t.Fatalf("FinalizedEvents error = %v, want a CursorAheadOfChainError", err)
	}
	// Retrying cannot lower a cursor recorded on a chain that no longer exists,
	// so the poller must surface this immediately rather than ride it out.
	if IsRetryable(err) {
		t.Fatalf("FinalizedEvents error = %v, want a terminal refusal", err)
	}
	for _, want := range []string{"33161", "13134", "trueopen-localnet-1", "keeping config.yaml, keystore/, secrets/ and data/evidence/"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("FinalizedEvents error = %q, want it to name %q", err.Error(), want)
		}
	}
}

// A cursor at the tip is a caught-up node, and a cursor above the finalized
// height but at or below the tip is an unfinalized head, not a dead chain.
// Refusing either would stop every healthy node.
func TestCometEventClientAcceptsCursorAtOrBelowChainTip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"node_info":{"network":"trueopen-localnet-1"},"sync_info":{"latest_block_height":"13134"}}}`))
	}))
	defer server.Close()

	client := NewCometEventClient(CometEventClientConfig{
		RPCURL:        server.URL,
		ChainID:       "trueopen-localnet-1",
		FinalityDepth: 2,
	})
	for _, cursor := range []uint64{13132, 13133, 13134} {
		page, err := client.FinalizedEvents(context.Background(), EventPosition{Height: cursor})
		if err != nil {
			t.Fatalf("FinalizedEvents(cursor %d) error = %v, want the caught-up empty page", cursor, err)
		}
		if page.ChainHeight != 13134 {
			t.Fatalf("FinalizedEvents(cursor %d) chain height = %d, want 13134", cursor, page.ChainHeight)
		}
	}
}

func TestCometEventClientClassifiesRetryableRPCFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := NewCometEventClient(CometEventClientConfig{RPCURL: server.URL, ChainID: "trueopen-devnet-1"})
	_, err := client.FinalizedEvents(context.Background(), EventPosition{})
	if err == nil || !IsRetryable(err) {
		t.Fatalf("FinalizedEvents error = %v, want retryable", err)
	}
}

func TestParseCometEventsQuarantinesMalformedKnownEvent(t *testing.T) {
	events, err := parseCometEvents(MessageNameEventIdentifier(), "trueopen-devnet-1", 10, 0, "tx-hash", []cometEvent{{
		Type: "task.v1.EventWorkerAssignmentFinalized",
		Attributes: []cometAttribute{
			{Key: "winner_worker", Value: "trueopen1node"},
		},
	}})
	if err != nil {
		t.Fatalf("parseCometEvents error = %v, want the page to survive", err)
	}
	if len(events) != 1 || !events[0].Quarantined {
		t.Fatalf("events = %#v, want the malformed event quarantined rather than accepted", events)
	}
}

func TestParseCometEventsRecognizesKeeperNamespacedEvents(t *testing.T) {
	events, err := parseCometEvents(MessageNameEventIdentifier(), "trueopen-devnet-1", 20, 0, "tx-1", []cometEvent{
		{
			Type: "task.v1.EventVerifierAssignmentFinalized",
			Attributes: []cometAttribute{
				{Key: "session_id", Value: "session-1"},
				{Key: "task_id", Value: "task-1"},
			},
		},
		{
			Type: "hub.v1.EventRewardEpochClosed",
			Attributes: []cometAttribute{
				{Key: "epoch_index", Value: "7"},
				{Key: "accepted_confirmations", Value: "2"},
			},
		},
		{
			Type: "hub.v1.EventMarkGateUpdated",
			Attributes: []cometAttribute{
				{Key: "role_address", Value: "node-1"},
				{Key: "role", Value: "WORKER"},
			},
		},
	})
	if err != nil {
		t.Fatalf("parseCometEvents returned error: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("len(events) = %d, want 3", len(events))
	}
	if !events[0].Known || events[0].Type != KeeperEventOpenVerifyAccepted {
		t.Fatalf("task event = %#v, want known verification seed event", events[0])
	}
	if !events[1].Known || events[1].Type != KeeperEventProtocolProjection {
		t.Fatalf("hub event = %#v, want known reward epoch projection", events[1])
	}
	if events[2].Known {
		t.Fatalf("mark gate event = %#v, want retired event to be unknown", events[2])
	}
}

// Typed events carry ProtoJSON fragments rather than an independent string
// schema: string and uint64 fields keep their JSON quoting, uint32 and bool
// fields do not, and repeated fields arrive as JSON arrays. Reading them as an
// untyped map left every task id quoted and every height unparsable.
func TestParseCometEventsDecodesProtoJSONTypedEventAttributes(t *testing.T) {
	events, err := parseCometEvents(MessageNameEventIdentifier(), "trueopen-devnet-1", 300, 0, "tx-typed", []cometEvent{{
		Type: "task.v1.EventWorkerAssignmentFinalized",
		Attributes: []cometAttribute{
			{Key: "session_id", Value: `"session-1"`},
			{Key: "task_id", Value: `"task-1"`},
			{Key: "worker_operator_address", Value: `"trueopen1worker"`},
			{Key: "winner_confirm_height", Value: `"300"`},
			{Key: "infer_deadline_height", Value: `"420"`},
			{Key: "profile_version", Value: `1`},
			{Key: "formal_verifier_operator_addresses", Value: `["trueopen1a","trueopen1b"]`},
		},
	}})
	if err != nil {
		t.Fatalf("parseCometEvents returned error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(events))
	}
	event := events[0]
	if event.Quarantined {
		t.Fatalf("event quarantined = %q, want a valid typed assignment", event.QuarantineReason)
	}
	if event.TaskID != "task-1" || event.SessionID != "session-1" || event.Worker != "trueopen1worker" {
		t.Fatalf("event identity = %#v, want unquoted ProtoJSON strings", event)
	}
	if event.WinnerConfirmHeight != 300 || event.InferDeadlineHeight != 420 {
		t.Fatalf("event heights = (%d, %d), want (300, 420) parsed from quoted uint64", event.WinnerConfirmHeight, event.InferDeadlineHeight)
	}
	if event.ProfileVersion != "1" {
		t.Fatalf("event profile version = %q, want an unquoted uint32 to pass through", event.ProfileVersion)
	}
	if got := event.Attributes["formal_verifier_operator_addresses"]; got != `["trueopen1a","trueopen1b"]` {
		t.Fatalf("repeated attribute = %q, want the raw JSON array preserved", got)
	}
}

func TestParseCometEventsMapsCurrentNodeValidTaskToSettlement(t *testing.T) {
	events, err := parseCometEvents(MessageNameEventIdentifier(), "trueopen-devnet-1", 124, 0, "tx-settle", []cometEvent{{
		Type: "task.v1.EventTaskSettled",
		Attributes: []cometAttribute{
			{Key: "session_id", Value: "session-1"},
			{Key: "task_id", Value: "task-1"},
			{Key: "verdict", Value: "PASS"},
			{Key: "settlement_height", Value: "124"},
		},
	}})
	if err != nil {
		t.Fatalf("parseCometEvents returned error: %v", err)
	}
	if len(events) != 1 || !events[0].Known || events[0].Type != KeeperEventSettleAccepted {
		t.Fatalf("events = %#v, want current Node valid_task settlement event", events)
	}
	if events[0].RawType != "task.v1.EventTaskSettled" || events[0].SessionID != "session-1" || events[0].TaskID != "task-1" || events[0].Attributes["verdict"] != "PASS" {
		t.Fatalf("settlement event = %#v", events[0])
	}
}

func TestParseCometEventsRecognizesCurrentBuilderSetNotification(t *testing.T) {
	events, err := parseCometEvents(MessageNameEventIdentifier(), "trueopen-devnet-1", 125, 0, "tx-builder-set", []cometEvent{{
		Type: "hub.v1.EventBuilderSetUpdated",
		Attributes: []cometAttribute{
			{Key: "term_id", Value: "term-9"},
			{Key: "set_hash", Value: "builder-set-hash"},
			{Key: "height", Value: "125"},
		},
	}})
	if err != nil {
		t.Fatalf("parseCometEvents returned error: %v", err)
	}
	if len(events) != 1 || !events[0].Known || events[0].Type != KeeperEventBuilderSetUpdated {
		t.Fatalf("events = %#v, want current builder-set projection event", events)
	}
	if events[0].Attributes["term_id"] != "term-9" || events[0].Attributes["set_hash"] != "builder-set-hash" {
		t.Fatalf("builder-set event = %#v", events[0])
	}
}

func TestParseCometEventsRecognizesCurrentAtomicModelProfileRegistration(t *testing.T) {
	events, err := parseCometEvents(MessageNameEventIdentifier(), "trueopen-devnet-1", 20, 0, "tx-atomic-registration", []cometEvent{{
		Type: "hub.v1.EventModelProfileRegistered",
		Attributes: []cometAttribute{
			{Key: "model_id", Value: "model-a"},
			{Key: "profile_version", Value: "1"},
			{Key: "registration_digest", Value: strings.Repeat("ab", 32)},
		},
	}})
	if err != nil {
		t.Fatalf("parseCometEvents returned error: %v", err)
	}
	if len(events) != 1 || !events[0].Known || events[0].Type != KeeperEventModelProfileRegistered || events[0].RawType != "hub.v1.EventModelProfileRegistered" || events[0].ContractVersion != KeeperEventContractVersionV1 {
		t.Fatalf("events = %#v, want current atomic model/profile registration", events)
	}

	incomplete, err := parseCometEvents(MessageNameEventIdentifier(), "trueopen-devnet-1", 20, 0, "tx-incomplete-registration", []cometEvent{{
		Type:       "hub.v1.EventModelProfileRegistered",
		Attributes: []cometAttribute{{Key: "model_id", Value: "model-a"}},
	}})
	if err != nil {
		t.Fatalf("parseCometEvents error = %v, want the page to survive", err)
	}
	if len(incomplete) != 1 || !incomplete[0].Quarantined {
		t.Fatalf("registration without profile_version = %#v, want it quarantined rather than accepted", incomplete)
	}
}

func TestParseCometEventsRecognizesModelSupportLifecycleEvents(t *testing.T) {
	for _, rawType := range []string{"hub.v1.EventModelSupportUpdated", "hub.v1.EventModelSupportActivated"} {
		events, err := parseCometEvents(MessageNameEventIdentifier(), "trueopen-devnet-1", 20, 0, "tx-1", []cometEvent{{
			Type: rawType,
			Attributes: []cometAttribute{
				{Key: "operator_address", Value: "node-1"},
				{Key: "model_id", Value: "model-a"},
				{Key: "profile_version", Value: "1"},
			},
		}})
		if err != nil {
			t.Fatalf("parseCometEvents(%s) error = %v", rawType, err)
		}
		if len(events) != 1 || events[0].Type != KeeperEventModelSupportUpdated || events[0].Worker != "node-1" {
			t.Fatalf("events for %s = %#v, want operator-scoped support update", rawType, events)
		}
	}
}

func TestKeeperEventTypeFromABCIDoesNotRecognizeUnregisteredLegacyEvents(t *testing.T) {
	if eventType, known := keeperEventTypeFromABCI("commit_accepted"); known {
		t.Fatalf("keeperEventTypeFromABCI(commit_accepted) = %q, true; Keeper emits no such event", eventType)
	}
}

func b64(value string) string {
	return base64.StdEncoding.EncodeToString([]byte(value))
}

func ExampleEventPosition_String() {
	position := EventPosition{Height: 42, TxIndex: 3, MsgIndex: 1, EventIndex: 7}
	fmt.Println(position.String())
	parsed, _ := ParseEventPosition(position.String())
	fmt.Println(parsed.Height, parsed.TxIndex, parsed.MsgIndex, parsed.EventIndex)
	// Output:
	// 42:3:1:7
	// 42 3 1 7
}

func TestParseEventPositionRejectsMalformedValues(t *testing.T) {
	for _, raw := range []string{"", "1", "1:2:3", "x:2:3:4", "1:-2:3:4", "1:2:3:" + strconv.FormatUint(uint64(^uint32(0))+1, 10)} {
		if _, err := ParseEventPosition(raw); err == nil {
			t.Fatalf("ParseEventPosition(%q) error = nil", raw)
		}
	}
}

// Keeper names operator attributes <role>_operator_address. The existing
// coverage used "winner_worker", which Keeper never emits, so a real
// assignment_finalized decoded with an empty Worker, Validate rejected it, and
// the poller -- which treats a malformed known event as terminal -- exited.
// Every node died on the block carrying the first genuine assignment.
//
// These attribute sets are copied from Keeper's emitters:
// x/task/keeper/assignment_randomness.go (emitAssignmentFinalizedEvent).
func TestParseCometEventsReadsKeeperOperatorAttributes(t *testing.T) {
	events, err := parseCometEvents(MessageNameEventIdentifier(), "trueopen-devnet-1", 53135, 0, "tx-1", []cometEvent{
		{
			Type: "task.v1.EventWorkerAssignmentFinalized",
			Attributes: []cometAttribute{
				{Key: "session_id", Value: "session-1"},
				{Key: "task_id", Value: "task-1"},
				{Key: "worker_operator_address", Value: "trueopen1worker"},
				{Key: "winner_confirm_height", Value: "53130"},
				{Key: "infer_deadline_height", Value: "53200"},
				{Key: "candidate_set_hash", Value: "abc"},
			},
		},
		{
			// A type Cortex recognizes, so this exercises validation and the
			// known-event path rather than only firstAttribute.
			Type: "task.v1.EventVerifierAssignmentFinalized",
			Attributes: []cometAttribute{
				{Key: "session_id", Value: "session-1"},
				{Key: "task_id", Value: "task-1"},
				{Key: "verifier_operator_address", Value: "trueopen1verifier"},
			},
		},
	})
	if err != nil {
		t.Fatalf("parseCometEvents() error = %v, want Keeper's own attribute names accepted", err)
	}
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	if events[0].Worker != "trueopen1worker" {
		t.Fatalf("Worker = %q, want it read from worker_operator_address", events[0].Worker)
	}
	if !events[1].Known {
		t.Fatalf("event = %#v, want a recognized type so validation actually runs", events[1])
	}
	if events[1].Quarantined {
		t.Fatalf("event = %#v, want it to pass validation", events[1])
	}
	if events[1].Verifier != "trueopen1verifier" {
		t.Fatalf("Verifier = %q, want it read from verifier_operator_address", events[1].Verifier)
	}
}

// A known event that fails validation is permanent chain history: retrying
// cannot repair it and the node cannot advance past it. Failing the whole page
// meant the poller saw a terminal error and the daemon exited -- on the devnet
// every node died on the block carrying the first real assignment, and died
// again on each restart.
//
// Quarantine the event instead: keep parsing the page, mark the event so no
// effect is derived from it, and let the cursor advance.
func TestParseCometEventsQuarantinesInvalidKnownEvent(t *testing.T) {
	events, err := parseCometEvents(MessageNameEventIdentifier(), "trueopen-devnet-1", 53135, 0, "tx-1", []cometEvent{
		{
			// Missing worker: exactly what an unmapped attribute name produced.
			Type: "task.v1.EventWorkerAssignmentFinalized",
			Attributes: []cometAttribute{
				{Key: "session_id", Value: "session-1"},
				{Key: "task_id", Value: "task-1"},
			},
		},
		{
			Type: "task.v1.EventWorkerAssignmentFinalized",
			Attributes: []cometAttribute{
				{Key: "session_id", Value: "session-2"},
				{Key: "task_id", Value: "task-2"},
				{Key: "worker_operator_address", Value: "trueopen1worker"},
			},
		},
	})
	if err != nil {
		t.Fatalf("parseCometEvents() error = %v, want the page to survive one invalid event", err)
	}
	if len(events) != 2 {
		t.Fatalf("events = %d, want both retained so the cursor can advance", len(events))
	}
	if !events[0].Quarantined {
		t.Fatalf("first event = %#v, want it quarantined", events[0])
	}
	if !strings.Contains(events[0].QuarantineReason, "worker") {
		t.Fatalf("quarantine reason = %q, want it to name the failure", events[0].QuarantineReason)
	}
	if events[1].Quarantined {
		t.Fatalf("valid event was quarantined: %#v", events[1])
	}
}

// The typed contract is a hard cut: the pre-#85 snake-case names are gone, so a
// node that still recognised them would silently accept events from a contract
// that no longer exists.
func TestParseCometEventsRejectsPreTypedEventNames(t *testing.T) {
	for _, rawType := range []string{
		"task.v1.assignment_finalized",
		"task.v1.verification_sample_seed_ready",
		"hub.v1.valid_task",
	} {
		t.Run(rawType, func(t *testing.T) {
			events, err := parseCometEvents(MessageNameEventIdentifier(), "trueopen-devnet-1", 400, 0, "tx-legacy", []cometEvent{{
				Type:       rawType,
				Attributes: []cometAttribute{{Key: "task_id", Value: `"task-1"`}, {Key: "session_id", Value: `"session-1"`}},
			}})
			if err != nil {
				t.Fatalf("parseCometEvents returned error: %v", err)
			}
			if len(events) != 1 || events[0].Known {
				t.Fatalf("events = %#v, want the legacy name classified as unknown", events)
			}
		})
	}
}

// The FSM has transitions for these three, so leaving them unmapped left a
// selected verifier never reaching VERIFY_ASSIGNED and accepted commits and
// results never advancing the local task past it.
func TestParseCometEventsRecognizesVerifyTransitionEvents(t *testing.T) {
	for rawType, want := range map[string]KeeperEventType{
		"task.v1.EventVerifierAssignmentFinalized": KeeperEventOpenVerifyAccepted,
		"task.v1.EventCommitAccepted":              KeeperEventCommitAccepted,
		"task.v1.EventResultAccepted":              KeeperEventResultCredentialAccepted,
	} {
		t.Run(rawType, func(t *testing.T) {
			events, err := parseCometEvents(MessageNameEventIdentifier(), "trueopen-devnet-1", 500, 0, "tx-verify", []cometEvent{{
				Type: rawType,
				Attributes: []cometAttribute{
					{Key: "session_id", Value: `"session-1"`},
					{Key: "task_id", Value: `"task-1"`},
					{Key: "verifier_operator_address", Value: `"trueopen1verifier"`},
				},
			}})
			if err != nil {
				t.Fatalf("parseCometEvents returned error: %v", err)
			}
			if len(events) != 1 || !events[0].Known || events[0].Type != want {
				t.Fatalf("events = %#v, want a known %s", events, want)
			}
		})
	}
}
