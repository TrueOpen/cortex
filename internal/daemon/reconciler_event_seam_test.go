package daemon

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/codec"
)

// syntheticEnvelopeABCIType stands in for the wire type of a future
// envelope-shaped protocol event. It is not a guess at what the frozen Node
// contract's ProtocolEventEnvelopeV1 will present -- that string is unobserved,
// see the migration seam note in internal/chainclient/events_identity.go -- only
// a type string sharing nothing with today's typed-event message names.
const syntheticEnvelopeABCIType = "cortex.test.v1.SyntheticProtocolEventEnvelope"

// syntheticEnvelopeIdentification is an alternative identification layer:
// one wire type for every protocol event, an attribute naming which event it is,
// and the task/session locator under keys today's Node never emits.
type syntheticEnvelopeIdentification struct{}

func (syntheticEnvelopeIdentification) Identify(raw chainclient.RawChainEvent) chainclient.EventIdentity {
	if raw.ABCIType != syntheticEnvelopeABCIType {
		return chainclient.MessageNameEventIdentifier().Identify(raw)
	}
	identity := chainclient.EventIdentity{
		TaskID:    raw.Attributes["locator_task_id"],
		SessionID: raw.Attributes["locator_session_id"],
	}
	switch raw.Attributes["synthetic_event"] {
	case "assign_accepted":
		identity.Type = chainclient.KeeperEventAssignAcceptedPendingRandomness
		identity.Known = true
	case "assignment_finalized":
		identity.Type = chainclient.KeeperEventAssignmentFinalized
		identity.Known = true
	}
	return identity
}

// The frozen Node contract deletes every message name Cortex subscribes to, so
// identification had to become a replaceable layer. This proves the layer is
// real end to end: an alternative identifier feeds the reconciler from a wire
// encoding it has never seen, and the downstream taskHash-keyed effect is
// identical. Nothing here reaches into handler internals.
func TestReconcilerHandlesAlternativelyIdentifiedEventsIdentically(t *testing.T) {
	const typedEvents = `[{"type":"task.v1.EventWorkerHandraisesAccepted","attributes":[{"key":"session_id","value":"session-1","index":true},{"key":"task_id","value":"task-1","index":true}]},` +
		`{"type":"task.v1.EventWorkerAssignmentFinalized","attributes":[{"key":"session_id","value":"session-1","index":true},{"key":"task_id","value":"task-1","index":true},{"key":"winner_worker","value":"worker-local","index":true}]}]`
	const syntheticEvents = `[{"type":"` + syntheticEnvelopeABCIType + `","attributes":[{"key":"locator_session_id","value":"session-1","index":true},{"key":"locator_task_id","value":"task-1","index":true},{"key":"synthetic_event","value":"assign_accepted","index":true}]},` +
		`{"type":"` + syntheticEnvelopeABCIType + `","attributes":[{"key":"locator_session_id","value":"session-1","index":true},{"key":"locator_task_id","value":"task-1","index":true},{"key":"synthetic_event","value":"assignment_finalized","index":true},{"key":"winner_worker","value":"worker-local","index":true}]}]`

	typed := applyIdentifiedBlock(t, nil, typedEvents)
	synthetic := applyIdentifiedBlock(t, syntheticEnvelopeIdentification{}, syntheticEvents)

	if len(typed.effects) != 1 || typed.effects[0].TaskID != "task-1" || typed.effects[0].Type != ReconcilerEffectAssignment {
		t.Fatalf("message-name effects = %#v, want assignment for task-1", typed.effects)
	}
	if len(synthetic.effects) != len(typed.effects) {
		t.Fatalf("synthetic effects = %#v, want the same as %#v", synthetic.effects, typed.effects)
	}
	if !reflect.DeepEqual(synthetic.effects, typed.effects) {
		t.Fatalf("synthetic effects = %#v, want %#v", synthetic.effects, typed.effects)
	}
	if synthetic.observedTypes != typed.observedTypes {
		t.Fatalf("synthetic observed event types = %q, want %q", synthetic.observedTypes, typed.observedTypes)
	}
	// The internal event kinds must not leak the encoding they came from.
	if synthetic.rawTypes == typed.rawTypes {
		t.Fatalf("raw types = %q on both runs, the two encodings were not distinct", synthetic.rawTypes)
	}
}

// Settlement without an authoritative Keeper reader must fail closed, and the
// gate has to survive the identification change: the frozen contract deletes the
// message name this check used to be keyed to, which would have turned it into a
// silent no-op. It is keyed to the identified event instead.
func TestReconcilerFailsClosedForAlternativelyIdentifiedSettlement(t *testing.T) {
	ctx := context.Background()
	var quarantined []chainclient.KeeperEvent
	reconciler := NewReconciler(ReconcilerOptions{OnQuarantinedEvent: func(event chainclient.KeeperEvent) { quarantined = append(quarantined, event) }})
	effects, err := reconciler.Apply(ctx, []chainclient.KeeperEvent{{
		Type:            chainclient.KeeperEventSettleAccepted,
		ContractVersion: chainclient.KeeperEventContractVersionV1,
		RawType:         syntheticEnvelopeABCIType,
		Known:           true,
		SessionID:       "session-settled",
		TaskID:          "task-settled",
		Height:          124,
		Attributes:      map[string]string{"verdict": "PASS", "settlement_height": "124"},
	}})
	if err != nil || len(effects) != 0 {
		t.Fatalf("Apply() effects=%#v error=%v, want no settlement effect and a live poll loop", effects, err)
	}
	if len(quarantined) != 1 || !strings.Contains(quarantined[0].QuarantineReason, "requires an authoritative Keeper task reader") {
		t.Fatalf("quarantined = %#v, want fail-closed Keeper reader requirement", quarantined)
	}
}

type identifiedBlockResult struct {
	effects       []ReconcilerEffect
	observedTypes string
	rawTypes      string
}

// applyIdentifiedBlock serves one block of raw ABCI events over a fake CometBFT
// RPC, reads it back through a CometEventClient configured with identifier (nil
// selects the shipped message-name layer), and applies the result to a fresh
// reconciler.
func applyIdentifiedBlock(t *testing.T, identifier chainclient.EventIdentifier, blockEvents string) identifiedBlockResult {
	t.Helper()
	ctx := context.Background()
	txBytes := []byte("assignment-tx")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"node_info":{"network":"trueopen-devnet-1"},"sync_info":{"latest_block_height":"12"}}}`))
		case "/block_results":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"height":"12","txs_results":[{"code":0,"events":` + blockEvents + `}],"finalize_block_events":[]}}`))
		case "/block":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"block":{"header":{"chain_id":"trueopen-devnet-1","height":"12"},"data":{"txs":["` + base64.StdEncoding.EncodeToString(txBytes) + `"]}}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	events := chainclient.NewCometEventClient(chainclient.CometEventClientConfig{
		RPCURL:     server.URL,
		ChainID:    "trueopen-devnet-1",
		Identifier: identifier,
	})
	page, err := events.FinalizedEvents(ctx, chainclient.EventPosition{Height: 11})
	if err != nil {
		t.Fatalf("FinalizedEvents() error = %v", err)
	}
	if len(page.Events) != 2 {
		t.Fatalf("page events = %#v, want both protocol events", page.Events)
	}
	result := identifiedBlockResult{}
	for _, event := range page.Events {
		if event.Quarantined {
			t.Fatalf("event %#v quarantined: %s", event, event.QuarantineReason)
		}
		result.observedTypes += string(event.Type) + ";"
		result.rawTypes += event.RawType + ";"
	}

	hash := codec.HashWithDomain("TEST_ORDER", []byte("task-1"))
	snapshot := validTaskSnapshot("session-1", "task-1", hash)
	snapshot.Assignment.SelectedWorker = "worker-local"
	reconciler := NewReconciler(ReconcilerOptions{TaskReader: staticKeeperTaskReader{snapshot: snapshot}})
	effects, err := reconciler.Apply(ctx, page.Events)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	result.effects = effects
	return result
}
