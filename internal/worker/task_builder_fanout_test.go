package worker

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// taskBuilderSet is the three Task Builders of one task, each with its own
// operator address, endpoint and service key, in the order the chain froze them.
// The first is the assigned Builder: the one the receipt is relayed through.
type taskBuilderSet struct {
	endpoints []BuilderEndpoint
	keys      map[string]*secp256k1.PrivateKey
}

func newTaskBuilderSet(assigned BuilderEndpoint) taskBuilderSet {
	set := taskBuilderSet{endpoints: []BuilderEndpoint{assigned}, keys: map[string]*secp256k1.PrivateKey{}}
	for _, member := range []struct {
		operator, endpoint string
		seed               byte
	}{
		{"trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe", "https://builder-2.example", 0x53},
		{"trueopen1q8fazf4duvmw5as74kgyyezdxdewahzydav3vl", "https://builder-3.example", 0x64},
	} {
		key := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{member.seed}, 32))
		set.endpoints = append(set.endpoints, BuilderEndpoint{
			OperatorAddress: member.operator, Endpoint: member.endpoint,
			ServicePubkey:      hex.EncodeToString(key.PubKey().SerializeCompressed()),
			CurrentHeight:      assigned.CurrentHeight,
			AuthorizationNonce: assigned.AuthorizationNonce,
		})
		set.keys[member.endpoint] = key
	}
	return set
}

type taskBuilderSetProvider struct{ set taskBuilderSet }

func (p taskBuilderSetProvider) ResolveReceivingBuilder(context.Context, ReceivingBuilderRef) (BuilderEndpoint, error) {
	return p.set.endpoints[0], nil
}

func (p taskBuilderSetProvider) ResolveReceivingBuilders(context.Context, ReceivingBuilderRef) ([]BuilderEndpoint, error) {
	return append([]BuilderEndpoint(nil), p.set.endpoints...), nil
}

// withTaskBuilderSet points the harness at three Task Builders instead of one
// and teaches the task-data fake which key each of them signs with.
func withTaskBuilderSet(t *testing.T, h harness) taskBuilderSet {
	t.Helper()
	assigned, err := h.worker.cfg.ReceivingBuilder.ResolveReceivingBuilder(context.Background(), ReceivingBuilderRef{})
	if err != nil {
		t.Fatalf("default receiving Builder: %v", err)
	}
	set := newTaskBuilderSet(assigned)
	h.worker.cfg.ReceivingBuilder = taskBuilderSetProvider{set: set}
	h.taskData.builderKeys = set.keys
	return set
}

func countEndpoint(endpoints []string, want string) int {
	n := 0
	for _, endpoint := range endpoints {
		if endpoint == want {
			n++
		}
	}
	return n
}

func confirmationsFor(records []StorageConfirmationCheckpoint, operator string) int {
	n := 0
	for _, record := range records {
		if record.BuilderOperator == operator {
			n++
		}
	}
	return n
}

// Every Task Builder has to end up holding the evidence and a Finalize of its
// own, because data-ready is judged per Builder from its own local copy: one
// that never received the evidence never sends OPEN_VERIFY and never proposes a
// Verifier, however complete the other two are.
func TestWorkerEvidenceReachesEveryTaskBuilder(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	set := withTaskBuilderSet(t, h)
	h.seedPreparedOutput(t, event)

	if _, err := New(h.worker.cfg).HandleAssignmentFinalized(context.Background(), event); err != nil {
		t.Fatalf("HandleAssignmentFinalized: %v", err)
	}

	// Six evidence objects and two finalizes on each Builder; the receipt relay
	// adds one more call to the assigned Builder alone.
	for i, builder := range set.endpoints {
		want := 8
		if i == 0 {
			want = 9
		}
		if got := countEndpoint(h.taskData.endpoints, builder.Endpoint); got != want {
			t.Fatalf("Task Builder %s saw %d task-data calls, want %d: %v",
				builder.OperatorAddress, got, want, h.taskData.endpoints)
		}
		// One output confirmation and one per bundle, verified against that
		// Builder's own service key.
		if got := confirmationsFor(h.persistence.confirmations, builder.OperatorAddress); got != 3 {
			t.Fatalf("Task Builder %s stored %d confirmations, want 3: %#v",
				builder.OperatorAddress, got, h.persistence.confirmations)
		}
	}
	if len(h.taskData.relays) != 1 {
		t.Fatalf("relays = %d, want the receipt to reach the chain once", len(h.taskData.relays))
	}
}

// One Builder being down must not take the task with it. The protocol wants the
// material on all three, but it only needs one to drive verification, and that
// is the floor the single-Builder path already ran at.
func TestWorkerFinalizesOnTheRemainingTaskBuildersWhenOneFails(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	set := withTaskBuilderSet(t, h)
	down := set.endpoints[2]
	h.taskData.finalizeEndpointErrors = map[string]error{down.Endpoint: fmt.Errorf("Task Builder is offline")}
	h.seedPreparedOutput(t, event)

	if _, err := New(h.worker.cfg).HandleAssignmentFinalized(context.Background(), event); err != nil {
		t.Fatalf("one Builder down failed the whole task: %v", err)
	}
	for _, builder := range set.endpoints[:2] {
		if got := confirmationsFor(h.persistence.confirmations, builder.OperatorAddress); got != 3 {
			t.Fatalf("Task Builder %s stored %d confirmations, want 3", builder.OperatorAddress, got)
		}
	}
	if got := confirmationsFor(h.persistence.confirmations, down.OperatorAddress); got != 0 {
		t.Fatalf("the offline Builder stored %d confirmations, want none", got)
	}

	// A Builder that failed left no confirmation behind, so re-entering the
	// relay retries precisely it and leaves the two that succeeded alone.
	before := len(h.taskData.endpoints)
	h.taskData.finalizeEndpointErrors = nil
	if _, err := New(h.worker.cfg).HandleAssignmentFinalized(context.Background(), event); err != nil {
		t.Fatalf("resumed HandleAssignmentFinalized: %v", err)
	}
	retried := h.taskData.endpoints[before:]
	if got := countEndpoint(retried, down.Endpoint); got != 8 {
		t.Fatalf("retry sent %d calls to the recovered Builder, want its six objects and two finalizes: %v", got, retried)
	}
	// The assigned Builder still sees the receipt relay, which is once per
	// re-entry rather than once per task and was already so before the fan-out;
	// what it must not see again is any of its evidence.
	if got := countEndpoint(retried, set.endpoints[0].Endpoint); got != 1 || len(h.taskData.relays) != 2 {
		t.Fatalf("retry sent %d calls and %d relays to the assigned Builder, want the receipt relay alone: %v",
			got, len(h.taskData.relays), retried)
	}
	if got := countEndpoint(retried, set.endpoints[1].Endpoint); got != 0 {
		t.Fatalf("retry re-uploaded %d objects to Task Builder %s, which was already confirmed",
			got, set.endpoints[1].OperatorAddress)
	}
	if got := confirmationsFor(h.persistence.confirmations, down.OperatorAddress); got != 3 {
		t.Fatalf("the recovered Builder stored %d confirmations, want 3", got)
	}
}
