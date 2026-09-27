package daemon

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
)

func TestReconcilerEmitsReplayStableAssignmentEffectsByTaskHash(t *testing.T) {
	ctx := context.Background()
	hash := codec.HashWithDomain("TEST_ORDER", []byte("task-1"))
	snapshot := validTaskSnapshot("session-1", "task-1", hash)
	r := NewReconciler(ReconcilerOptions{TaskReader: staticKeeperTaskReader{snapshot: snapshot}})
	event := chainclient.KeeperEvent{Type: chainclient.KeeperEventAssignmentFinalized, TaskID: "task-1", SessionID: "session-1", Worker: "worker-1", Height: 12}

	first, err := r.Apply(ctx, []chainclient.KeeperEvent{event})
	if err != nil {
		t.Fatalf("first Apply() error = %v", err)
	}
	second, err := r.Apply(ctx, []chainclient.KeeperEvent{event})
	if err != nil {
		t.Fatalf("replayed Apply() error = %v", err)
	}
	if !reflect.DeepEqual(second, first) {
		t.Fatalf("replayed effects = %#v, want stable %#v", second, first)
	}
	if len(first) != 1 || first[0].Type != ReconcilerEffectAssignment || first[0].TaskHash != hash || first[0].TaskID != "task-1" {
		t.Fatalf("effects = %#v, want task-hash-keyed assignment", first)
	}
	if first[0].AssignmentDigest == (codec.Hash{}) {
		t.Fatal("assignment digest is zero")
	}
}

func TestReconcilerEmitsTerminalCleanupByTaskHash(t *testing.T) {
	hash := codec.HashWithDomain("TEST_ORDER", []byte("task-terminal"))
	snapshot := validTaskSnapshot("session-1", "task-terminal", hash)
	snapshot.Status = "SETTLED"
	snapshot.Settlement = chainclient.SettlementSnapshot{TaskVerdict: "PASS", SettlementHeight: chainclient.NewUint64String(30)}
	r := NewReconciler(ReconcilerOptions{TaskReader: staticKeeperTaskReader{snapshot: snapshot}})
	effects, err := r.Apply(context.Background(), []chainclient.KeeperEvent{{
		Type: chainclient.KeeperEventSettleAccepted, TaskID: "task-terminal", SessionID: "session-1", OrderDigest: hash, Height: 30,
		ModelID: testModelID, ProfileVersion: "1", InferDeadlineHeight: 100,
		Attributes: map[string]string{"verdict": "PASS", "settlement_height": "30"},
	}})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(effects) != 1 || effects[0].Type != ReconcilerEffectTaskTerminal || effects[0].TaskHash != hash || effects[0].SettlementHeight != 30 || effects[0].TaskVerdict != "PASS" {
		t.Fatalf("effects = %#v, want terminal cleanup", effects)
	}
}

// A disagreement between an event and the Keeper snapshot it names is a
// permanent fact about a finalized block, so it must produce no effect *and*
// leave the poll loop alive: the reason reaches the operator as a quarantine
// record instead of as the error that used to stop the daemon.
func TestReconcilerRejectsTaskEventFactsThatDisagreeWithKeeperSnapshot(t *testing.T) {
	hash := codec.HashWithDomain("TEST_ORDER", []byte("task-1"))
	snapshot := validTaskSnapshot("session-1", "task-1", hash)
	snapshot.Status = "SETTLED"
	snapshot.Settlement = chainclient.SettlementSnapshot{TaskVerdict: "PASS", SettlementHeight: chainclient.NewUint64String(30)}

	tests := []struct {
		name string
		edit func(*chainclient.KeeperEvent)
		want string
	}{
		{name: "model", edit: func(e *chainclient.KeeperEvent) { e.ModelID = "model-other" }, want: "model"},
		{name: "profile", edit: func(e *chainclient.KeeperEvent) { e.ProfileVersion = "2" }, want: "profile"},
		{name: "infer deadline", edit: func(e *chainclient.KeeperEvent) { e.InferDeadlineHeight = 101 }, want: "infer deadline"},
		{name: "settlement height", edit: func(e *chainclient.KeeperEvent) { e.Attributes["settlement_height"] = "31" }, want: "settlement height"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := chainclient.KeeperEvent{Type: chainclient.KeeperEventSettleAccepted, TaskID: "task-1", SessionID: "session-1", OrderDigest: hash, Height: 30,
				ModelID: testModelID, ProfileVersion: "1", InferDeadlineHeight: 100,
				Attributes: map[string]string{"verdict": "PASS", "settlement_height": "30"}}
			test.edit(&event)
			var quarantined []chainclient.KeeperEvent
			r := NewReconciler(ReconcilerOptions{
				TaskReader:         staticKeeperTaskReader{snapshot: snapshot},
				OnQuarantinedEvent: func(event chainclient.KeeperEvent) { quarantined = append(quarantined, event) },
			})
			effects, err := r.Apply(context.Background(), []chainclient.KeeperEvent{event})
			if err != nil || len(effects) != 0 {
				t.Fatalf("Apply() effects=%#v error=%v, want no deletion effect and a live poll loop", effects, err)
			}
			if len(quarantined) != 1 || !strings.Contains(quarantined[0].QuarantineReason, test.want) {
				t.Fatalf("quarantined = %#v, want one record naming the %q mismatch", quarantined, test.want)
			}
		})
	}
}

func TestReconcilerNeverEmitsTerminalEffectWithoutAuthoritativeTaskSnapshot(t *testing.T) {
	hash := codec.HashWithDomain("TEST_ORDER", []byte("task-terminal"))
	var quarantined []chainclient.KeeperEvent
	r := NewReconciler(ReconcilerOptions{OnQuarantinedEvent: func(event chainclient.KeeperEvent) { quarantined = append(quarantined, event) }})
	effects, err := r.Apply(context.Background(), []chainclient.KeeperEvent{{
		Type: chainclient.KeeperEventAssignmentFailed, TaskID: "task-terminal", SessionID: "session-1", OrderDigest: hash, Height: 30,
	}})
	if err != nil || len(effects) != 0 {
		t.Fatalf("Apply() effects=%#v error=%v, want no unverified terminal deletion", effects, err)
	}
	if len(quarantined) != 1 || !strings.Contains(quarantined[0].QuarantineReason, "requires an authoritative Keeper task reader") {
		t.Fatalf("quarantined = %#v, want the missing-reader reason reported", quarantined)
	}
}

func TestReconcilerEmitsRoleCompletionEffects(t *testing.T) {
	hash := codec.HashWithDomain("TEST_ORDER", []byte("task-roles"))
	snapshot := validTaskSnapshot("session-1", "task-roles", hash)
	r := NewReconciler(ReconcilerOptions{TaskReader: staticKeeperTaskReader{snapshot: snapshot}})
	effects, err := r.Apply(context.Background(), []chainclient.KeeperEvent{
		// WorkerTimeout, not InferReceiptAccepted: the chain accepting the
		// receipt does not complete the Worker role, so it releases nothing.
		// See TestInferReceiptAcceptedKeepsTheInferResponsibility.
		{Type: chainclient.KeeperEventWorkerTimeout, TaskID: "task-roles", SessionID: "session-1", OrderDigest: hash, Height: 20},
		{Type: chainclient.KeeperEventResultCredentialAccepted, TaskID: "task-roles", SessionID: "session-1", OrderDigest: hash, Height: 21},
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	want := []ReconcilerEffectType{ReconcilerEffectInferTerminal, ReconcilerEffectVerifyTerminal}
	if len(effects) != len(want) {
		t.Fatalf("effects = %#v, want %v", effects, want)
	}
	for i := range want {
		if effects[i].Type != want[i] || effects[i].TaskHash != hash {
			t.Fatalf("effect %d = %#v, want %s for task hash", i, effects[i], want[i])
		}
	}
}

func TestReconcilerRequiresTaskHashForDurableEffect(t *testing.T) {
	snapshot := validTaskSnapshot("session-1", "task-no-hash", codec.HashWithDomain("TEST_ORDER", []byte("task-no-hash")))
	snapshot.Assignment.TaskReceiptFactsSnapshot = chainclient.TaskReceiptFactsSnapshot{}
	var quarantined []chainclient.KeeperEvent
	r := NewReconciler(ReconcilerOptions{
		TaskReader:         staticKeeperTaskReader{snapshot: snapshot},
		OnQuarantinedEvent: func(event chainclient.KeeperEvent) { quarantined = append(quarantined, event) },
	})
	effects, err := r.Apply(context.Background(), []chainclient.KeeperEvent{{Type: chainclient.KeeperEventAssignmentFailed, TaskID: "task-no-hash", SessionID: "session-1", Height: 10}})
	if err != nil || len(effects) != 0 {
		t.Fatalf("Apply() effects=%#v error=%v, want no effect keyed by a hash that does not exist", effects, err)
	}
	if len(quarantined) != 1 || !strings.Contains(quarantined[0].QuarantineReason, "missing accepted_task_hash") {
		t.Fatalf("quarantined = %#v, want the missing accepted_task_hash reason reported", quarantined)
	}
}

func TestReconcilerSkipsQuarantinedEventAndContinues(t *testing.T) {
	hash := codec.HashWithDomain("TEST_ORDER", []byte("task-good"))
	var quarantined []chainclient.KeeperEvent
	r := NewReconciler(ReconcilerOptions{TaskReader: staticKeeperTaskReader{snapshot: validTaskSnapshot("session-1", "good", hash)}, OnQuarantinedEvent: func(event chainclient.KeeperEvent) { quarantined = append(quarantined, event) }})
	effects, err := r.Apply(context.Background(), []chainclient.KeeperEvent{
		{Type: chainclient.KeeperEventAssignmentFinalized, TaskID: "bad", Height: 10, Quarantined: true},
		{Type: chainclient.KeeperEventAssignmentFailed, TaskID: "good", SessionID: "session-1", OrderDigest: hash, Height: 10},
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(quarantined) != 1 || len(effects) != 1 || effects[0].TaskHash != hash {
		t.Fatalf("quarantined=%#v effects=%#v", quarantined, effects)
	}
}

type staticKeeperTaskReader struct {
	snapshot chainclient.TaskSnapshot
	err      error
}

func (r staticKeeperTaskReader) Task(context.Context, string, string) (chainclient.TaskSnapshot, error) {
	if r.err != nil {
		return chainclient.TaskSnapshot{}, r.err
	}
	return r.snapshot, nil
}

func validTaskSnapshot(sessionID, taskID string, acceptedTaskHash codec.Hash) chainclient.TaskSnapshot {
	return chainclient.TaskSnapshot{Status: "ASSIGNED", Assignment: chainclient.AssignmentSnapshot{
		SessionID: sessionID, TaskID: taskID, OrderSequence: chainclient.NewUint64String(1),
		SelectedWorker: "worker-1", InferDeadlineHeight: chainclient.NewUint64String(100), WinnerConfirmHeight: chainclient.NewUint64String(12),
		ModelID: testModelID, ProfileVersion: chainclient.NewProfileVersion(1),
		AcceptedOrderPayloadHash: chainclient.HexHash(codec.HashWithDomain("TEST_PAYLOAD", []byte(taskID))),
		TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{AcceptedTaskHash: chainclient.ProtoBytes32(acceptedTaskHash[:])},
	}}
}

// TestReconcilerEffectTaskHashFromAcceptedTaskHash fails if the reconciler ever
// derives the durable effect key from OrderDigest instead of from the snapshot's
// AcceptedTaskHash. The event's OrderDigest is the order-envelope digest, which
// must remain separate from the accepted task hash used as the idempotency key.
func TestReconcilerEffectTaskHashFromAcceptedTaskHash(t *testing.T) {
	acceptedHash := codec.HashWithDomain("TEST_ACCEPTED", []byte("task-1"))
	orderDigest := codec.HashWithDomain("TEST_ORDER", []byte("task-1"))
	if acceptedHash == orderDigest {
		t.Fatal("test fixture must use distinct accepted and order digests")
	}
	snapshot := validTaskSnapshot("session-1", "task-1", acceptedHash)
	r := NewReconciler(ReconcilerOptions{TaskReader: staticKeeperTaskReader{snapshot: snapshot}})
	event := chainclient.KeeperEvent{
		Type: chainclient.KeeperEventAssignmentFinalized, TaskID: "task-1", SessionID: "session-1",
		Worker: "worker-1", Height: 12, OrderDigest: orderDigest,
	}
	effects, err := r.Apply(context.Background(), []chainclient.KeeperEvent{event})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(effects) != 1 {
		t.Fatalf("effects = %#v, want one assignment effect", effects)
	}
	if effects[0].TaskHash != acceptedHash {
		t.Fatalf("effect.TaskHash = %x, want accepted task hash %x", effects[0].TaskHash, acceptedHash)
	}
	if effects[0].Event.OrderDigest != orderDigest {
		t.Fatalf("effect.Event.OrderDigest = %x, want preserved order envelope digest %x", effects[0].Event.OrderDigest, orderDigest)
	}
}

func TestReconcilerEffectTaskHashFromGoldenFixture(t *testing.T) {
	ctx := context.Background()
	path := "../nodewire/testdata/accepted_task_hash_golden.json"
	fixtureData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden fixture: %v", err)
	}
	var fixture struct {
		OrderEnvelopeBase64   string `json:"order_envelope_base64"`
		AcceptedTaskHash      string `json:"accepted_task_hash"`
		AssignmentOrderDigest string `json:"assignment_order_digest"`
	}
	if err := json.Unmarshal(fixtureData, &fixture); err != nil {
		t.Fatalf("decode golden fixture: %v", err)
	}
	acceptedHash, err := hex.DecodeString(fixture.AcceptedTaskHash)
	if err != nil || len(acceptedHash) != 32 {
		t.Fatalf("invalid accepted_task_hash in fixture: %v", err)
	}
	orderDigest, err := hex.DecodeString(fixture.AssignmentOrderDigest)
	if err != nil || len(orderDigest) != 32 {
		t.Fatalf("invalid assignment_order_digest in fixture: %v", err)
	}

	var accepted codec.Hash
	copy(accepted[:], acceptedHash)
	var orderDigestHash codec.Hash
	copy(orderDigestHash[:], orderDigest)

	snapshot := validTaskSnapshot("session-1", "task-1", accepted)
	r := NewReconciler(ReconcilerOptions{TaskReader: staticKeeperTaskReader{snapshot: snapshot}})
	event := chainclient.KeeperEvent{
		Type: chainclient.KeeperEventAssignmentFinalized, TaskID: "task-1", SessionID: "session-1",
		Worker: "worker-1", Height: 12, OrderDigest: orderDigestHash,
	}
	effects, err := r.Apply(ctx, []chainclient.KeeperEvent{event})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(effects) != 1 {
		t.Fatalf("effects = %#v, want one assignment effect", effects)
	}
	if effects[0].TaskHash != accepted {
		t.Fatalf("effect.TaskHash = %x, want accepted task hash %x from golden fixture", effects[0].TaskHash, accepted)
	}
}

// TestReconcilerIgnoresSessionScopedDeadlineSweep pins the second half of the
// session-lifecycle sweep. Cortex keys every durable obligation by
// accepted_task_hash, and a sweep that names only a session has no task to
// terminate — so it must produce no effect and, crucially, no quarantine
// record: quarantining it reported a chain-side design decision as a Cortex
// fault on every session that ever expires.
func TestReconcilerIgnoresSessionScopedDeadlineSweep(t *testing.T) {
	var quarantined []chainclient.KeeperEvent
	r := NewReconciler(ReconcilerOptions{
		TaskReader:         staticKeeperTaskReader{err: errKeeperTaskUnavailable},
		OnQuarantinedEvent: func(event chainclient.KeeperEvent) { quarantined = append(quarantined, event) },
	})
	effects, err := r.Apply(context.Background(), []chainclient.KeeperEvent{{
		Type: chainclient.KeeperEventDeadlineSwept, SessionID: "session-1", Height: 13872,
	}})
	if err != nil {
		t.Fatalf("Apply() error = %v, want a session-scoped sweep accepted", err)
	}
	if len(effects) != 0 {
		t.Fatalf("effects = %#v, want none: a session sweep names no task obligation", effects)
	}
	if len(quarantined) != 0 {
		t.Fatalf("quarantined = %#v, want none", quarantined)
	}
}

var errKeeperTaskUnavailable = errors.New("Keeper task query must not be reached for a session-scoped sweep")

// TestTerminalEventFallsBackToLocalTaskHashWhenTheSnapshotIsUnreadable pins the
// recovery for a chain view that has become permanently unreadable.
//
// Observed on devnet: the sweep wrote VERIFY_FAILED without a verifier
// assignment (there was none - that is why it failed), and task's
// Query/Task treats VERIFY_FAILED as a status that must have one, so it answers
// codespace sdk code 6 forever. The reconciler needs the snapshot only for
// accepted_task_hash, so it quarantined the terminal event; the cost is not the
// quarantine record but that ReconcilerEffectTaskTerminal never landed, so the
// task's evidence was never marked terminal and its retention clock never
// started. The evidence then never expires.
//
// The local record is not a second authority: it is keyed by the very
// accepted_task_hash the snapshot would have supplied, written earlier from a
// snapshot that was readable. So the fallback is only ever used for a task this
// node already worked on, and only to key a terminal effect.
func TestTerminalEventFallsBackToLocalTaskHashWhenTheSnapshotIsUnreadable(t *testing.T) {
	hash := codec.HashWithDomain("TEST_ORDER", []byte("swept-task"))
	var quarantined []chainclient.KeeperEvent
	unreadable := errors.New(`Keeper /task.v1.Query/Task ABCI query failed (codespace "sdk" code 6): task verification status requires a verifier assignment`)
	r := NewReconciler(ReconcilerOptions{
		TaskReader:         staticKeeperTaskReader{err: unreadable},
		OnQuarantinedEvent: func(event chainclient.KeeperEvent) { quarantined = append(quarantined, event) },
		LocalTaskHash: func(_ context.Context, taskID string) (codec.Hash, bool) {
			if taskID != "swept-task" {
				return codec.Hash{}, false
			}
			return hash, true
		},
	})

	effects, err := r.Apply(context.Background(), []chainclient.KeeperEvent{{
		Type: chainclient.KeeperEventDeadlineSwept, TaskID: "swept-task", SessionID: "session-1", Height: 13772,
	}})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(effects) != 1 || effects[0].Type != ReconcilerEffectTaskTerminal || effects[0].TaskHash != hash {
		t.Fatalf("effects = %#v, want one terminal effect keyed by the local accepted task hash", effects)
	}
	if effects[0].Event.Height != 13772 {
		t.Fatalf("effect event = %#v, want the sweep height kept: it is where retention starts", effects[0].Event)
	}
	// The unreadable chain view is still reported. Recovering the obligation
	// must not hide a chain that cannot answer for one of its own tasks.
	if len(quarantined) != 1 || !strings.Contains(quarantined[0].QuarantineReason, "code 6") {
		t.Fatalf("quarantined = %#v, want the unreadable snapshot still reported", quarantined)
	}
}

// Without a local record there is nothing to key an effect by, so the event is
// quarantined exactly as before: inventing a task hash would write an
// obligation against a task this node never held.
func TestTerminalEventWithNoLocalRecordIsStillQuarantined(t *testing.T) {
	var quarantined []chainclient.KeeperEvent
	r := NewReconciler(ReconcilerOptions{
		TaskReader:         staticKeeperTaskReader{err: errors.New("code 6")},
		OnQuarantinedEvent: func(event chainclient.KeeperEvent) { quarantined = append(quarantined, event) },
		LocalTaskHash:      func(context.Context, string) (codec.Hash, bool) { return codec.Hash{}, false },
	})
	effects, err := r.Apply(context.Background(), []chainclient.KeeperEvent{{
		Type: chainclient.KeeperEventDeadlineSwept, TaskID: "never-mine", SessionID: "session-1", Height: 13772,
	}})
	if err != nil || len(effects) != 0 || len(quarantined) != 1 {
		t.Fatalf("effects=%#v quarantined=%#v error=%v", effects, quarantined, err)
	}
}

// The fallback is for terminal events only. A non-terminal event whose snapshot
// cannot be read carries facts the local record cannot supply - the assignment
// deadline, the model, the receipt commitments - so acting on it from local
// state would be inventing authority rather than recovering an obligation.
func TestNonTerminalEventDoesNotFallBackToLocalState(t *testing.T) {
	hash := codec.HashWithDomain("TEST_ORDER", []byte("assigned-task"))
	var quarantined []chainclient.KeeperEvent
	r := NewReconciler(ReconcilerOptions{
		TaskReader:         staticKeeperTaskReader{err: errors.New("code 6")},
		OnQuarantinedEvent: func(event chainclient.KeeperEvent) { quarantined = append(quarantined, event) },
		LocalTaskHash:      func(context.Context, string) (codec.Hash, bool) { return hash, true },
	})
	effects, err := r.Apply(context.Background(), []chainclient.KeeperEvent{{
		Type: chainclient.KeeperEventAssignmentFinalized, TaskID: "assigned-task", SessionID: "session-1",
		Worker: "worker-1", Height: 12,
	}})
	if err != nil || len(effects) != 0 || len(quarantined) != 1 {
		t.Fatalf("effects=%#v quarantined=%#v error=%v, want an unreadable assignment still refused", effects, quarantined, err)
	}
}

// terminalTaskSnapshot mirrors chainclient.snapshotFromTerminalTask: once a task
// settles the Keeper compacts it into TaskTerminalSummaryState, so the snapshot
// carries the settlement and the assignment identity and nothing else. The
// absent fields are the point of the fixture - no AcceptedOrderPayloadHash, no
// InferDeadlineHeight, no VerifierAssignment - so do not "complete" it.
func terminalTaskSnapshot(sessionID, taskID string, acceptedTaskHash codec.Hash) chainclient.TaskSnapshot {
	return chainclient.TaskSnapshot{
		Status: chainclient.TaskStatusTerminal, UpdatedHeight: chainclient.NewUint64String(30), CurrentContract: true,
		Assignment: chainclient.AssignmentSnapshot{
			SessionID: sessionID, TaskID: taskID, OrderSequence: chainclient.NewUint64String(1),
			SelectedWorker: "worker-1", ModelID: "model-1", ProfileVersion: chainclient.NewProfileVersion(1),
			TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{AcceptedTaskHash: chainclient.ProtoBytes32(acceptedTaskHash[:])},
		},
		Settlement: chainclient.SettlementSnapshot{TaskVerdict: "PASS", SettlementHeight: chainclient.NewUint64String(30)},
	}
}

// A node replaying from genesis reaches phase events of tasks that settled long
// ago. Their snapshots report zero for every phase field because the Keeper
// compacted them away, not because the event disagrees, so cross-checking those
// fields can never pass - and for EventRevealPhaseStarted the answer used to be
// a *retryable* error, which stopped the whole poll, left the cursor parked
// before that block, and made every fresh node replay the same window forever
// while chain_sync stayed 503 (#34).
//
// Each case here fails on the pre-fix reconciler: the reveal one as a returned
// error, the other two as quarantine records.
func TestReconcilerReplaysPhaseEventsOfSettledTasksWithoutStalling(t *testing.T) {
	hash := codec.HashWithDomain("TEST_ORDER", []byte("settled-task"))
	snapshot := terminalTaskSnapshot("session-1", "settled-task", hash)

	tests := []struct {
		name  string
		event chainclient.KeeperEvent
	}{
		{
			name: "reveal phase started",
			event: chainclient.KeeperEvent{
				Type: chainclient.KeeperEventRevealPhaseStarted, TaskID: "settled-task", SessionID: "session-1", Height: 15011,
				Attributes: map[string]string{"reveal_deadline_height": "115011"},
			},
		},
		{
			name: "open verify accepted",
			event: chainclient.KeeperEvent{
				Type: chainclient.KeeperEventOpenVerifyAccepted, TaskID: "settled-task", SessionID: "session-1", Height: 15012,
				Verifier: "verifier-1",
			},
		},
		{
			name: "assignment finalized with a compacted infer deadline",
			event: chainclient.KeeperEvent{
				Type: chainclient.KeeperEventAssignmentFinalized, TaskID: "settled-task", SessionID: "session-1", Height: 15011,
				Worker: "worker-1", InferDeadlineHeight: 115011,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var quarantined []chainclient.KeeperEvent
			r := NewReconciler(ReconcilerOptions{
				TaskReader:         staticKeeperTaskReader{snapshot: snapshot},
				OnQuarantinedEvent: func(event chainclient.KeeperEvent) { quarantined = append(quarantined, event) },
			})
			_, err := r.Apply(context.Background(), []chainclient.KeeperEvent{test.event})
			if err != nil {
				t.Fatalf("Apply() error = %v, want replay to advance past a settled task", err)
			}
			if chainclient.IsRetryable(err) {
				t.Fatal("Apply() returned a retryable error: the poller would park the cursor and re-read this block forever")
			}
			if len(quarantined) != 0 {
				t.Fatalf("quarantined = %#v, want none: a compacted phase field is not a contract mismatch", quarantined)
			}
		})
	}
}

// The allowance above is for compacted tasks only. While the chain still tracks
// a task, a zero reveal deadline means the queried node has not caught up -
// keeper §10.7 writes the height inside the very transition this event
// announces - so it must stay retryable. Quarantining it would discard the only
// carrier of the value and block the reveal for good.
func TestReconcilerStillRetriesZeroRevealDeadlineOnALiveTask(t *testing.T) {
	hash := codec.HashWithDomain("TEST_ORDER", []byte("live-task"))
	snapshot := validTaskSnapshot("session-1", "live-task", hash)
	if snapshot.Status == chainclient.TaskStatusTerminal {
		t.Fatal("fixture must be a live task for this test to mean anything")
	}
	if snapshot.VerifierAssignment.RevealDeadlineHeight.Uint64() != 0 {
		t.Fatal("fixture must carry a zero reveal deadline")
	}

	var quarantined []chainclient.KeeperEvent
	r := NewReconciler(ReconcilerOptions{
		TaskReader:         staticKeeperTaskReader{snapshot: snapshot},
		OnQuarantinedEvent: func(event chainclient.KeeperEvent) { quarantined = append(quarantined, event) },
	})
	_, err := r.Apply(context.Background(), []chainclient.KeeperEvent{{
		Type: chainclient.KeeperEventRevealPhaseStarted, TaskID: "live-task", SessionID: "session-1", Height: 40,
		Attributes: map[string]string{"reveal_deadline_height": "140"},
	}})
	if !chainclient.IsRetryable(err) {
		t.Fatalf("Apply() error = %v, want a retryable error so the poll re-reads the height", err)
	}
	if len(quarantined) != 0 {
		t.Fatalf("quarantined = %#v, want none: the event still carries the only copy of the deadline", quarantined)
	}
}
