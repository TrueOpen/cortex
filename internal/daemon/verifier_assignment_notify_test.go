package daemon

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	busv1 "github.com/TrueOpen/cortex/proto/bus/v1"
	bustaskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

const notifyTestTaskID = "abababababababababababababababababababababababababababababababab"

// §5.9 puts VERIFIER_ASSIGNMENT_NOTIFY on one per-task subject that every
// candidate is subscribed to, so a node the chain did not select receives the
// announcement of a duty it does not hold. Not being selected is a normal
// terminal state -- the losing-Worker half of WORKER_ASSIGNMENT_NOTIFY has
// always been acknowledged this way -- and refusing instead costs a JetStream
// redelivery loop: measured on trueopen-localnet-1, 78 refusals over 36 seconds
// per task until the envelope expired.
func TestVerifierAssignmentNotifyIsAcknowledgedByANodeTheChainDidNotSelect(t *testing.T) {
	ctx := context.Background()
	runner := notifyTestRunner(t, "verifier-9")
	message := notifyTestMessage()

	if err := runner.recordVerifierAssignment(ctx, notifyTestEnvelope(t, message), message); err != nil {
		t.Fatalf("recordVerifierAssignment() error = %v, want an acknowledged no-op for an unselected node", err)
	}
}

// A node the announcement does name still has to wait for the Keeper effect
// that writes its verify record, and the wait must say which record is missing.
// The refusal used to read "Keeper verifier assignment ... is not available",
// which sent an operator to the chain for a lookup that never happened: the
// failing read is the local Pebble secondary index.
func TestVerifierAssignmentNotifyNamesTheLocalRecordItIsWaitingFor(t *testing.T) {
	ctx := context.Background()
	runner := notifyTestRunner(t, "verifier-1")
	message := notifyTestMessage()

	err := runner.recordVerifierAssignment(ctx, notifyTestEnvelope(t, message), message)
	if err == nil || !builderclient.IsRetryable(err) {
		t.Fatalf("recordVerifierAssignment() error = %v, want a retryable wait for the selected node", err)
	}
	if strings.Contains(err.Error(), "Keeper verifier assignment") || !strings.Contains(err.Error(), "local verify record") {
		t.Fatalf("refusal = %q, want it to name the local verify record", err)
	}
}

// A notify with no output_hash cannot be reconciled against the Keeper
// snapshot, so it is refused -- but the refusal has to assert that no
// redelivery can fix it. verifier-assignment is in outbox.verifierFrame, whose
// blanket redelivery is by subject rather than by verdict, so an unmarked
// refusal NAKs until the envelope expires: measured on devnet 2026-09-07,
// 50/50/51 refusals per Verifier over 32 seconds for task 3a29ef28..., because
// two of the three Builders in the proposal group publish this frame without
// ever having held the Worker's receipt (nexus#67). The obligation itself is
// never at risk -- it was written by the Keeper effect 27 seconds earlier --
// and the refusal must name the field so the peer's defect is readable.
func TestVerifierAssignmentNotifyWithoutAnOutputHashIsRefusedPermanently(t *testing.T) {
	ctx := context.Background()
	fixture := newVerifierControlFixture(t)
	incomplete := fixture.keeperVerifierAssignment()
	incomplete.OutputHash = nil

	err := fixture.runner.recordVerifierAssignment(ctx, fixture.verifierAssignmentEnvelope(t, incomplete), incomplete)
	if err == nil {
		t.Fatal("recordVerifierAssignment() = nil, want a refusal for a notify with no output hash")
	}
	if !builderclient.IsPermanent(err) {
		t.Fatalf("refusal = %v, want it asserted permanent so the frame is acknowledged instead of redelivered", err)
	}
	if !strings.Contains(err.Error(), "output_hash") {
		t.Fatalf("refusal = %q, want it to name output_hash", err)
	}
}

func notifyTestRunner(t *testing.T, localVerifier string) *TaskRunner {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	snapshot := verifierAssignedTaskSnapshot("session-1", notifyTestTaskID,
		codec.HashWithDomain("TEST_ORDER", []byte(notifyTestTaskID)), "verifier-1", "verifier-2", "verifier-3")
	return NewTaskRunner(TaskRunnerConfig{
		Store: db, LocalVerifierAddress: localVerifier,
		TaskReader: staticKeeperTaskReader{snapshot: snapshot},
	})
}

func notifyTestMessage() *busv1.VerifierAssignmentNotifyV1 {
	taskID, _ := hex.DecodeString(notifyTestTaskID)
	return &busv1.VerifierAssignmentNotifyV1{
		TaskId: taskID, VerifyRound: 1,
		Verifiers: []*bustaskv1.SelectedVerifierV1{
			{OperatorAddress: "verifier-1"}, {OperatorAddress: "verifier-2"}, {OperatorAddress: "verifier-3"},
		},
		OutputHash:       make([]byte, 32),
		OpenVerifyHeight: 22, CommitDeadlineHeight: 30, RevealDeadlineHeight: 50, VerifyDeadlineHeight: 60,
	}
}

func notifyTestEnvelope(t *testing.T, message *busv1.VerifierAssignmentNotifyV1) builderclient.BusEnvelope {
	t.Helper()
	return testBusEnvelope(t, builderclient.KindVerifierAssignmentNotify, builderclient.ParticipantBuilder,
		builderclient.NATSVerifierAssignmentSubject(notifyTestTaskID), message)
}
