package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
)

// openVerifyCall is the OPEN_VERIFY body a Builder sends when it agrees with the
// chain: the Keeper receipt this fixture serves, restated (interface-and-topic-list.md §5.6).
func (f *openVerifyFixture) openVerifyCall() *nexusv1.OpenVerifyV1 {
	receiptHash := codec.Hash(f.snapshot.InferReceipt.InferReceiptHash)
	taskHash := codec.Hash(f.snapshot.Assignment.TaskReceiptFactsSnapshot.AcceptedTaskHash)
	taskID, _ := hex.DecodeString(f.taskID)
	return &nexusv1.OpenVerifyV1{
		TaskId: taskID, TaskHash: append([]byte(nil), taskHash[:]...), ModelId: bytes.Repeat([]byte{0x01}, 32), ProfileVersion: 1,
		InferReceiptHash:      append([]byte(nil), receiptHash[:]...),
		OutputHash:            append([]byte(nil), f.pkg.OutputHash[:]...),
		WorkerOperatorAddress: "worker-1", VerifyRound: 1,
	}
}

// deliverOpenVerify hands the call to the runner as the stream session will,
// with builder-1 as the Builder the stream is bound to.
func (f *openVerifyFixture) deliverOpenVerify(t *testing.T, message *nexusv1.OpenVerifyV1) error {
	t.Helper()
	return f.runner.admitOpenVerify(context.Background(), "builder-1", message)
}

// OPEN_VERIFY is the Verifier-side counterpart of OPEN_TASK (interface-and-topic-list.md
// §5.6): receiving it has to reach the Verifier precheck and send the
// handraise, or a node that received the call can never appear in the
// assignment the call is collecting candidates for.
func TestOpenVerifyReachesTheVerifierPrecheckAndPublishesTheHandraise(t *testing.T) {
	fixture := newOpenVerifyFixture(t)

	if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err != nil {
		t.Fatalf("OpenVerify was refused: %v", err)
	}
	fixture.assertHandraised(t)
}

// Every OpenVerify delivery shares one at-most-once claim, so a task that
// receives the frame twice raises its hand once; two handraises for one verify
// round would be two competing candidacies from the same operator.
func TestRepeatedOpenVerifyRaisesOneHand(t *testing.T) {
	fixture := newOpenVerifyFixture(t)

	if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err != nil {
		t.Fatalf("OpenVerify was refused: %v", err)
	}
	if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err != nil {
		t.Fatalf("second OpenVerify: %v", err)
	}
	fixture.assertHandraised(t)
}

// infer_receipt_hash is the commitment OPEN_VERIFY carries, and it is the whole
// point of the message: a
// Builder calling for verification of a receipt the chain does not hold is
// calling for verification of nothing. Nothing may be published on that call.
func TestOpenVerifyRefusesAnInferReceiptHashTheChainDoesNotHold(t *testing.T) {
	fixture := newOpenVerifyFixture(t)
	forged := fixture.openVerifyCall()
	other := codec.HashBytes([]byte("some other receipt"))
	forged.InferReceiptHash = append([]byte(nil), other[:]...)

	err := fixture.deliverOpenVerify(t, forged)
	if err == nil {
		t.Fatal("an OpenVerify naming a receipt Keeper does not hold was accepted")
	}
	if !strings.Contains(err.Error(), "infer_receipt_hash does not match") {
		t.Fatalf("error = %v, want the Keeper receipt comparison", err)
	}
	if len(fixture.sender.handraises) != 0 || len(fixture.confirmer.received) != 0 {
		t.Fatalf("published=%#v confirmed=%#v, want neither for a refused call",
			fixture.sender.handraises, fixture.confirmer.received)
	}
}
