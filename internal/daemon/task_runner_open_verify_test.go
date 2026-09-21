package daemon

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/codec"
	busv1 "github.com/SingaXYZ/cortex/proto/bus/v1"
)

// openVerifyCall is the OPEN_VERIFY body a Builder sends when it agrees with the
// chain: the Keeper receipt this fixture serves, restated (interface-and-topic-list.md §5.6).
func (f *outputAvailableFixture) openVerifyCall() *busv1.OpenVerifyV1 {
	receiptHash := codec.Hash(f.snapshot.InferReceipt.InferReceiptHash)
	taskHash := codec.Hash(f.snapshot.Assignment.TaskReceiptFactsSnapshot.AcceptedTaskHash)
	taskID, _ := hex.DecodeString(f.taskID)
	return &busv1.OpenVerifyV1{
		TaskId: taskID, TaskHash: append([]byte(nil), taskHash[:]...), ModelId: "model-1", ProfileVersion: 1,
		InferReceiptHash:      append([]byte(nil), receiptHash[:]...),
		OutputHash:            append([]byte(nil), f.pkg.OutputHash[:]...),
		WorkerOperatorAddress: "worker-1", VerifyRound: 1,
	}
}

// deliverOpenVerify publishes the call the way the Core tier would, through the
// subject and envelope decode path rather than straight into the handler.
func (f *outputAvailableFixture) deliverOpenVerify(t *testing.T, message *busv1.OpenVerifyV1) error {
	t.Helper()
	subject := builderclient.NATSVerifyOpenSubject(f.taskID)
	frame, err := builderclient.EncodeUnsignedBusMessage(builderclient.UnsignedEnvelopeInput{
		Kind: builderclient.KindOpenVerify, ChainID: "chain", Subject: subject,
		SenderOperatorAddress: "builder-1", SenderParticipantType: builderclient.ParticipantBuilder,
		ServiceAuthorizationNonce: envelopeTestAuthorizationNonce,
	}, message, true)
	if err != nil {
		t.Fatal(err)
	}
	return f.runner.HandleNexusMessage(context.Background(), builderclient.NATSMessage{Subject: subject, Data: frame})
}

// OPEN_VERIFY is the Verifier-side counterpart of OPEN_TASK (interface-and-topic-list.md
// §5.6): receiving it has to reach the Verifier precheck and publish on
// trueopen.handraise.verifier.<task_id>, or a node subscribed to the call can never
// appear in the assignment the call is collecting candidates for.
//
// Before the v1 vocabulary Cortex had no OPEN_VERIFY at all - the pre-v1 bus
// merged the call and the selection into VERIFY_SELECT_NOTIFY, and the only
// thing that could start a Verifier handraise here was the OUTPUT_AVAILABLE
// hint, a message §5.8 says triggers nothing.
func TestOpenVerifyReachesTheVerifierPrecheckAndPublishesTheHandraise(t *testing.T) {
	fixture := newOutputAvailableFixture(t)

	if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err != nil {
		t.Fatalf("OpenVerify was refused: %v", err)
	}
	fixture.assertHandraised(t)
}

// The call and the hint share one at-most-once claim, so a task that receives
// both raises its hand once. They are independent messages on different tiers
// and either can arrive first; two handraises for one verify round would be two
// competing candidacies from the same operator.
func TestOpenVerifyAndOutputAvailableRaiseOneHandBetweenThem(t *testing.T) {
	fixture := newOutputAvailableFixture(t)

	if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err != nil {
		t.Fatalf("OpenVerify was refused: %v", err)
	}
	if err := fixture.deliver(t, fixture.fullHint()); err != nil {
		t.Fatalf("OutputAvailable after OpenVerify: %v", err)
	}
	fixture.assertHandraised(t)
}

// infer_receipt_hash is the one commitment OPEN_VERIFY carries that the
// OUTPUT_AVAILABLE hint does not, and it is the whole point of the message: a
// Builder calling for verification of a receipt the chain does not hold is
// calling for verification of nothing. Nothing may be published on that call.
func TestOpenVerifyRefusesAnInferReceiptHashTheChainDoesNotHold(t *testing.T) {
	fixture := newOutputAvailableFixture(t)
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
	if len(fixture.builder.published) != 0 || len(fixture.confirmer.received) != 0 {
		t.Fatalf("published=%#v confirmed=%#v, want neither for a refused call",
			fixture.builder.published, fixture.confirmer.received)
	}
}
