package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	busv1 "github.com/TrueOpen/cortex/proto/bus/v1"
)

// The handraise itself no longer needs to know which Builder to fetch from - per
// data-plane-and-evidence-transfer.md §6 a candidate is not allowed to query the data plane at all - but
// "who sent the OPEN_VERIFY" is still the only clue that locates the holder when
// debugging, and the on-chain task snapshot does not carry that field.
//
// Only a Builder that accepted the receipt and holds the data locally sends
// OPEN_VERIFY (§5.8), so the envelope's sender necessarily holds the output. When the
// snapshot has none, the sender is recorded into the trace instead - the same thing
// the Worker side does when it fills BroadcastingBuilder from the sender of
// ORDER_BROADCAST. Without it, a V7a fetch has nothing left but "receiving Builder
// operator is required" and no candidate address anywhere in the log.
func TestOpenVerifyFallsBackToTheSendingBuilderForOutputConfirmation(t *testing.T) {
	fixture := newOutputAvailableFixture(t)
	if fixture.snapshot.Assignment.BuilderOperatorAddress != "" {
		t.Fatal("test premise: the on-chain snapshot carries no Builder address")
	}

	if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err != nil {
		t.Fatalf("OpenVerify was refused: %v", err)
	}
	// Not one data-plane call happens during the handraise.
	if len(fixture.confirmer.received) != 0 {
		t.Fatalf("task-data plane calls = %#v, want none from a candidate", fixture.confirmer.received)
	}
	requireTraceFields(t, fixture.trace.event(t, "output_metadata_confirmed"),
		`source="open_verify+keeper"`, `builder="builder-1"`, "output_size_bytes=4096")
}

func TestBuilderRelayedOutputAvailableDoesNotBecomeTheDataReadyBuilder(t *testing.T) {
	ctx := context.Background()
	fixture := newOutputAvailableFixture(t)
	subject := builderclient.NATSOutputAvailableSubject(fixture.taskID)
	frame, err := builderclient.EncodeUnsignedBusMessage(builderclient.UnsignedEnvelopeInput{
		Kind: builderclient.KindOutputAvailable, ChainID: "chain", Subject: subject,
		SenderOperatorAddress: "relay-builder", SenderParticipantType: builderclient.ParticipantBuilder,
		ServiceAuthorizationNonce: envelopeTestAuthorizationNonce,
	}, fixture.fullHint(), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.runner.HandleNexusMessage(ctx, builderclient.NATSMessage{Subject: subject, Data: frame, JetStream: true}); err != nil {
		t.Fatal(err)
	}

	taskHash := codec.Hash(fixture.snapshot.Assignment.TaskReceiptFactsSnapshot.AcceptedTaskHash)
	admission, err := layout.GetVerifierAdmission(ctx, fixture.runner.cfg.Store, layout.StoredHash(taskHash), 1)
	if err != nil {
		t.Fatal(err)
	}
	if admission.DataReadyBuilderOperator != "" {
		t.Fatalf("Builder-relayed OUTPUT_AVAILABLE persisted data-ready Builder %q", admission.DataReadyBuilderOperator)
	}

	if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err != nil {
		t.Fatal(err)
	}
	admission, err = layout.GetVerifierAdmission(ctx, fixture.runner.cfg.Store, layout.StoredHash(taskHash), 1)
	if err != nil {
		t.Fatal(err)
	}
	if admission.DataReadyBuilderOperator != "builder-1" {
		t.Fatalf("data-ready Builder = %q, want OPEN_VERIFY sender builder-1", admission.DataReadyBuilderOperator)
	}
	taskHash, ready, _ := formalVerifyReadySnapshot(t, fixture)
	if err := fixture.runner.ApplyReconcilerEffects(ctx, []ReconcilerEffect{{
		Type: ReconcilerEffectVerifyReady, TaskHash: taskHash, TaskID: fixture.taskID, Snapshot: ready,
	}}); err != nil {
		t.Fatal(err)
	}
	task, err := layout.GetTaskRecord(ctx, fixture.runner.cfg.Store, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatal(err)
	}
	if task.BuilderOperatorAddress != "builder-1" {
		t.Fatalf("formal responsibility Builder = %q, want OPEN_VERIFY sender builder-1", task.BuilderOperatorAddress)
	}
}

// OPEN_VERIFY's authenticated sender is a data-ready Task Builder:
// interface-and-topic-list.md §5.8 permits it only "when it holds the data the protocol requires
// locally". QueryTask's assignment projection deliberately carries no Builder, so the
// completed candidacy is the only currently deployable source that can survive until
// this node is formally selected.
func TestVerifyReadyCarriesOpenVerifyBuilderReceiptAndSelectionBeacon(t *testing.T) {
	ctx := context.Background()
	fixture := newOutputAvailableFixture(t)
	if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err != nil {
		t.Fatalf("OpenVerify was refused: %v", err)
	}
	taskHash := codec.Hash(fixture.snapshot.Assignment.TaskReceiptFactsSnapshot.AcceptedTaskHash)
	admission, err := layout.GetVerifierAdmission(ctx, fixture.runner.cfg.Store, layout.StoredHash(taskHash), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !admission.Completed || admission.DataReadyBuilderOperator != "builder-1" {
		t.Fatalf("completed admission = %#v, want its authenticated data-ready Builder", admission)
	}

	taskHash, ready, seed := formalVerifyReadySnapshot(t, fixture)
	if err := fixture.runner.ApplyReconcilerEffects(ctx, []ReconcilerEffect{{
		Type: ReconcilerEffectVerifyReady, TaskHash: taskHash, TaskID: fixture.taskID, Snapshot: ready,
	}}); err != nil {
		t.Fatal(err)
	}

	task, err := layout.GetTaskRecord(ctx, fixture.runner.cfg.Store, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatal(err)
	}
	verify, err := layout.GetVerifyRecord(ctx, fixture.runner.cfg.Store, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatal(err)
	}
	wantReceipt := layout.StoredHashFromCodec(codec.Hash(ready.InferReceipt.InferReceiptHash))
	if task.BuilderOperatorAddress != "builder-1" || verify.InferReceiptDigest != wantReceipt || verify.VerificationSampleSeed != layout.StoredHash(seed) {
		t.Fatalf("formal verify responsibility = task %#v verify %#v", task, verify)
	}
	requireTraceFields(t, fixture.trace.event(t, "keeper_verify_ready"),
		`builder="builder-1"`, `infer_receipt_hash=`+wantReceipt.String())
}

func TestOpenVerifyBackfillsTheDataReadyBuilderAfterVerifyReady(t *testing.T) {
	ctx := context.Background()
	fixture := newOutputAvailableFixture(t)
	if err := fixture.deliver(t, fixture.fullHint()); err != nil {
		t.Fatal(err)
	}
	taskHash, ready, _ := formalVerifyReadySnapshot(t, fixture)
	if err := fixture.runner.ApplyReconcilerEffects(ctx, []ReconcilerEffect{{
		Type: ReconcilerEffectVerifyReady, TaskHash: taskHash, TaskID: fixture.taskID, Snapshot: ready,
	}}); err != nil {
		t.Fatal(err)
	}
	before, err := layout.GetTaskRecord(ctx, fixture.runner.cfg.Store, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatal(err)
	}
	if before.BuilderOperatorAddress != "" {
		t.Fatalf("Builder before OPEN_VERIFY = %q, want empty", before.BuilderOperatorAddress)
	}

	if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err != nil {
		t.Fatal(err)
	}
	after, err := layout.GetTaskRecord(ctx, fixture.runner.cfg.Store, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatal(err)
	}
	if after.BuilderOperatorAddress != "builder-1" {
		t.Fatalf("Builder after OPEN_VERIFY = %q, want builder-1", after.BuilderOperatorAddress)
	}
}

func TestVerifyReadyDoesNotInheritABuilderFromDifferentReceiptFacts(t *testing.T) {
	ctx := context.Background()
	fixture := newOutputAvailableFixture(t)
	if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err != nil {
		t.Fatal(err)
	}
	taskHash, ready, _ := formalVerifyReadySnapshot(t, fixture)
	otherReceipt := codec.HashBytes([]byte("different-keeper-receipt"))
	ready.InferReceipt.InferReceiptHash = chainclient.HexHash(otherReceipt)
	if err := fixture.runner.ApplyReconcilerEffects(ctx, []ReconcilerEffect{{
		Type: ReconcilerEffectVerifyReady, TaskHash: taskHash, TaskID: fixture.taskID, Snapshot: ready,
	}}); err != nil {
		t.Fatal(err)
	}
	task, err := layout.GetTaskRecord(ctx, fixture.runner.cfg.Store, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatal(err)
	}
	if task.BuilderOperatorAddress != "" {
		t.Fatalf("mismatched admission supplied Builder %q", task.BuilderOperatorAddress)
	}
}

func formalVerifyReadySnapshot(t *testing.T, fixture *outputAvailableFixture) (codec.Hash, chainclient.TaskSnapshot, codec.Hash) {
	t.Helper()
	ctx := context.Background()
	taskHash := codec.Hash(fixture.snapshot.Assignment.TaskReceiptFactsSnapshot.AcceptedTaskHash)
	currentTask, err := layout.GetTaskRecord(ctx, fixture.runner.cfg.Store, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatal(err)
	}
	ready := fixture.snapshot
	ready.Status = "VERIFY_READY"
	ready.Assignment.BuilderOperatorAddress = ""
	ready.Assignment.AcceptedOrderPayloadHash = chainclient.HexHash(currentTask.AssignmentOrderDigest)
	seed := codec.HashBytes([]byte("selection-randomness-beacon"))
	ready.VerifierAssignment = chainclient.VerifierAssignmentSnapshot{VerifyRound: chainclient.NewUint64String(1),
		SessionID: fixture.sessionID, TaskID: fixture.taskID,
		OpenVerifyHeight:            chainclient.NewUint64String(22),
		FormalVerifierSet:           chainclient.CSVStrings{"verifier-1"},
		SampleSeedReadyHeight:       chainclient.NewUint64String(25),
		VerificationSampleSeed:      chainclient.HexHash(seed),
		CommitDeadlineHeight:        chainclient.NewUint64String(30),
		VerifyDeadlineHeight:        chainclient.NewUint64String(60),
		SampleSeedStatus:            "READY",
		VerifierCandidateWindowHash: chainclient.HexHash(codec.HashBytes([]byte("candidate-window"))),
	}
	return taskHash, ready, seed
}

func TestCompletedOutputHintDoesNotTrustAnUnvalidatedOpenVerifySender(t *testing.T) {
	ctx := context.Background()
	fixture := newOutputAvailableFixture(t)
	if err := fixture.deliver(t, fixture.fullHint()); err != nil {
		t.Fatal(err)
	}
	forged := fixture.openVerifyCall()
	otherReceipt := codec.HashBytes([]byte("other-infer-receipt"))
	forged.InferReceiptHash = append([]byte(nil), otherReceipt[:]...)
	if err := fixture.deliverOpenVerify(t, forged); err == nil {
		t.Fatal("completed candidacy accepted an OPEN_VERIFY that contradicts Keeper")
	}

	taskHash := codec.Hash(fixture.snapshot.Assignment.TaskReceiptFactsSnapshot.AcceptedTaskHash)
	admission, err := layout.GetVerifierAdmission(ctx, fixture.runner.cfg.Store, layout.StoredHash(taskHash), 1)
	if err != nil {
		t.Fatal(err)
	}
	wantReceipt := layout.StoredHashFromCodec(codec.Hash(fixture.snapshot.InferReceipt.InferReceiptHash))
	if admission.DataReadyBuilderOperator != "" || admission.InferReceiptHash != wantReceipt {
		t.Fatalf("completed admission trusted unvalidated sender facts: %#v", admission)
	}
}

func TestOpenVerifyContradictionsNeverPersistTheDataReadyBuilder(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*outputAvailableFixture, *busv1.OpenVerifyV1)
	}{
		{name: "missing task hash", mutate: func(_ *outputAvailableFixture, call *busv1.OpenVerifyV1) { call.TaskHash = nil }},
		{name: "wrong task hash with local record", mutate: func(_ *outputAvailableFixture, call *busv1.OpenVerifyV1) {
			wrong := codec.HashBytes([]byte("wrong-task-hash"))
			call.TaskHash = append([]byte(nil), wrong[:]...)
		}},
		{name: "wrong model", mutate: func(_ *outputAvailableFixture, call *busv1.OpenVerifyV1) { call.ModelId = "other-model" }},
		{name: "wrong profile", mutate: func(_ *outputAvailableFixture, call *busv1.OpenVerifyV1) { call.ProfileVersion = 2 }},
		{name: "wrong round", mutate: func(_ *outputAvailableFixture, call *busv1.OpenVerifyV1) { call.VerifyRound = 2 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			fixture := newOutputAvailableFixture(t)
			if err := fixture.deliver(t, fixture.fullHint()); err != nil {
				t.Fatal(err)
			}
			call := fixture.openVerifyCall()
			test.mutate(fixture, call)
			if err := fixture.deliverOpenVerify(t, call); err == nil {
				t.Fatal("contradictory OPEN_VERIFY was accepted")
			}

			taskHash := codec.Hash(fixture.snapshot.Assignment.TaskReceiptFactsSnapshot.AcceptedTaskHash)
			admission, err := layout.GetVerifierAdmission(ctx, fixture.runner.cfg.Store, layout.StoredHash(taskHash), 1)
			if errors.Is(err, store.ErrNotFound) {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if admission.DataReadyBuilderOperator != "" {
				t.Fatalf("contradictory OPEN_VERIFY persisted Builder %q", admission.DataReadyBuilderOperator)
			}
		})
	}
}

func TestVerifyReadySurfacesAMalformedVerifierAdmission(t *testing.T) {
	ctx := context.Background()
	fixture := newOutputAvailableFixture(t)
	taskHash, ready, _ := formalVerifyReadySnapshot(t, fixture)
	if err := fixture.runner.cfg.Store.PutRaw(ctx, layout.VerifyCandidateKey(layout.StoredHash(taskHash), 1), []byte("{")); err != nil {
		t.Fatal(err)
	}

	err := fixture.runner.ApplyReconcilerEffects(ctx, []ReconcilerEffect{{
		Type: ReconcilerEffectVerifyReady, TaskHash: taskHash, TaskID: fixture.taskID, Snapshot: ready,
	}})
	if err == nil || !strings.Contains(err.Error(), "read verifier admission") {
		t.Fatalf("ApplyReconcilerEffects() error = %v, want malformed admission surfaced", err)
	}
	verify, err := layout.GetVerifyRecord(ctx, fixture.runner.cfg.Store, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatal(err)
	}
	if !verify.VerificationSampleSeed.IsZero() {
		t.Fatalf("formal responsibility was partially written: %#v", verify)
	}
}
