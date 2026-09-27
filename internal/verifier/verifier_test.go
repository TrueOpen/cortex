package verifier

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TrueOpen/cortex/internal/evidence"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidencebundle"
	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/keepercontract"
	"github.com/TrueOpen/cortex/internal/metric"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/policy"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/taskfacts"
	"github.com/TrueOpen/cortex/internal/txclient"
	bustaskv1 "github.com/TrueOpen/cortex/proto/task/v1"
	"google.golang.org/protobuf/proto"
)

// The frozen TRUEOPEN_COMMIT_V1 preimage frames verifier_operator_address as
// address codec bytes, so the fixtures have to be real Bech32 addresses: a
// "verifier-1" placeholder is refused by the derivation rather than hashed.
const (
	fixtureVerifierAddress      = "trueopen1c5mpzp95cwm4syklatc07u2p2knan53rl38lmx"
	fixtureOtherVerifierAddress = "trueopen1zjfm0d6rcnc8jmkqlkllhw7gkf6kdr2pft0s6y"
	fixtureWorkerAddress        = "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc"
	fixtureThirdVerifierAddress = "trueopen13twauuzs7swcd2hxxa4e0detz9exzwegj5hncc"
	fixtureResultReveal         = "p000000=42|salt=001122"
)

func TestHandraiseOccursBeforeOpenVerifyAccepted(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = false

	result, err := h.verifier.EvaluateAndHandraise(context.Background(), state)
	if err != nil {
		t.Fatalf("handraise: %v", err)
	}

	if !result.Signed {
		t.Fatalf("verifier handraise was not signed")
	}
	if len(h.builder.Published) != 1 {
		t.Fatalf("published messages = %d, want handraise", len(h.builder.Published))
	}
	if h.model.VerifyCalls != 0 {
		t.Fatalf("verify calls = %d, want no verify before open verify", h.model.VerifyCalls)
	}
}

func TestVerifierHandraisePersistsBeforePublishing(t *testing.T) {
	h := newHarness(t)
	events := []string{}
	h.builder.Events = &events
	h.persistence.events = &events
	state := h.validTask()
	state.OpenVerifyAccepted = false

	result, err := h.verifier.EvaluateAndHandraise(context.Background(), state)
	if err != nil {
		t.Fatalf("handraise: %v", err)
	}

	if !result.Signed {
		t.Fatalf("verifier handraise was not signed")
	}
	if len(h.persistence.evidence) != 1 {
		t.Fatalf("evidence writes = %d, want verifier handraise evidence", len(h.persistence.evidence))
	}
	if h.persistence.evidence[0].Kind != "verifier-handraise" {
		t.Fatalf("evidence kind = %q, want verifier-handraise", h.persistence.evidence[0].Kind)
	}
	if len(h.persistence.settle) != 1 {
		t.Fatalf("settle materials = %d, want verifier handraise material", len(h.persistence.settle))
	}
	if h.persistence.settle[0].Kind != "verifier-handraise" {
		t.Fatalf("settle kind = %q, want verifier-handraise", h.persistence.settle[0].Kind)
	}
	wantSubject := builderclient.NATSVerifierHandraiseSubject(state.TaskID)
	wantEvents := []string{
		"evidence:verifier-handraise",
		"settle:verifier-handraise",
		"builder:publish",
	}
	if strings.Join(events, "|") != strings.Join(wantEvents, "|") {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
	}
	if len(h.builder.Published) != 1 || h.builder.Published[0].Subject != wantSubject {
		t.Fatalf("published = %#v, want subject %q", h.builder.Published, wantSubject)
	}
	envelope, err := builderclient.DecodeBusEnvelope(h.builder.Published[0].Payload)
	if err != nil {
		t.Fatalf("decode verifier handraise envelope: %v", err)
	}
	var handraise bustaskv1.VerifierHandraiseV1
	if err := envelope.DecodePayload(&handraise); err != nil {
		t.Fatalf("decode verifier handraise payload: %v", err)
	}
	if envelope.Kind != builderclient.KindVerifierHandraise || envelope.SenderOperatorAddress != fixtureVerifierAddress ||
		handraise.GetSchemaVersion() != 1 || handraise.GetChainId() != h.verifier.cfg.ChainID ||
		hex.EncodeToString(handraise.GetTaskId()) != state.TaskID ||
		handraise.GetVerifyRound() != uint32(state.VerifyRound) ||
		!bytes.Equal(handraise.GetInferReceiptHash(), state.InferReceiptHash[:]) ||
		!bytes.Equal(handraise.GetOutputHash(), state.OutputPackage.OutputHash[:]) || hex.EncodeToString(handraise.GetModelId()) != state.ModelID ||
		handraise.GetProfileVersion() != state.ProfileVersion ||
		hex.EncodeToString(handraise.GetMember().GetCandidatePoolSnapshotId()) != state.Member.CandidatePoolSnapshotID ||
		handraise.GetDuty() != 2 ||
		handraise.GetServiceAuthorizationNonce() != h.verifier.cfg.ServiceAuthorizationNonce ||
		handraise.GetExpiryHeight() != state.HandraiseExpiryHeight || len(handraise.GetServiceSignature()) != 64 {
		t.Fatalf("verifier handraise = %#v", &handraise)
	}
	if envelope.SenderParticipantType != builderclient.ParticipantCortex ||
		envelope.ServiceAuthorizationNonce != h.verifier.cfg.ServiceAuthorizationNonce {
		t.Fatalf("verifier handraise envelope = %#v", envelope)
	}
}

func TestVerifierHandraiseRejectDoesNotPersistOrPublish(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true

	result, err := h.verifier.EvaluateAndHandraise(context.Background(), state)
	if err != nil {
		t.Fatalf("handraise reject: %v", err)
	}

	if result.Signed {
		t.Fatalf("verifier handraise signed rejected state")
	}
	if len(h.persistence.evidence) != 0 || len(h.persistence.settle) != 0 || len(h.builder.Published) != 0 {
		t.Fatalf("side effects on rejected handraise: evidence=%d settle=%d publish=%d", len(h.persistence.evidence), len(h.persistence.settle), len(h.builder.Published))
	}
}

func TestVerifierHandraiseRequiresEnvelopeSignerOutsideFixtures(t *testing.T) {
	h := newHarness(t)
	h.verifier.cfg.NexusEnvelopeSigner = nil
	h.verifier.cfg.FakeOutput = false
	state := h.validTask()
	state.OpenVerifyAccepted = false

	_, err := h.verifier.EvaluateAndHandraise(context.Background(), state)
	if !errors.Is(err, builderclient.ErrBusEnvelopeAuthenticationUnavailable) {
		t.Fatalf("EvaluateAndHandraise error = %v, want envelope authentication unavailable", err)
	}
	if len(h.persistence.evidence) != 0 || len(h.persistence.settle) != 0 || len(h.builder.Published) != 0 {
		t.Fatalf("side effects before authenticated envelope: evidence=%d settle=%d publish=%d", len(h.persistence.evidence), len(h.persistence.settle), len(h.builder.Published))
	}
}

func TestTrustedNATSDevEncodesUnsignedVerifierEnvelope(t *testing.T) {
	v := New(Config{TrustedNATSDev: true})
	input := builderclient.UnsignedEnvelopeInput{
		Kind: builderclient.KindVerifyResult, ChainID: "chain-A", Subject: builderclient.NATSVerifyResultSubject("task-1"),
		SenderOperatorAddress: fixtureVerifierAddress, SenderParticipantType: builderclient.ParticipantCortex,
		ServiceAuthorizationNonce: 11,
	}
	message, err := builderclient.ResultReceiptProto(nodewire.ResultReceiptV3{
		SchemaVersion: nodewire.ResultReceiptSchemaVersionV3, ChainID: "chain-A", TaskID: bytes.Repeat([]byte{0xab}, 32),
		VerifyRound: 1, VerifierOperatorAddress: fixtureVerifierAddress,
		ServiceAuthorizationNonce:         11,
		GenerationParamsDigest:            bytes.Repeat([]byte{0x01}, 32),
		MetricRoot:                        bytes.Repeat([]byte{0x02}, 32),
		MetricSummary:                     nodewire.MetricSummaryV1{FiniteCount: 1},
		AggregateProofHash:                bytes.Repeat([]byte{0x03}, 32),
		VerifierEvidenceBundleHash:        bytes.Repeat([]byte{0x04}, 32),
		VerifierEvidenceManifestSizeBytes: 123,
		Salt:                              bytes.Repeat([]byte{0x06}, 32),
		ExpiryHeight:                      9, ServiceSignature: bytes.Repeat([]byte{0x05}, 64),
		VerifierValueRoot: bytes.Repeat([]byte{0x07}, 32), MetricLeafCount: 1, VerifierEvidenceKeyCommitment: make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := v.encodeNexusMessage(input, message)
	if err != nil {
		t.Fatalf("encodeNexusMessage error = %v", err)
	}
	envelope, err := builderclient.DecodeBusEnvelope(encoded)
	if err != nil {
		t.Fatalf("DecodeBusEnvelope error = %v", err)
	}
	if len(envelope.Signature) != 0 || envelope.Subject != input.Subject {
		t.Fatalf("trusted verifier envelope = %#v", envelope)
	}
}

func TestHandraiseRejectsAfterOpenVerifyAccepted(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true

	result, err := h.verifier.EvaluateAndHandraise(context.Background(), state)
	if err != nil {
		t.Fatalf("handraise after open verify: %v", err)
	}

	if result.Signed {
		t.Fatalf("verifier handraise signed after OpenVerify accepted")
	}
	if len(h.builder.Published) != 0 {
		t.Fatalf("published handraise after OpenVerify accepted")
	}
	if result.Decision.RejectCode != "L4_OPEN_VERIFY_ALREADY_ACCEPTED" {
		t.Fatalf("reject code = %q, want L4_OPEN_VERIFY_ALREADY_ACCEPTED", result.Decision.RejectCode)
	}
}

func TestHandraiseRejectsMissingTaskIdentityBeforeSigning(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.SessionID = ""
	state.OrderDigest = codec.Hash{}

	result, err := h.verifier.EvaluateAndHandraise(context.Background(), state)
	if err != nil {
		t.Fatalf("handraise missing identity: %v", err)
	}

	if result.Signed {
		t.Fatalf("verifier handraise signed without task identity")
	}
	if len(h.builder.Published) != 0 {
		t.Fatalf("published handraise without task identity")
	}
	if result.Decision.RejectCode != "L2_TASK_IDENTITY_MISSING" {
		t.Fatalf("reject code = %q, want L2_TASK_IDENTITY_MISSING", result.Decision.RejectCode)
	}
}

// TestVerifierDoesNotSignHandraiseUntilOutputIsConfirmed pins the confirmation
// precondition. The Verifier used to confirm the output itself through
// FetchOutputRef; the target-state task-data contract deleted the OutputRef
// object, and a confirmation now needs the Keeper snapshot and the receiving
// Builder's descriptor, neither of which is in TaskState. So the caller confirms
// (daemon.TaskRunner through daemon.OutputConfirmer) and an unconfirmed state is
// refused outright rather than confirmed here on weaker evidence.
func TestVerifierDoesNotSignHandraiseUntilOutputIsConfirmed(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OutputConfirmed = false

	result, err := h.verifier.EvaluateAndHandraise(context.Background(), state)
	if err != nil {
		t.Fatalf("handraise without a confirmed output: %v", err)
	}
	if result.Signed {
		t.Fatalf("verifier handraise signed without a confirmed output")
	}
	if result.Decision.RejectCode != "L2_OUTPUT_PACKAGE_MISSING" {
		t.Fatalf("reject code = %q, want L2_OUTPUT_PACKAGE_MISSING", result.Decision.RejectCode)
	}
	if len(h.persistence.evidence) != 0 || len(h.builder.Published) != 0 {
		t.Fatalf("side effects on an unconfirmed output: evidence=%d publish=%d", len(h.persistence.evidence), len(h.builder.Published))
	}

	// A Builder client cannot substitute for the confirmation: there is no
	// FetchOutputRef to fall back to any more.
	h.builder.PutOutputPackageForTest(state.OutputPackage.OutputRef, outputPackageFromState(t, state))
	if result, err = h.verifier.EvaluateAndHandraise(context.Background(), state); err != nil {
		t.Fatalf("handraise with a seeded Builder package: %v", err)
	}
	if result.Signed || result.Decision.RejectCode != "L2_OUTPUT_PACKAGE_MISSING" {
		t.Fatalf("handraise result = %#v, want the same refusal with a seeded Builder package", result)
	}

	// Confirmed by the caller, the same state signs.
	state.OutputConfirmed = true
	confirmed, err := h.verifier.EvaluateAndHandraise(context.Background(), state)
	if err != nil {
		t.Fatalf("handraise with a confirmed output: %v", err)
	}
	if !confirmed.Signed {
		t.Fatalf("handraise result = %#v, want a signed handraise once the output is confirmed", confirmed)
	}
}

func TestVerifyStartsOnlyAfterOpenVerifyAcceptedAndFormalAssignmentIncludesNode(t *testing.T) {
	h := newHarness(t)

	notOpen := h.validTask()
	notOpen.OpenVerifyAccepted = false
	if result, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), notOpen); err != nil {
		t.Fatalf("not-open verify: %v", err)
	} else if result.Started {
		t.Fatalf("verify started before open verify accepted")
	}

	notAssigned := h.validTask()
	notAssigned.OpenVerifyAccepted = true
	notAssigned.AssignedVerifiers = []string{"other-verifier"}
	if result, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), notAssigned); err != nil {
		t.Fatalf("not-assigned verify: %v", err)
	} else if result.Started {
		t.Fatalf("verify started without formal assignment")
	}

	assigned := h.validTask()
	assigned.OpenVerifyAccepted = true
	result := verifyLocally(t, h, assigned)
	if !result.Started {
		t.Fatalf("verify did not start after open verify and assignment")
	}
	if h.model.VerifyCalls != 1 {
		t.Fatalf("verify calls = %d, want 1", h.model.VerifyCalls)
	}
}

func TestOpenVerifyAcceptedPersistsModelServiceJobLifecycle(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true

	verifyLocally(t, h, state)

	want := []ModelJobCheckpoint{
		{JobID: "verifier-verify-" + state.TaskID, TaskID: state.TaskID, Role: "verifier", ModelServiceID: "fake-model-service", Status: "running", Intent: "verify"},
		{JobID: "verifier-verify-" + state.TaskID, TaskID: state.TaskID, Role: "verifier", ModelServiceID: "fake-model-service", Status: "succeeded", Intent: "verify"},
	}
	if len(h.persistence.jobs) != len(want) {
		t.Fatalf("model service jobs = %#v, want %#v", h.persistence.jobs, want)
	}
	for i := range want {
		if h.persistence.jobs[i] != want[i] {
			t.Fatalf("model service job %d = %#v, want %#v", i, h.persistence.jobs[i], want[i])
		}
	}
}

func TestSampleSeedUsesFutureBeaconIntervalChainIDAndExcludesBatchLogRoot(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true
	state.BatchLogRoot = codec.HashWithDomain("BATCH_LOG_ROOT", []byte("optional"))

	result := verifyLocally(t, h, state)

	want := VerificationSampleSeed(SeedInput{
		ChainID:          "chain-A",
		TaskID:           state.TaskID,
		VerifyRound:      1,
		OpenVerifyHeight: 220,
		Profile:          "1",
		FutureBeaconID:   "proposer-vrf-epoch-12",
		PackageHash:      state.OutputPackage.PackageHash,
		OutputHash:       state.OutputPackage.OutputHash,
	})
	if result.VerificationSampleSeed != want {
		t.Fatalf("seed = %x, want %x", result.VerificationSampleSeed, want)
	}
	withBatchRoot := codec.HashWithDomain(
		"TRUEOPEN_VERIFICATION_SAMPLE_SEED_V1",
		[]byte("chain-A"),
		[]byte(state.TaskID),
		codec.Uint64Bytes(2),
		[]byte("proposer-vrf-epoch-12"),
		state.BatchLogRoot[:],
	)
	if result.VerificationSampleSeed == withBatchRoot {
		t.Fatalf("seed included optional batch log root")
	}
	changedPackage := state
	changedPackage.OutputPackage.PackageHash = codec.HashWithDomain("OTHER_PACKAGE", []byte("package"))
	changedSeed := VerificationSampleSeed(SeedInput{
		ChainID:          "chain-A",
		TaskID:           state.TaskID,
		VerifyRound:      1,
		OpenVerifyHeight: 220,
		Profile:          "1",
		FutureBeaconID:   "proposer-vrf-epoch-12",
		PackageHash:      changedPackage.OutputPackage.PackageHash,
		OutputHash:       changedPackage.OutputPackage.OutputHash,
	})
	if result.VerificationSampleSeed == changedSeed {
		t.Fatalf("seed did not change when package hash changed")
	}
	changedHeightSeed := VerificationSampleSeed(SeedInput{
		ChainID:          "chain-A",
		TaskID:           state.TaskID,
		VerifyRound:      2,
		OpenVerifyHeight: 221,
		Profile:          "1",
		FutureBeaconID:   "proposer-vrf-epoch-12",
		PackageHash:      state.OutputPackage.PackageHash,
		OutputHash:       state.OutputPackage.OutputHash,
	})
	if result.VerificationSampleSeed == changedHeightSeed {
		t.Fatalf("seed did not change when open verify height changed")
	}
}

func TestOutputPackageMustMatchTaskState(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true
	state.OutputPackage.TaskID = "other-task"
	state.OutputPackage.PackageHash = codec.HashWithDomain(
		"TRUEOPEN_OUTPUT_PACKAGE_V1",
		[]byte(state.OutputPackage.TaskID),
		[]byte(state.OutputPackage.OutputRef),
		[]byte(state.OutputPackage.TokenIDsRef),
		[]byte(state.OutputPackage.PositionValuesRef),
		state.OutputPackage.OutputHash[:],
	)

	_, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if err == nil || !strings.Contains(err.Error(), "L2_OUTPUT_PACKAGE_TASK_MISMATCH") {
		t.Fatalf("verify error = %v, want package task mismatch", err)
	}
	if h.model.VerifyCalls != 0 {
		t.Fatalf("verify calls = %d, want 0", h.model.VerifyCalls)
	}
}

func TestTaskStateMustMatchCanonicalChainIdentity(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true
	state.TaskID = "task-1"
	state.OutputPackage.TaskID = "task-1"

	_, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if err == nil || !strings.Contains(err.Error(), "canonical task id") {
		t.Fatalf("verify error = %v, want canonical task id rejection", err)
	}
	if h.model.VerifyCalls != 0 {
		t.Fatalf("verify calls = %d, want 0 before canonical identity validation", h.model.VerifyCalls)
	}
}

func TestHandraiseRejectsNonCanonicalTaskID(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.TaskID = "task-1"

	result, err := h.verifier.EvaluateAndHandraise(context.Background(), state)
	if err != nil {
		t.Fatalf("handraise returned error: %v", err)
	}
	if result.Signed {
		t.Fatalf("handraise signed non-canonical task id")
	}
	if result.Decision.RejectCode != "L2_TASK_IDENTITY_MISMATCH" {
		t.Fatalf("reject code = %q, want L2_TASK_IDENTITY_MISMATCH", result.Decision.RejectCode)
	}
}

func TestVerifyResponseHasNoPassFailAndMismatchCountIsDiagnosticOnly(t *testing.T) {
	typ := reflect.TypeOf(modelservice.VerifyResponse{})
	if _, ok := typ.FieldByName("Pass"); ok {
		t.Fatalf("VerifyResponse must not expose Pass field")
	}
	if _, ok := typ.FieldByName("Fail"); ok {
		t.Fatalf("VerifyResponse must not expose Fail field")
	}

	h := newHarness(t)
	h.model.MainMismatchCount = 7
	state := h.validTask()
	state.OpenVerifyAccepted = true

	result := verifyLocally(t, h, state)
	if !result.Started {
		t.Fatalf("verify did not start")
	}
	if result.MainMismatchCount != 7 {
		t.Fatalf("mismatch count = %d, want diagnostic 7", result.MainMismatchCount)
	}
	if result.ResultDigest == policy.VerificationResultDigest([][]byte{[]byte{0}}) ||
		result.ResultDigest == policy.VerificationResultDigest([][]byte{[]byte{1}}) {
		t.Fatalf("result digest appears to be verdict-bit derived")
	}
}

func TestVerifyStoresEvidenceAndCommitMaterialsWithoutFullRevealInSettleInput(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true

	result := verifyLocally(t, h, state)

	if result.CommitHash == (codec.Hash{}) || result.ResultDigest == (codec.Hash{}) || result.Salt == (codec.Hash{}) {
		t.Fatalf("missing commit materials: %#v", result)
	}
	if len(h.persistence.evidence) != 4 {
		t.Fatalf("evidence writes = %d, want V_i, reveal skeleton, commit receipt, confirmed delivery", len(h.persistence.evidence))
	}
	kinds := []string{h.persistence.evidence[0].Kind, h.persistence.evidence[1].Kind, h.persistence.evidence[2].Kind, h.persistence.evidence[3].Kind}
	if strings.Join(kinds, "|") != "verifier-v-values|verifier-full-result-reveal-state|verifier-result-commit-receipt|verifier-commit-delivery" {
		t.Fatalf("evidence kinds = %#v", kinds)
	}
	if len(h.persistence.settle) != 1 {
		t.Fatalf("settle materials = %d, want 1", len(h.persistence.settle))
	}
	if bytes.Contains(h.persistence.settle[0].Payload, []byte("V_i:")) {
		t.Fatalf("normal settle input contains full V_i values")
	}
}

// TestVerifyNormalPathSelfSubmitsTheCommitAndPublishesNothing pins the two
// independent obligations of the verify path and the boundary between them.
//
// It replaces a test that asserted the normal path never broadcasts a
// transaction, on the belief that "the Task Builder relays the items". It does
// not: the bus registers no VERIFY_COMMIT kind and nexus's ingress returns
// FailedPrecondition + NEXUS_INGRESS_RELAY_NOT_OFFERED for the unary rpc, so the
// self-submission IS the normal path for a commit (keeper §10.6 rule 6,
// nexus §4-B).
//
// Nothing is published on the bus here, and the reason is the responsibility
// boundary rather than an incomplete credential: the reveal is opened by
// EventRevealPhaseStarted, which has not happened while this call is running.
func TestVerifyNormalPathSelfSubmitsTheCommitAndPublishesNothing(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true

	result := verifyLocally(t, h, state)

	requests := h.tx.Requests()
	if len(requests) != 1 || requests[0].Kind != txclient.MsgSubmitVerifyCommit {
		t.Fatalf("tx requests = %#v, want exactly one MsgSubmitVerifyCommit", requests)
	}
	if requests[0].TaskID != state.TaskID || requests[0].SessionID != state.SessionID {
		t.Fatalf("commit tx scope = %#v, want task %s session %s", requests[0], state.TaskID, state.SessionID)
	}
	// expiry_height in the signed body and timeout_height on the transaction are
	// the same commit deadline: a commit that misses the window must not be
	// includable after it.
	if requests[0].DeadlineHeight != state.CommitDeadlineHeight {
		t.Fatalf("commit tx timeout height = %d, want the commit deadline %d", requests[0].DeadlineHeight, state.CommitDeadlineHeight)
	}
	if requests[0].FeeCap.Amount != 25 || requests[0].FeeCap.Denom != "utrueopen" {
		t.Fatalf("commit tx fee cap = %#v, want the configured bound", requests[0].FeeCap)
	}
	delivery := result.CommitDelivery
	if !delivery.SelfSubmitted || delivery.Relayed || delivery.Reason != CommitExitRelayChannelAbsent {
		t.Fatalf("delivery = %#v, want a self-submission triggered by the absent relay channel", delivery)
	}
	if !delivery.ChainAccepted || delivery.TxHash == "" {
		t.Fatalf("delivery = %#v, want Keeper confirmation and a tx hash", delivery)
	}
	// The bytes submitted on chain and the bytes kept as the local receipt come
	// from one assembler, so an evidence file can never describe a body the
	// chain did not receive.
	if len(h.persistence.settle) != 1 || !bytes.Equal(h.persistence.settle[0].Payload, requests[0].Payload) {
		t.Fatalf("submitted payload differs from the persisted commit receipt")
	}
	if len(h.builder.Published) != 0 {
		t.Fatalf("published = %#v, want nothing: the commit path never reveals", h.builder.Published)
	}
}

// TestSubmittedVerifyCommitSignatureCoversTheFrozenPreimage rebuilds the frozen
// VerifyCommitV1 out of the bytes that were actually submitted and checks the
// service_signature against that body's own TRUEOPEN_COMMIT_V1 digest. Nothing here
// reads the production wire value: if the signing call ever moves back to a
// preimage that is not the submitted body, this reconstruction stops matching.
//
// The retired keepercontract.Commit preimage bound five text fields, so
// schema_version, the raw Hash32 task_id, the address codec bytes,
// service_authorization_nonce and expiry_height all travelled unsigned. The
// per-field mutation loop is what pins that they no longer do.
func TestSubmittedVerifyCommitSignatureCoversTheFrozenPreimage(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true

	verifyLocally(t, h, state)
	if len(h.persistence.settle) != 1 {
		t.Fatalf("settle materials = %d, want 1", len(h.persistence.settle))
	}
	var submitted txclient.SubmitVerifyCommitMessage
	if err := json.Unmarshal(h.persistence.settle[0].Payload, &submitted); err != nil {
		t.Fatalf("decode submitted MsgSubmitVerifyCommit: %v", err)
	}
	body := frozenCommitFromSubmitted(t, submitted.Commit)
	digest, err := nodewire.VerifyCommitSigningDigest(body)
	if err != nil {
		t.Fatalf("derive frozen digest of the submitted body: %v", err)
	}
	signature, err := hex.DecodeString(submitted.Commit.ServiceSignature.Hex())
	if err != nil {
		t.Fatalf("decode submitted service_signature: %v", err)
	}
	if !bytes.Equal(signature, fixtureSignature(digest)) {
		t.Fatalf("submitted service_signature does not verify against the frozen preimage of the submitted body")
	}

	// Every field the frozen preimage carries must move the digest, otherwise the
	// signature would authorize a body that differs in that field.
	for name, mutate := range map[string]func(*nodewire.VerifyCommitV1){
		"schema_version":              func(c *nodewire.VerifyCommitV1) { c.SchemaVersion++ },
		"chain_id":                    func(c *nodewire.VerifyCommitV1) { c.ChainID += "-other" },
		"task_id":                     func(c *nodewire.VerifyCommitV1) { c.TaskID[0] ^= 0xff },
		"verify_round":                func(c *nodewire.VerifyCommitV1) { c.VerifyRound++ },
		"verifier_operator_address":   func(c *nodewire.VerifyCommitV1) { c.VerifierOperatorAddress = fixtureOtherVerifierAddress },
		"service_authorization_nonce": func(c *nodewire.VerifyCommitV1) { c.ServiceAuthorizationNonce++ },
		"commit_hash":                 func(c *nodewire.VerifyCommitV1) { c.CommitHash[0] ^= 0xff },
		"expiry_height":               func(c *nodewire.VerifyCommitV1) { c.ExpiryHeight++ },
	} {
		mutated := frozenCommitFromSubmitted(t, submitted.Commit)
		mutate(&mutated)
		mutatedDigest, err := nodewire.VerifyCommitSigningDigest(mutated)
		if err != nil {
			t.Fatalf("derive frozen digest with mutated %s: %v", name, err)
		}
		if mutatedDigest == digest {
			t.Fatalf("frozen commit digest ignores %s, so the signature does not cover it", name)
		}
	}
}

// frozenCommitFromSubmitted rebuilds the frozen wire from the ProtoJSON body
// alone. It deliberately duplicates no production helper: the point is to derive
// the digest from what was submitted, not from what was signed.
func frozenCommitFromSubmitted(t *testing.T, commit txclient.VerifyCommitMessage) nodewire.VerifyCommitV1 {
	t.Helper()
	taskID, err := hex.DecodeString(commit.TaskID.Hex())
	if err != nil {
		t.Fatalf("decode submitted task_id: %v", err)
	}
	commitHash, err := hex.DecodeString(commit.CommitHash.Hex())
	if err != nil {
		t.Fatalf("decode submitted commit_hash: %v", err)
	}
	return nodewire.VerifyCommitV1{
		SchemaVersion:             uint32(commit.SchemaVersion),
		ChainID:                   commit.ChainID,
		TaskID:                    taskID,
		VerifyRound:               uint32(commit.VerifyRound),
		VerifierOperatorAddress:   commit.VerifierOperatorAddress,
		ServiceAuthorizationNonce: uint64(commit.ServiceAuthorizationNonce),
		CommitHash:                commitHash,
		ExpiryHeight:              uint64(commit.ExpiryHeight),
	}
}

// TestVerifyRefusesIncompleteCommitBodyBeforeSigning pins the ordering the fix
// depends on. The frozen body is completed first and signed second, so a missing
// preimage field stops the path instead of producing a real signature over a
// body carrying a zero in a consensus field. The signer counter is the assertion
// that matters: an implementation that signs first and validates later would
// still return an error here.
func TestVerifyRefusesIncompleteCommitBodyBeforeSigning(t *testing.T) {
	for name, mutate := range map[string]func(*Config, *TaskState){
		"service_authorization_nonce": func(cfg *Config, _ *TaskState) { cfg.ServiceAuthorizationNonce = 0 },
		"expiry_height":               func(_ *Config, state *TaskState) { state.CommitDeadlineHeight = 0 },
		// math.MaxUint32+2 narrows to 1, the only round the wire accepts, so a
		// silent truncation would pass every downstream check while the digest
		// covered a different round than the caller asked for.
		"verify_round": func(_ *Config, state *TaskState) { state.VerifyRound = math.MaxUint32 + 2 },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			signed := 0
			h.verifier.cfg.Signer = signer.DigestSignerFunc(func(_ context.Context, req signer.DigestRequest) ([]byte, error) {
				signed++
				return fixtureSignature(req.Digest), nil
			})
			state := h.validTask()
			state.OpenVerifyAccepted = true
			mutate(&h.verifier.cfg, &state)

			_, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
			wantErr := ErrVerifyCommitInputUnavailable
			if name == "verify_round" {
				wantErr = errTaskIdentityMissing
			}
			if !errors.Is(err, wantErr) {
				t.Fatalf("HandleOpenVerifyAccepted error = %v, want the %s gap refused", err, name)
			}
			if signed != 0 {
				t.Fatalf("signer called %d times: an incomplete frozen commit body was signed", signed)
			}
			if len(h.persistence.settle) != 0 {
				t.Fatalf("settle materials = %d, want none for a refused commit", len(h.persistence.settle))
			}
		})
	}
}

// TestVerifyCommitWireRefusesNonCanonicalTaskID covers the Hash32 rule directly.
// HandleOpenVerifyAccepted cannot reach it - validateCanonicalTaskState already
// pins state.TaskID to the canonical identity - but the frozen preimage frames
// task_id as raw 32 bytes, so the builder must refuse rather than pad or
// truncate whatever text it is handed.
func TestVerifyCommitWireRefusesNonCanonicalTaskID(t *testing.T) {
	cfg := Config{ChainID: "chain-A", VerifierAddress: fixtureVerifierAddress, ServiceAuthorizationNonce: 11}
	for _, taskID := range []string{"", "task-1", strings.Repeat("ab", 31), strings.Repeat("ab", 33)} {
		state := TaskState{TaskID: taskID, VerifyRound: 1, CommitDeadlineHeight: 260}
		if _, err := verifyCommitWire(cfg, state, codec.HashBytes([]byte("commit"))); !errors.Is(err, ErrVerifyCommitInputUnavailable) {
			t.Fatalf("verifyCommitWire(%q) error = %v, want the task_id shape refused", taskID, err)
		}
	}
}

func TestCommitPayloadBindsLocalVerifierAddress(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true
	state.AssignedVerifiers = []string{fixtureVerifierAddress, fixtureOtherVerifierAddress, fixtureThirdVerifierAddress}

	verifyLocally(t, h, state)
	if len(h.persistence.settle) != 1 {
		t.Fatalf("settle materials = %d, want 1", len(h.persistence.settle))
	}
	payload := string(h.persistence.settle[0].Payload)
	if !strings.Contains(payload, `"verifier_operator_address":"`+fixtureVerifierAddress+`"`) || !strings.Contains(payload, `"submitter_address":"service-1"`) {
		t.Fatalf("commit payload does not bind local verifier address: %s", payload)
	}
	if strings.Contains(payload, fixtureOtherVerifierAddress) || strings.Contains(payload, fixtureThirdVerifierAddress) {
		t.Fatalf("commit payload includes other assigned verifiers: %s", payload)
	}
}

func TestRepeatedOpenVerifyChangedRoundDoesNotReturnStaleResult(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true

	first := verifyLocally(t, h, state)
	changed := state
	changed.VerifyRound = 2
	second := verifyLocally(t, h, changed)
	if second.CommitHash == first.CommitHash {
		t.Fatalf("changed verify round returned stale commit hash")
	}
	if h.model.VerifyCalls != 2 {
		t.Fatalf("verify calls = %d, want one per distinct commit identity", h.model.VerifyCalls)
	}
}

// verifyLocally runs the commit half of the verify responsibility and requires
// it to COMPLETE.
//
// It used to require the frozen result-credential gap instead, because the
// reveal was assembled on the tail of this same call and always failed there. It
// no longer is: the reveal is its own responsibility, opened by
// EventRevealPhaseStarted (reveal.go). So the commit half now ends where its own
// obligation ends -- verification done, evidence stored, commit on chain -- and
// the gap moved to revealLocally, which is the only place it can still be
// reached.
func verifyLocally(t *testing.T, h harness, state TaskState) VerifyResult {
	t.Helper()
	result, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if err != nil {
		t.Fatalf("HandleOpenVerifyAccepted error = %v, want the commit half to complete", err)
	}
	return result
}

// revealLocally runs the reveal half and requires it to complete. With the
// metric pipeline in place every frozen preimage value has a producer, so a
// refusal here is a regression rather than the shipped state it used to be.
func revealLocally(t *testing.T, h harness, state TaskState) RevealResult {
	t.Helper()
	result, err := h.verifier.HandleRevealPhaseStarted(context.Background(), state)
	if err != nil {
		t.Fatalf("HandleRevealPhaseStarted error = %v, want the frozen result credential to be complete", err)
	}
	return result
}

// revealRefused is the opposite helper: it runs the reveal and requires the
// frozen input gap. Tests use it to pin the cases that MUST still refuse - a
// node with no locked profile, a model service that returned no metric samples -
// so "the gate stopped refusing" and "the gate was removed" cannot look alike.
func revealRefused(t *testing.T, h harness, state TaskState) error {
	t.Helper()
	_, err := h.verifier.HandleRevealPhaseStarted(context.Background(), state)
	if !errors.Is(err, ErrResultReceiptInputUnavailable) {
		t.Fatalf("HandleRevealPhaseStarted error = %v, want the frozen result-receipt input gap", err)
	}
	return err
}

// TestCommitHalfPublishesNoRevealAtAll is the boundary this split exists to
// create, asserted as a COUNT rather than as "no error".
//
// Task-04-Verification-flow.md admits MsgSubmitVerifyResult only after
// EventRevealPhaseStarted, and that event cannot have been emitted while this
// call is running: the chain starts the reveal phase from the commits, and this
// call is what produces one of them. So a reveal assembled here is early by
// construction, whatever it contains -- which is why "the commit path did not
// error" is not the assertion. Zero publishes is.
func TestCommitHalfPublishesNoRevealAtAll(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true
	// The reveal deadline is deliberately KNOWN here. If the split were only a
	// fail-closed check on a zero deadline, a state carrying a real one would
	// still be assembled; the point is that the commit call never reveals, not
	// that it happens to lack an input.
	state.RevealDeadlineHeight = 300

	result := verifyLocally(t, h, state)

	if len(h.builder.Published) != 0 {
		t.Fatalf("bus publishes on the commit path = %d, want 0: %#v", len(h.builder.Published), h.builder.Published)
	}
	if !result.CommitDelivery.ChainAccepted {
		t.Fatalf("delivery = %#v, want the commit itself to have landed", result.CommitDelivery)
	}
	// And the reveal, run as its own responsibility on the same state, DOES
	// publish. That is what makes the count above an assertion about the
	// boundary rather than about an inability: the credential is complete, so a
	// commit path that assembled one would have published it.
	revealLocally(t, h, state)
	if len(h.builder.Published) != 1 {
		t.Fatalf("bus publishes after the reveal = %d, want exactly the result credential", len(h.builder.Published))
	}
}

// countingTaskFacts answers like fixtureTaskFacts and counts how many times the
// verify path needed the consensus read only the result body uses.
type countingTaskFacts struct{ reads int }

func (c *countingTaskFacts) TaskFacts(_ context.Context, taskID string) (taskfacts.Facts, error) {
	c.reads++
	return servedTaskFacts(taskID), nil
}

// TestRevealRefusesUntilThePhaseStarts is FR3/AC2 and AC4 together: with the
// reveal phase unopened the reveal is refused, and refused as a WAIT rather than
// as the frozen-input gap, because the two mean opposite things to a caller.
//
// The zero is the protocol's own answer, not a hole: keeper §10.7 writes
// reveal_deadline_height only inside StartRevealPhase, so before the phase there
// is nothing to read anywhere.
func TestRevealRefusesUntilThePhaseStarts(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true
	verifyLocally(t, h, state)

	notStarted := state
	notStarted.RevealDeadlineHeight = 0
	_, err := h.verifier.HandleRevealPhaseStarted(context.Background(), notStarted)
	if !errors.Is(err, ErrRevealPhaseNotStarted) {
		t.Fatalf("HandleRevealPhaseStarted error = %v, want the reveal phase reported as not started", err)
	}
	// A wait must never be reported as the credential gap. The gap says "Cortex
	// has no producer for a frozen value"; this says "the chain has not spoken
	// yet", and only one of them is a reason to stop retrying.
	if errors.Is(err, ErrResultReceiptInputUnavailable) {
		t.Fatalf("error = %v, want the wait kept distinct from the frozen-input gap", err)
	}
	if len(h.builder.Published) != 0 {
		t.Fatalf("published = %#v, want nothing before the reveal phase opens", h.builder.Published)
	}
}

// TestRevealCredentialIsCompleteOnceTheMetricPipelineRuns is the whole point of
// the metric pipeline, asserted at the gate that used to refuse.
//
// resultReceiptCredential is unchanged - it still refuses any zero among the
// twelve frozen preimage values. What changed is that a verify run now produces
// metric_root, the ten typed MetricSummaryV1 members and aggregate_proof_hash,
// so the gate has nothing left to refuse. The assertion is deliberately on the
// SIGNED, PUBLISHED body rather than on the assembler's return value: a
// credential that assembles but never reaches the bus is not a reveal.
func TestRevealCredentialIsCompleteOnceTheMetricPipelineRuns(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true
	result := verifyLocally(t, h, state)

	reveal := revealLocally(t, h, state)
	if !reveal.Published {
		t.Fatalf("reveal did not publish: %#v", reveal)
	}
	if reveal.ResultSigningDigest.IsZero() {
		t.Fatalf("published reveal carries no TRUEOPEN_RESULT_V1 digest")
	}
	// The three values this issue exists to produce, checked against the ones
	// the verify run derived rather than merely against "not zero".
	material := result.MetricMaterial
	if material.Root.IsZero() || material.AggregateProof.Hash.IsZero() || material.LeafCount == 0 {
		t.Fatalf("verify produced no metric material: %#v", material)
	}
	if material.Summary == (nodewire.MetricSummaryV1{}) {
		t.Fatalf("verify produced an all-zero MetricSummaryV1")
	}
	// The locked fixture profile sets compare_topk_jaccard and compare_union_js,
	// so both optional members must be present. Absent here would mean the
	// pipeline ignored the profile and read the measurement instead.
	if !material.Summary.TopkJaccardMeanFP1e6.Present || !material.Summary.UnionJSP99FP1e6.Present {
		t.Fatalf("the locked profile asks for both optional summary members and the summary omits one: %#v", material.Summary)
	}
}

// TestRevealCredentialIsCompleteAfterVerifierRestart is the durability half.
// The reveal phase opens after the commits are counted, so a process that
// restarted in between must rebuild the whole credential from Pebble - the
// compact reveal AND the metric material, which was derived by a model run that
// is not going to happen again.
func TestRevealCredentialIsCompleteAfterVerifierRestart(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true
	before := verifyLocally(t, h, state)

	h.verifier = New(h.verifier.cfg)
	reveal := revealLocally(t, h, state)
	if !reveal.Published {
		t.Fatalf("reveal after restart did not publish: %#v", reveal)
	}

	// The restarted process must sign the SAME body, not merely some body: the
	// commit already on chain is bound to this run's material.
	receipt := publishedResultReceipt(t, h)
	if !bytes.Equal(receipt.MetricRoot, before.MetricMaterial.Root[:]) {
		t.Fatalf("metric_root after restart = %x, want the persisted %x", receipt.MetricRoot, before.MetricMaterial.Root[:])
	}
	if !bytes.Equal(receipt.AggregateProofHash, before.MetricMaterial.AggregateProof.Hash[:]) {
		t.Fatalf("aggregate_proof_hash after restart = %x, want the persisted %x",
			receipt.AggregateProofHash, before.MetricMaterial.AggregateProof.Hash[:])
	}
	if receipt.MetricSummary != before.MetricMaterial.Summary {
		t.Fatalf("metric_summary after restart = %#v, want the persisted %#v", receipt.MetricSummary, before.MetricMaterial.Summary)
	}
}

// TestNoMetricMaterialStopsTheCommitNotJustTheReveal pins where a verifier that
// cannot produce metric material has to stop.
//
// It used to stop at the reveal: the commit was derived by a Cortex-local
// formula that needed nothing from the metric pipeline, so it was signed, put on
// chain, and counted toward StartRevealPhase before anything noticed. That
// commit could never have survived §10.11 rule 5, which recomputes commit_hash
// from verifier_evidence_bundle_hash and aggregate_proof_hash.
//
// Now aggregate_proof_hash is one of the six fields the commit commits to, so a
// run without metric material has no commit to make either, and it says so at
// the commit rather than one phase later. The reveal gate is unchanged and still
// refuses - it just is not reached, which is the point.
func TestNoMetricMaterialStopsTheCommitNotJustTheReveal(t *testing.T) {
	h := newHarness(t)
	h.verifier.cfg.ProfileReader = nil
	h.verifier = New(h.verifier.cfg)
	state := h.validTask()
	state.OpenVerifyAccepted = true

	_, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if !errors.Is(err, ErrVerifyCommitInputUnavailable) {
		t.Fatalf("verify error = %v, want the commit refused for a missing frozen input", err)
	}
	if !strings.Contains(err.Error(), "verifier_value_root") {
		t.Fatalf("commit refusal %q does not name the field it cannot source", err)
	}
	if len(h.tx.Requests()) != 0 {
		t.Fatalf("tx requests = %#v, want nothing: a commit the chain cannot re-derive must not be submitted", h.tx.Requests())
	}
	if len(h.builder.Published) != 0 {
		t.Fatalf("published = %#v, want nothing", h.builder.Published)
	}
}

// The result-credential gate itself is unchanged and must stay that way: it
// refuses any zero among the twelve frozen preimage values. Asserted directly
// on the assembler, because the commit now stops first and the reveal path can
// no longer reach it with an empty material.
func TestResultCredentialStillRefusesAnUnsourcedMetricBody(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()

	_, err := resultReceiptCredential(
		h.verifier.cfg, state, servedTaskFacts(state.TaskID), []byte(fixtureResultReveal), metric.Material{}, []byte("manifest"), codec.HashBytes([]byte("salt")))
	if !errors.Is(err, ErrResultReceiptInputUnavailable) {
		t.Fatalf("resultReceiptCredential error = %v, want the frozen input gap", err)
	}
	for _, want := range []string{"metric_root", "metric_summary", "aggregate_proof_hash"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal %q does not name %s", err, want)
		}
	}
	for _, forbidden := range []string{"verifier_evidence_bundle_hash", "expiry_height"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("refusal %q names a sourced field %q", err, forbidden)
		}
	}
}

// A model service that answers a verify request without per-token samples
// cannot serve its own reveal. That is an error at the point the material was
// owed, not a silent skip that surfaces later as an unexplained credential gap.
func TestVerifyRefusesAModelServiceThatReturnsNoMetricSamples(t *testing.T) {
	h := newHarness(t)
	h.model.DropMetricSamples = true
	state := h.validTask()
	state.OpenVerifyAccepted = true

	_, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if err == nil {
		t.Fatal("verify accepted a model service that returned no verifier values")
	}
	if !strings.Contains(err.Error(), "verifier values") {
		t.Fatalf("verify error %q does not say what was missing", err)
	}
}

// TestRevealBodyExpiryIsTheRevealDeadlineNotTheCommitDeadline is AC5. The Keeper
// bounds the credential by the verifier assignment's reveal deadline
// (x/task/keeper/verification_runtime.go:230), and the commit deadline is
// the value most likely to be reached for by mistake because the commit half
// used it a few lines earlier.
func TestRevealBodyExpiryIsTheRevealDeadlineNotTheCommitDeadline(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	if state.CommitDeadlineHeight == state.RevealDeadlineHeight {
		t.Fatal("the fixture cannot tell the two deadlines apart")
	}
	receipt, err := resultReceiptWire(h.verifier.cfg, state, servedTaskFacts(state.TaskID), []byte(fixtureResultReveal), metric.Material{}, []byte("manifest"), codec.HashBytes([]byte("salt")))
	if err != nil {
		t.Fatalf("resultReceiptWire: %v", err)
	}
	if receipt.ExpiryHeight != state.RevealDeadlineHeight {
		t.Fatalf("expiry_height = %d, want the reveal deadline %d (commit deadline is %d)",
			receipt.ExpiryHeight, state.RevealDeadlineHeight, state.CommitDeadlineHeight)
	}
}

func TestResultReceiptWireHashesCanonicalRevealWithHashV1(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	resultReveal := []byte(fixtureResultReveal)
	want := evidencebundle.Hash([]byte("manifest"))

	receipt, err := resultReceiptWire(h.verifier.cfg, state, servedTaskFacts(state.TaskID), resultReveal, metric.Material{}, []byte("manifest"), codec.HashBytes([]byte("salt")))
	if err != nil {
		t.Fatalf("resultReceiptWire: %v", err)
	}
	if !bytes.Equal(receipt.VerifierEvidenceBundleHash, want[:]) {
		t.Fatalf("verifier_evidence_bundle_hash = %x, want H_V1 digest %x", receipt.VerifierEvidenceBundleHash, want)
	}
}

func TestLateCurrentHeightRejectsVerifyBeforeModelCall(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true
	state.CurrentHeight = state.OpenVerifyHeight + h.verifier.cfg.VerifyDeadlineDeltaHeight

	_, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if err == nil || !strings.Contains(err.Error(), "L4_VERIFY_DEADLINE_EXPIRED") {
		t.Fatalf("verify error = %v, want deadline expired", err)
	}
	if h.model.VerifyCalls != 0 {
		t.Fatalf("verify calls = %d, want 0 after deadline", h.model.VerifyCalls)
	}
}

type harness struct {
	model       *countingModel
	builder     *builderclient.FakeClient
	persistence *recordingPersistence
	tx          *txclient.Fake
	verifier    *Verifier
}

func newHarness(t *testing.T) harness {
	t.Helper()
	model := &countingModel{FakeService: modelservice.NewFakeService()}
	builder := builderclient.NewFakeClient()
	persistence := &recordingPersistence{}
	tx := txclient.NewFake()
	v := New(Config{
		EvidencePublisher:         evidencePublisherStub{},
		VerifierAddress:           fixtureVerifierAddress,
		ModelServiceID:            "fake-model-service",
		Model:                     model,
		Builder:                   builder,
		Persistence:               persistence,
		ChainID:                   "chain-A",
		SignerAddress:             "service-1",
		SignerKeyRef:              "test-verifier-key",
		Signer:                    testDigestSigner(),
		VerifyDeadlineDeltaHeight: 40,
		FakeOutput:                true,
		// A fake-inference node signs envelopes just the same: FakeOutput says the output
		// is synthetic, not that this node's identity is fake. The harness must therefore
		// provide a signer, or the test exercises an "unsigned" path that exists in no
		// real deployment.
		NexusEnvelopeSigner: testEnvelopeSigner(),
		// The daemon does not publish the binding nonce into the task plane yet;
		// the tests supply it so the frozen commit/result wires can be built.
		ServiceAuthorizationNonce: 11,
		// The Keeper read the verifier result body's generation_params_digest
		// comes from. The fixture value is a function of the task id, so a reader
		// wired to the wrong task serves visibly different bytes.
		TaskFacts: fixtureTaskFacts{},
		// No CommitRelay: the bus registers no VERIFY_COMMIT kind, so the
		// shipped configuration has no relay channel and every commit takes the
		// self-submission exit. The submitter is wired because a real-mode node
		// has one -- a harness without it would be testing a deployment that
		// cannot put a commit on chain at all.
		CommitSubmitter: testCommitSubmitter(tx),
		// The locked model profile. It is wired even though FakeOutput is set,
		// because the metric pipeline binds every leaf to the profile's version
		// tokens and its MetricSpec decides whether the two optional
		// MetricSummaryV1 members are present. A harness without one would
		// exercise the no-profile dev path and never reach a complete result
		// credential at all.
		ProfileReader: &fixtureProfileReader{profile: fixtureLockedProfile()},
	})
	return harness{model: model, builder: builder, persistence: persistence, tx: tx, verifier: v}
}

// fixtureProfileReader serves one locked profile snapshot. Tests that need a
// different profile - a BATCH_SAMPLES mode, an absent optional metric - mutate
// the snapshot rather than swapping the reader, so the deviation is visible at
// the test that needs it.
type fixtureProfileReader struct {
	profile chainclient.CurrentModelProfileSnapshot
	err     error
}

func (r *fixtureProfileReader) CurrentModelProfile(_ context.Context, _, _ string) (chainclient.CurrentModelProfileSnapshot, error) {
	if r.err != nil {
		return chainclient.CurrentModelProfileSnapshot{}, r.err
	}
	return r.profile, nil
}

// fixtureLockedProfile is the SINGLE_SAMPLE / FP_1E6 profile the shipped
// verification profile uses. Both compare_topk_jaccard and compare_union_js are
// set, so the fixture credential carries the two optional summary members and a
// test that turns one off can observe the summary change.
//
// evidence_schema_hash is DERIVED from the rest of the snapshot rather than
// written as a fixture constant, because profileRequiredEvidence re-derives and
// compares it. A hard-coded hash would either be wrong forever or freeze the
// projection this fixture is not the owner of.
func fixtureLockedProfile() chainclient.CurrentModelProfileSnapshot {
	schemaHash := codec.HashWithDomain("TEST_PROFILE_SCHEMA_HASH_V1", []byte(modelservice.FakeModelID))
	tokenizerHash := codec.HashWithDomain("TEST_TOKENIZER_HASH_V1", []byte(modelservice.FakeModelID))
	profile := chainclient.CurrentModelProfileSnapshot{
		Profile: chainclient.CurrentProfileSnapshot{
			ModelID:        modelservice.FakeModelID,
			ProfileVersion: chainclient.ProfileVersion("1"),
			SchemaHash:     chainclient.ProtoBytes32(schemaHash[:]),
			TokenizerHash:  chainclient.ProtoBytes32(tokenizerHash[:]),
			GenerationType: "GENERATION_TYPE_DETERMINISTIC",
			RequiredTopK:   4,
			VerificationProfile: chainclient.CurrentVerificationProfileSnapshot{
				VerificationProfileID:       1,
				JudgmentFunctionVersion:     "PREFILL_GENERATED_TOKEN_METRICS_V1",
				VerificationMode:            "VERIFICATION_MODE_SINGLE_SAMPLE",
				TokenScope:                  "TOKEN_SCOPE_ALL_GENERATED_OUTPUT_TOKENS",
				RequireOutputTokenIDs:       true,
				RequireFinishReason:         true,
				CanonicalEncodingVersion:    "CANONICAL_ENCODING_V1",
				MetricAggregateProofVersion: metric.AggregateProofVersionV1,
				Metrics: chainclient.CurrentMetricSpecSnapshot{
					CompareLogprobDiff: true, CompareRankDelta: true,
					CompareTopKJaccard: true, CompareUnionJS: true,
					ComparedTopK: 4, NumericScale: "NUMERIC_SCALE_FP_1E6",
				},
				EvidenceSchema: chainclient.CurrentEvidenceSchemaSnapshot{
					SchemaVersion: 1,
					RequiredInferEvidence: []chainclient.CurrentInferEvidenceRequirementSnapshot{{
						EvidenceKind:            int32(nodewire.EvidenceKindWorkerValueOpening),
						CommitmentSchemaVersion: nodewire.WorkerValueCommitmentSchemaVersionV3,
						MaxEncodedSizeBytes:     chainclient.Uint64String(1 << 20),
					}, {
						EvidenceKind:            int32(nodewire.EvidenceKindWorkerTokenOpening),
						CommitmentSchemaVersion: nodewire.WorkerTokenCommitmentSchemaVersionV1,
						MaxEncodedSizeBytes:     chainclient.Uint64String(1 << 20),
					}},
				},
			},
		},
	}
	evidenceSchemaHash, err := keepercontract.ComputeEvidenceSchemaHashFromCurrentModelProfile(profile)
	if err != nil {
		panic(err)
	}
	profile.Profile.VerificationProfile.EvidenceSchemaHash = chainclient.ProtoBytes32(evidenceSchemaHash[:])
	return profile
}

// testCommitSubmitter is the production submitter over the fake tx client. The
// addresses match the harness Config so §10.6 rule 6 is satisfied: the body
// names fixtureVerifierAddress as its operator and "service-1" as its submitter,
// and those are the two values this manager is configured with.
func testCommitSubmitter(tx txclient.Client) CommitSubmitter {
	return NewSettlementManager(SettlementConfig{
		Tx:               tx,
		VerifierAddress:  fixtureVerifierAddress,
		SubmitterAddress: "service-1",
		GasPayer:         "service-1",
		FeeCap:           txclient.Coin{Amount: 25, Denom: "utrueopen"},
	})
}

// testDigestSigner is digest-aware on purpose. A signer that returns the same
// bytes for every request cannot tell a signature over the frozen body apart
// from a signature over anything else, which is precisely why the retired
// pre-freeze commit preimage survived the cutover unnoticed.
// testEnvelopeSigner is a deterministic envelope signer: same origin as
// testDigestSigner, returning a fixed signature of a legal length (64 bytes) for
// cases that do not check signature content.
func testEnvelopeSigner() builderclient.BusEnvelopeSigner {
	return builderclient.BusEnvelopeSignerFunc(func(envelope builderclient.BusEnvelope) ([]byte, error) {
		return fixtureSignature(codec.HashWithDomain("TEST_ENVELOPE_V1", []byte(envelope.MessageID))), nil
	})
}

func testDigestSigner() signer.DigestSigner {
	return signer.DigestSignerFunc(func(_ context.Context, req signer.DigestRequest) ([]byte, error) {
		return fixtureSignature(req.Digest), nil
	})
}

// fixtureSignature is a deterministic 64-byte stand-in that is a function of the
// requested digest and nothing else, so a test can recompute the signature a
// correctly derived digest must have produced.
func fixtureSignature(digest codec.Hash) []byte {
	low := codec.HashWithDomain("TEST_VERIFIER_SIGNATURE_V1", digest[:])
	high := codec.HashWithDomain("TEST_VERIFIER_SIGNATURE_V1", low[:])
	s := high
	// validateCompactSignature refuses a high-S scalar, and s here is a hash, so
	// roughly half of all digests would produce one. Clearing the top two bits
	// puts s far below the secp256k1 half order (which begins 0x7fff...) for
	// every input, so the helper's validity no longer depends on which digest it
	// happens to be keyed by. It stays deterministic and nonzero.
	s[0] &= 0x3f
	return append(append(make([]byte, 0, 64), low[:]...), s[:]...)
}

// fixtureTaskGenerationParamsDigest stands in for
// TaskAssignmentViewV1.generation_params_digest as the frozen view serves it
// (TrueOpen/node d8792e6 proto/task/v1/query_task.proto:106). It is keyed
// by task id so a fetch answering for another task cannot coincidentally match.
func fixtureTaskGenerationParamsDigest(taskID string) chainclient.ProtoBytes32 {
	digest := codec.HashWithDomain("TEST_GENERATION_PARAMS_DIGEST_V1", []byte(taskID))
	return chainclient.ProtoBytes32(digest[:])
}

// fixtureTaskAcceptedTaskHash is the other fact the same Keeper read serves. The
// verifier body does not carry it, but the seam does, so the fixture supplies it
// rather than leaving an absent field the consumer would have to tolerate.
func fixtureTaskAcceptedTaskHash(taskID string) chainclient.ProtoBytes32 {
	digest := codec.HashWithDomain("TEST_ACCEPTED_TASK_HASH_V1", []byte(taskID))
	return chainclient.ProtoBytes32(digest[:])
}

// fixtureTaskFacts is the honest reader: it answers for the task it was asked
// about and serves both facts. Every failure mode is a deliberate deviation from
// it, written at the test that needs it.
type fixtureTaskFacts struct{}

func (fixtureTaskFacts) TaskFacts(_ context.Context, taskID string) (taskfacts.Facts, error) {
	return servedTaskFacts(taskID), nil
}

func servedTaskFacts(taskID string) taskfacts.Facts {
	return taskfacts.Facts{
		TaskID: taskID,
		TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
			AcceptedTaskHash:             fixtureTaskAcceptedTaskHash(taskID),
			GenerationParamsDigest:       fixtureTaskGenerationParamsDigest(taskID),
			ProfileExecutionSnapshotHash: bytes.Repeat([]byte{0x93}, 32),
		},
	}
}

func (h harness) validTask() TaskState {
	taskID := canonicalTaskID("84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", 9)
	outputHash, _ := codec.OutputMMRRoot([][]byte{[]byte("worker output")})
	pkg := policy.OutputPackageSummary{
		TaskID:            taskID,
		OutputRef:         h.model.PutArtifactForTest([]byte("worker output")),
		TokenIDsRef:       h.model.PutArtifactForTest(testTokenIDsMaterial()),
		PositionValuesRef: h.model.PutArtifactForTest(testPositionValuesMaterial()),
		OutputHash:        outputHash,
	}
	pkg.PackageHash = codec.HashWithDomain(
		"TRUEOPEN_OUTPUT_PACKAGE_V1",
		[]byte(pkg.TaskID),
		[]byte(pkg.OutputRef),
		[]byte(pkg.TokenIDsRef),
		[]byte(pkg.PositionValuesRef),
		pkg.OutputHash[:],
	)
	return TaskState{
		TaskID:        taskID,
		SessionID:     "84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b",
		OrderSequence: 9,
		OrderDigest:   codec.HashWithDomain("TEST_ORDER_DIGEST", []byte("order-9")),
		// verify_round is pinned to 1 by the frozen contract: it exists to stop
		// cross-round replay and is not a caller-selectable counter.
		VerifyRound:      1,
		InferReceiptHash: codec.HashWithDomain("TEST_INFER_RECEIPT", []byte(taskID)),
		Member: builderclient.CandidateMemberRefMessage{
			CandidatePoolSnapshotID: strings.Repeat("31", 32), Slot: 1, SlotVersion: 1,
			OperatorAddress: fixtureVerifierAddress,
		},
		ModelID:                     modelservice.FakeModelID,
		ProfileVersion:              1,
		Capability:                  modelservice.CapabilityLLMTextV1,
		WorkerAddress:               fixtureWorkerAddress,
		OutputPackage:               pkg,
		OutputConfirmed:             true,
		ConfirmedOutputChunkLengths: []uint64{uint64(len("worker output"))},
		OpenVerifyAccepted:          false,
		AssignedVerifiers:           []string{fixtureVerifierAddress},
		OpenVerifyHeight:            220,
		HandraiseExpiryHeight:       240,
		CurrentHeight:               220,
		FutureBeaconID:              "proposer-vrf-epoch-12",
		CommitDeadlineHeight:        260,
		RevealDeadlineHeight:        300,
		// TRUEOPEN_BUS_ENVELOPE_V1 fields 11 and 12. Every verifier-stage message is
		// OPEN_VERIFY, so the admissible authority is the Task's locked reference.
	}
}

func outputPackageFromState(t *testing.T, state TaskState) builderclient.OutputPackage {
	t.Helper()
	receiptHash := codec.HashWithDomain("TEST_RECEIPT", []byte(state.TaskID), state.OutputPackage.OutputHash[:], state.OutputPackage.PackageHash[:])
	receiptPayload, err := builderclient.EncodeInferReceiptMaterial(builderclient.InferReceiptMaterial{
		TaskID:              state.TaskID,
		OutputRef:           state.OutputPackage.OutputRef,
		OutputHash:          state.OutputPackage.OutputHash,
		PackageHash:         state.OutputPackage.PackageHash,
		ReceiptResultHash:   receiptHash,
		ActualOutputSummary: "13 bytes output",
	})
	if err != nil {
		t.Fatalf("EncodeInferReceiptMaterial returned error: %v", err)
	}
	return builderclient.OutputPackage{
		TaskID:            state.TaskID,
		OutputRef:         state.OutputPackage.OutputRef,
		TokenIDsRef:       state.OutputPackage.TokenIDsRef,
		PositionValuesRef: state.OutputPackage.PositionValuesRef,
		OutputHash:        state.OutputPackage.OutputHash,
		PackageHash:       state.OutputPackage.PackageHash,
		ReceiptHash:       receiptHash,
		ReceiptPayload:    receiptPayload,
	}
}

func canonicalTaskID(sessionID string, orderSequence uint64) string {
	return identity.TaskIDString(sessionID, orderSequence)
}

// publishedResultReceipt rebuilds the frozen result credential from the bytes
// that actually went onto the bus.
//
// It decodes rather than reading a struct the production code handed back, for
// the same reason frozenResultFromSubmitted exists: the assertion has to be
// about what was PUBLISHED. A body that was assembled correctly and then
// published as something else is precisely the failure a returned struct cannot
// see.
func publishedResultReceipt(t *testing.T, h harness) nodewire.ResultReceiptV3 {
	t.Helper()
	if len(h.builder.Published) != 1 {
		t.Fatalf("published messages = %d, want exactly the result credential", len(h.builder.Published))
	}
	envelope, err := builderclient.DecodeBusEnvelope(h.builder.Published[0].Payload)
	if err != nil {
		t.Fatalf("DecodeBusEnvelope: %v", err)
	}
	var wire bustaskv1.ResultReceiptV3
	if err := proto.Unmarshal(envelope.Payload, &wire); err != nil {
		t.Fatalf("unmarshal published ResultReceiptV3: %v", err)
	}
	optional := func(value *uint32) nodewire.OptionalUint32 {
		if value == nil {
			return nodewire.OptionalUint32{}
		}
		return nodewire.PresentUint32(*value)
	}
	summary := wire.GetMetricSummary()
	return nodewire.ResultReceiptV3{
		SchemaVersion:             wire.GetSchemaVersion(),
		ChainID:                   wire.GetChainId(),
		TaskID:                    wire.GetTaskId(),
		VerifyRound:               wire.GetVerifyRound(),
		VerifierOperatorAddress:   wire.GetVerifierOperatorAddress(),
		ServiceAuthorizationNonce: wire.GetServiceAuthorizationNonce(),
		GenerationParamsDigest:    wire.GetGenerationParamsDigest(),
		MetricRoot:                wire.GetMetricRoot(),
		MetricSummary: nodewire.MetricSummaryV1{
			FiniteCount:               summary.GetFiniteCount(),
			MissingComparedCount:      summary.GetMissingComparedCount(),
			MeanAbsLogprobDiffFP1e6:   summary.GetMeanAbsLogprobDiffFp_1E6(),
			AbsLogprobDiffP95FP1e6:    summary.GetAbsLogprobDiffP95Fp_1E6(),
			AbsLogprobDiffP99FP1e6:    summary.GetAbsLogprobDiffP99Fp_1E6(),
			RankDeltaNonzeroRateFP1e6: summary.GetRankDeltaNonzeroRateFp_1E6(),
			TopkJaccardMeanFP1e6:      optional(summary.TopkJaccardMeanFp_1E6),
			UnionJSP99FP1e6:           optional(summary.UnionJsP99Fp_1E6),
			ComparedTopkCount:         summary.GetComparedTopkCount(),
			ComparedRankCount:         summary.GetComparedRankCount(),
		},
		AggregateProofHash:                wire.GetAggregateProofHash(),
		VerifierEvidenceBundleHash:        wire.GetVerifierEvidenceBundleHash(),
		VerifierEvidenceManifestSizeBytes: wire.GetVerifierEvidenceManifestSizeBytes(),
		Salt:                              wire.GetSalt(),
		ExpiryHeight:                      wire.GetExpiryHeight(),
		ServiceSignature:                  wire.GetServiceSignature(),
		VerifierValueRoot:                 wire.GetVerifierValueRoot(),
		MetricLeafCount:                   wire.GetMetricLeafCount(),
		VerifierEvidenceKeyCommitment:     wire.GetVerifierEvidenceKeyCommitment(),
	}
}

type countingModel struct {
	*modelservice.FakeService
	VerifyCalls        int
	FetchArtifactCalls int
	MainMismatchCount  int
	// DropMetricSamples makes the model service answer a verify request without
	// the per-token comparison. It stands for a model service that predates the
	// metric contract, which is a real deployment shape and must not silently
	// produce a verifier that cannot reveal.
	DropMetricSamples bool
	// SampleValueEnvelope makes the sample-value sequence ref resolve to these
	// bytes instead of to the fake's bare decimal. It stands for
	// modelservice.LocalService, which publishes a JSON verificationEnvelope
	// there - the shape the retired compact reveal encoding could not accept.
	// See reveal_payload_test.go.
	SampleValueEnvelope []byte
	verifyRequests      []modelservice.VerifyRequest
	// fetchedKinds records the Kind of every artifact fetch, which is how a test
	// tells an evidence download apart from the sample-value-sequence read that
	// follows a successful verification. fetchedRefs is the same record by ref.
	fetchedKinds []string
	fetchedRefs  []string
}

func (m *countingModel) Verify(ctx context.Context, req modelservice.VerifyRequest) (modelservice.VerifyResponse, error) {
	m.VerifyCalls++
	m.verifyRequests = append(m.verifyRequests, req)
	resp, err := m.FakeService.Verify(ctx, req)
	resp.MainMismatchCount = m.MainMismatchCount
	if m.DropMetricSamples {
		resp.VerifierValues = nil
	}
	if len(m.SampleValueEnvelope) > 0 && err == nil {
		resp.SampleValueSequenceRef = envelopeSampleValueRef
	}
	return resp, err
}

func (m *countingModel) FetchArtifact(ctx context.Context, req modelservice.FetchArtifactRequest) (modelservice.Artifact, error) {
	m.FetchArtifactCalls++
	m.fetchedKinds = append(m.fetchedKinds, req.Kind)
	m.fetchedRefs = append(m.fetchedRefs, req.Ref)
	if len(m.SampleValueEnvelope) > 0 && req.Ref == envelopeSampleValueRef {
		return modelservice.Artifact{Ref: req.Ref, Data: m.SampleValueEnvelope}, nil
	}
	return m.FakeService.FetchArtifact(ctx, req)
}

type recordingPersistence struct {
	evidence []EvidenceRecord
	settle   []SettleMaterial
	jobs     []ModelJobCheckpoint
	events   *[]string
}

func (r *recordingPersistence) WriteEvidence(_ context.Context, record EvidenceRecord) error {
	r.evidence = append(r.evidence, record)
	r.record("evidence:" + record.Kind)
	return nil
}

func (r *recordingPersistence) WriteSettleMaterial(_ context.Context, material SettleMaterial) error {
	r.settle = append(r.settle, material)
	r.record("settle:" + material.Kind)
	return nil
}

func (r *recordingPersistence) ReadVerifierEvidence(_ context.Context, kind string) ([]byte, error) {
	for index := len(r.evidence) - 1; index >= 0; index-- {
		if r.evidence[index].Kind == kind {
			return append([]byte(nil), r.evidence[index].Data...), nil
		}
	}
	return nil, fmt.Errorf("%w: evidence kind %q not found", evidence.ErrArtifactNotFound, kind)
}

func (r *recordingPersistence) CheckpointModelJob(_ context.Context, record ModelJobCheckpoint) error {
	r.jobs = append(r.jobs, record)
	r.record("job:" + record.Status)
	return nil
}

func (r *recordingPersistence) record(event string) {
	if r.events != nil {
		*r.events = append(*r.events, event)
	}
}

// completeResultReceipt is a frozen ResultReceiptV2 with all twelve signed
// fields populated. Production cannot build one yet - five of the values have no
// Cortex producer - so the signing and submission halves of the path are
// exercised from here. The four Hash32 fields carry deliberately distinct
// patterns so a swap between any two of them changes the digest.
func completeResultReceipt(t *testing.T) nodewire.ResultReceiptV3 {
	t.Helper()
	taskID, err := hex.DecodeString(canonicalTaskID("84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", 9))
	if err != nil {
		t.Fatalf("decode canonical task id: %v", err)
	}
	return nodewire.ResultReceiptV3{
		SchemaVersion:             nodewire.ResultReceiptSchemaVersionV3,
		ChainID:                   "chain-A",
		TaskID:                    taskID,
		VerifyRound:               1,
		VerifierOperatorAddress:   fixtureVerifierAddress,
		ServiceAuthorizationNonce: 11,
		GenerationParamsDigest:    bytes.Repeat([]byte{0x71}, 32),
		MetricRoot:                bytes.Repeat([]byte{0x72}, 32),
		MetricSummary: nodewire.MetricSummaryV1{
			FiniteCount:               1024,
			MissingComparedCount:      7,
			MeanAbsLogprobDiffFP1e6:   250000,
			AbsLogprobDiffP95FP1e6:    900000,
			AbsLogprobDiffP99FP1e6:    990000,
			RankDeltaNonzeroRateFP1e6: 125000,
			TopkJaccardMeanFP1e6:      nodewire.PresentUint32(333333),
			UnionJSP99FP1e6:           nodewire.PresentUint32(444444),
			ComparedTopkCount:         512,
			ComparedRankCount:         768,
		},
		AggregateProofHash:                bytes.Repeat([]byte{0x73}, 32),
		VerifierEvidenceBundleHash:        bytes.Repeat([]byte{0x74}, 32),
		VerifierEvidenceManifestSizeBytes: 123,
		Salt:                              bytes.Repeat([]byte{0x75}, 32),
		ExpiryHeight:                      300,
		VerifierValueRoot:                 bytes.Repeat([]byte{0x76}, 32),
		MetricLeafCount:                   1031,
		VerifierEvidenceKeyCommitment:     make([]byte, 32),
	}
}

// frozenResultFromSubmitted rebuilds the frozen wire from the ProtoJSON body
// alone. Like frozenCommitFromSubmitted it deliberately shares no production
// helper: the point is to derive the digest from what was SUBMITTED, not from
// what was signed, so the two can be compared.
func frozenResultFromSubmitted(t *testing.T, receipt txclient.ResultReceiptMessage) nodewire.ResultReceiptV3 {
	t.Helper()
	decode := func(name string, value txclient.ProtoBytes32) []byte {
		raw, err := hex.DecodeString(value.Hex())
		if err != nil {
			t.Fatalf("decode submitted %s: %v", name, err)
		}
		return raw
	}
	optional := func(value *txclient.ProtoUint32) nodewire.OptionalUint32 {
		if value == nil {
			return nodewire.OptionalUint32{}
		}
		return nodewire.PresentUint32(uint32(*value))
	}
	summary := receipt.MetricSummary
	return nodewire.ResultReceiptV3{
		SchemaVersion:             uint32(receipt.SchemaVersion),
		ChainID:                   receipt.ChainID,
		TaskID:                    decode("task_id", receipt.TaskID),
		VerifyRound:               uint32(receipt.VerifyRound),
		VerifierOperatorAddress:   receipt.VerifierOperatorAddress,
		ServiceAuthorizationNonce: uint64(receipt.ServiceAuthorizationNonce),
		GenerationParamsDigest:    decode("generation_params_digest", receipt.GenerationParamsDigest),
		MetricRoot:                decode("metric_root", receipt.MetricRoot),
		MetricSummary: nodewire.MetricSummaryV1{
			FiniteCount:               uint32(summary.FiniteCount),
			MissingComparedCount:      uint32(summary.MissingComparedCount),
			MeanAbsLogprobDiffFP1e6:   uint32(summary.MeanAbsLogprobDiffFP1e6),
			AbsLogprobDiffP95FP1e6:    uint32(summary.AbsLogprobDiffP95FP1e6),
			AbsLogprobDiffP99FP1e6:    uint32(summary.AbsLogprobDiffP99FP1e6),
			RankDeltaNonzeroRateFP1e6: uint32(summary.RankDeltaNonzeroRateFP1e6),
			TopkJaccardMeanFP1e6:      optional(summary.TopkJaccardMeanFP1e6),
			UnionJSP99FP1e6:           optional(summary.UnionJSP99FP1e6),
			ComparedTopkCount:         uint32(summary.ComparedTopkCount),
			ComparedRankCount:         uint32(summary.ComparedRankCount),
		},
		AggregateProofHash:                decode("aggregate_proof_hash", receipt.AggregateProofHash),
		VerifierEvidenceBundleHash:        decode("verifier_evidence_bundle_hash", receipt.VerifierEvidenceBundleHash),
		VerifierEvidenceManifestSizeBytes: uint64(receipt.VerifierEvidenceManifestSizeBytes),
		Salt:                              decode("salt", receipt.Salt),
		ExpiryHeight:                      uint64(receipt.ExpiryHeight),
		VerifierValueRoot:                 decode("verifier_value_root", receipt.VerifierValueRoot),
		MetricLeafCount:                   uint32(receipt.MetricLeafCount),
		VerifierEvidenceKeyCommitment:     decode("verifier_evidence_key_commitment", receipt.VerifierEvidenceKeyCommitment),
	}
}

// TestVerifyRefusesIncompleteResultBodyBeforeSigning pins the ordering for the
// result path the way TestVerifyRefusesIncompleteCommitBodyBeforeSigning does for
// the commit. The signer counter is the assertion that matters: exactly one
// signature is produced on this path - the commit's - so the result signer is
// never asked to authorize a body that is still missing consensus fields.
func TestVerifyRefusesIncompleteResultBodyBeforeSigning(t *testing.T) {
	h := newHarness(t)
	digests := []codec.Hash{}
	h.verifier.cfg.Signer = signer.DigestSignerFunc(func(_ context.Context, req signer.DigestRequest) ([]byte, error) {
		digests = append(digests, req.Digest)
		return fixtureSignature(req.Digest), nil
	})
	state := h.validTask()
	state.OpenVerifyAccepted = true

	result := verifyLocally(t, h, state)
	// Asserted BEFORE the reveal runs. The commit half must ask the signer for
	// exactly one digest - its own - and the reveal is a separate responsibility
	// with a separate signature; folding the two calls together would no longer
	// show which half signed what.
	commitDigest, err := nodewire.VerifyCommitSigningDigest(nodewire.VerifyCommitV1{
		SchemaVersion:             result.CommitWire.SchemaVersion,
		ChainID:                   result.CommitWire.ChainID,
		TaskID:                    result.CommitWire.TaskID,
		VerifyRound:               result.CommitWire.VerifyRound,
		VerifierOperatorAddress:   result.CommitWire.VerifierOperatorAddress,
		ServiceAuthorizationNonce: result.CommitWire.ServiceAuthorizationNonce,
		CommitHash:                result.CommitWire.CommitHash,
		ExpiryHeight:              result.CommitWire.ExpiryHeight,
	})
	if err != nil {
		t.Fatalf("derive commit digest: %v", err)
	}
	if len(digests) != 1 || digests[0] != commitDigest {
		t.Fatalf("signer saw %d digests %x, want exactly the commit digest: an incomplete frozen result body was signed",
			len(digests), digests)
	}
	if len(h.builder.Published) != 0 {
		t.Fatalf("published = %#v, want nothing: the commit half never reveals", h.builder.Published)
	}

	// The reveal then adds exactly one more signature, over the frozen result
	// body it actually published - so the second digest is not just "another
	// signature", it is the one the Keeper will recompute.
	revealLocally(t, h, state)
	if len(digests) != 2 {
		t.Fatalf("signer saw %d digests after the reveal, want the commit and the result", len(digests))
	}
	resultDigest, err := nodewire.ResultReceiptSigningDigest(publishedResultReceipt(t, h))
	if err != nil {
		t.Fatalf("derive result digest: %v", err)
	}
	if digests[1] != resultDigest {
		t.Fatalf("the reveal signed %x, want the published body's own TRUEOPEN_RESULT_V1 digest %x", digests[1], resultDigest)
	}
}

// TestResultReceiptWireRefusesAvailableInputGaps covers the gates that guard
// values Cortex does have. HandleOpenVerifyAccepted cannot reach the task_id case
// - validateCanonicalTaskState pins the identity first - but the frozen preimage
// frames task_id as raw 32 bytes, so the builder must refuse rather than pad or
// truncate whatever text it is handed.
func TestResultReceiptWireRefusesAvailableInputGaps(t *testing.T) {
	base := Config{ChainID: "chain-A", VerifierAddress: fixtureVerifierAddress, ServiceAuthorizationNonce: 11}
	valid := TaskState{TaskID: canonicalTaskID("84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", 9), VerifyRound: 1, RevealDeadlineHeight: 300}
	for name, mutate := range map[string]func(*Config, *TaskState){
		"service_authorization_nonce": func(cfg *Config, _ *TaskState) { cfg.ServiceAuthorizationNonce = 0 },
		"expiry_height":               func(_ *Config, state *TaskState) { state.RevealDeadlineHeight = 0 },
		"task_id":                     func(_ *Config, state *TaskState) { state.TaskID = "task-1" },
		"verify_round":                func(_ *Config, state *TaskState) { state.VerifyRound = math.MaxUint32 + 1 },
	} {
		cfg, state := base, valid
		mutate(&cfg, &state)
		_, err := resultReceiptWire(cfg, state, servedTaskFacts(state.TaskID), []byte(fixtureResultReveal), metric.Material{}, []byte("manifest"), codec.HashBytes([]byte("salt")))
		if !errors.Is(err, ErrResultReceiptInputUnavailable) {
			t.Fatalf("resultReceiptWire with a bad %s error = %v, want the input gap refused", name, err)
		}
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("the %s refusal does not name the field: %v", name, err)
		}
	}
	// With every sourced input satisfied the refusal must be the remaining
	// producer gap, and it must still name the fields it cannot fill rather than
	// reporting a generic failure.
	_, err := resultReceiptCredential(base, valid, servedTaskFacts(valid.TaskID), []byte(fixtureResultReveal), metric.Material{}, []byte("manifest"), codec.HashBytes([]byte("salt")))
	if !errors.Is(err, ErrResultReceiptInputUnavailable) {
		t.Fatalf("resultReceiptCredential error = %v, want the remaining producer gap", err)
	}
	for _, field := range []string{"metric_root", "MetricSummaryV1", "aggregate_proof_hash"} {
		if !strings.Contains(err.Error(), field) {
			t.Fatalf("the producer-gap refusal does not name %s: %v", field, err)
		}
	}
	// generation_params_digest is not among the gaps any more: the verifier reads
	// it through chainclient.KeeperABCIClient.TaskReceiptFacts, so naming it here
	// would send an operator after work that is already done.
	if strings.Contains(err.Error(), "generation_params_digest") {
		t.Fatalf("the producer-gap refusal still blames generation_params_digest, which is now wired: %v", err)
	}
	// The negative guard #182 added. Every refusal on this path must describe the
	// world d8792e6 actually froze.
	for _, stale := range []string{"node#99", "node#100", "never writes", "does not read yet", "no verifier path calls"} {
		if strings.Contains(err.Error(), stale) {
			t.Fatalf("the refusal still blames %q, which d8792e6 contradicts: %v", stale, err)
		}
	}
}

// TestResultReceiptWireCarriesTheServedGenerationParamsDigest is the positive
// half of the wiring: the bytes the Keeper read served have to be the bytes the
// frozen body carries, byte for byte and with no re-derivation, because the
// handler only ever compares them.
func TestResultReceiptWireCarriesTheServedGenerationParamsDigest(t *testing.T) {
	cfg := Config{ChainID: "chain-A", VerifierAddress: fixtureVerifierAddress, ServiceAuthorizationNonce: 11}
	state := TaskState{TaskID: canonicalTaskID("84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", 9), VerifyRound: 1, RevealDeadlineHeight: 300}
	served := servedTaskFacts(state.TaskID)

	receipt, err := resultReceiptWire(cfg, state, served, []byte(fixtureResultReveal), metric.Material{}, []byte("manifest"), codec.HashBytes([]byte("salt")))
	if err != nil {
		t.Fatalf("resultReceiptWire: %v", err)
	}
	if !bytes.Equal(receipt.GenerationParamsDigest, served.GenerationParamsDigest) {
		t.Fatalf("generation_params_digest = %x, want the served %x",
			receipt.GenerationParamsDigest, served.GenerationParamsDigest)
	}
	// A copy, not an alias: a body that shared the reader's backing array would
	// let a later read mutate an already-signed value.
	receipt.GenerationParamsDigest[0] ^= 0xff
	if bytes.Equal(receipt.GenerationParamsDigest, served.GenerationParamsDigest) {
		t.Fatal("the frozen body aliases the reader's slice instead of copying it")
	}
}

// TestResultReceiptWireRefusesUnusableServedFacts is the fail-closed half. Each
// case is a well-formed response the verifier must not sign, and they are kept
// apart on purpose: "answered for another task", "did not carry the value" and
// "served 32 zero bytes" are three different faults with three different fixes.
func TestResultReceiptWireRefusesUnusableServedFacts(t *testing.T) {
	cfg := Config{ChainID: "chain-A", VerifierAddress: fixtureVerifierAddress, ServiceAuthorizationNonce: 11}
	state := TaskState{TaskID: canonicalTaskID("84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", 9), VerifyRound: 1, RevealDeadlineHeight: 300}
	other := canonicalTaskID("84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", 10)
	for name, tc := range map[string]struct {
		facts    taskfacts.Facts
		contains string
	}{
		"another task": {servedTaskFacts(other), "not the task"},
		"absent generation_params_digest": {taskfacts.Facts{
			TaskID: state.TaskID,
			TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
				AcceptedTaskHash: fixtureTaskAcceptedTaskHash(state.TaskID),
			},
		}, "carries no generation_params_digest"},
		"all-zero generation_params_digest": {taskfacts.Facts{
			TaskID: state.TaskID,
			TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
				AcceptedTaskHash:       fixtureTaskAcceptedTaskHash(state.TaskID),
				GenerationParamsDigest: make(chainclient.ProtoBytes32, 32),
			},
		}, "all-zero generation_params_digest"},
	} {
		t.Run(name, func(t *testing.T) {
			receipt, err := resultReceiptWire(cfg, state, tc.facts, []byte(fixtureResultReveal), metric.Material{}, []byte("manifest"), codec.HashBytes([]byte("salt")))
			if !errors.Is(err, ErrResultReceiptInputUnavailable) {
				t.Fatalf("resultReceiptWire error = %v, want the input gap refused", err)
			}
			if !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("refusal does not say %q: %v", tc.contains, err)
			}
			if receipt.GenerationParamsDigest != nil {
				t.Fatalf("a refused build still returned a body: %#v", receipt)
			}
		})
	}
}

// TestVerifierTaskFactsRefusesAnUnusableAnswerAtTheReadBoundary pins the
// guarantee taskFacts's own doc comment makes, independently of the assembler.
//
// Today resultReceiptWire is the only consumer of a Facts value in this package,
// so deleting the Validate call in taskFacts leaves every path-level test green
// and the comment silently false. That coupling is the fragility being removed:
// this test fails the moment the read boundary stops refusing.
func TestVerifierTaskFactsRefusesAnUnusableAnswerAtTheReadBoundary(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	other := canonicalTaskID("84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", 10)
	for name, tc := range map[string]struct {
		served   taskfacts.Facts
		contains string
	}{
		"another task": {servedTaskFacts(other), "not the task"},
		"absent generation_params_digest": {taskfacts.Facts{
			TaskID: state.TaskID,
			TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
				AcceptedTaskHash: fixtureTaskAcceptedTaskHash(state.TaskID),
			},
		}, "carries no generation_params_digest"},
		"all-zero generation_params_digest": {taskfacts.Facts{
			TaskID: state.TaskID,
			TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
				AcceptedTaskHash:       fixtureTaskAcceptedTaskHash(state.TaskID),
				GenerationParamsDigest: make(chainclient.ProtoBytes32, 32),
			},
		}, "all-zero generation_params_digest"},
	} {
		t.Run(name, func(t *testing.T) {
			h.verifier.cfg.TaskFacts = taskfacts.ReaderFunc(
				func(context.Context, string) (taskfacts.Facts, error) { return tc.served, nil },
			)
			facts, err := h.verifier.taskFacts(context.Background(), state.TaskID)
			if !errors.Is(err, ErrResultReceiptInputUnavailable) {
				t.Fatalf("taskFacts error = %v, want the input gap refused at the read", err)
			}
			if !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("refusal does not say %q: %v", tc.contains, err)
			}
			// Nothing usable escapes the boundary, so a second consumer cannot
			// inherit an answer the first would have refused.
			if facts.TaskID != "" || facts.AcceptedTaskHash.IsSet() || facts.GenerationParamsDigest.IsSet() {
				t.Fatalf("a refused read still returned facts: %#v", facts)
			}
			// Permanent: the same query returns the same bytes.
			if builderclient.IsRetryable(err) {
				t.Fatalf("an unusable answer was reported as retryable: %v", err)
			}
		})
	}
}

// TestVerifyPropagatesARetryableTaskFactsFetchFailure keeps the two failure
// modes apart at the path level. A Keeper transport failure is retryable and
// must stay so; a well-formed answer that lacks the fact is the permanent
// refusal the test above pins. Collapsing them would either spin forever on a
// gap or give up on a blip.
func TestVerifyPropagatesARetryableTaskFactsFetchFailure(t *testing.T) {
	h := newHarness(t)
	h.verifier.cfg.TaskFacts = taskfacts.ReaderFunc(func(context.Context, string) (taskfacts.Facts, error) {
		return taskfacts.Facts{}, builderclient.Retryable(errors.New("keeper ABCI query timed out"))
	})
	state := h.validTask()
	state.OpenVerifyAccepted = true

	_, err := h.verifier.HandleRevealPhaseStarted(context.Background(), state)
	if err == nil || !builderclient.IsRetryable(err) {
		t.Fatalf("HandleRevealPhaseStarted error = %v, want a retryable Keeper read failure", err)
	}
	if errors.Is(err, ErrResultReceiptInputUnavailable) {
		t.Fatalf("a failed fetch was reported as a permanent input gap: %v", err)
	}
}

// TestVerifyWithoutATaskFactsReaderRefusesBeforeSigning pins that a verifier
// built without the reader cannot reach the result signer at all.
func TestVerifyWithoutATaskFactsReaderRefusesBeforeSigning(t *testing.T) {
	h := newHarness(t)
	h.verifier.cfg.TaskFacts = nil
	state := h.validTask()
	state.OpenVerifyAccepted = true

	_, err := h.verifier.HandleRevealPhaseStarted(context.Background(), state)
	if !errors.Is(err, ErrResultReceiptInputUnavailable) ||
		!strings.Contains(err.Error(), "Keeper task facts reader") {
		t.Fatalf("HandleRevealPhaseStarted error = %v, want the missing-reader refusal", err)
	}
	if len(h.builder.Published) != 0 {
		t.Fatalf("published = %#v, want nothing without the consensus read", h.builder.Published)
	}
}

// profileReaderStub serves a fixed locked profile snapshot for verifier tests.
type profileReaderStub struct {
	profile chainclient.CurrentModelProfileSnapshot
	err     error
}

func (s profileReaderStub) CurrentModelProfile(context.Context, string, string) (chainclient.CurrentModelProfileSnapshot, error) {
	return s.profile, s.err
}

// profileWithRequiredEvidence builds a minimal locked profile snapshot that
// requires the supplied evidence kinds with a generous default size bound.
func profileWithRequiredEvidence(kinds ...int32) chainclient.CurrentModelProfileSnapshot {
	return profileWithRequiredEvidenceAndMaxSize(1<<30, kinds)
}

// profileWithRequiredEvidenceAndMaxSize builds a locked profile snapshot that
// requires the supplied evidence kinds, each bound by maxSize, and whose typed
// evidence_schema re-derives to its evidence_schema_hash.
func profileWithRequiredEvidenceAndMaxSize(maxSize uint64, kinds []int32) chainclient.CurrentModelProfileSnapshot {
	profile := newProfileStub(kinds, maxSize, nil)
	hash, err := keepercontract.ComputeEvidenceSchemaHashFromCurrentModelProfile(profile)
	if err != nil {
		panic(fmt.Sprintf("compute evidence schema hash: %v", err))
	}
	profile.Profile.VerificationProfile.EvidenceSchemaHash = chainclient.ProtoBytes32(hash[:])
	return profile
}

func fixtureProtoBytes32(domain string) chainclient.ProtoBytes32 {
	digest := codec.HashWithDomain(domain, []byte("test-model"))
	return chainclient.ProtoBytes32(digest[:])
}

// evidenceCommitmentSchemaFor is the commitment schema wire v0.3.0 pairs with
// each Worker evidence kind.
func evidenceCommitmentSchemaFor(kind int32) uint32 {
	switch nodewire.EvidenceKind(kind) {
	case nodewire.EvidenceKindWorkerValueOpening:
		return nodewire.WorkerValueCommitmentSchemaVersionV3
	case nodewire.EvidenceKindWorkerTokenOpening:
		return nodewire.WorkerTokenCommitmentSchemaVersionV1
	default:
		return 2
	}
}

// newProfileStub builds a locked profile snapshot with the supplied evidence kinds.
// The evidence_schema_hash is left unset (or set to override if provided) so tests
// can exercise both valid and invalid schemas.
func newProfileStub(kinds []int32, maxSize uint64, evidenceSchemaHash chainclient.ProtoBytes32) chainclient.CurrentModelProfileSnapshot {
	requirements := make([]chainclient.CurrentInferEvidenceRequirementSnapshot, len(kinds))
	for i, kind := range kinds {
		requirements[i] = chainclient.CurrentInferEvidenceRequirementSnapshot{
			EvidenceKind:            kind,
			CommitmentSchemaVersion: evidenceCommitmentSchemaFor(kind),
			MaxEncodedSizeBytes:     chainclient.NewUint64String(maxSize),
		}
	}
	return chainclient.CurrentModelProfileSnapshot{
		Profile: chainclient.CurrentProfileSnapshot{
			ModelID:        modelservice.FakeModelID,
			ProfileVersion: chainclient.NewProfileVersion(1),
			// Non-zero on purpose. keeper §10.0.2 requires schema_hash and tokenizer_hash
			// to be "exactly 32 bytes and not all zero", and tokenizer_hash enters every
			// metric leaf preimage - a stub of 32 zero bytes is a profile the chain would
			// never have registered, and the metric binding refuses it rather than hashing
			// it into a leaf.
			SchemaHash:     fixtureProtoBytes32("TEST_PROFILE_STUB_SCHEMA_HASH_V1"),
			TokenizerHash:  fixtureProtoBytes32("TEST_PROFILE_STUB_TOKENIZER_HASH_V1"),
			GenerationType: "GENERATION_TYPE_DETERMINISTIC",
			RequiredTopK:   1,
			BatchVerification: chainclient.CurrentBatchVerificationSnapshot{
				Enabled:                       false,
				MinSampleCount:                0,
				MinValidSampleCount:           0,
				PassMinSamplePassRatioBPS:     0,
				RejectMinSampleRejectRatioBPS: 0,
			},
			VerificationProfile: chainclient.CurrentVerificationProfileSnapshot{
				VerificationProfileID:         1,
				JudgmentFunctionVersion:       "PREFILL_GENERATED_TOKEN_METRICS_V1",
				VerificationMode:              "VERIFICATION_MODE_SINGLE_SAMPLE",
				TokenScope:                    "TOKEN_SCOPE_ALL_GENERATED_OUTPUT_TOKENS",
				IncludeGeneratedSpecialTokens: false,
				IncludePromptTokens:           false,
				IncludePaddingTokens:          false,
				RequireOutputTokenIDs:         false,
				RequireFinishReason:           false,
				Metrics: chainclient.CurrentMetricSpecSnapshot{
					CompareLogprobDiff: true,
					CompareRankDelta:   true,
					CompareTopKJaccard: true,
					CompareUnionJS:     true,
					ComparedTopK:       1,
					NumericScale:       "NUMERIC_SCALE_FP_1E6",
				},
				CanonicalEncodingVersion:    "CANONICAL_OUTPUT_TEXT_V1",
				MetricAggregateProofVersion: "PREFILL_METRIC_AGGREGATE_PROOF_V1",
				EvidenceSchema:              chainclient.CurrentEvidenceSchemaSnapshot{SchemaVersion: 1, RequiredInferEvidence: requirements},
				EvidenceSchemaHash:          evidenceSchemaHash,
			},
		},
	}
}

func newHarnessWithProfileReader(t *testing.T, reader ProfileReader) harness {
	h := newHarness(t)
	v := New(Config{
		VerifierAddress:           h.verifier.cfg.VerifierAddress,
		ModelServiceID:            h.verifier.cfg.ModelServiceID,
		Model:                     h.verifier.cfg.Model,
		Builder:                   h.verifier.cfg.Builder,
		Persistence:               h.verifier.cfg.Persistence,
		ChainID:                   h.verifier.cfg.ChainID,
		SignerAddress:             h.verifier.cfg.SignerAddress,
		SignerKeyRef:              h.verifier.cfg.SignerKeyRef,
		Signer:                    h.verifier.cfg.Signer,
		VerifyDeadlineDeltaHeight: h.verifier.cfg.VerifyDeadlineDeltaHeight,
		FakeOutput:                h.verifier.cfg.FakeOutput,
		TrustedNATSDev:            h.verifier.cfg.TrustedNATSDev,
		NexusEnvelopeSigner:       h.verifier.cfg.NexusEnvelopeSigner,
		EnvelopeTTL:               h.verifier.cfg.EnvelopeTTL,
		TaskFacts:                 h.verifier.cfg.TaskFacts,
		ServiceAuthorizationNonce: h.verifier.cfg.ServiceAuthorizationNonce,
		ProfileReader:             reader,
		CommitSubmitter:           h.verifier.cfg.CommitSubmitter,
		EvidencePublisher:         h.verifier.cfg.EvidencePublisher,
	})
	return harness{model: h.model, builder: h.builder, persistence: h.persistence, tx: h.tx, verifier: v}
}

// TestVerifierRejectsProfileRequiringUnsupportedEvidenceKind checks that a
// locked profile requiring an evidence kind the verifier cannot yet fetch is
// refused rather than silently ignored.
func TestVerifierRejectsProfileRequiringUnsupportedEvidenceKind(t *testing.T) {
	h := newHarnessWithProfileReader(t, profileReaderStub{profile: profileWithRequiredEvidence(int32(nodewire.EvidenceKindVerifierValueOpening))})
	state := h.validTask()
	state.OpenVerifyAccepted = true

	_, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if err == nil || !strings.Contains(err.Error(), "unsupported evidence kind") {
		t.Fatalf("expected unsupported evidence kind error, got: %v", err)
	}
}

// TestVerifierRejectsProfileWithEmptyEvidenceSchema checks that a profile whose
// evidence schema lists no required kinds is treated as unsupported.
func TestVerifierRejectsProfileWithEmptyEvidenceSchema(t *testing.T) {
	h := newHarnessWithProfileReader(t, profileReaderStub{profile: profileWithRequiredEvidence()})
	state := h.validTask()
	state.OpenVerifyAccepted = true

	_, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if err == nil || !strings.Contains(err.Error(), "must require exactly the Worker value and token evidence") {
		t.Fatalf("expected no evidence schema error, got: %v", err)
	}
}

// TestVerifierRequiresProfileReaderInRealMode checks that a non-fake verifier
// without a profile reader fails closed.
func TestVerifierRequiresProfileReaderInRealMode(t *testing.T) {
	h := newHarnessWithProfileReader(t, nil)
	// Disable fake mode so the profile reader is mandatory.
	h.verifier.cfg.FakeOutput = false
	state := h.validTask()
	state.OpenVerifyAccepted = true

	_, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if err == nil || !strings.Contains(err.Error(), "profile reader is required") {
		t.Fatalf("expected profile reader required error, got: %v", err)
	}
}

// TestVerifierRejectsUnsupportedEvidenceKindBeforeFetch checks that an
// unsupported required kind is refused before any artifact is downloaded.
func TestVerifierRejectsUnsupportedEvidenceKindBeforeFetch(t *testing.T) {
	h := newHarnessWithProfileReader(t, profileReaderStub{profile: profileWithRequiredEvidence(int32(nodewire.EvidenceKindVerifierValueOpening))})
	state := h.validTask()
	state.OpenVerifyAccepted = true

	_, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if err == nil || !strings.Contains(err.Error(), "unsupported evidence kind") {
		t.Fatalf("expected unsupported evidence kind error, got: %v", err)
	}
	if h.model.FetchArtifactCalls != 0 {
		t.Fatalf("FetchArtifact calls = %d, want 0 (rejected before download)", h.model.FetchArtifactCalls)
	}
}

// TestVerifierRejectsOversizedTrace checks that a trace larger than the
// profile's per-kind max_encoded_size_bytes is refused.
func TestVerifierRejectsOversizedTrace(t *testing.T) {
	h := newHarnessWithProfileReader(t, profileReaderStub{profile: profileWithRequiredEvidenceAndMaxSize(1, []int32{int32(nodewire.EvidenceKindWorkerValueOpening), int32(nodewire.EvidenceKindWorkerTokenOpening)})})
	state := h.validTask()
	state.OpenVerifyAccepted = true

	_, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if err == nil || !errors.Is(err, modelservice.ErrArtifactSizeExceeded) {
		t.Fatalf("expected size limit exceeded error, got: %v", err)
	}
}

func TestVerifierRejectsOversizedPositionValues(t *testing.T) {
	h := newHarnessWithProfileReader(t, profileReaderStub{profile: profileWithRequiredEvidenceAndMaxSize(100, []int32{int32(nodewire.EvidenceKindWorkerValueOpening), int32(nodewire.EvidenceKindWorkerTokenOpening)})})
	state := h.validTask()
	state.OpenVerifyAccepted = true
	// Token-id material fits within the bound, position-value material exceeds it.
	state.OutputPackage.TokenIDsRef = h.model.PutArtifactForTest(make([]byte, 50))
	state.OutputPackage.PositionValuesRef = h.model.PutArtifactForTest(make([]byte, 101))
	state.OutputPackage.PackageHash = codec.HashWithDomain(
		"TRUEOPEN_OUTPUT_PACKAGE_V1",
		[]byte(state.OutputPackage.TaskID),
		[]byte(state.OutputPackage.OutputRef),
		[]byte(state.OutputPackage.TokenIDsRef),
		[]byte(state.OutputPackage.PositionValuesRef),
		state.OutputPackage.OutputHash[:],
	)

	_, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if err == nil || !errors.Is(err, modelservice.ErrArtifactSizeExceeded) {
		t.Fatalf("expected size limit exceeded error, got: %v", err)
	}
}

// boundedRefModel wraps a FakeService and refuses FetchArtifact requests whose
// SizeLimitBytes is smaller than the artifact size declared in the ref, without
// buffering the body. It lets the verifier test prove the bound is forwarded to
// the model service before any artifact content is buffered.
type boundedRefModel struct {
	*modelservice.FakeService
}

func (m *boundedRefModel) FetchArtifact(ctx context.Context, req modelservice.FetchArtifactRequest) (modelservice.Artifact, error) {
	ref, err := modelservice.ParseArtifactRef(req.Ref)
	if err != nil {
		return modelservice.Artifact{}, err
	}
	if req.SizeLimitBytes > 0 && uint64(ref.SizeBytes) > req.SizeLimitBytes {
		return modelservice.Artifact{}, fmt.Errorf("%w: kind=%s, bound=%d, observed=%d", modelservice.ErrArtifactSizeExceeded, req.Kind, req.SizeLimitBytes, ref.SizeBytes)
	}
	return m.FakeService.FetchArtifact(ctx, req)
}

func TestVerifierRejectsOversizedArtifactBeforeBuffering(t *testing.T) {
	fake := modelservice.NewFakeService()
	model := &boundedRefModel{FakeService: fake}
	h := newHarnessWithProfileReader(t, profileReaderStub{profile: profileWithRequiredEvidenceAndMaxSize(10, []int32{int32(nodewire.EvidenceKindWorkerValueOpening), int32(nodewire.EvidenceKindWorkerTokenOpening)})})
	// Replace the model with the bounded-ref wrapper while keeping counters.
	h.verifier.cfg.Model = model
	h.model.FakeService = fake
	state := h.validTask()
	state.OpenVerifyAccepted = true
	// The token-id material is 14 bytes, exceeding the 10-byte bound.
	state.OutputPackage.TokenIDsRef = fake.PutArtifactForTest(make([]byte, 14))
	state.OutputPackage.PackageHash = codec.HashWithDomain(
		"TRUEOPEN_OUTPUT_PACKAGE_V1",
		[]byte(state.OutputPackage.TaskID),
		[]byte(state.OutputPackage.OutputRef),
		[]byte(state.OutputPackage.TokenIDsRef),
		[]byte(state.OutputPackage.PositionValuesRef),
		state.OutputPackage.OutputHash[:],
	)

	_, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if err == nil || !errors.Is(err, modelservice.ErrArtifactSizeExceeded) {
		t.Fatalf("expected size limit exceeded error before buffering, got: %v", err)
	}
}

// fetchBoundRecorder records the bound and kind each FetchArtifact carried.
type fetchBoundRecorder struct {
	*modelservice.FakeService
	limits map[string]uint64
	kinds  map[string]string
}

func (m *fetchBoundRecorder) FetchArtifact(ctx context.Context, req modelservice.FetchArtifactRequest) (modelservice.Artifact, error) {
	if m.limits == nil {
		m.limits, m.kinds = map[string]uint64{}, map[string]string{}
	}
	m.limits[req.RequestID] = req.SizeLimitBytes
	m.kinds[req.RequestID] = req.Kind
	return m.FakeService.FetchArtifact(ctx, req)
}

// The sample-value ref is the least trustworthy input in the verify path: it
// arrives inside the model service's own Verify response, so a malicious service
// chooses both the ref and the bytes behind it. An unbounded fetch there lets one
// response make the verifier buffer without limit, which is the same failure the
// evidence bound exists to prevent.
func TestVerificationValuesFetchCarriesTheProfileBound(t *testing.T) {
	fake := modelservice.NewFakeService()
	recorder := &fetchBoundRecorder{FakeService: fake}
	ref := fake.PutArtifactForTest([]byte("sample-values"))
	v := New(Config{Model: recorder, MaxOutputBytes: 4096})

	if _, err := v.fetchVerificationValues(context.Background(), "task-1", ref); err != nil {
		t.Fatalf("fetchVerificationValues returned error: %v", err)
	}
	if got := recorder.limits["verifier-fetch-values-task-1"]; got != 4096 {
		t.Fatalf("SizeLimitBytes = %d, want the profile maximum forwarded", got)
	}
	if got := recorder.kinds["verifier-fetch-values-task-1"]; got != "verifier-sample-values" {
		t.Fatalf("Kind = %q, want the sample-values label so an overflow names itself", got)
	}
}

// The output is fetched before its hash can reject anything, so an unbounded
// fetch lets a model service stream arbitrarily many individually valid chunks
// into this node's memory. Unlike the Worker evidence, no profile field sizes
// the output, which is why the bound is configured rather than derived.
func TestOutputFetchCarriesTheConfiguredBound(t *testing.T) {
	fake := modelservice.NewFakeService()
	recorder := &fetchBoundRecorder{FakeService: fake}
	h := newHarnessWithProfileReader(t, profileReaderStub{profile: profileWithRequiredEvidenceAndMaxSize(4096, []int32{int32(nodewire.EvidenceKindWorkerValueOpening), int32(nodewire.EvidenceKindWorkerTokenOpening)})})
	h.verifier.cfg.Model = recorder
	h.verifier.cfg.MaxOutputBytes = 12345
	h.model.FakeService = fake
	state := h.validTask()
	state.OpenVerifyAccepted = true

	// The call may fail further along; all this test cares about is the request.
	_, _ = h.verifier.HandleOpenVerifyAccepted(context.Background(), state)

	limit, ok := recorder.limits["verifier-fetch-output-"+state.TaskID]
	if !ok {
		t.Fatalf("the output fetch never happened; requests = %v", recorder.limits)
	}
	if limit != 12345 {
		t.Fatalf("SizeLimitBytes = %d, want the configured output bound", limit)
	}
}

// Zero must mean "use the default", never "unbounded". An omitted wiring path is
// the likeliest way this bound would go missing, so New closes that door.
func TestNewAppliesTheDefaultOutputBound(t *testing.T) {
	v := New(Config{})
	if v.cfg.MaxOutputBytes != DefaultMaxOutputBytes {
		t.Fatalf("MaxOutputBytes = %d, want the default %d", v.cfg.MaxOutputBytes, DefaultMaxOutputBytes)
	}
	kept := New(Config{MaxOutputBytes: 7})
	if kept.cfg.MaxOutputBytes != 7 {
		t.Fatalf("MaxOutputBytes = %d, want the configured value kept", kept.cfg.MaxOutputBytes)
	}
}

// TestVerifierRejectsMismatchedEvidenceSchemaHash checks that a profile whose typed
// evidence_schema does not re-derive to its evidence_schema_hash is refused before
// any artifact is downloaded.
func TestVerifierRejectsMismatchedEvidenceSchemaHash(t *testing.T) {
	profile := profileWithRequiredEvidence(int32(nodewire.EvidenceKindWorkerValueOpening), int32(nodewire.EvidenceKindWorkerTokenOpening))
	profile.Profile.VerificationProfile.EvidenceSchemaHash = chainclient.ProtoBytes32(make([]byte, 32))
	h := newHarnessWithProfileReader(t, profileReaderStub{profile: profile})
	state := h.validTask()
	state.OpenVerifyAccepted = true

	_, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if err == nil || !strings.Contains(err.Error(), "evidence_schema_hash does not match typed evidence_schema") {
		t.Fatalf("expected evidence schema hash mismatch error, got: %v", err)
	}
	if h.model.FetchArtifactCalls != 0 {
		t.Fatalf("FetchArtifact calls = %d, want 0 (rejected before download)", h.model.FetchArtifactCalls)
	}
}

// TestVerifierRejectsOutOfOrderEvidenceRequirements checks that a requirement list
// not in ascending numeric EvidenceKind order is refused before any download.
func TestVerifierRejectsOutOfOrderEvidenceRequirements(t *testing.T) {
	profile := newProfileStub([]int32{int32(nodewire.EvidenceKindVerifierValueOpening), int32(nodewire.EvidenceKindWorkerValueOpening)}, 1<<30, make(chainclient.ProtoBytes32, 32))
	h := newHarnessWithProfileReader(t, profileReaderStub{profile: profile})
	state := h.validTask()
	state.OpenVerifyAccepted = true

	_, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if err == nil || !strings.Contains(err.Error(), "required_infer_evidence must be known, sorted, unique, and bounded") {
		t.Fatalf("expected required_infer_evidence ordering error, got: %v", err)
	}
}

// TestVerifierRejectsDuplicateEvidenceRequirements checks that a requirement list
// with duplicate kinds is refused before any download.
func TestVerifierRejectsDuplicateEvidenceRequirements(t *testing.T) {
	profile := newProfileStub([]int32{int32(nodewire.EvidenceKindWorkerValueOpening), int32(nodewire.EvidenceKindWorkerValueOpening)}, 1<<30, make(chainclient.ProtoBytes32, 32))
	h := newHarnessWithProfileReader(t, profileReaderStub{profile: profile})
	state := h.validTask()
	state.OpenVerifyAccepted = true

	_, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if err == nil || !strings.Contains(err.Error(), "required_infer_evidence must be known, sorted, unique, and bounded") {
		t.Fatalf("expected required_infer_evidence uniqueness error, got: %v", err)
	}
}

// testGeneratedTokenIDs is the generation the harness Worker reports; the fake
// model service scores tokens counted up from 1000.
var testGeneratedTokenIDs = []uint32{1000, 1001, 1002}

// testTokenIDsMaterial is the model service's TokenIDsV1 material for the
// harness generation.
func testTokenIDsMaterial() []byte {
	data, err := modelservice.EncodeTokenIDsArtifact(modelservice.TokenIDs{Input: []uint32{1, 2}, Generated: testGeneratedTokenIDs})
	if err != nil {
		panic(err)
	}
	return data
}

// testPositionValuesMaterial is the Worker's PositionValuesV1 material: each
// generated token at rank 1 with a ranked top-k list.
func testPositionValuesMaterial() []byte {
	values := make([]metric.PositionValue, len(testGeneratedTokenIDs))
	for i, id := range testGeneratedTokenIDs {
		// The same alternatives the fake model service ranks, so the two sides
		// agree up to the fake's small drift.
		logprob := -0.5 - float64(i)/64
		topK := make([]metric.TokenLogprob, 32)
		topK[0] = metric.TokenLogprob{TokenID: id, Logprob: logprob}
		for rank := 1; rank < len(topK); rank++ {
			topK[rank] = metric.TokenLogprob{TokenID: 900000 + id*64 + uint32(rank), Logprob: logprob - float64(rank)}
		}
		values[i] = metric.PositionValue{TokenID: id, Logprob: logprob, Rank: 1, TopK: topK}
	}
	data, err := modelservice.EncodePositionValuesArtifact(values)
	if err != nil {
		panic(err)
	}
	return data
}
