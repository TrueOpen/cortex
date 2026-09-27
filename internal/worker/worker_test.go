package worker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidencebundle"
	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/policy"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/taskdataauth"
	"github.com/TrueOpen/cortex/internal/taskfacts"
	"github.com/TrueOpen/cortex/internal/txclient"
	bustaskv1 "github.com/TrueOpen/cortex/proto/task/v1"
	"github.com/TrueOpen/wire/bus"
)

func TestAssignmentAcceptedDoesNotStartInfer(t *testing.T) {
	h := newHarness(t)

	if err := h.worker.HandleAssignmentAccepted(context.Background(), chainclient.AssignmentAccepted{
		TaskID: "task-1",
		Height: 100,
	}); err != nil {
		t.Fatalf("handle assignment accepted: %v", err)
	}

	if h.model.InferCalls != 0 {
		t.Fatalf("infer calls = %d, want 0", h.model.InferCalls)
	}
}

func TestEvaluateAndHandraisePersistsBeforePublishingWorkerHandraise(t *testing.T) {
	h := newHarness(t)
	events := []string{}
	h.builder.Events = &events
	recorder := &recordingPersistence{events: &events}
	h.worker.cfg.Persistence = recorder
	event := finalizedTask()

	result, err := h.worker.EvaluateAndHandraise(context.Background(), WorkerHandraiseRequest{TaskID: event.TaskID,
		SessionID:     event.SessionID,
		OrderSequence: event.OrderSequence, TaskHash: workerTestHandraiseTaskHash(event.OrderDigest), ModelID: workerTestModelID, ProfileVersion: 1, Member: workerTestCandidateMember(), CurrentHeight: 120,
		HandraiseExpireHeight:     150,
		ServiceAuthorizationNonce: workerTestHandraiseNonce,
		BuilderSelectionDigest:    codec.HashWithDomain("TEST_BUILDER_SELECTION", []byte("stage1")),
		Precheck:                  validWorkerPrecheck()})
	if err != nil {
		t.Fatalf("worker handraise: %v", err)
	}

	if !result.Signed {
		t.Fatalf("worker handraise was not signed")
	}
	if len(recorder.evidence) != 1 {
		t.Fatalf("evidence writes = %d, want worker handraise evidence", len(recorder.evidence))
	}
	if recorder.evidence[0].Kind != "worker-handraise" {
		t.Fatalf("evidence kind = %q, want worker-handraise", recorder.evidence[0].Kind)
	}
	if len(recorder.outbox) != 1 {
		t.Fatalf("outbox writes = %d, want worker handraise outbox", len(recorder.outbox))
	}
	wantSubject := builderclient.NATSWorkerHandraiseSubject(event.TaskID)
	if recorder.outbox[0].Subject != wantSubject {
		t.Fatalf("outbox subject = %q, want %q", recorder.outbox[0].Subject, wantSubject)
	}
	if len(h.builder.Published) != 0 {
		t.Fatalf("published messages = %d, want durable outbox ownership", len(h.builder.Published))
	}
	nexusEnvelope, err := builderclient.DecodeBusEnvelope(result.Payload)
	if err != nil {
		t.Fatalf("decode worker handraise envelope: %v", err)
	}
	var handraise bustaskv1.WorkerHandraiseV1
	if err := nexusEnvelope.DecodePayload(&handraise); err != nil {
		t.Fatalf("decode worker handraise payload: %v", err)
	}
	wantTaskHash := workerTestHandraiseTaskHash(event.OrderDigest)
	wantMember := workerTestCandidateMember()
	if nexusEnvelope.Kind != builderclient.KindWorkerHandraise || nexusEnvelope.SenderOperatorAddress != workerTestOperatorAddress ||
		handraise.GetSchemaVersion() != 1 || handraise.GetChainId() != h.worker.cfg.ChainID ||
		hex.EncodeToString(handraise.GetTaskId()) != event.TaskID ||
		!bytes.Equal(handraise.GetTaskHash(), wantTaskHash[:]) || hex.EncodeToString(handraise.GetModelId()) != workerTestModelID || handraise.GetProfileVersion() != 1 ||
		hex.EncodeToString(handraise.GetMember().GetCandidatePoolSnapshotId()) != wantMember.CandidatePoolSnapshotID ||
		handraise.GetMember().GetOperatorAddress() != wantMember.OperatorAddress ||
		handraise.GetDuty() != 1 ||
		handraise.GetServiceAuthorizationNonce() != workerTestHandraiseNonce || handraise.GetExpiryHeight() != 150 || len(handraise.GetServiceSignature()) != 64 {
		t.Fatalf("worker handraise = %#v", &handraise)
	}
	// The signed handraise digest must verify against the recomputed frozen
	// preimage of the carried fields: what travels is what was signed.
	back, err := builderclient.WorkerHandraiseFromProto(&handraise)
	if err != nil {
		t.Fatalf("worker handraise from proto: %v", err)
	}
	if _, err := nodewire.WorkerHandraiseSigningDigest(back); err != nil {
		t.Fatalf("recompute worker handraise digest: %v", err)
	}
	if nexusEnvelope.SenderParticipantType != builderclient.ParticipantCortex ||
		nexusEnvelope.ServiceAuthorizationNonce != workerTestHandraiseNonce {
		t.Fatalf("worker handraise envelope identity = %#v", nexusEnvelope)
	}
	if digest := bus.PayloadDigest(nexusEnvelope.Payload); !bytes.Equal(nexusEnvelope.PayloadDigest, digest[:]) {
		t.Fatalf("payload_digest does not commit the transmitted payload bytes")
	}
	wantEvents := []string{
		"evidence:worker-handraise",
		"outbox:" + wantSubject,
	}
	if strings.Join(events, "|") != strings.Join(wantEvents, "|") {
		t.Fatalf("events = %#v, want %#v", events, wantEvents)
	}
}

func TestEvaluateAndHandraiseRejectDoesNotPersistOrPublish(t *testing.T) {
	h := newHarness(t)
	recorder := &recordingPersistence{}
	h.worker.cfg.Persistence = recorder
	event := finalizedTask()
	precheck := validWorkerPrecheck()
	precheck.ChainSynced = false

	result, err := h.worker.EvaluateAndHandraise(context.Background(), WorkerHandraiseRequest{TaskID: event.TaskID,
		SessionID:     event.SessionID,
		OrderSequence: event.OrderSequence, TaskHash: workerTestHandraiseTaskHash(event.OrderDigest), ModelID: workerTestModelID, ProfileVersion: 1, Member: workerTestCandidateMember(), CurrentHeight: 120,
		HandraiseExpireHeight:     150,
		ServiceAuthorizationNonce: workerTestHandraiseNonce,
		Precheck:                  precheck})
	if err != nil {
		t.Fatalf("worker handraise reject: %v", err)
	}

	if result.Signed {
		t.Fatalf("worker handraise signed rejected precheck")
	}
	if result.Decision.RejectCode != "L0_CHAIN_NOT_SYNCED" {
		t.Fatalf("reject code = %q, want L0_CHAIN_NOT_SYNCED", result.Decision.RejectCode)
	}
	if len(recorder.evidence) != 0 || len(recorder.outbox) != 0 || len(h.builder.Published) != 0 {
		t.Fatalf("side effects on rejected handraise: evidence=%d outbox=%d publish=%d", len(recorder.evidence), len(recorder.outbox), len(h.builder.Published))
	}
}

// The published handraise must not carry payload_keyring_hash at all. Node's
// frozen WorkerHandraiseV1 and nexus's msgbus.WorkerHandraise have no such
// field, and Cortex used to emit it -- empty on every real order -- and commit
// it into its own signing preimage.
func TestEvaluateAndHandraiseEmitsNoPayloadKeyringHash(t *testing.T) {
	h := newHarness(t)
	recorder := &recordingPersistence{}
	h.worker.cfg.Persistence = recorder
	event := finalizedTask()

	result, err := h.worker.EvaluateAndHandraise(context.Background(), WorkerHandraiseRequest{TaskID: event.TaskID, SessionID: event.SessionID, OrderSequence: event.OrderSequence, TaskHash: workerTestHandraiseTaskHash(event.OrderDigest), ModelID: workerTestModelID, ProfileVersion: 1, Member: workerTestCandidateMember(), CurrentHeight: 120, HandraiseExpireHeight: 150,
		ServiceAuthorizationNonce: workerTestHandraiseNonce,
		BuilderSelectionDigest:    codec.HashWithDomain("TEST_BUILDER_SELECTION", []byte("stage1")),
		Precheck:                  validWorkerPrecheck()})
	if err != nil {
		t.Fatalf("EvaluateAndHandraise() error = %v", err)
	}
	if !result.Signed || result.Decision.RejectCode != "" {
		t.Fatalf("result = %#v, want a signed handraise for the real Builder shape", result)
	}
	if len(recorder.outbox) != 1 || recorder.outbox[0].Subject != builderclient.NATSWorkerHandraiseSubject(event.TaskID) {
		t.Fatalf("outbox = %#v, want one persisted WorkerHandraise", recorder.outbox)
	}
	nexusEnvelope, err := builderclient.DecodeBusEnvelope(result.Payload)
	if err != nil {
		t.Fatalf("DecodeBusEnvelope() error = %v", err)
	}
	if bytes.Contains(nexusEnvelope.Payload, []byte("payload_keyring_hash")) {
		t.Fatalf("published payload carries payload_keyring_hash: %s", nexusEnvelope.Payload)
	}
	var handraise bustaskv1.WorkerHandraiseV1
	if err := nexusEnvelope.DecodePayload(&handraise); err != nil {
		t.Fatalf("DecodePayload() error = %v", err)
	}
	if handraise.GetExpiryHeight() != 150 || len(handraise.GetServiceSignature()) != 64 {
		t.Fatalf("handraise = %#v, want a signed handraise for the real Builder shape", &handraise)
	}
}

// The rest of validateWorkerHandraiseRequest must stay closed. Dropping the
// payload_keyring_hash clause must not have relaxed identity or the height
// window, both of which still gate signing.
func TestEvaluateAndHandraiseStillRefusesBrokenIdentityAndHeightWindow(t *testing.T) {
	event := finalizedTask()
	valid := WorkerHandraiseRequest{TaskID: event.TaskID, SessionID: event.SessionID, OrderSequence: event.OrderSequence, TaskHash: workerTestHandraiseTaskHash(event.OrderDigest), ModelID: workerTestModelID, ProfileVersion: 1, Member: workerTestCandidateMember(), CurrentHeight: 120, HandraiseExpireHeight: 150,
		ServiceAuthorizationNonce: workerTestHandraiseNonce,
		BuilderSelectionDigest:    codec.HashWithDomain("TEST_BUILDER_SELECTION", []byte("stage1")),
		Precheck:                  validWorkerPrecheck()}
	for name, mutate := range map[string]func(*WorkerHandraiseRequest){
		"missing session_id":    func(req *WorkerHandraiseRequest) { req.SessionID = "" },
		"missing task_id":       func(req *WorkerHandraiseRequest) { req.TaskID = "" },
		"non-canonical task_id": func(req *WorkerHandraiseRequest) { req.TaskID = "task-from-payload" },
		// order_sequence 0 is the first order of every session, not "the caller
		// did not state one", so the identity equation must be applied to it
		// like any other value. Guarding the check with `req.OrderSequence != 0`
		// made the session-first order the one order whose task_id nothing
		// checked: this task_id is canonical Hash32 hex, so nothing downstream
		// catches it either - it simply derives from a different sequence.
		"task_id from another sequence at sequence zero": func(req *WorkerHandraiseRequest) {
			req.OrderSequence, req.TaskID = 0, identity.TaskIDString(req.SessionID, 7)
		},
		"zero task_hash":       func(req *WorkerHandraiseRequest) { req.TaskHash = codec.Hash{} },
		"zero current height":  func(req *WorkerHandraiseRequest) { req.CurrentHeight = 0 },
		"zero expire height":   func(req *WorkerHandraiseRequest) { req.HandraiseExpireHeight = 0 },
		"expiry below current": func(req *WorkerHandraiseRequest) { req.HandraiseExpireHeight = req.CurrentHeight - 1 },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			recorder := &recordingPersistence{}
			h.worker.cfg.Persistence = recorder
			candidate := valid
			mutate(&candidate)
			result, err := h.worker.EvaluateAndHandraise(context.Background(), candidate)
			if err != nil {
				t.Fatalf("EvaluateAndHandraise() error = %v", err)
			}
			if result.Signed || result.Decision.RejectCode != "L2_TASK_IDENTITY_MISSING" {
				t.Fatalf("result = %#v, want refusal", result)
			}
			if len(recorder.outbox) != 0 {
				t.Fatalf("outbox = %#v, want no persisted handraise", recorder.outbox)
			}
		})
	}
}

// The two envelope identity values a handraise cannot derive -- field 7's
// service_authorization_nonce and fields 11/12's BuilderSet reference -- are
// caller-supplied, and §5.2/:368 forbid an empty one on a task-control message.
// Their absence must therefore stop the publish outright rather than put a field
// on the wire that authenticates nothing.
func TestEvaluateAndHandraiseRefusesMissingEnvelopeIdentity(t *testing.T) {
	event := finalizedTask()
	valid := WorkerHandraiseRequest{TaskID: event.TaskID, SessionID: event.SessionID, OrderSequence: event.OrderSequence, TaskHash: workerTestHandraiseTaskHash(event.OrderDigest), ModelID: workerTestModelID, ProfileVersion: 1, Member: workerTestCandidateMember(), CurrentHeight: 120, HandraiseExpireHeight: 150,
		BuilderSelectionDigest:    codec.HashWithDomain("TEST_BUILDER_SELECTION", []byte("stage1")),
		ServiceAuthorizationNonce: workerTestHandraiseNonce,
		Precheck:                  validWorkerPrecheck()}
	for name, tc := range map[string]struct {
		mutate   func(*WorkerHandraiseRequest)
		contains string
	}{
		"zero service authorization nonce": {
			// Refused at envelope encode now: a zero nonce is the absent value
			// and cannot appear on the wire.
			mutate:   func(req *WorkerHandraiseRequest) { req.ServiceAuthorizationNonce = 0 },
			contains: "service_authorization_nonce is required",
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			recorder := &recordingPersistence{}
			h.worker.cfg.Persistence = recorder
			candidate := valid
			tc.mutate(&candidate)

			result, err := h.worker.EvaluateAndHandraise(context.Background(), candidate)
			if err == nil || !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("EvaluateAndHandraise() error = %v, want a refusal naming %q", err, tc.contains)
			}
			if result.Signed || len(result.Payload) != 0 {
				t.Fatalf("result = %#v, want no handraise material at all", result)
			}
			if len(recorder.evidence) != 0 || len(recorder.outbox) != 0 || len(h.builder.Published) != 0 {
				t.Fatalf("refused handraise had side effects: evidence=%d outbox=%d publish=%d",
					len(recorder.evidence), len(recorder.outbox), len(h.builder.Published))
			}
		})
	}
}

func TestEvaluateAndHandraiseRequiresEnvelopeSignerOutsideFixtures(t *testing.T) {
	h := newHarness(t)
	h.worker.cfg.NexusEnvelopeSigner = nil
	h.worker.cfg.FakeOutput = false
	recorder := &recordingPersistence{}
	h.worker.cfg.Persistence = recorder
	event := finalizedTask()

	_, err := h.worker.EvaluateAndHandraise(context.Background(), WorkerHandraiseRequest{TaskID: event.TaskID, SessionID: event.SessionID, OrderSequence: event.OrderSequence, TaskHash: workerTestHandraiseTaskHash(event.OrderDigest), ModelID: workerTestModelID, ProfileVersion: 1, Member: workerTestCandidateMember(), CurrentHeight: 120, HandraiseExpireHeight: 150,
		ServiceAuthorizationNonce: workerTestHandraiseNonce,
		BuilderSelectionDigest:    codec.HashWithDomain("TEST_BUILDER_SELECTION", []byte("stage1")),
		Precheck:                  validWorkerPrecheck()})
	if !errors.Is(err, builderclient.ErrBusEnvelopeAuthenticationUnavailable) {
		t.Fatalf("EvaluateAndHandraise error = %v, want envelope authentication unavailable", err)
	}
	if len(recorder.evidence) != 0 || len(recorder.outbox) != 0 || len(h.builder.Published) != 0 {
		t.Fatalf("side effects before authenticated envelope: evidence=%d outbox=%d publish=%d", len(recorder.evidence), len(recorder.outbox), len(h.builder.Published))
	}
}

func TestTrustedNATSDevEncodesUnsignedEnvelopeWithoutWeakeningWireShape(t *testing.T) {
	w := New(Config{TrustedNATSDev: true})
	input := builderclient.UnsignedEnvelopeInput{
		Kind: builderclient.KindWorkerHandraise, ChainID: "chain-A", Subject: builderclient.NATSWorkerHandraiseSubject("task-1"),
		SenderOperatorAddress: workerTestOperatorAddress, SenderParticipantType: builderclient.ParticipantCortex,
		ServiceAuthorizationNonce: workerTestHandraiseNonce,
	}
	message, err := builderclient.WorkerHandraiseProto(nodewireTestHandraise())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := w.encodeNexusMessage(input, message)
	if err != nil {
		t.Fatalf("encodeNexusMessage error = %v", err)
	}
	envelope, err := builderclient.DecodeBusEnvelope(encoded)
	if err != nil {
		t.Fatalf("DecodeBusEnvelope error = %v", err)
	}
	// The wire shape stays intact under the trusted transport: only the
	// signature is absent.
	if len(envelope.Signature) != 0 || envelope.ChainID != "chain-A" || envelope.Subject != input.Subject {
		t.Fatalf("trusted envelope = %#v", envelope)
	}
}

// nodewireTestHandraise is a fully populated digest-authority handraise for
// envelope-shape tests.
func nodewireTestHandraise() nodewire.WorkerHandraiseV1 {
	return nodewire.WorkerHandraiseV1{
		SchemaVersion: 1, ChainID: "chain-A",
		TaskID: bytes.Repeat([]byte{0xab}, 32), TaskHash: bytes.Repeat([]byte{0xcd}, 32),
		ModelID: bytes.Repeat([]byte{0x01}, 32), ProfileVersion: 1,
		Member: nodewire.CandidateMemberRefV1{
			CandidatePoolSnapshotID: bytes.Repeat([]byte{0x11}, 32),
			Slot:                    1, SlotVersion: 1, OperatorAddress: workerTestOperatorAddress,
		},
		Duty: nodewire.DutyWorker, ServiceAuthorizationNonce: workerTestHandraiseNonce, ExpiryHeight: 150,
		ServiceSignature: bytes.Repeat([]byte{0x22}, 64),
	}
}

// prepareOutput still cannot populate the frozen receipt: the locked Profile's
// evidence_schema_hash has no reader, so a local winner's fresh pass ends in the
// worker-value commitment's refusal. Everything before it still runs, and that
// is what this pins: the Keeper's assignment drives exactly one inference whose
// artifacts are recomputed into a canonical output package, and only then does
// the Worker refuse rather than sign a receipt it cannot fill.
func TestFinalizedLocalWinnerRunsInferenceThenRefusesTheFrozenReceipt(t *testing.T) {
	h := newHarness(t)
	sessionID := "84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b"
	orderSequence := uint64(7)

	event := chainclient.AssignmentFinalized{
		TaskID:                 canonicalTaskID(sessionID, orderSequence),
		SessionID:              sessionID,
		OrderSequence:          orderSequence,
		OrderDigest:            codec.HashWithDomain("TEST_ORDER_DIGEST", []byte("order-7")),
		Winner:                 workerTestOperatorAddress,
		WinnerConfirmHeight:    200,
		InferDeadlineHeight:    225,
		ModelID:                modelservice.FakeModelID,
		ProfileVersion:         1,
		Capability:             modelservice.CapabilityLLMTextV1,
		Input:                  []byte("hello"),
		BuilderOperatorAddress: "trueopen1j7r6u8nwvw93l2tc0wd75v07vu89lxyfqf8fut",
	}
	_, err := h.worker.HandleAssignmentFinalized(context.Background(), event)
	if !errors.Is(err, builderclient.ErrInferReceiptInputUnavailable) {
		t.Fatalf("HandleAssignmentFinalized error = %v, want a frozen receipt input refusal", err)
	}

	if h.model.InferCalls != 1 {
		t.Fatalf("infer calls = %d, want the local winner to have run the Keeper assignment once", h.model.InferCalls)
	}
	if len(h.builder.ValidatedPackages) != 1 {
		t.Fatalf("validated output packages = %d, want the pre-receipt package still assembled",
			len(h.builder.ValidatedPackages))
	}
	pkg := h.builder.ValidatedPackages[0]
	if pkg.TaskID != event.TaskID || pkg.SessionID != sessionID || pkg.ModelID != event.ModelID {
		t.Fatalf("validated package identity = %#v, want the Keeper assignment identity", pkg)
	}
}

// The Keeper's deadline binds the receipt envelope rather than a locally invented
// window. loadPreparedOutput re-derives every envelope field from the
// authoritative assignment before it hands the material back, so a resumed pass
// returning the Keeper deadline and the canonical task id is proof the binding
// survived the checkpoint.
func TestResumedLocalWinnerResultCarriesKeeperDeadlineAndCanonicalTaskID(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	event.InferDeadlineHeight = 225
	h.seedPreparedOutput(t, event)

	result, err := h.worker.HandleAssignmentFinalized(context.Background(), event)
	if err != nil {
		t.Fatalf("handle assignment finalized: %v", err)
	}

	if result.InferDeadlineHeight != 225 {
		t.Fatalf("infer deadline = %d, want Keeper deadline 225", result.InferDeadlineHeight)
	}
	if result.SignedReceipt.ValidUntilHeight != 225 || result.SignedReceipt.ValidFromHeight != event.WinnerConfirmHeight {
		t.Fatalf("receipt height window = [%d,%d], want the Keeper window",
			result.SignedReceipt.ValidFromHeight, result.SignedReceipt.ValidUntilHeight)
	}
	if result.Receipt.TaskID != canonicalTaskID("84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", 7) {
		t.Fatalf("receipt task id = %q", result.Receipt.TaskID)
	}
}

// The "running" half of the model-job lifecycle belongs to prepareOutput, which
// now ends in a refusal (see TestWorkerRefusesToSignAReceiptItCannotFullyPopulate).
// What is still reachable is the closing half: finalizing a resumed task must
// mark the job id the durable checkpoint carries as succeeded, and nothing else.
func TestResumedPreparedOutputMarksTheModelServiceJobSucceeded(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	h.seedPreparedOutput(t, event)

	if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err != nil {
		t.Fatalf("handle assignment finalized: %v", err)
	}

	// The prepareOutput path records a running job while inference is in
	// progress and then a succeeded job once the receipt is built. The final
	// status must be succeeded.
	var latest ModelJobCheckpoint
	for _, job := range h.persistence.jobs {
		if job.JobID == "worker-infer-"+event.TaskID {
			latest = job
		}
	}
	if latest.Status != "succeeded" {
		t.Fatalf("model service job final status = %q, want succeeded; jobs = %#v", latest.Status, h.persistence.jobs)
	}
}

func TestFinalizedRemoteWinnerDoesNotStartInfer(t *testing.T) {
	h := newHarness(t)

	result, err := h.worker.HandleAssignmentFinalized(context.Background(), chainclient.AssignmentFinalized{
		TaskID:              "task-1",
		Winner:              "other-worker",
		WinnerConfirmHeight: 200,
		ModelID:             modelservice.FakeModelID,
		ProfileVersion:      1,
		Capability:          modelservice.CapabilityLLMTextV1,
		Input:               []byte("hello"),
	})
	if err != nil {
		t.Fatalf("handle assignment finalized: %v", err)
	}

	if result.Started {
		t.Fatalf("remote winner started infer")
	}
	if h.model.InferCalls != 0 {
		t.Fatalf("infer calls = %d, want 0", h.model.InferCalls)
	}
}

// The Worker must hash the output artifact itself instead of trusting whatever
// the model service reports. The recomputed hash is what reaches the canonical
// output package, which is assembled and validated before the frozen receipt
// build refuses, so the contract stays observable through the refusal.
func TestModelServiceOutputHashIsRecomputedBeforeSigning(t *testing.T) {
	h := newHarness(t)
	reported := bytes.Repeat([]byte{0x99}, 32)
	h.model.ReportedOutputHash = reported

	_, err := h.worker.HandleAssignmentFinalized(context.Background(), finalizedTask())
	if !errors.Is(err, builderclient.ErrInferReceiptInputUnavailable) {
		t.Fatalf("HandleAssignmentFinalized error = %v, want a frozen receipt input refusal", err)
	}

	if len(h.builder.ValidatedPackages) != 1 {
		t.Fatalf("validated output packages = %d, want one", len(h.builder.ValidatedPackages))
	}
	pkg := h.builder.ValidatedPackages[0]
	artifact, err := h.model.FetchArtifact(context.Background(), modelservice.FetchArtifactRequest{Ref: pkg.OutputRef})
	if err != nil {
		t.Fatalf("fetch output artifact: %v", err)
	}
	want, err := codec.OutputMMRRootFromLengths(artifact.Data, []uint64{uint64(len(artifact.Data))})
	if err != nil {
		t.Fatal(err)
	}
	if pkg.OutputHash != want {
		t.Fatalf("package output hash = %s, want recomputed %s",
			hex.EncodeToString(pkg.OutputHash[:]), hex.EncodeToString(want[:]))
	}
	if bytes.Equal(pkg.OutputHash[:], reported) {
		t.Fatalf("package output hash echoed the model service report")
	}
}

// The legacy receipt material is built and signed before the frozen receipt, so
// its result hash, byte summary and Worker signature are still observable on the
// refusal path through the canonical output package.
func TestInferReceiptIncludesResultHashAndActualOutputSummary(t *testing.T) {
	h := newHarness(t)

	_, err := h.worker.HandleAssignmentFinalized(context.Background(), finalizedTask())
	if !errors.Is(err, builderclient.ErrInferReceiptInputUnavailable) {
		t.Fatalf("HandleAssignmentFinalized error = %v, want a frozen receipt input refusal", err)
	}

	if len(h.builder.ValidatedPackages) != 1 {
		t.Fatalf("validated output packages = %d, want one", len(h.builder.ValidatedPackages))
	}
	pkg := h.builder.ValidatedPackages[0]
	material, err := builderclient.DecodeInferReceiptMaterial(pkg.ReceiptPayload)
	if err != nil {
		t.Fatalf("decode legacy receipt material: %v", err)
	}
	if material.ReceiptResultHash == (codec.Hash{}) {
		t.Fatalf("receipt_result_hash is missing")
	}
	if material.ActualOutputSummary == "" || !strings.Contains(material.ActualOutputSummary, "bytes") {
		t.Fatalf("actual_output_summary = %q, want byte summary", material.ActualOutputSummary)
	}
	if len(pkg.WorkerSignature) == 0 {
		t.Fatalf("canonical output package carries no Worker signature over the receipt material")
	}
}

func TestSignedReceiptBindsChainTaskIdentity(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	event.SessionID = "8e6fc9f3f3a398bbb6a2472d2d8afb7b4264814e043322922e7d18e80b5b5e4e"
	event.OrderSequence = 42
	event.TaskID = canonicalTaskID(event.SessionID, event.OrderSequence)
	event.OrderDigest = codec.HashWithDomain("TEST_ORDER_DIGEST", []byte("chain-order"))
	h.seedPreparedOutput(t, event)

	result, err := h.worker.HandleAssignmentFinalized(context.Background(), event)
	if err != nil {
		t.Fatalf("handle assignment finalized: %v", err)
	}

	// The exact task-id preimage is pinned in internal/identity; here the
	// assertion is only that the signed receipt carries the canonical id.
	want := identity.TaskID(event.SessionID, event.OrderSequence)
	if result.SignedReceipt.SessionID != event.SessionID ||
		result.SignedReceipt.OrderSequence != event.OrderSequence ||
		result.SignedReceipt.TaskID != want {
		t.Fatalf("signed receipt identity = session %q sequence %d task %x, want session %q sequence %d task %x",
			result.SignedReceipt.SessionID,
			result.SignedReceipt.OrderSequence,
			result.SignedReceipt.TaskID,
			event.SessionID,
			event.OrderSequence,
			want)
	}
	if err := result.SignedReceipt.Validate(); err != nil {
		t.Fatalf("signed receipt validation failed: %v", err)
	}
	if result.SignedReceipt.OrderDigest != event.OrderDigest {
		t.Fatalf("signed order digest = %x, want chain order digest %x", result.SignedReceipt.OrderDigest, event.OrderDigest)
	}
}

func TestSignedReceiptAllowsOrderSequenceZero(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	event.SessionID = "540a06be4c1c6f3ee86f9619e96ab56bc8c9103d01dd94aa7ace93dc4bc8e50f"
	event.OrderSequence = 0
	event.TaskID = canonicalTaskID(event.SessionID, event.OrderSequence)
	event.OrderDigest = codec.HashWithDomain("TEST_ORDER_DIGEST", []byte("first-order"))
	h.seedPreparedOutput(t, event)

	result, err := h.worker.HandleAssignmentFinalized(context.Background(), event)
	if err != nil {
		t.Fatalf("handle assignment finalized: %v", err)
	}

	if result.SignedReceipt.SessionID != event.SessionID || result.SignedReceipt.OrderSequence != 0 {
		t.Fatalf("signed identity = session %q sequence %d, want first order identity", result.SignedReceipt.SessionID, result.SignedReceipt.OrderSequence)
	}
	want := identity.TaskID(event.SessionID, 0)
	if result.SignedReceipt.TaskID != want {
		t.Fatalf("signed task id = %x, want %x", result.SignedReceipt.TaskID, want)
	}
}

func TestFinalizedWithoutChainIdentityRejectsBeforeInfer(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	event.SessionID = ""
	event.OrderDigest = codec.Hash{}

	_, err := h.worker.HandleAssignmentFinalized(context.Background(), event)
	if err == nil {
		t.Fatalf("missing chain identity accepted")
	}
	if h.model.InferCalls != 0 {
		t.Fatalf("infer calls = %d, want 0 before chain identity validation", h.model.InferCalls)
	}
}

func TestFinalizedTaskIDMustMatchCanonicalChainIdentity(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	event.TaskID = "task-1"

	_, err := h.worker.HandleAssignmentFinalized(context.Background(), event)
	if err == nil || !strings.Contains(err.Error(), "canonical task id") {
		t.Fatalf("mismatched task id error = %v, want canonical task id rejection", err)
	}
	if h.model.InferCalls != 0 {
		t.Fatalf("infer calls = %d, want 0 before canonical identity validation", h.model.InferCalls)
	}
}

func TestWorkerPersistsReceiptBeforeRelay(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	enableEvidenceSchema(&h)
	events := []string{}
	h.taskData.events = &events
	h.persistence.events = &events

	if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err != nil {
		t.Fatalf("HandleAssignmentFinalized: %v", err)
	}
	receiptIndex := slicesIndex(events, "receipt:persist")
	relayIndex := slicesIndex(events, "task-data:relay")
	if receiptIndex < 0 || relayIndex < 0 || receiptIndex >= relayIndex {
		t.Fatalf("events = %#v, want canonical receipt persisted before relay", events)
	}
	if len(h.persistence.receipts) != 1 {
		t.Fatalf("persisted receipts = %d, want 1", len(h.persistence.receipts))
	}
	var persisted builderclient.SignedInferReceipt
	if err := json.Unmarshal(h.persistence.receipts[0].Payload, &persisted); err != nil {
		t.Fatalf("decode persisted receipt: %v", err)
	}
	if !reflect.DeepEqual(persisted, h.taskData.relays[0].Receipt) {
		t.Fatalf("persisted receipt differs from relayed receipt")
	}
}

func TestWorkerRelaysReceiptBeforeEvidenceUploadCompletes(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	h.seedPreparedOutput(t, event)
	entered := make(chan struct{})
	release := make(chan struct{})
	h.taskData.uploadEntered = entered
	h.taskData.uploadRelease = release
	errs := make(chan error, 1)
	go func() {
		_, err := h.worker.HandleAssignmentFinalized(context.Background(), event)
		errs <- err
	}()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("upload was not reached")
	}
	if len(h.taskData.relays) != 1 {
		t.Fatalf("receipt relays = %d, want relay completed before blocked upload", len(h.taskData.relays))
	}
	if len(h.persistence.confirmations) != 0 || pendingOutputAvailable(h.persistence.outbox) {
		t.Fatal("confirmation or availability persisted before upload completed")
	}
	close(release)
	if err := <-errs; err != nil {
		t.Fatalf("HandleAssignmentFinalized: %v", err)
	}
}

func TestWorkerRetriesWithStableReceiptAndOutputMaterial(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	h.seedPreparedOutput(t, event)
	h.taskData.uploadErrors = []error{builderclient.Retryable(errors.New("upload interrupted")), nil}

	if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err == nil || !builderclient.IsRetryable(err) {
		t.Fatalf("first HandleAssignmentFinalized error = %v, want retryable upload failure", err)
	}
	if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err != nil {
		t.Fatalf("retry HandleAssignmentFinalized: %v", err)
	}
	if h.model.InferCalls != 1 {
		t.Fatalf("model infer calls = %d, want the durable prepared output reused", h.model.InferCalls)
	}
	// The first evidence artifact fails once, then four artifacts and two
	// manifests are staged on retry. The already stored output stream is reused.
	if len(h.taskData.relays) != 2 || len(h.taskData.uploads) != 7 {
		t.Fatalf("relay/upload attempts = %d/%d, want 2/7", len(h.taskData.relays), len(h.taskData.uploads))
	}
	for index, upload := range h.taskData.uploads[:2] {
		if upload.Key.Kind != builderclient.DataKindEvidenceArtifact {
			t.Fatalf("upload[%d] kind = %s, want the evidence attempts first", index, upload.Key.Kind)
		}
	}
	// The frozen receipt carries task_hash and the evidence commitments itself,
	// so receipt equality is the whole responsibility-fact comparison.
	if !reflect.DeepEqual(h.taskData.relays[0].Receipt, h.taskData.relays[1].Receipt) {
		t.Fatal("receipt responsibility facts changed across retry")
	}
	if !bytes.Equal(h.taskData.uploads[0].Data, h.taskData.uploads[1].Data) ||
		h.taskData.uploads[0].Key != h.taskData.uploads[1].Key {
		t.Fatal("output upload material changed across retry")
	}
	if bytes.Equal(h.taskData.uploads[0].Auth.RequestNonce, h.taskData.uploads[1].Auth.RequestNonce) {
		t.Fatal("retry reused a task-data request nonce")
	}
	if len(h.persistence.receipts) != 1 {
		t.Fatalf("canonical receipt writes = %d, want one signing/persistence step", len(h.persistence.receipts))
	}
}

func TestWorkerPublishesOutputAvailableOnlyAfterValidConfirmation(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	h.seedPreparedOutput(t, event)
	events := []string{}
	h.taskData.events = &events
	h.persistence.events = &events

	if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err != nil {
		t.Fatalf("HandleAssignmentFinalized: %v", err)
	}
	confirmationIndex := slicesIndex(events, "confirmation:persist")
	pendingIndex := slicesIndex(events, "outbox:pending")
	if confirmationIndex < 0 || pendingIndex < 0 || confirmationIndex >= pendingIndex {
		t.Fatalf("events = %#v, want verified confirmation persisted before availability release", events)
	}
	// Finalization confirms the OUTPUT and the complete evidence manifest.
	if len(h.persistence.confirmations) != 3 || !pendingOutputAvailable(h.persistence.outbox) {
		t.Fatalf("confirmation/outbox = %d/%#v", len(h.persistence.confirmations), h.persistence.outbox)
	}
}
func TestWorkerRestartAfterAvailabilityReleaseDoesNotDowngradeOrRepublish(t *testing.T) {
	for _, status := range []string{"pending", "sent"} {
		t.Run(status, func(t *testing.T) {
			h := newHarness(t)
			event := finalizedTask()
			h.seedPreparedOutput(t, event)
			if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err != nil {
				t.Fatalf("first HandleAssignmentFinalized: %v", err)
			}
			h.persistence.outbox[0].Status = status
			writesBefore := len(h.persistence.outboxWriteStatuses)

			if _, err := New(h.worker.cfg).HandleAssignmentFinalized(context.Background(), event); err != nil {
				t.Fatalf("restarted HandleAssignmentFinalized: %v", err)
			}
			// The stored output and manifest confirmations avoid repeating any of
			// the six uploads or the finalization request after restart.
			if len(h.taskData.relays) != 1 || len(h.taskData.uploads) != 6 || len(h.persistence.confirmations) != 3 {
				t.Fatalf("restart duplicated relay/upload/confirmation = %d/%d/%d",
					len(h.taskData.relays), len(h.taskData.uploads), len(h.persistence.confirmations))
			}
			if len(h.persistence.outboxWriteStatuses) != writesBefore {
				t.Fatalf("restart outbox writes = %#v, want no duplicate availability write", h.persistence.outboxWriteStatuses)
			}
			if len(h.persistence.outbox) != 1 || h.persistence.outbox[0].Status != status {
				t.Fatalf("restarted outbox = %#v, want preserved %s", h.persistence.outbox, status)
			}
		})
	}
}

func TestWorkerRejectsStorageConfirmationMismatch(t *testing.T) {
	mutations := map[string]func(*builderclient.StorageConfirmation){
		"schema":      func(c *builderclient.StorageConfirmation) { c.SchemaVersion = 2 },
		"chain":       func(c *builderclient.StorageConfirmation) { c.ChainID = "wrong-chain" },
		"task":        func(c *builderclient.StorageConfirmation) { c.Key.TaskID = "wrong-task" },
		"kind":        func(c *builderclient.StorageConfirmation) { c.Key.Kind = builderclient.DataKindInput },
		"output hash": func(c *builderclient.StorageConfirmation) { c.Key.ContentHash = strings.Repeat("f", 64) },
		"nonce":       func(c *builderclient.StorageConfirmation) { c.ServiceAuthorizationNonce++ },
		"size":        func(c *builderclient.StorageConfirmation) { c.SizeBytes++ },
		"builder":     func(c *builderclient.StorageConfirmation) { c.BuilderOperator = "trueopen1other" },
		"expired":     func(c *builderclient.StorageConfirmation) { c.RetentionUntilHeight = 99 },
		"signature":   func(c *builderclient.StorageConfirmation) { c.Signature[0] ^= 0xff },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			event := finalizedTask()
			h.seedPreparedOutput(t, event)
			h.taskData.mutateConfirmation = mutate
			_, err := h.worker.HandleAssignmentFinalized(context.Background(), event)
			if err == nil {
				t.Fatal("HandleAssignmentFinalized error = nil, want permanent confirmation rejection")
			}
			if builderclient.IsRetryable(err) {
				t.Fatalf("confirmation mismatch classified retryable: %v", err)
			}
			if len(h.persistence.confirmations) != 0 || pendingOutputAvailable(h.persistence.outbox) {
				t.Fatalf("confirmation mismatch released output: confirmations=%d outbox=%#v", len(h.persistence.confirmations), h.persistence.outbox)
			}
		})
	}
}
func TestWorkerRejectsStorageConfirmationAtCurrentHeight(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	h.seedPreparedOutput(t, event)
	h.taskData.mutateConfirmationBeforeSign = func(confirmation *builderclient.StorageConfirmation) {
		confirmation.RetentionUntilHeight = 100
	}

	if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err == nil || builderclient.IsRetryable(err) {
		t.Fatalf("HandleAssignmentFinalized error = %v, want permanent retention boundary failure", err)
	}
	if len(h.persistence.confirmations) != 0 {
		t.Fatal("storage confirmation at current height was persisted")
	}
	if pendingOutputAvailable(h.persistence.outbox) {
		t.Fatal("availability was published for storage expiring at current height")
	}
}

// A receipt whose service signature does not verify under this Worker's own
// service key must never reach a Builder. prepareOutput verifies its freshly
// signed receipt locally; the durable-recovery pass re-verifies the recovered
// one, which is the reachable half of that contract today.
func TestWorkerRejectsInvalidReceiptSignatureBeforeRelay(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	h.seedPreparedOutput(t, event)
	h.worker.cfg.SignerPubkey = "02" + strings.Repeat("11", 32)

	_, err := New(h.worker.cfg).HandleAssignmentFinalized(context.Background(), event)
	if err == nil || builderclient.IsRetryable(err) {
		t.Fatalf("HandleAssignmentFinalized error = %v, want permanent local signature verification failure", err)
	}
	if len(h.taskData.relays) != 0 {
		t.Fatal("receipt with invalid service signature was relayed")
	}
}

func TestReceiptOnlySelfRescueTriggersAtMarginWhenOpenVerifyNotAccepted(t *testing.T) {
	h := newHarness(t)
	tx := &recordingTxClient{obs: txclient.Observation{Accepted: true, TxHash: "0xreceipt-rescue"}}
	h.worker.cfg.Tx = tx
	h.worker.RecordReceipt(ReceiptState{
		TaskID:               "task-1",
		InferReceiptAccepted: true,
		OpenVerifyAccepted:   false,
		WorkerRevealDeadline: 300,
		SelfRescueMargin:     5,
		ReceiptOnlyRescue:    testSubmitInferReceiptMessage("task-1", h.worker.cfg.SignerAddress),
	})

	triggered, err := h.worker.CheckReceiptOnlySelfRescue(context.Background(), 294)
	if err != nil {
		t.Fatalf("check self rescue before margin: %v", err)
	}
	if triggered {
		t.Fatalf("self rescue triggered before margin")
	}

	triggered, err = h.worker.CheckReceiptOnlySelfRescue(context.Background(), 295)
	if err != nil {
		t.Fatalf("check self rescue at margin: %v", err)
	}
	if !triggered {
		t.Fatalf("self rescue did not trigger at margin")
	}
	if len(tx.requests) != 1 || tx.requests[0].Kind != txclient.MsgSubmitInferReceipt {
		t.Fatalf("self-rescue tx requests = %#v, want direct service-key tx", tx.requests)
	}
	triggered, err = h.worker.CheckReceiptOnlySelfRescue(context.Background(), 296)
	if err != nil {
		t.Fatalf("second self rescue check: %v", err)
	}
	if triggered {
		t.Fatalf("self rescue should be idempotent after first trigger")
	}

	h2 := newHarness(t)
	h2.worker.RecordReceipt(ReceiptState{
		TaskID:               "task-2",
		InferReceiptAccepted: true,
		OpenVerifyAccepted:   true,
		WorkerRevealDeadline: 300,
		SelfRescueMargin:     5,
		ReceiptOnlyRescue:    testSubmitInferReceiptMessage("task-2", h2.worker.cfg.SignerAddress),
	})
	triggered, err = h2.worker.CheckReceiptOnlySelfRescue(context.Background(), 295)
	if err != nil {
		t.Fatalf("accepted open verify self rescue check: %v", err)
	}
	if triggered {
		t.Fatalf("self rescue triggered despite OpenVerify accepted")
	}
}

func TestReceiptOnlySelfRescueUsesDirectTxClientWhenConfigured(t *testing.T) {
	h := newHarness(t)
	tx := &recordingTxClient{obs: txclient.Observation{Accepted: true, TxHash: "0xreceipt"}}
	h.worker.cfg.Tx = tx
	h.worker.RecordReceipt(ReceiptState{
		TaskID:               "task-1",
		InferReceiptAccepted: true,
		OpenVerifyAccepted:   false,
		WorkerRevealDeadline: 300,
		SelfRescueMargin:     5,
		ReceiptOnlyRescue:    testSubmitInferReceiptMessage("task-1", h.worker.cfg.SignerAddress),
	})

	triggered, err := h.worker.CheckReceiptOnlySelfRescue(context.Background(), 295)
	if err != nil {
		t.Fatalf("check self rescue with txclient: %v", err)
	}
	if !triggered {
		t.Fatalf("self rescue did not trigger")
	}
	if len(tx.requests) != 1 {
		t.Fatalf("txclient requests = %d, want 1", len(tx.requests))
	}
	req := tx.requests[0]
	if req.Kind != txclient.MsgSubmitInferReceipt {
		t.Fatalf("tx kind = %s, want %s", req.Kind, txclient.MsgSubmitInferReceipt)
	}
	// The frozen receipt carries no infer_receipt_hash: the Keeper recomputes it
	// from the signing preimage. What must be on the wire is the typed receipt
	// body plus its evidence commitment list.
	if req.TaskID != "task-1" || !bytes.Contains(req.Payload, []byte(`"required_evidence_commitments"`)) ||
		!bytes.Contains(req.Payload, []byte(`"generation_params_digest"`)) || !bytes.Contains(req.Payload, []byte(`"service_signature"`)) {
		t.Fatalf("tx request = %#v, want the frozen MsgSubmitInferReceipt body for task-1", req)
	}
	if bytes.Contains(req.Payload, []byte(`"infer_receipt_hash"`)) || bytes.Contains(req.Payload, []byte(`"session_id"`)) {
		t.Fatalf("tx request = %#v, carries fields the frozen receipt deleted", req)
	}
	if req.DeadlineHeight != 300 {
		t.Fatalf("deadline height = %d, want 300", req.DeadlineHeight)
	}
	if req.MaterialDigest == (codec.Hash{}) {
		t.Fatalf("material digest is empty")
	}
}

func TestWorkerRevealTriggerPersistsFullOpeningButPublishesOnlyReceiptMaterial(t *testing.T) {
	h := newHarness(t)
	recorder := &recordingPersistence{}
	h.worker.cfg.Persistence = recorder
	trigger := WorkerRevealTrigger{
		SessionID:                  "84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b",
		TaskID:                     "task-1",
		VerifyRound:                2,
		InferReceiptHash:           codec.HashWithDomain("TEST_RECEIPT", []byte("receipt")),
		VerificationSampleSeed:     codec.HashWithDomain("TEST_SAMPLE_SEED", []byte("seed")),
		SelectedPositions:          []uint64{9, 2, 5},
		SampledValueSet:            [][]byte{[]byte("w2"), []byte("w5"), []byte("w9")},
		OpeningMaterial:            []byte("full W_i opening with merkle path"),
		SampleEncodingProfile:      "llm-text-topk-v1",
		SourceRootKind:             "trace",
		EvidenceSchemaVersion:      "worker-opening-v1",
		WorkerRevealDeadlineHeight: 410,
	}

	result, err := h.worker.HandleWorkerRevealTrigger(context.Background(), trigger)
	if err != nil {
		t.Fatalf("handle worker reveal trigger: %v", err)
	}

	if result.Receipt.SampledValueSetHash == (codec.Hash{}) {
		t.Fatalf("sampled value set hash is empty")
	}
	if len(recorder.evidence) != 1 {
		t.Fatalf("evidence writes = %d, want full opening evidence", len(recorder.evidence))
	}
	if recorder.evidence[0].Kind != "worker-reveal-opening" || !bytes.Equal(recorder.evidence[0].Data, trigger.OpeningMaterial) {
		t.Fatalf("evidence = %#v, want full opening material", recorder.evidence[0])
	}
	if len(h.builder.Published) != 1 {
		t.Fatalf("published messages = %d, want worker reveal receipt", len(h.builder.Published))
	}
	if h.builder.Published[0].Subject != "trueopen.worker-reveal.task-1" {
		t.Fatalf("publish subject = %q, want worker reveal subject", h.builder.Published[0].Subject)
	}
	if bytes.Contains(h.builder.Published[0].Payload, trigger.OpeningMaterial) {
		t.Fatalf("published worker reveal payload leaked full opening material")
	}
	if !bytes.Contains(h.builder.Published[0].Payload, []byte("CORTEX_WORKER_REVEAL_RECEIPT_V1")) {
		t.Fatalf("published payload missing worker reveal receipt marker")
	}
}

func TestWorkerRevealNormalPathUsesBuilderEvenWhenTxConfigured(t *testing.T) {
	h := newHarness(t)
	tx := &recordingTxClient{obs: txclient.Observation{Accepted: true, TxHash: "0xworkerreveal"}}
	h.worker.cfg.Tx = tx
	trigger := WorkerRevealTrigger{
		SessionID:                  "84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b",
		TaskID:                     "task-1",
		VerifyRound:                2,
		InferReceiptHash:           codec.HashWithDomain("TEST_RECEIPT", []byte("receipt")),
		VerificationSampleSeed:     codec.HashWithDomain("TEST_SAMPLE_SEED", []byte("seed")),
		SelectedPositions:          []uint64{1},
		SampledValueSet:            [][]byte{[]byte("w1")},
		OpeningMaterial:            []byte("full opening not for tx"),
		SampleEncodingProfile:      "llm-text-topk-v1",
		SourceRootKind:             "trace",
		EvidenceSchemaVersion:      "worker-opening-v1",
		WorkerRevealDeadlineHeight: 410,
	}

	_, err := h.worker.HandleWorkerRevealTrigger(context.Background(), trigger)
	if err != nil {
		t.Fatalf("handle worker reveal trigger: %v", err)
	}

	if len(tx.requests) != 0 {
		t.Fatalf("normal worker reveal submitted direct tx: %#v", tx.requests)
	}
	if len(h.builder.Published) != 1 {
		t.Fatalf("Builder publishes = %d, want one signed reveal item", len(h.builder.Published))
	}
}

// testSubmitInferReceiptMessage builds the frozen task.v1.MsgSubmitInferReceipt
// body. Every field the frozen InferReceiptV1 requires is present, including the
// generation_params_digest and the required evidence commitment list that no
// wired Cortex path can supply yet; the self-rescue trigger under test is about
// scheduling, not about sourcing those values.
func testSubmitInferReceiptMessage(taskID, submitter string) txclient.SubmitInferReceiptMessage {
	digest := codec.HashWithDomain("TEST_TASK_ID_V1", []byte(taskID))
	hash := txclient.ProtoBytes32(fmt.Sprintf("%x", digest[:]))
	zero := txclient.ProtoBytes32(strings.Repeat("00", 32))
	return txclient.SubmitInferReceiptMessage{
		Receipt: txclient.InferReceiptMessage{
			SchemaVersion: txclient.InferReceiptSchemaVersionV3, ChainID: "trueopen-devnet-1",
			TaskID: hash, TaskHash: hash, WorkerOperatorAddress: workerTestOperatorAddress,
			ServiceAuthorizationNonce: 3, GenerationParamsDigest: hash, OutputHash: hash,
			OutputSizeBytes: 2_048, GeneratedTokenCount: 32, OutputLeafCount: 2,
			RequiredEvidenceCommitments: []txclient.EvidenceCommitmentMessage{
				{EvidenceKind: txclient.EvidenceKindWorkerValueOpening, EvidenceHashOrRoot: hash, EncodedSizeBytes: 256},
				{EvidenceKind: txclient.EvidenceKindWorkerTokenOpening, EvidenceHashOrRoot: hash, EncodedSizeBytes: 136},
			},
			ExpiryHeight: 300, ServiceSignature: txclient.ProtoBytes(strings.Repeat("ab", 64)),
			OutputKeyCommitment: zero, WorkerTokenKeyCommitment: zero, WorkerValueKeyCommitment: zero, CiphertextOutputRoot: zero,
		},
		SubmitterAddress: submitter,
	}
}

func TestWorkerRevealNormalPathRequiresBuilder(t *testing.T) {
	h := newHarness(t)
	tx := &recordingTxClient{obs: txclient.Observation{Accepted: true, TxHash: "0xworkerreveal"}}
	h.worker.cfg.Builder = nil
	h.worker.cfg.Tx = tx
	trigger := WorkerRevealTrigger{
		SessionID:                  "84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b",
		TaskID:                     "task-1",
		VerifyRound:                2,
		InferReceiptHash:           codec.HashWithDomain("TEST_RECEIPT", []byte("receipt")),
		VerificationSampleSeed:     codec.HashWithDomain("TEST_SAMPLE_SEED", []byte("seed")),
		SelectedPositions:          []uint64{1},
		SampledValueSet:            [][]byte{[]byte("w1")},
		OpeningMaterial:            []byte("full opening not for tx"),
		SampleEncodingProfile:      "llm-text-topk-v1",
		SourceRootKind:             "trace",
		EvidenceSchemaVersion:      "worker-opening-v1",
		WorkerRevealDeadlineHeight: 410,
	}

	if _, err := h.worker.HandleWorkerRevealTrigger(context.Background(), trigger); err == nil || !strings.Contains(err.Error(), "Builder client is required") {
		t.Fatalf("worker reveal without Builder error = %v", err)
	}
	if len(tx.requests) != 0 {
		t.Fatalf("normal worker reveal submitted direct tx: %#v", tx.requests)
	}
}

func TestWorkerRevealSampledValueHashCanonicalizesPositionValuePairs(t *testing.T) {
	base := WorkerRevealTrigger{
		SessionID:              "84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b",
		TaskID:                 "task-1",
		VerifyRound:            2,
		InferReceiptHash:       codec.HashWithDomain("TEST_RECEIPT", []byte("receipt")),
		VerificationSampleSeed: codec.HashWithDomain("TEST_SAMPLE_SEED", []byte("seed")),
		SampleEncodingProfile:  "llm-text-topk-v1",
		SourceRootKind:         "trace",
		EvidenceSchemaVersion:  "worker-opening-v1",
	}
	a := base
	a.SelectedPositions = []uint64{9, 2, 5}
	a.SampledValueSet = [][]byte{[]byte("w9"), []byte("w2"), []byte("w5")}
	b := base
	b.SelectedPositions = []uint64{2, 5, 9}
	b.SampledValueSet = [][]byte{[]byte("w2"), []byte("w5"), []byte("w9")}

	ah, err := canonicalSampledValueSetHash(a)
	if err != nil {
		t.Fatalf("canonical hash a: %v", err)
	}
	bh, err := canonicalSampledValueSetHash(b)
	if err != nil {
		t.Fatalf("canonical hash b: %v", err)
	}

	if ah != bh {
		t.Fatalf("canonical sampled value hash differs for equivalent position/value pairs")
	}
}

type randomizedWorkerSigner struct {
	mu      sync.Mutex
	private *secp256k1.PrivateKey
	address string
	keyRef  string
	digests []codec.Hash
}

func (s *randomizedWorkerSigner) SignDigest(_ context.Context, request signer.DigestRequest) ([]byte, error) {
	if request.KeyRef != s.keyRef || request.ExpectedSignerAddress != s.address {
		return nil, errors.New("unexpected randomized signer identity")
	}
	signature, err := randomizedCompactSignature(s.private, request.Digest)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.digests = append(s.digests, request.Digest)
	s.mu.Unlock()
	return signature, nil
}

func (*randomizedWorkerSigner) SignCosmosTx(context.Context, signer.CosmosTxRequest) ([]byte, error) {
	return nil, errors.New("not supported")
}

func (*randomizedWorkerSigner) CanSignCosmosTx() bool { return false }

func (s *randomizedWorkerSigner) countDigest(digest codec.Hash) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, signed := range s.digests {
		if signed == digest {
			count++
		}
	}
	return count
}

func randomizedCompactSignature(private *secp256k1.PrivateKey, digest codec.Hash) ([]byte, error) {
	curve := secp256k1.S256()
	order := curve.Params().N
	one := big.NewInt(1)
	max := new(big.Int).Sub(order, one)
	privateScalar := new(big.Int).SetBytes(private.Serialize())
	message := new(big.Int).SetBytes(digest[:])
	for {
		nonce, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, err
		}
		nonce.Add(nonce, one)
		x, _ := curve.ScalarBaseMult(nonce.Bytes())
		r := new(big.Int).Mod(x, order)
		if r.Sign() == 0 {
			continue
		}
		s := new(big.Int).Mul(r, privateScalar)
		s.Add(s, message)
		s.Mul(s, new(big.Int).ModInverse(nonce, order))
		s.Mod(s, order)
		if s.Sign() == 0 {
			continue
		}
		halfOrder := new(big.Int).Rsh(new(big.Int).Set(order), 1)
		if s.Cmp(halfOrder) > 0 {
			s.Sub(order, s)
		}
		signature := make([]byte, 64)
		r.FillBytes(signature[:32])
		s.FillBytes(signature[32:])
		return signature, nil
	}
}

type harness struct {
	model                *countingModel
	builder              *builderclient.FakeClient
	taskData             *recordingTaskData
	persistence          *recordingPersistence
	signer               *workerTestSigner
	serviceKeys          *workerTestServiceKeys
	builderServicePubkey string
	taskFacts            *workerTestTaskFacts
	snapshotReader       *workerTestSnapshotReader
	worker               *Worker
}

func newHarness(t *testing.T) harness {
	return newHarnessWithConfig(t, nil)
}

// newHarnessWithConfig builds the standard fake harness and lets the caller
// adjust the Config before the Worker is constructed. Every existing test wants
// it untouched; the real vLLM test swaps in a live model service, turns off
// FakeOutput, and supplies the locked Profile fields a receipt has to commit.
//
// A mutator rather than more parameters: the fields a real run has to override
// are not one axis, and a signature that grew one argument per field would hide
// which of them matter.
func newHarnessWithConfig(t *testing.T, mutate func(*Config)) harness {
	t.Helper()
	model := &countingModel{FakeService: modelservice.NewFakeService()}
	modelClient := modelservice.Client(model)
	builder := builderclient.NewFakeClient()
	packageStore, err := builderclient.NewFixtureOutputPackageStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFixtureOutputPackageStore error = %v", err)
	}
	servicePrivate := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{0x31}, 32))
	servicePubkey := servicePrivate.PubKey().SerializeCompressed()
	serviceAddress, err := signer.AddressFromCompressedPublicKey("trueopen", servicePubkey)
	if err != nil {
		t.Fatalf("derive service address: %v", err)
	}
	serviceSigner := &workerTestSigner{private: servicePrivate, address: serviceAddress, keyRef: "test-worker-key"}
	serviceKeys := &workerTestServiceKeys{binding: chainclient.ServiceKeySnapshot{
		ParticipantType:    chainclient.ParticipantTypeCortexNode,
		OperatorAddress:    workerTestOperatorAddress,
		ServiceAddress:     serviceAddress,
		ServicePubkey:      hex.EncodeToString(servicePubkey),
		AuthorizationNonce: chainclient.NewUint64String(1),
		Status:             "ACTIVE",
	}}
	auth, err := taskdataauth.New(taskdataauth.Config{
		ServiceKeys: serviceKeys, Signer: serviceSigner,
		ChainID: "chain-A", OperatorAddress: workerTestOperatorAddress, ServiceAddress: serviceAddress,
		ServicePubkey: hex.EncodeToString(servicePubkey), ServiceKeyRef: "test-worker-key", ExpiryBlocks: 20,
	})
	if err != nil {
		t.Fatalf("taskdataauth.New: %v", err)
	}
	endpoint := BuilderEndpoint{
		OperatorAddress:    "trueopen1j7r6u8nwvw93l2tc0wd75v07vu89lxyfqf8fut",
		Endpoint:           "https://builder.example",
		ServicePubkey:      hex.EncodeToString(secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{0x41}, 32)).PubKey().SerializeCompressed()),
		CurrentHeight:      100,
		AuthorizationNonce: 1,
	}
	taskData := &recordingTaskData{
		FakeClient:     builderclient.NewFakeClient(),
		builderPrivate: secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{0x41}, 32)),
		retention:      200,
	}
	persistence := &recordingPersistence{}
	taskFacts := &workerTestTaskFacts{}
	snapshotReader := &workerTestSnapshotReader{}
	snapshotReader.seedFrom(finalizedTask())
	cfg := Config{
		WorkerAddress: workerTestOperatorAddress, ModelServiceID: "fake-model-service", Model: modelClient, Builder: builder,
		TaskData: taskData, TaskDataAuth: auth, Persistence: persistence,
		StreamLimits:              &chainclient.OutputStreamLimitsSnapshot{MaxOutputMMRLeaves: 1024, MinOutputStreamFrameBytes: 16, SnapshotHeight: 100},
		InferDeadlineDeltaHeights: 30, ChainID: "chain-A", SessionID: "84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", OrderSequence: 7,
		SignerAddress: serviceAddress, SignerKeyRef: "test-worker-key", SignerPubkey: hex.EncodeToString(servicePubkey),
		Signer: serviceSigner, FakeOutput: true, PackageStore: packageStore,
		// A fake-inference node signs envelopes just the same: FakeOutput says the output
		// is synthetic and says nothing about the node's identity. The harness must provide
		// a signer, or the test exercises an "unsigned" path that exists in no real
		// deployment.
		NexusEnvelopeSigner: testEnvelopeSigner(),
		ReceivingBuilder: ReceivingBuilderFunc(func(context.Context, ReceivingBuilderRef) (BuilderEndpoint, error) {
			return endpoint, nil
		}),
		// The Keeper read the receipt's task_hash and generation_params_digest
		// come from. Both are keyed by task id, so a reader pointed at the wrong
		// task serves visibly different bytes.
		TaskFacts: taskFacts,
		GenerationReader: generationReaderFunc(func(context.Context, string, codec.Hash) (nodewire.GenerationContext, error) {
			return workerTestGeneration(), nil
		}),
		// SnapshotReader re-reads the canonical assignment before the worker
		// accepts an event. Tests use a fixed snapshot that matches the event.
		SnapshotReader: snapshotReader,
		// Fields 11 and 12 of every envelope this Worker publishes on the
		// OUTPUT_AVAILABLE path. It is Task state the daemon copies out of the
		// admitted task record, and an absent reference is a refusal (§5.2).
	}
	if mutate != nil {
		mutate(&cfg)
	}
	w := New(cfg)
	t.Cleanup(w.closeOutputStream)
	return harness{
		serviceKeys: serviceKeys,
		model:       model, builder: builder, taskData: taskData, persistence: persistence,
		signer: serviceSigner, builderServicePubkey: endpoint.ServicePubkey, worker: w,
		taskFacts: taskFacts, snapshotReader: snapshotReader,
	}
}

// workerTestOperatorAddress is the WORKER operator identity for this whole
// package. It is Node's own published infer_receipt_v1 golden worker address, so
// it is known to decode: the frozen receipt preimage frames this value as its
// address codec bytes, and a placeholder such as "worker-1" is refused outright.
const workerTestOperatorAddress = "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc"

// workerTestRequiredTopK frames the harness worker_values; the mocked engines
// report one alternative per position.
const workerTestRequiredTopK = 1

// workerTestModelID is the Hash32 model id, as canonical hex, the harness serves.
const workerTestModelID = "0101010101010101010101010101010101010101010101010101010101010101"

// workerTestHandraiseNonce is the committed ServiceKey authorization_nonce a
// handraise caller reads with taskdataauth.CommittedBusEnvelopeIdentity and hands
// to EvaluateAndHandraise for envelope field 7. It is deliberately not 1 so an
// envelope that carried a default rather than the caller's value is visible.
const workerTestHandraiseNonce = uint64(23)

// seedPreparedOutput runs the inference+receipt path and persists the resulting
// artifacts, descriptor and signed receipt, but stops short of publishing
// OUTPUT_AVAILABLE or relaying to a Builder. This simulates the state a crashed
// predecessor would leave behind so that the finalize pass can recover from
// durable storage rather than re-running inference.
func (h harness) seedPreparedOutput(t *testing.T, event chainclient.AssignmentFinalized) builderclient.SignedInferReceipt {
	t.Helper()
	h.snapshotReader.seedFrom(event)
	enableEvidenceSchema(&h)
	produced, err := h.worker.prepareOutput(context.Background(), event)
	if err != nil {
		t.Fatalf("seed prepared output: %v", err)
	}
	return produced.receipt
}

// workerTestServedTaskFacts is what the Keeper's frozen section 16.2 read serves
// for one task. It is the single source for both fixture facts, so the seeded
// prepared output and the production fetch cannot drift apart.
// workerTestGeneration is the harness task's generation context: its digest is
// the served generation_params_digest and its canonical bytes are the A-level
// generation_params artifact.
func workerTestGeneration() nodewire.GenerationContext {
	return nodewire.GenerationContext{
		ModelID: finalizedTask().ModelID, ProfileVersion: 1, TaskType: 2, OutputBudgetBucket: 1,
		Params: nodewire.GenerationParamsV1{SchemaVersion: 1, MaxOutputTokens: 1024, MaxOutputDuration: 30000,
			DecodingParams: nodewire.DecodingParamsV1{TopPPPM: 1000000, RepetitionPenaltyPPM: 1000000}},
	}
}

func workerTestServedTaskFacts(taskID string) taskfacts.Facts {
	accepted := codec.HashWithDomain("WORKER_TEST_ACCEPTED_TASK_HASH_V1", []byte(taskID))
	generation, err := workerTestGeneration().Digest()
	if err != nil {
		panic(err)
	}
	return taskfacts.Facts{
		TaskID: taskID,
		TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
			AcceptedTaskHash:       chainclient.ProtoBytes32(accepted[:]),
			GenerationParamsDigest: chainclient.ProtoBytes32(generation[:]),
		},
	}
}

// workerTestAcceptedTaskHash stands in for TaskCoreState.accepted_task_hash as
// the frozen Query/Task response serves it. It is deliberately unrelated to
// event.OrderDigest so a test asserting the relayed task_hash catches the
func workerTestCandidateMember() builderclient.CandidateMemberRefMessage {
	return builderclient.CandidateMemberRefMessage{
		CandidatePoolSnapshotID: strings.Repeat("31", 32), Slot: 1, SlotVersion: 1,
		OperatorAddress: workerTestOperatorAddress,
	}
}

// order-digest substitution the frozen contract forbids.
func workerTestHandraiseTaskHash(orderDigest codec.Hash) codec.Hash {
	return codec.HashWithDomain("TEST_TASK_ORDER_HASH_V1", orderDigest[:])
}

func workerTestAcceptedTaskHash(taskID string) string {
	return workerTestServedTaskFacts(taskID).AcceptedTaskHash.Hex()
}

// workerTestGenerationParamsDigest stands in for
// TaskAssignmentViewV1.generation_params_digest, field 16 of the frozen view. It
// is deliberately non-zero, and that is load-bearing rather than decorative: the
// task-facts seam, the receipt signer and the recovery boundary all refuse an
// all-zero generation_params_digest, so a zero fixture would make every seeded
// test fail instead of exercising the seeded path.
func workerTestGenerationParamsDigest(taskID string) string {
	return workerTestServedTaskFacts(taskID).GenerationParamsDigest.Hex()
}

// workerTestTaskFacts is the honest reader: it answers for the task it was asked
// about. It records every id it was asked for, so a test can pin that the Worker
// queried the assignment it is acting on rather than something it invented.
type workerTestTaskFacts struct {
	mu       sync.Mutex
	asked    []string
	override func(string) (taskfacts.Facts, error)
}

func (r *workerTestTaskFacts) TaskFacts(_ context.Context, taskID string) (taskfacts.Facts, error) {
	r.mu.Lock()
	r.asked = append(r.asked, taskID)
	override := r.override
	r.mu.Unlock()
	if override != nil {
		return override(taskID)
	}
	return workerTestServedTaskFacts(taskID), nil
}

// workerTestWorkerValueEvidenceInputs stands in for the two
// TRUEOPEN_WORKER_VALUE_COMMITMENT_V1 inputs the frozen receipt wire does not carry
// and the Worker cannot read yet: the locked Profile's evidence_schema_hash
// (hub.v1.Query/Profile). The FinishReasonV1 outcome is now read from the
// model service through internal/modelservice/finish_reason.go.
//
// The commitment itself is NOT a fixture. It is derived from these two values
// plus the receipt's own task scope and the persisted artifacts, so the seeded
// evidence list is exactly what production will emit once those two reads land,
// and recovery's re-derivation is being checked against a real digest rather
// than against a hand-picked root.
func workerTestWorkerValueEvidenceInputs() workerValueEvidenceInputs {
	digest := codec.HashWithDomain("WORKER_TEST_EVIDENCE_SCHEMA_HASH_V1", []byte("locked profile"))
	return workerValueEvidenceInputs{
		EvidenceSchemaHash: hex.EncodeToString(digest[:]),
		FinishReason:       nodewire.FinishReasonV1EosToken,
	}
}

type workerTestSigner struct {
	mu      sync.Mutex
	private *secp256k1.PrivateKey
	address string
	keyRef  string
	digests []codec.Hash
}

func (s *workerTestSigner) SignDigest(_ context.Context, request signer.DigestRequest) ([]byte, error) {
	if request.KeyRef != s.keyRef || request.ExpectedSignerAddress != s.address {
		return nil, errors.New("unexpected signer identity")
	}
	s.mu.Lock()
	s.digests = append(s.digests, request.Digest)
	s.mu.Unlock()
	return compactTestSignature(s.private, request.Digest), nil
}

func (*workerTestSigner) SignCosmosTx(context.Context, signer.CosmosTxRequest) ([]byte, error) {
	return nil, errors.New("not supported")
}

func (*workerTestSigner) CanSignCosmosTx() bool { return false }

func (s *workerTestSigner) countDigest(digest codec.Hash) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, signed := range s.digests {
		if signed == digest {
			count++
		}
	}
	return count
}

func compactTestSignature(private *secp256k1.PrivateKey, digest codec.Hash) []byte {
	signature := ecdsa.Sign(private, digest[:])
	r, s := signature.R(), signature.S()
	rBytes, sBytes := r.Bytes(), s.Bytes()
	out := make([]byte, 64)
	copy(out[:32], rBytes[:])
	copy(out[32:], sBytes[:])
	return out
}

type workerTestServiceKeys struct {
	binding chainclient.ServiceKeySnapshot
	height  uint64
	err     error
}

// workerTestServedHeight is the height Keeper serves the committed service-key
// read at; signed requests expire relative to it.
const workerTestServedHeight = uint64(100)

func (s workerTestServiceKeys) CommittedCurrentServiceKey(context.Context, string, string) (chainclient.ServiceKeySnapshot, uint64, error) {
	height := s.height
	if height == 0 {
		height = workerTestServedHeight
	}
	return s.binding, height, s.err
}

type recordingTaskData struct {
	*builderclient.FakeClient
	events  *[]string
	relays  []builderclient.SubmitInferReceiptRequest
	uploads []builderclient.UploadTaskResultRequest
	// endpoints records every Nexus endpoint the Worker relayed or uploaded to,
	// so a test can observe which Builder the receiving-Builder seam selected.
	endpoints []string
	// pins records the tls_pubkey_hash each relay/upload carried in its context.
	pins                         []string
	relayErrors                  []error
	uploadErrors                 []error
	uploadEntered                chan struct{}
	uploadRelease                chan struct{}
	builderPrivate               *secp256k1.PrivateKey
	retention                    uint64
	mutateConfirmation           func(*builderclient.StorageConfirmation)
	mutateConfirmationBeforeSign func(*builderclient.StorageConfirmation)
}

func (*recordingTaskData) GetTaskDataMetadata(context.Context, string, builderclient.GetTaskDataMetadataRequest) (builderclient.TaskDataMetadata, error) {
	return builderclient.TaskDataMetadata{}, errors.New("unexpected metadata request")
}

func (*recordingTaskData) FetchTaskData(context.Context, string, builderclient.FetchTaskDataRequest, func(builderclient.TaskDataChunk) error) error {
	return errors.New("unexpected fetch request")
}

func (*recordingTaskData) SubmitVerifyCommit(context.Context, string, builderclient.SubmitVerifyCommitRequest) (builderclient.VerifyRelayAck, error) {
	return builderclient.VerifyRelayAck{}, errors.New("unexpected verify commit relay")
}

func (c *recordingTaskData) SubmitInferReceipt(ctx context.Context, endpoint string, request builderclient.SubmitInferReceiptRequest) error {
	c.endpoints = append(c.endpoints, endpoint)
	pin, _ := builderclient.TLSPubkeyHashFromContext(ctx)
	c.pins = append(c.pins, pin)
	c.relays = append(c.relays, cloneRelayRequest(request))
	c.record("task-data:relay")
	attempt := len(c.relays) - 1
	if attempt < len(c.relayErrors) && c.relayErrors[attempt] != nil {
		return c.relayErrors[attempt]
	}
	return nil
}

func (c *recordingTaskData) UploadTaskResultObject(ctx context.Context, endpoint string, request builderclient.UploadTaskResultRequest) (builderclient.TaskDataMetadata, error) {
	c.endpoints = append(c.endpoints, endpoint)
	pin, _ := builderclient.TLSPubkeyHashFromContext(ctx)
	c.pins = append(c.pins, pin)
	c.uploads = append(c.uploads, cloneUploadRequest(request))
	c.record("task-data:upload")
	// Hold the first evidence upload while the test inspects relay ordering.
	if c.uploadEntered != nil {
		close(c.uploadEntered)
		c.uploadEntered = nil
		<-c.uploadRelease
	}
	attempt := len(c.uploads) - 1
	if attempt < len(c.uploadErrors) && c.uploadErrors[attempt] != nil {
		return builderclient.TaskDataMetadata{}, c.uploadErrors[attempt]
	}
	if c.FakeClient == nil {
		c.FakeClient = builderclient.NewFakeClient()
	}
	return c.FakeClient.UploadTaskResultObject(ctx, endpoint, request)
}

func (c *recordingTaskData) FinalizeTaskResult(ctx context.Context, endpoint string, request builderclient.FinalizeTaskResultRequest) (builderclient.FinalizeTaskResultResponse, error) {
	c.endpoints = append(c.endpoints, endpoint)
	pin, _ := builderclient.TLSPubkeyHashFromContext(ctx)
	c.pins = append(c.pins, pin)
	result, err := c.FakeClient.FinalizeTaskResult(ctx, endpoint, request)
	if err != nil {
		return result, err
	}
	c.record("task-data:finalize")
	confirmations := []*builderclient.StorageConfirmation{&result.OutputConfirmation}
	for i := range result.EvidenceBundleConfirmations {
		confirmations = append(confirmations, &result.EvidenceBundleConfirmations[i])
	}
	for _, confirmation := range confirmations {
		confirmation.RetentionUntilHeight = c.retention
		if c.mutateConfirmationBeforeSign != nil {
			c.mutateConfirmationBeforeSign(confirmation)
		}
		digest, err := builderclient.StorageConfirmationSigningHash(*confirmation)
		if err != nil {
			return builderclient.FinalizeTaskResultResponse{}, err
		}
		confirmation.Signature = compactTestSignature(c.builderPrivate, digest)
		if c.mutateConfirmation != nil {
			c.mutateConfirmation(confirmation)
		}
	}
	return result, nil
}

func (c *recordingTaskData) record(event string) {
	if c.events != nil {
		*c.events = append(*c.events, event)
	}
}

func cloneRelayRequest(request builderclient.SubmitInferReceiptRequest) builderclient.SubmitInferReceiptRequest {
	request.Receipt.RequiredEvidenceCommitments = append(
		[]builderclient.EvidenceCommitment(nil), request.Receipt.RequiredEvidenceCommitments...)
	return request
}

func cloneUploadRequest(request builderclient.UploadTaskResultRequest) builderclient.UploadTaskResultRequest {
	request.Data = append([]byte(nil), request.Data...)
	request.Auth.RequestNonce = append([]byte(nil), request.Auth.RequestNonce...)
	request.Auth.Signature = append([]byte(nil), request.Auth.Signature...)
	return request
}

func slicesIndex(values []string, target string) int {
	for i, value := range values {
		if value == target {
			return i
		}
	}
	return -1
}

func pendingOutputAvailable(records []OutboxRecord) bool {
	for _, record := range records {
		if record.Status == "pending" && record.Subject == builderclient.NATSOutputAvailableSubject(record.TaskID) {
			return true
		}
	}
	return false
}

type countingModel struct {
	*modelservice.FakeService
	InferCalls         int
	ReportedOutputHash []byte
}

type recordingPersistence struct {
	evidenceWriteError  func(EvidenceRecord) error
	evidence            []EvidenceRecord
	outbox              []OutboxRecord
	outboxErrors        map[string][]error
	outboxWriteStatuses []string
	jobs                []ModelJobCheckpoint
	receipts            []InferReceiptCheckpoint
	confirmations       []StorageConfirmationCheckpoint
	events              *[]string
	bundles             map[string]recordedBundle
}

// recordedBundle is one published Worker bundle.
type recordedBundle struct {
	manifest  []byte
	artifacts map[string][]byte
}

func (r *recordingPersistence) PublishWorkerBundle(_ context.Context, taskID string, kind nodewire.EvidenceKind, manifest []byte, artifacts [][]byte) error {
	decoded, err := evidencebundle.Decode(manifest)
	if err != nil {
		return err
	}
	byHash := make(map[string][]byte, len(artifacts))
	for _, data := range artifacts {
		byHash[codec.HashBytes(data).String()] = append([]byte(nil), data...)
	}
	bundle := recordedBundle{manifest: append([]byte(nil), manifest...), artifacts: map[string][]byte{}}
	for _, artifact := range decoded.Artifacts {
		bundle.artifacts[artifact.ID] = byHash[artifact.ContentHash]
	}
	key := fmt.Sprintf("%s/%d", taskID, kind)
	if existing, ok := r.bundles[key]; ok {
		if !bytes.Equal(existing.manifest, manifest) {
			return fmt.Errorf("bundle %s already published with a different manifest", key)
		}
		return nil
	}
	if r.bundles == nil {
		r.bundles = map[string]recordedBundle{}
	}
	r.bundles[key] = bundle
	r.record(fmt.Sprintf("bundle:%d", kind))
	return nil
}

func (r *recordingPersistence) WorkerBundle(_ context.Context, taskID string, kind nodewire.EvidenceKind) ([]byte, map[string][]byte, error) {
	bundle, ok := r.bundles[fmt.Sprintf("%s/%d", taskID, kind)]
	if !ok {
		return nil, nil, ErrCheckpointNotFound
	}
	return bundle.manifest, bundle.artifacts, nil
}

func (r *recordingPersistence) ReadArtifact(_ context.Context, taskID, kind string) ([]byte, error) {
	for i := len(r.evidence) - 1; i >= 0; i-- {
		if r.evidence[i].TaskID == taskID && r.evidence[i].Kind == kind {
			return r.evidence[i].Data, nil
		}
	}
	return nil, ErrCheckpointNotFound
}

func (r *recordingPersistence) OutputStreamFrames(_ context.Context, taskID string) ([]builderclient.OutputChunk, error) {
	bySequence := make(map[uint64]builderclient.OutputChunk)
	for _, record := range r.evidence {
		if record.TaskID != taskID || !strings.HasPrefix(record.Kind, OutputStreamFramePrefix) {
			continue
		}
		var frame builderclient.OutputChunk
		if err := json.Unmarshal(record.Data, &frame); err != nil {
			return nil, err
		}
		bySequence[frame.Seq] = frame
	}
	frames := make([]builderclient.OutputChunk, 0, len(bySequence))
	for _, frame := range bySequence {
		frames = append(frames, frame)
	}
	sort.Slice(frames, func(i, j int) bool { return frames[i].Seq < frames[j].Seq })
	return frames, nil
}

type recordingTxClient struct {
	requests []txclient.Request
	obs      txclient.Observation
	err      error
}

func (r *recordingTxClient) Submit(_ context.Context, req txclient.Request) (txclient.Observation, error) {
	r.requests = append(r.requests, txclient.Request{
		TaskID:         req.TaskID,
		Kind:           req.Kind,
		Payload:        append([]byte(nil), req.Payload...),
		DeadlineHeight: req.DeadlineHeight,
		MaterialDigest: req.MaterialDigest,
	})
	if r.err != nil {
		return txclient.Observation{}, r.err
	}
	return r.obs, nil
}

func (r *recordingPersistence) WriteEvidence(_ context.Context, record EvidenceRecord) error {
	if r.evidenceWriteError != nil {
		if err := r.evidenceWriteError(record); err != nil {
			return err
		}
	}
	r.evidence = append(r.evidence, record)
	r.record("evidence:" + record.Kind)
	return nil
}

func (r *recordingPersistence) CheckpointInferOutput(_ context.Context, taskID string, output, tokenIDs, positionValues []byte, cp InferOutputCheckpoint) error {
	r.evidence = append(r.evidence, EvidenceRecord{TaskID: taskID, Kind: "worker-output", Data: append([]byte(nil), output...)})
	r.evidence = append(r.evidence, EvidenceRecord{TaskID: taskID, Kind: "worker-token-ids-material", Data: append([]byte(nil), tokenIDs...)})
	r.evidence = append(r.evidence, EvidenceRecord{TaskID: taskID, Kind: "worker-position-values-material", Data: append([]byte(nil), positionValues...)})
	r.evidence = append(r.evidence, EvidenceRecord{TaskID: taskID, Kind: "worker-output-descriptor", Data: append([]byte(nil), cp.DescriptorJSON...)})
	r.record("checkpoint:infer-output")
	return nil
}

func (r *recordingPersistence) WriteBuilderOutbox(_ context.Context, record OutboxRecord) error {
	r.outboxWriteStatuses = append(r.outboxWriteStatuses, record.Status)
	if queued := r.outboxErrors[record.Status]; len(queued) > 0 {
		err := queued[0]
		r.outboxErrors[record.Status] = queued[1:]
		return err
	}
	key := record.DedupID
	if key == "" {
		key = hex.EncodeToString(record.Digest[:])
	}
	for i, existing := range r.outbox {
		existingKey := existing.DedupID
		if existingKey == "" {
			existingKey = hex.EncodeToString(existing.Digest[:])
		}
		if existingKey == key {
			r.outbox[i] = record
			r.recordOutbox(record)
			return nil
		}
	}
	r.outbox = append(r.outbox, record)
	r.recordOutbox(record)
	return nil
}

func (r *recordingPersistence) CheckpointInferReceipt(_ context.Context, record InferReceiptCheckpoint) error {
	for _, existing := range r.receipts {
		if existing.TaskID != record.TaskID {
			continue
		}
		if existing.MaterialDigest != record.MaterialDigest || !bytes.Equal(existing.Payload, record.Payload) {
			return errors.New("conflicting infer receipt")
		}
		return nil
	}
	record.Payload = append([]byte(nil), record.Payload...)
	r.receipts = append(r.receipts, record)
	r.record("receipt:persist")
	return nil
}

func (r *recordingPersistence) InferReceipts(_ context.Context, _ string) ([]InferReceiptCheckpoint, error) {
	return append([]InferReceiptCheckpoint(nil), r.receipts...), nil
}

func (r *recordingPersistence) CheckpointStorageConfirmation(_ context.Context, record StorageConfirmationCheckpoint) error {
	record.Signature = append([]byte(nil), record.Signature...)
	r.confirmations = append(r.confirmations, record)
	r.record("confirmation:persist")
	return nil
}

type nondeterministicModel struct {
	*modelservice.FakeService
	calls int
}

func (m *nondeterministicModel) Infer(ctx context.Context, request modelservice.InferRequest) (modelservice.InferResponse, error) {
	m.calls++
	response, err := m.FakeService.Infer(ctx, request)
	if err != nil {
		return modelservice.InferResponse{}, err
	}
	suffix := fmt.Sprintf("-%d", m.calls)
	response.OutputRef = m.PutArtifactForTest([]byte("varying output" + suffix))
	response.TokenIDsRef = m.PutArtifactForTest([]byte("varying trace" + suffix))
	response.PositionValuesRef = m.PutArtifactForTest([]byte("varying checkpoint" + suffix))
	return response, nil
}

func (r *recordingPersistence) StorageConfirmations(_ context.Context, taskID string) ([]StorageConfirmationCheckpoint, error) {
	var records []StorageConfirmationCheckpoint
	for _, record := range r.confirmations {
		if record.TaskID == taskID {
			record.Signature = append([]byte(nil), record.Signature...)
			records = append(records, record)
		}
	}
	return records, nil
}

func (r *recordingPersistence) CheckpointInferInput(_ context.Context, checkpoint InferInputCheckpoint) error {
	return nil
}
func (r *recordingPersistence) InferInput(_ context.Context, taskID string) (InferInputCheckpoint, error) {
	return InferInputCheckpoint{}, ErrCheckpointNotFound
}
func (r *recordingPersistence) BuilderMessage(_ context.Context, key string) (BuilderMessageCheckpoint, error) {
	for _, record := range r.outbox {
		recordKey := record.DedupID
		if recordKey == "" {
			recordKey = hex.EncodeToString(record.Digest[:])
		}
		if recordKey == key {
			return BuilderMessageCheckpoint{
				Digest: key, Subject: record.Subject, TaskID: record.TaskID,
				Payload: append([]byte(nil), record.Payload...), Status: record.Status,
			}, nil
		}
	}
	return BuilderMessageCheckpoint{}, ErrCheckpointNotFound
}

func (r *recordingPersistence) recordOutbox(record OutboxRecord) {
	if record.Subject == builderclient.NATSOutputAvailableSubject(record.TaskID) {
		r.record("outbox:" + record.Status)
		return
	}
	r.record("outbox:" + record.Subject)
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

func (m *countingModel) Infer(ctx context.Context, req modelservice.InferRequest) (modelservice.InferResponse, error) {
	m.InferCalls++
	resp, err := m.FakeService.Infer(ctx, req)
	if err != nil {
		return resp, err
	}
	if len(m.ReportedOutputHash) > 0 {
		resp.RequestDigest = append([]byte(nil), m.ReportedOutputHash...)
	}
	return resp, nil
}

func finalizedTask() chainclient.AssignmentFinalized {
	sessionID := "84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b"
	orderSequence := uint64(7)
	return chainclient.AssignmentFinalized{
		TaskID:                 canonicalTaskID(sessionID, orderSequence),
		SessionID:              sessionID,
		OrderSequence:          orderSequence,
		OrderDigest:            codec.HashWithDomain("TEST_ORDER_DIGEST", []byte("order-7")),
		Winner:                 workerTestOperatorAddress,
		WinnerConfirmHeight:    200,
		InferDeadlineHeight:    230,
		ModelID:                modelservice.FakeModelID,
		ProfileVersion:         1,
		Capability:             modelservice.CapabilityLLMTextV1,
		Input:                  []byte("hello"),
		BuilderOperatorAddress: "trueopen1j7r6u8nwvw93l2tc0wd75v07vu89lxyfqf8fut",
	}
}

// workerTestSnapshotReader returns snapshots derived from registered events.
type workerTestSnapshotReader struct {
	mu        sync.Mutex
	snapshots map[string]chainclient.TaskSnapshot
}

func (r *workerTestSnapshotReader) seedFrom(event chainclient.AssignmentFinalized) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.snapshots == nil {
		r.snapshots = make(map[string]chainclient.TaskSnapshot)
	}
	r.snapshots[event.TaskID] = snapshotFromEvent(event)
}

func (r *workerTestSnapshotReader) TaskSnapshot(ctx context.Context, taskID string) (chainclient.TaskSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.snapshots[taskID]; ok {
		return s, nil
	}
	// Return a default snapshot for tests that do not explicitly seed one.
	defaultEvent := finalizedTask()
	defaultSnapshot := snapshotFromEvent(defaultEvent)
	defaultSnapshot.Assignment.TaskID = taskID
	return defaultSnapshot, nil
}

func snapshotFromEvent(event chainclient.AssignmentFinalized) chainclient.TaskSnapshot {
	inputHash := codec.HashBytes(event.Input)
	return chainclient.TaskSnapshot{
		Status: "ASSIGNED",
		Assignment: chainclient.AssignmentSnapshot{
			SessionID:                event.SessionID,
			TaskID:                   event.TaskID,
			OrderSequence:            chainclient.NewUint64String(event.OrderSequence),
			SelectedWorker:           event.Winner,
			InferDeadlineHeight:      chainclient.NewUint64String(event.InferDeadlineHeight),
			ModelID:                  event.ModelID,
			ProfileVersion:           chainclient.NewProfileVersion(event.ProfileVersion),
			AcceptedOrderPayloadHash: chainclient.HexHash(inputHash),
		},
		CurrentContract: true,
	}
}

func canonicalTaskID(sessionID string, orderSequence uint64) string {
	return identity.TaskIDString(sessionID, orderSequence)
}

func validWorkerPrecheck() policy.WorkerPrecheckInput {
	return policy.WorkerPrecheckInput{
		ChainSynced:                     true,
		CurrentHeight:                   100,
		SupportState:                    policy.SupportActive,
		SupportLastConfirmedHeight:      95,
		SupportFreshnessWindow:          30,
		Profile:                         modelservice.CapabilityLLMTextV1,
		SupportedProfiles:               []string{modelservice.CapabilityLLMTextV1},
		AvailableSlots:                  1,
		CapacitySnapshotRef:             "capacity://snapshot/1",
		SelfRescueGasAvailable:          true,
		SelfRescueGasBudgetNanoTRUEOPEN: 10,
	}
}

// The relayed facts must be exactly the signed receipt's, with no locally
// re-derived copy alongside it: task_hash is receipt field 4 and the evidence
// commitments live on the receipt, not on the request.
func TestWorkerRelaysExactReceiptAndEvidenceFacts(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	seeded := h.seedPreparedOutput(t, event)
	if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err != nil {
		t.Fatalf("HandleAssignmentFinalized: %v", err)
	}
	relay := h.taskData.relays[0]
	outputKey := builderclient.TaskDataKey{TaskHash: relay.Receipt.TaskHash, SessionID: event.SessionID, TaskID: event.TaskID, Kind: builderclient.DataKindOutput, ContentHash: relay.Receipt.OutputHash}
	storedOutput := h.taskData.TaskData[outputKey]
	if !reflect.DeepEqual(relay.Receipt, seeded) {
		t.Fatalf("relayed receipt = %#v, want the durable signed receipt", relay.Receipt)
	}
	if len(storedOutput) == 0 || relay.Receipt.TaskID != event.TaskID {
		t.Fatalf("relay routing does not match finalized task identity")
	}
	if relay.Receipt.TaskHash == hex.EncodeToString(event.OrderDigest[:]) {
		t.Fatal("relayed task_hash is the order digest, which the frozen contract forbids")
	}
	if relay.Receipt.SchemaVersion != nodewire.InferReceiptSchemaVersionV3 ||
		relay.Receipt.ChainID != "chain-A" ||
		relay.Receipt.WorkerOperatorAddress != workerTestOperatorAddress ||
		relay.Receipt.ServiceAuthorizationNonce == 0 ||
		relay.Receipt.ExpiryHeight != event.InferDeadlineHeight {
		t.Fatalf("relayed receipt identity = %#v", relay.Receipt)
	}
	if relay.Receipt.OutputSizeBytes != uint64(len(storedOutput)) || relay.Receipt.OutputLeafCount != 1 {
		t.Fatalf("receipt output facts = %#v, streamed bytes = %d", relay.Receipt, len(storedOutput))
	}
	// The receipt carries the value and the token commitments, each a typed
	// digest distinct from its manifest's content hash and sized to its bundle.
	if len(relay.Receipt.RequiredEvidenceCommitments) != 2 {
		t.Fatalf("evidence commitments = %#v, want the value and token openings", relay.Receipt.RequiredEvidenceCommitments)
	}
	for i, want := range []struct {
		kind       nodewire.EvidenceKind
		manifestAt int
	}{{nodewire.EvidenceKindWorkerValueOpening, 1}, {nodewire.EvidenceKindWorkerTokenOpening, 5}} {
		commitment := relay.Receipt.RequiredEvidenceCommitments[i]
		manifestBytes := h.taskData.uploads[want.manifestAt].Data
		manifest, err := evidencebundle.Decode(manifestBytes)
		if err != nil {
			t.Fatal(err)
		}
		if commitment.EvidenceKind != want.kind || commitment.EvidenceHashOrRoot == (codec.Hash{}) ||
			commitment.EvidenceHashOrRoot == evidencebundle.Hash(manifestBytes) || commitment.EncodedSizeBytes != manifest.CommittedSize() {
			t.Fatalf("relayed evidence commitment %d = %#v", i, commitment)
		}
	}
	finalize := h.taskData.FinalizedTaskResults[0]
	if relay.Receipt.ServiceSignature == "" || !reflect.DeepEqual(relay.Receipt, finalize.Receipt) {
		t.Fatal("relay and finalize did not use the same signed receipt")
	}
	stream := h.taskData.UploadedOutputStreams[0]
	if finalize.Auth.Method != "/nexus.v1.IngressAPI/FinalizeTaskResult" || stream.Auth.Method != "/nexus.v1.IngressAPI/UploadTaskOutputStream" {
		t.Fatalf("task-data auth methods = %q/%q", finalize.Auth.Method, stream.Auth.Method)
	}
	if bytes.Equal(finalize.Auth.RequestNonce, stream.Auth.RequestNonce) {
		t.Fatal("finalize and stream reused a request nonce")
	}
	root, err := codec.OutputMMRRootFromLengths(storedOutput, []uint64{uint64(len(storedOutput))})
	if err != nil || outputKey.ContentHash != root.String() {
		t.Fatalf("stream output root = %s, error=%v", outputKey.ContentHash, err)
	}
}

// A refusal must be total. task_hash and generation_params_digest are wired now,
// but the locked Profile's evidence_schema_hash still has no source, so a fresh
// assignment ends in ErrInferReceiptInputUnavailable and leaves no partially
// signed responsibility behind: nothing relayed, nothing uploaded, no persisted
// receipt, no prepared checkpoint, no availability row and no job marked succeeded.
func TestWorkerRefusesToSignAReceiptItCannotFullyPopulate(t *testing.T) {
	h := newHarness(t)

	_, err := h.worker.HandleAssignmentFinalized(context.Background(), finalizedTask())
	if !errors.Is(err, builderclient.ErrInferReceiptInputUnavailable) {
		t.Fatalf("HandleAssignmentFinalized error = %v, want ErrInferReceiptInputUnavailable", err)
	}
	// evidence_schema_hash is the first blocking input now, and the refusal must
	// name where the value comes from instead of blaming the caller.
	for _, want := range []string{
		"evidence_schema_hash",
		"verification_profile.evidence_schema_hash",
		"hub.v1.Query/Profile",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal = %q, want it to name %q", err.Error(), want)
		}
	}
	// The two facts that ARE wired must not appear as reasons any more: the
	// Worker read them, and a refusal that still blamed them would send an
	// operator after work that is already done.
	for _, stale := range []string{
		"task_hash requires", "TaskCoreState.accepted_task_hash",
		"no Worker or verifier path calls yet", "node#99", "node#100", "never writes", "does not read yet",
	} {
		if strings.Contains(err.Error(), stale) {
			t.Fatalf("refusal = %q still blames %q, which is wired now", err.Error(), stale)
		}
	}
	// And the read really happened, for exactly the task in hand.
	if len(h.taskFacts.asked) < 2 {
		t.Fatalf("task facts asked = %#v, want stream and receipt reads for the finalized assignment", h.taskFacts.asked)
	}
	for _, asked := range h.taskFacts.asked {
		if asked != finalizedTask().TaskID {
			t.Fatalf("task facts asked = %#v, want only the finalized assignment", h.taskFacts.asked)
		}
	}
	if len(h.taskData.relays) != 0 || len(h.taskData.uploads) != 0 {
		t.Fatalf("refusal reached the network: relays=%d uploads=%d", len(h.taskData.relays), len(h.taskData.uploads))
	}
	if len(h.persistence.receipts) != 0 {
		t.Fatalf("refusal persisted responsibility: receipts=%d", len(h.persistence.receipts))
	}
	if len(h.persistence.outbox) != 0 {
		t.Fatalf("refusal persisted an availability row: %#v", h.persistence.outbox)
	}
	if len(h.persistence.jobs) == 0 {
		t.Fatal("the refused pass never opened a model service job")
	}
	for _, job := range h.persistence.jobs {
		if job.Status != "running" {
			t.Fatalf("model service job status = %q, want the refused job left running", job.Status)
		}
	}
}

// TestWorkerReceiptCarriesTheServedTaskFacts is the positive half of the wiring.
// The reader serves values unrelated to anything the Worker could derive, and
// those exact bytes have to appear in the signed receipt, be covered by the
// service signature and be what is relayed. It is the check that would fail if
// the receipt path ever went back to deriving either fact locally.
func TestWorkerReceiptCarriesTheServedTaskFacts(t *testing.T) {
	h := newHarness(t)
	event := finalizedTask()
	// The served digest is of parameters only this test's order carries, so it
	// cannot be the harness default; the generation_params artifact must hash
	// to it.
	generation := workerTestGeneration()
	generation.Params.DecodingParams.Seed = 0x6c6c
	generationDigest, err := generation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	h.worker.cfg.GenerationReader = generationReaderFunc(func(context.Context, string, codec.Hash) (nodewire.GenerationContext, error) {
		return generation.Clone(), nil
	})
	served := taskfacts.Facts{
		TaskID: event.TaskID,
		TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
			AcceptedTaskHash:       chainclient.ProtoBytes32(bytes.Repeat([]byte{0x5b}, 32)),
			GenerationParamsDigest: chainclient.ProtoBytes32(generationDigest[:]),
		},
	}
	h.taskFacts.override = func(string) (taskfacts.Facts, error) { return served, nil }

	receipt := h.seedPreparedOutput(t, event)
	if _, err := h.worker.HandleAssignmentFinalized(context.Background(), event); err != nil {
		t.Fatalf("HandleAssignmentFinalized: %v", err)
	}
	relayed := h.taskData.relays[0].Receipt
	if relayed.TaskHash != served.AcceptedTaskHash.Hex() {
		t.Fatalf("relayed task_hash = %q, want the served accepted_task_hash %q",
			relayed.TaskHash, served.AcceptedTaskHash.Hex())
	}
	if relayed.GenerationParamsDigest != served.GenerationParamsDigest.Hex() {
		t.Fatalf("relayed generation_params_digest = %q, want the served %q",
			relayed.GenerationParamsDigest, served.GenerationParamsDigest.Hex())
	}
	// order_digest is the substitution the frozen contract forbids, and the
	// served value is deliberately not it.
	if relayed.TaskHash == hex.EncodeToString(event.OrderDigest[:]) {
		t.Fatal("task_hash is the order digest, which commits the order envelope rather than canonical TaskOrderV1")
	}
	// The signature has to cover the served bytes: it must verify against the
	// relayed receipt's own frozen preimage, and moving either fact must move
	// that digest.
	digest, err := builderclient.InferReceiptSigningDigest(relayed)
	if err != nil {
		t.Fatalf("derive frozen digest of the relayed receipt: %v", err)
	}
	if h.signer.countDigest(digest) != 1 {
		t.Fatalf("the relayed receipt's own frozen digest %x was never the digest that was signed", digest)
	}
	if err := signer.VerifyDigestSignature(
		h.worker.cfg.SignerPubkey, digest, mustDecodeHex(t, relayed.ServiceSignature),
	); err != nil {
		t.Fatalf("relayed service_signature does not verify against the relayed body: %v", err)
	}
	if !reflect.DeepEqual(relayed, receipt) {
		t.Fatal("the relayed receipt is not the receipt that was checkpointed")
	}
	for name, mutate := range map[string]func(*builderclient.SignedInferReceipt){
		"task_hash":                func(r *builderclient.SignedInferReceipt) { r.TaskHash = strings.Repeat("5c", 32) },
		"generation_params_digest": func(r *builderclient.SignedInferReceipt) { r.GenerationParamsDigest = strings.Repeat("6d", 32) },
	} {
		mutated := relayed
		mutate(&mutated)
		mutatedDigest, err := builderclient.InferReceiptSigningDigest(mutated)
		if err != nil {
			t.Fatalf("derive frozen digest with mutated %s: %v", name, err)
		}
		if mutatedDigest == digest {
			t.Fatalf("the frozen receipt digest ignores %s, so the signature does not cover it", name)
		}
	}
}

// TestWorkerRefusesUnusableServedTaskFacts is the fail-closed half. Each case is
// a well-formed response the Worker must refuse, and the three reasons stay
// apart: a fetch that answered for another task, a view that did not carry the
// value, and a view that served 32 zero bytes. The last is the dangerous one -
// it is shape-valid all the way to a signature - and the frozen Hash32 has no
// absent encoding, so it is a claim about consensus state rather than a gap.
func TestWorkerRefusesUnusableServedTaskFacts(t *testing.T) {
	event := finalizedTask()
	other := canonicalTaskID("84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b", 8)
	zero := make(chainclient.ProtoBytes32, 32)
	for name, tc := range map[string]struct {
		facts    taskfacts.Facts
		contains string
	}{
		"answers for another task": {workerTestServedTaskFacts(other), "not the task"},
		"absent accepted_task_hash": {taskfacts.Facts{
			TaskID: event.TaskID,
			TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
				GenerationParamsDigest: workerTestServedTaskFacts(event.TaskID).GenerationParamsDigest,
			},
		}, "carries no accepted_task_hash"},
		"absent generation_params_digest": {taskfacts.Facts{
			TaskID: event.TaskID,
			TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
				AcceptedTaskHash: workerTestServedTaskFacts(event.TaskID).AcceptedTaskHash,
			},
		}, "carries no generation_params_digest"},
		"all-zero accepted_task_hash": {taskfacts.Facts{
			TaskID: event.TaskID,
			TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
				AcceptedTaskHash:       zero,
				GenerationParamsDigest: workerTestServedTaskFacts(event.TaskID).GenerationParamsDigest,
			},
		}, "all-zero accepted_task_hash"},
		"all-zero generation_params_digest": {taskfacts.Facts{
			TaskID: event.TaskID,
			TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
				AcceptedTaskHash:       workerTestServedTaskFacts(event.TaskID).AcceptedTaskHash,
				GenerationParamsDigest: zero,
			},
		}, "all-zero generation_params_digest"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.taskFacts.override = func(string) (taskfacts.Facts, error) { return tc.facts, nil }

			_, err := h.worker.HandleAssignmentFinalized(context.Background(), event)
			if err == nil || !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("HandleAssignmentFinalized error = %v, want a refusal saying %q", err, tc.contains)
			}
			// A well-formed answer that cannot be used is permanent: retrying the
			// same query gets the same bytes, so marking it retryable would spin.
			if builderclient.IsRetryable(err) {
				t.Fatalf("an unusable answer was reported as retryable: %v", err)
			}
			if len(h.taskData.relays) != 0 || len(h.persistence.receipts) != 0 {
				t.Fatalf("a refused fetch still produced work: relays=%d receipts=%d",
					len(h.taskData.relays), len(h.persistence.receipts))
			}
			if h.signer.countDigest(codec.Hash{}) != 0 || len(h.signer.digests) > 2 {
				t.Fatalf("signer saw %d digests, want the legacy and canonical receipt signatures", len(h.signer.digests))
			}
		})
	}
}

// TestWorkerPropagatesARetryableTaskFactsFetchFailure is the other side of the
// distinction: the read itself failing is transient, and the task runner retries
// it. Collapsing it into the fail-closed refusal above would abandon a task over
// a network blip.
func TestWorkerPropagatesARetryableTaskFactsFetchFailure(t *testing.T) {
	h := newHarness(t)
	h.taskFacts.override = func(string) (taskfacts.Facts, error) {
		return taskfacts.Facts{}, builderclient.Retryable(errors.New("keeper ABCI query timed out"))
	}

	_, err := h.worker.HandleAssignmentFinalized(context.Background(), finalizedTask())
	if err == nil || !builderclient.IsRetryable(err) {
		t.Fatalf("HandleAssignmentFinalized error = %v, want a retryable Keeper read failure", err)
	}
	if errors.Is(err, builderclient.ErrInferReceiptInputUnavailable) {
		t.Fatalf("a failed fetch was reported as a permanent input gap: %v", err)
	}
}

// TestWorkerWithoutATaskFactsReaderRefusesBeforeInference pins that a Worker
// built without the reader stops at the dependency check rather than running a
// model job it can never turn into a receipt.
func TestWorkerWithoutATaskFactsReaderRefusesBeforeInference(t *testing.T) {
	h := newHarness(t)
	h.worker.cfg.TaskFacts = nil

	_, err := h.worker.HandleAssignmentFinalized(context.Background(), finalizedTask())
	if err == nil || !strings.Contains(err.Error(), "Keeper task facts reader is required") {
		t.Fatalf("HandleAssignmentFinalized error = %v, want the missing-reader refusal", err)
	}
	if h.model.InferCalls != 0 {
		t.Fatalf("infer calls = %d, want none without the consensus read", h.model.InferCalls)
	}
}

// TestWorkerTaskFactsFailureModesAreDistinguishable is the operator-facing
// property at the Worker's own boundary. Four different faults reach the same
// callsite, and each sends a different person to a different place: nobody wired
// the reader, the configured Keeper cannot perform the read, the read failed, or
// the chain answered without the value. Collapsing any two of them means an
// operator debugging the wrong system.
//
// The "cannot perform the read" case is the error daemon.NewTaskFacts produces
// for a Keeper client that does not implement the capability; what is pinned
// here is that the Worker propagates it intact instead of flattening it into its
// own missing-reader wording.
func TestWorkerTaskFactsFailureModesAreDistinguishable(t *testing.T) {
	event := finalizedTask()
	capability := errors.New(
		"configured Keeper client daemon.heightOnlyKeeper cannot serve the frozen task.v1 Query/Task " +
			"and Query/TaskAssignment reads")
	transport := builderclient.Retryable(errors.New("dial tcp: connection refused"))

	run := func(t *testing.T, configure func(h harness)) error {
		t.Helper()
		h := newHarness(t)
		configure(h)
		_, err := h.worker.HandleAssignmentFinalized(context.Background(), event)
		if err == nil {
			t.Fatal("HandleAssignmentFinalized accepted a task whose consensus facts were never read")
		}
		return err
	}

	noReader := run(t, func(h harness) { h.worker.cfg.TaskFacts = nil })
	unsupported := run(t, func(h harness) {
		h.taskFacts.override = func(string) (taskfacts.Facts, error) { return taskfacts.Facts{}, capability }
	})
	failed := run(t, func(h harness) {
		h.taskFacts.override = func(string) (taskfacts.Facts, error) { return taskfacts.Facts{}, transport }
	})
	absent := run(t, func(h harness) {
		h.taskFacts.override = func(string) (taskfacts.Facts, error) {
			return taskfacts.Facts{
				TaskID: event.TaskID,
				TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
					GenerationParamsDigest: workerTestServedTaskFacts(event.TaskID).GenerationParamsDigest,
				},
			}, nil
		}
	})

	faults := map[string]struct {
		err       error
		contains  string
		retryable bool
	}{
		"no reader":   {noReader, "Keeper task facts reader is required", false},
		"unsupported": {unsupported, "cannot serve the frozen task.v1 Query/Task", false},
		"read failed": {failed, "dial tcp: connection refused", true},
		"absent fact": {absent, "carries no accepted_task_hash", false},
	}
	for name, fault := range faults {
		if !strings.Contains(fault.err.Error(), fault.contains) {
			t.Fatalf("the %s refusal = %q, want it to say %q", name, fault.err, fault.contains)
		}
		if builderclient.IsRetryable(fault.err) != fault.retryable {
			t.Fatalf("the %s refusal retryable = %t, want %t: %v",
				name, !fault.retryable, fault.retryable, fault.err)
		}
	}
	for a, faultA := range faults {
		for b, faultB := range faults {
			if a < b && faultA.err.Error() == faultB.err.Error() {
				t.Fatalf("the %s and %s faults are one indistinguishable message: %v", a, b, faultA.err)
			}
		}
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode %q: %v", value, err)
	}
	return raw
}

// testEnvelopeSigner is a deterministic envelope signer: it returns a fixed signature
// of a legal length (64 bytes) for cases that do not check signature content. A
// fake-inference node signs envelopes too, see encodeNexusMessage.
func testEnvelopeSigner() builderclient.BusEnvelopeSigner {
	return builderclient.BusEnvelopeSignerFunc(func(envelope builderclient.BusEnvelope) ([]byte, error) {
		low := codec.HashWithDomain("TEST_WORKER_ENVELOPE_V1", []byte(envelope.MessageID))
		high := codec.HashWithDomain("TEST_WORKER_ENVELOPE_V1", low[:])
		return append(append(make([]byte, 0, 64), low[:]...), high[:]...), nil
	})
}
