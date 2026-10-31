package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/policy"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/taskdataauth"
	"github.com/TrueOpen/cortex/internal/worker"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	bustaskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

func TestInferReceiptCheckpointSurvivesReopenBeforeRunOnceCompletes(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "cortex.kv")
	db, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	evRoot := t.TempDir()
	evidenceStore, err := evidence.NewStore(evRoot, db)
	if err != nil {
		t.Fatal(err)
	}
	taskHash := codec.HashBytes([]byte("receipt-crash"))
	task := store.InferTask{TaskID: "task-receipt", SessionID: "session-receipt", Stage: "queued"}
	seedInferTask(ctx, t, db, taskHash, task)
	runner := NewTaskRunner(TaskRunnerConfig{Store: db})
	receipt := worker.InferReceiptCheckpoint{TaskID: task.TaskID, MaterialDigest: "deadbeef", Payload: []byte(`{"receipt":"byte-identical-signed-material"}`), CreatedAt: time.Unix(123, 0).UTC()}
	persistence := &evidenceWorkerPersistence{taskHash: taskHash, task: &task, evidence: evidenceStore, persist: runner.persistInferCheckpoint}
	if err := persistence.CheckpointInferReceipt(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	// This simulates the process ending immediately in the checkpoint callback:
	// RunOnce never gets a completion result to merge back into the document.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	evRec, err := layout.GetEvidenceRecord(ctx, reopened, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatalf("evidence record missing after reopen: %v", err)
	}
	found := false
	for _, a := range evRec.Artifacts {
		if a.Kind == layout.ArtifactInferReceipt {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("receipt artifact ref missing after reopen: %#v", evRec.Artifacts)
	}
	reopenedEvidence, err := evidence.NewStore(evRoot, reopened)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := reopenedEvidence.ReadTaskKind(ctx, taskHash, "worker-infer-receipt:deadbeef")
	if err != nil {
		t.Fatalf("receipt payload missing from evidence: %v", err)
	}
	if !bytes.Equal(payload, receipt.Payload) {
		t.Fatalf("reopened receipt = %q, want byte-identical %q", payload, receipt.Payload)
	}
}

// openVerifyFixture is one Verifier-side world: a Keeper snapshot that is
// the sole authority on what the task committed, and a runner wired to raise a
// Verifier hand off it. Tests vary only the OPEN_VERIFY call.
type openVerifyFixture struct {
	runner    *TaskRunner
	builder   *outputAdmissionBuilder
	sender    *recordingFrameSender
	confirmer *recordingOutputConfirmer
	trace     *collectTrace
	snapshot  chainclient.TaskSnapshot
	pkg       builderclient.OutputPackage
	sessionID string
	taskID    string
}

func newOpenVerifyFixture(t *testing.T) *openVerifyFixture {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sessionID := "5c7d7453ba8e8ae99fa1fd30a5076eaa9cc371ea5595f3c059ff2e96ad8a1803"
	orderSequence := uint64(1)
	taskID := identity.TaskIDString(sessionID, orderSequence)
	acceptedTaskHash := codec.HashBytes([]byte("accepted-task-hash"))
	orderDigest := codec.HashWithDomain("TEST_ORDER_ENVELOPE", []byte("order"))
	outputHash := codec.HashBytes([]byte("output"))
	pkg := builderclient.OutputPackage{TaskID: taskID, OutputRef: "cid://output", TokenIDsRef: "cid://trace", PositionValuesRef: "cid://checkpoint", OutputHash: outputHash}
	pkg.PackageHash = codec.HashWithDomain("TRUEOPEN_OUTPUT_PACKAGE_V1", []byte(taskID), []byte(pkg.OutputRef), []byte(pkg.TokenIDsRef), []byte(pkg.PositionValuesRef), outputHash[:])
	nonzero := func(label string) chainclient.HexHash { return chainclient.HexHash(codec.HashBytes([]byte(label))) }
	seedInferTask(ctx, t, db, acceptedTaskHash, store.InferTask{TaskID: taskID, SessionID: sessionID, OrderSequence: orderSequence, OrderDigest: orderDigest, ModelID: testModelID, ProfileVersion: 1, Capability: modelservice.CapabilityLLMTextV1, Stage: "queued"})
	if err := layout.MergeVerify(ctx, db, layout.StoredHash(acceptedTaskHash), layout.VerifyRecord{TaskID: taskID, Stage: layout.StageQueued, VerifyRound: 1}); err != nil {
		t.Fatal(err)
	}
	snapshot := chainclient.TaskSnapshot{
		Status: "VERIFY_OPEN",
		Assignment: chainclient.AssignmentSnapshot{
			SessionID: sessionID, TaskID: taskID, OrderSequence: chainclient.NewUint64String(orderSequence),
			SelectedWorker: "worker-1", InferDeadlineHeight: chainclient.NewUint64String(100), WinnerConfirmHeight: chainclient.NewUint64String(12),
			ModelID: testModelID, ProfileVersion: chainclient.NewProfileVersion(1), AcceptedOrderPayloadHash: nonzero("payload"),
			TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{AcceptedTaskHash: chainclient.ProtoBytes32(acceptedTaskHash[:])},
		},
		InferReceipt: chainclient.InferReceiptSnapshot{
			SessionID: sessionID, TaskID: taskID, WinnerWorker: "worker-1", InferReceiptCommitHash: nonzero("commit"), InferReceiptHash: nonzero("receipt"),
			OutputHash: chainclient.HexHash(outputHash), OutputSizeBytes: chainclient.NewUint64String(4096),
			TraceCommitRoot: nonzero("trace"), CheckpointCommitRoot: nonzero("checkpoint"), BatchLogRoot: nonzero("batch"),
			TokenCount: chainclient.NewUint64String(1), WorkUnit: chainclient.NewUint64String(1), WorkerSignature: "signature",
			CanonicalOutputPackageHash: chainclient.HexHash(pkg.PackageHash), OutputDeliveryCommitment: nonzero("delivery"), ReceiptMode: "DIRECT", ReceiptHeight: chainclient.NewUint64String(20),
		},
	}
	builder := &outputAdmissionBuilder{pkg: pkg}
	sender := &recordingFrameSender{}
	confirmer := &recordingOutputConfirmer{pkg: pkg}
	trace := &collectTrace{}
	eligibility := staticEligibility{verifierInput: policy.VerifierPrecheckInput{
		ChainSynced: true, SupportState: policy.SupportActive, SupportLastConfirmedHeight: 0, SupportFreshnessWindow: 20,
		SupportedProfiles: []string{modelservice.CapabilityLLMTextV1}, AvailableSlots: 1,
	}}
	runner := NewTaskRunner(TaskRunnerConfig{
		Store: db, Builder: builder, VerifierSender: sender, LocalVerifierAddress: "verifier-1", ChainID: "chain", FakeOutput: true,
		OutputConfirmer: confirmer, Trace: trace.trace(),
		VerifierMemberReader: openVerifierWindow{snapshot: chainclient.VerifierCandidateMemberSnapshot{
			CandidateMemberRefSnapshot: chainclient.CandidateMemberRefSnapshot{
				CandidatePoolSnapshotID: chainclient.ProtoBytes32(bytes.Repeat([]byte{0x11}, 32)),
				Slot:                    1, SlotVersion: 1, OperatorAddress: "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe",
			},
			InferReceiptHash: chainclient.ProtoBytes32(snapshot.InferReceipt.InferReceiptHash[:]), ExpiryHeight: 40,
		}},
		TaskReader: staticKeeperTaskReader{snapshot: snapshot}, HandraiseEligibility: eligibility,
		// admitOpenVerify reads this node's own current ServiceKey binding for
		// the verifier handraise's service_authorization_nonce (interface-and-topic-list.md
		// §5.2 field 7).
		TaskDataAuth:        taskRunnerTaskDataAuth(t),
		ProfileCapabilities: map[string]string{testModelID + "\x001": modelservice.CapabilityLLMTextV1},
		ChainStatus:         fixedChainStatus{height: 10, chainID: "chain"},
		SignerAddress:       "verifier-service", SignerKeyRef: "key", Signer: signer.DigestSignerFunc(func(context.Context, signer.DigestRequest) ([]byte, error) { return bytes.Repeat([]byte{1}, 64), nil }),
	})
	return &openVerifyFixture{runner: runner, builder: builder, sender: sender, confirmer: confirmer, trace: trace, snapshot: snapshot, pkg: pkg, sessionID: sessionID, taskID: taskID}
}

func (f *openVerifyFixture) assertHandraised(t *testing.T) {
	t.Helper()
	if len(f.sender.handraises) != 1 {
		t.Fatalf("sent = %#v, want one verifier handraise without an active infer document", f.sender.handraises)
	}
	// data-plane-and-evidence-transfer.md §6: a candidate's metadata comes off the control message
	// and the Keeper snapshot, never off the data plane. So a handraise must be
	// signed with ZERO task-data calls -- nexus authorises the plane for a
	// selected Worker, a selected Verifier or the original User, and a candidate
	// asking anyway is refused NEXUS_DATA_UNAUTHORIZED, which is how no handraise
	// at all ever got sent.
	if len(f.confirmer.received) != 0 {
		t.Fatalf("task-data plane calls before the handraise = %#v, want none from a candidate", f.confirmer.received)
	}
	// And the output hash it commits to is the chain's, not the frame's: that is
	// what the deleted metadata round trip used to be asked to prove.
	handraise := f.sender.handraises[0]
	if !bytes.Equal(handraise.GetOutputHash(), f.snapshot.InferReceipt.OutputHash[:]) {
		t.Fatalf("handraise output_hash = %x, want the Keeper infer receipt's %x",
			handraise.GetOutputHash(), f.snapshot.InferReceipt.OutputHash)
	}
}

// recordingFrameSender stands in for the per-Builder stream the Verifier sends
// its handraise on.
type recordingFrameSender struct {
	handraises []*bustaskv1.VerifierHandraiseV1
}

func (s *recordingFrameSender) SendVerifierHandraise(_ context.Context, h *bustaskv1.VerifierHandraiseV1) error {
	s.handraises = append(s.handraises, h)
	return nil
}

// openVerifierWindow is a verifier candidate window that is open for this node.
type openVerifierWindow struct {
	snapshot chainclient.VerifierCandidateMemberSnapshot
}

func (w openVerifierWindow) VerifierCandidateMember(context.Context, string, uint32, string) (chainclient.VerifierCandidateMemberSnapshot, error) {
	return w.snapshot, nil
}

func (w openVerifierWindow) FrozenVerifierWindowMember(context.Context, string, uint32, string) (chainclient.VerifierCandidateMemberSnapshot, error) {
	return w.snapshot, nil
}

// Two OPEN_VERIFY calls for the same task produce one verifier handraise (and one output confirmation) because the
// durable verify-candidate claim suppresses the duplicate.
func TestOpenVerifyDuplicateSuppressed(t *testing.T) {
	fixture := newOpenVerifyFixture(t)
	hint1 := fixture.openVerifyCall()
	if err := fixture.deliverOpenVerify(t, hint1); err != nil {
		t.Fatal(err)
	}
	fixture.assertHandraised(t)

	hint2 := fixture.openVerifyCall()
	if err := fixture.deliverOpenVerify(t, hint2); err != nil {
		t.Fatalf("second OPEN_VERIFY: %v", err)
	}
	// Still only one handraise.
	if len(fixture.sender.handraises) != 1 {
		t.Fatalf("published = %d, want 1", len(fixture.sender.handraises))
	}
}

// The claim is taken before the Keeper read, and the chain can legitimately be
// behind the hint - TestOpenVerifyAheadOfTheKeeperReceiptIsRetryable pins
// exactly that. So a claim left by a failed attempt must not suppress the
// redelivery, or the "not yet" silently becomes "never": no confirmation and no
// handraise, for good.
func TestOpenVerifyRetriesAfterAClaimedButFailedAttempt(t *testing.T) {
	fixture := newOpenVerifyFixture(t)
	behind := fixture.snapshot
	behind.InferReceipt = chainclient.InferReceiptSnapshot{}
	fixture.runner.cfg.TaskReader = staticKeeperTaskReader{snapshot: behind}

	first := fixture.openVerifyCall()
	if err := fixture.deliverOpenVerify(t, first); err == nil || !builderclient.IsRetryable(err) {
		t.Fatalf("first delivery error = %v, want a retryable not-yet", err)
	}
	if len(fixture.sender.handraises) != 0 {
		t.Fatalf("published=%#v, want no handraise while the chain is behind", fixture.sender.handraises)
	}

	// The chain catches up and the frame is redelivered.
	fixture.runner.cfg.TaskReader = staticKeeperTaskReader{snapshot: fixture.snapshot}
	second := fixture.openVerifyCall()
	if err := fixture.deliverOpenVerify(t, second); err != nil {
		t.Fatalf("redelivery after the chain caught up: %v", err)
	}
	fixture.assertHandraised(t)
}

// The output hash is read only from the Keeper receipt (§4.4 removed it from
// the hint payload), and the frame has no say either way - which is the point:
// what the chain commits is not something a peer can supply, contradict, or
// withhold. It is also, per cortex-detailed-design.md:1032, the ONLY output content
// commitment there is; a frame that disagrees with the chain about it is
// refused rather than reconciled.
func TestOpenVerifyTakesTheOutputHashFromKeeperNotTheFrame(t *testing.T) {
	fixture := newOpenVerifyFixture(t)

	if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err != nil {
		t.Fatalf("OpenVerify was refused: %v", err)
	}
	fixture.assertHandraised(t)
}

// The hint may be dropped, but it may not lie. A frame whose commitments
// contradict the chain is a permanent refusal, not a retry.
func TestOpenVerifyContradictingTheKeeperSnapshotIsStillRefused(t *testing.T) {
	other := codec.HashBytes([]byte("other"))
	for _, testCase := range []struct {
		name   string
		mutate func(*nexusv1.OpenVerifyV1)
	}{
		{"output hash", func(m *nexusv1.OpenVerifyV1) { m.OutputHash = other[:] }},
		{"sender is not the Keeper winner", func(m *nexusv1.OpenVerifyV1) { m.WorkerOperatorAddress = "worker-2" }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newOpenVerifyFixture(t)
			message := fixture.openVerifyCall()
			testCase.mutate(message)

			err := fixture.deliverOpenVerify(t, message)
			if err == nil {
				t.Fatal("a hint contradicting the Keeper snapshot was admitted")
			}
			if builderclient.IsRetryable(err) {
				t.Fatalf("admitOpenVerify() error = %v, want a permanent refusal", err)
			}
			if len(fixture.confirmer.received) != 0 || len(fixture.sender.handraises) != 0 {
				t.Fatalf("confirmations = %#v published = %#v, want neither", fixture.confirmer.received, fixture.sender.handraises)
			}
		})
	}
}

// A call can outrun the chain. Before Keeper has the infer receipt there is no
// authority to read the commitments from, and that has to be a retryable
// "not yet" rather than a permanent refusal that strands the task.
func TestOpenVerifyAheadOfTheKeeperReceiptIsRetryable(t *testing.T) {
	fixture := newOpenVerifyFixture(t)
	snapshot := fixture.snapshot
	snapshot.InferReceipt = chainclient.InferReceiptSnapshot{}
	fixture.runner.cfg.TaskReader = staticKeeperTaskReader{snapshot: snapshot}

	err := fixture.deliverOpenVerify(t, fixture.openVerifyCall())
	if err == nil || !builderclient.IsRetryable(err) {
		t.Fatalf("admitOpenVerify() error = %v, want a retryable not-yet", err)
	}
}

// A node with no frame sender cannot raise a hand however often the call is
// redelivered, so that is a permanent refusal, not a retry loop.
func TestOpenVerifyWithoutAFrameSenderIsPermanent(t *testing.T) {
	fixture := newOpenVerifyFixture(t)
	fixture.runner.cfg.VerifierSender = nil

	err := fixture.deliverOpenVerify(t, fixture.openVerifyCall())
	if err == nil || !builderclient.IsPermanent(err) || !strings.Contains(err.Error(), "verifier frame sender is not configured") {
		t.Fatalf("admitOpenVerify() error = %v, want a permanent missing-sender refusal", err)
	}
}

// Verifiability is decided by OPEN_VERIFY plus the Keeper snapshot, so a
// Verifier needs no other frame to get the responsibility and confirm the
// output. Both halves run production code: the chain admits the task, and the
// real Nexus confirmer resolves the package from the chain-committed canonical
// package hash with no locator anywhere in the path.
func TestVerifyPathCompletesFromOpenVerifyAlone(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sessionID, taskID := strings.Repeat("11", 32), outputTestTaskID
	pkg := canonicalOutputPackage(t, sessionID, taskID, outputTestOutputRef)
	metadata, receipt := outputConfirmationMaterial(t, outputTestChainID, outputTestWorker, pkg)
	nonzero := func(label string) chainclient.HexHash { return chainclient.HexHash(codec.HashBytes([]byte(label))) }
	snapshot := chainclient.TaskSnapshot{
		Status: "VERIFY_READY",
		Assignment: chainclient.AssignmentSnapshot{
			SessionID: sessionID, TaskID: taskID, OrderSequence: chainclient.NewUint64String(1), OrderDigest: nonzero("order"),
			SelectedWorker: outputTestWorker, InferDeadlineHeight: chainclient.NewUint64String(100),
			ModelID: testModelID, ProfileVersion: chainclient.NewProfileVersion(1), AcceptedOrderPayloadHash: nonzero("payload"),
			BuilderOperatorAddress: inputTestBuilder,
		},
		InferReceipt: receipt,
		VerifierAssignment: chainclient.VerifierAssignmentSnapshot{VerifyRound: chainclient.NewUint64String(1),
			SessionID: sessionID, TaskID: taskID, OpenVerifyHeight: chainclient.NewUint64String(22),
			FormalVerifierSet: chainclient.CSVStrings{"verifier-1"}, SampleSeedReadyHeight: chainclient.NewUint64String(25),
			VerificationSampleSeed: nonzero("seed"), CommitDeadlineHeight: chainclient.NewUint64String(30),
			WorkerRevealDeadlineHeight: chainclient.NewUint64String(40), RevealDeadlineHeight: chainclient.NewUint64String(50),
			VerifyDeadlineHeight: chainclient.NewUint64String(60), SampleSeedStatus: "READY",
			VerifierCandidateWindowHash: nonzero("window"), ParamVersion: "v1",
			SampleRandomnessAggregationBlocks: chainclient.NewUint64String(1), WorkerRevealWindowBlocks: chainclient.NewUint64String(1),
			RevealWindowBlocks: chainclient.NewUint64String(1), Stage3BuilderGraceBlocks: chainclient.NewUint64String(1),
		},
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("fixture snapshot is not a Keeper snapshot: %v", err)
	}
	taskHash := codec.HashBytes([]byte("open-verify-only"))
	runner := NewTaskRunner(TaskRunnerConfig{
		Store: db, LocalVerifierAddress: "verifier-1",
		ProfileCapabilities: map[string]string{testModelID + "\x001": modelservice.CapabilityLLMTextV1},
	})
	if err := runner.ApplyReconcilerEffects(ctx, []ReconcilerEffect{{
		Type: ReconcilerEffectVerifyReady, TaskHash: taskHash, TaskID: taskID, Snapshot: snapshot,
	}}); err != nil {
		t.Fatal(err)
	}
	verifyRecord, err := layout.GetVerifyRecord(ctx, db, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatal(err)
	}
	if verifyRecord.Stage != layout.StageQueued {
		t.Fatalf("verify record = %#v, want the task admitted from OPEN_VERIFY alone", verifyRecord)
	}
	// Build a minimal legacy VerifyTask for the commitment helper until the
	// helper is migrated to the new layout.
	task := store.VerifyTask{
		TaskID: taskID, SessionID: sessionID, OrderSequence: 1,
		ModelID: testModelID, ProfileVersion: 1, Stage: "queued",
		VerifyRound:            1,
		BuilderOperatorAddress: snapshot.Assignment.BuilderOperatorAddress,
		WorkerAddress:          snapshot.Assignment.SelectedWorker,
		OutputDigest:           codec.Hash(snapshot.InferReceipt.OutputHash),
		PackageDigest:          codec.Hash(snapshot.InferReceipt.CanonicalOutputPackageHash),
		ReceiptDigest:          codec.Hash(snapshot.InferReceipt.InferReceiptHash),
		KeeperReceiptJSON:      func() []byte { b, _ := json.Marshal(snapshot.InferReceipt); return b }(),
	}

	commitments, err := verifyTaskCommitments(task)
	if err != nil {
		t.Fatal(err)
	}
	commitments.TaskHash = pkg.ReceiptHash
	packages := outputPackagesFor(pkg)
	confirmed, err := newOutputConfirmer(t, outputTestChainID, &inputTaskDataClient{metadata: metadata}, packages).
		ConfirmOutput(ctx, commitments)
	if err != nil {
		t.Fatalf("ConfirmOutput for a task admitted from OPEN_VERIFY alone: %v", err)
	}
	if confirmed.PackageHash != pkg.PackageHash || confirmed.OutputHash != pkg.OutputHash {
		t.Fatalf("confirmed package = %#v, want the chain-committed output", confirmed)
	}
	wantRef := builderclient.FixtureOutputPackageRef(codec.Hash(snapshot.InferReceipt.CanonicalOutputPackageHash))
	if len(packages.requested) != 1 || packages.requested[0] != wantRef {
		t.Fatalf("package references requested = %#v, want exactly [%q] derived from the chain", packages.requested, wantRef)
	}
}

// Deriving the package address from the chain does not conjure a package body.
// A node with no shared package store -- every real model transport today --
// still has no way to read the output, and must say so instead of quietly
// verifying nothing.
func TestVerifyWithoutAPackageStoreStillFailsClosed(t *testing.T) {
	executor := newProductionVerifyExecutor(TaskRunnerConfig{LocalVerifierAddress: "verifier-1"})
	task := store.VerifyTask{TaskID: "task-1", SessionID: "session-1", Stage: "queued"}

	updated, terminal, err := executor.RunVerify(context.Background(), codec.HashBytes([]byte("no-store")), task)
	if err == nil || !strings.Contains(err.Error(), "verify requires a Nexus output confirmer") {
		t.Fatalf("RunVerify() error = %v, want the actionable task-data-plane refusal", err)
	}
	if terminal || updated.Stage == "succeeded" {
		t.Fatalf("RunVerify() = %#v terminal=%v, want the responsibility left unfinished", updated, terminal)
	}
}

// verifierControlFixture is one Verifier-side world: a Keeper snapshot that is
// the sole authority on the task's control fields, and a verify record already
// admitted from it, so a test can drive recordVerifierControl against both.
type verifierControlFixture struct {
	runner     *TaskRunner
	db         *store.Store
	taskHash   codec.Hash
	seed       codec.Hash
	outputHash codec.Hash
}

func newVerifierControlFixture(t *testing.T) verifierControlFixture {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	taskHash := codec.HashBytes([]byte("verifier-control"))
	orderDigest := codec.HashBytes([]byte("control-order"))
	outputHash := codec.HashBytes([]byte("control-output"))
	packageHash := codec.HashBytes([]byte("control-package"))
	seed := codec.HashBytes([]byte("keeper-seed"))
	nonzero := func(label string) chainclient.HexHash { return chainclient.HexHash(codec.HashBytes([]byte(label))) }
	snapshot := chainclient.TaskSnapshot{
		Status:             "VERIFY_READY",
		Assignment:         chainclient.AssignmentSnapshot{SessionID: "session-1", TaskID: "abababababababababababababababababababababababababababababababab", OrderSequence: chainclient.NewUint64String(1), OrderDigest: chainclient.HexHash(orderDigest), SelectedWorker: "worker-1", InferDeadlineHeight: chainclient.NewUint64String(20), ModelID: testModelID, ProfileVersion: chainclient.NewProfileVersion(1), AcceptedOrderPayloadHash: nonzero("payload")},
		InferReceipt:       chainclient.InferReceiptSnapshot{SessionID: "session-1", TaskID: "abababababababababababababababababababababababababababababababab", WinnerWorker: "worker-1", InferReceiptCommitHash: nonzero("commit"), InferReceiptHash: nonzero("receipt"), OutputHash: chainclient.HexHash(outputHash), TraceCommitRoot: nonzero("trace"), CheckpointCommitRoot: nonzero("checkpoint"), BatchLogRoot: nonzero("batch"), TokenCount: chainclient.NewUint64String(1), WorkUnit: chainclient.NewUint64String(1), WorkerSignature: "signature", CanonicalOutputPackageHash: chainclient.HexHash(packageHash), OutputDeliveryCommitment: nonzero("delivery"), ReceiptMode: "DIRECT", ReceiptHeight: chainclient.NewUint64String(21)},
		VerifierAssignment: chainclient.VerifierAssignmentSnapshot{VerifyRound: chainclient.NewUint64String(1), SessionID: "session-1", TaskID: "abababababababababababababababababababababababababababababababab", OpenVerifyHeight: chainclient.NewUint64String(22), FormalVerifierSet: chainclient.CSVStrings{"verifier-1"}, SampleSeedReadyHeight: chainclient.NewUint64String(25), VerificationSampleSeed: chainclient.HexHash(seed), CommitDeadlineHeight: chainclient.NewUint64String(30), WorkerRevealDeadlineHeight: chainclient.NewUint64String(40), RevealDeadlineHeight: chainclient.NewUint64String(50), VerifyDeadlineHeight: chainclient.NewUint64String(60), SampleSeedStatus: "READY", VerifierCandidateWindowHash: nonzero("candidate-window"), ParamVersion: "v1", SampleRandomnessAggregationBlocks: chainclient.NewUint64String(1), WorkerRevealWindowBlocks: chainclient.NewUint64String(1), RevealWindowBlocks: chainclient.NewUint64String(1), Stage3BuilderGraceBlocks: chainclient.NewUint64String(1)},
	}
	task := store.VerifyTask{TaskID: "abababababababababababababababababababababababababababababababab", SessionID: "session-1", OrderSequence: 1, ModelID: testModelID, ProfileVersion: 1, WorkerAddress: "worker-1", OrderDigest: orderDigest, OutputDigest: outputHash, PackageDigest: packageHash, VerifyRound: 1, OpenVerifyHeight: 22, CurrentHeight: 25, CommitDeadlineHeight: 30, WorkerRevealDeadlineHeight: 40, RevealDeadlineHeight: 50, DeadlineHeight: 60, AssignedVerifiers: []string{"verifier-1"}, VerificationSampleSeed: seed}
	seedVerifyTask(ctx, t, db, taskHash, task)
	return verifierControlFixture{
		// The fixture node is one of the verifiers the snapshot's formal set names:
		// recordVerifierAssignment is only ever reached with a Verifier address
		// configured, and a node the announcement does not name acknowledges the
		// frame instead of judging its fields.
		runner:     NewTaskRunner(TaskRunnerConfig{Store: db, LocalVerifierAddress: "verifier-1", TaskReader: staticKeeperTaskReader{snapshot: snapshot}}),
		db:         db,
		taskHash:   taskHash,
		seed:       seed,
		outputHash: outputHash,
	}
}

// keeperVerifierAssignment is the notify a Builder sends when it agrees with the
// chain: every field equals the Keeper snapshot the fixture serves.
func (f verifierControlFixture) keeperVerifierAssignment() *nexusv1.VerifierAssignmentNotifyV1 {
	taskID, _ := hex.DecodeString("abababababababababababababababababababababababababababababababab")
	return &nexusv1.VerifierAssignmentNotifyV1{
		TaskId: taskID, TaskHash: bytes.Repeat([]byte{0x5a}, 32), VerifyRound: 1,
		Verifiers:        []*bustaskv1.SelectedVerifierV1{{OperatorAddress: "verifier-1"}},
		OutputHash:       append([]byte(nil), f.outputHash[:]...),
		OpenVerifyHeight: 22, CommitDeadlineHeight: 30, RevealDeadlineHeight: 50, VerifyDeadlineHeight: 60,
	}
}

// A VERIFIER_ASSIGNMENT_NOTIFY is a Builder's report of what the chain decided,
// never an authority over it. A field that disagrees with the Keeper snapshot is
// refused outright rather than written through, and the refusal leaves the
// record exactly as the chain established it.
func TestVerifierAssignmentRefusesFieldsThatDisagreeWithTheKeeperSnapshot(t *testing.T) {
	ctx := context.Background()
	fixture := newVerifierControlFixture(t)
	forged := fixture.keeperVerifierAssignment()
	forged.VerifyDeadlineHeight = 61

	if err := fixture.runner.recordVerifierAssignment(ctx, forged); err == nil {
		t.Fatal("a verify deadline that contradicts Keeper was accepted")
	}
	rec, err := layout.GetVerifyRecord(ctx, fixture.db, layout.StoredHash(fixture.taskHash))
	if err != nil {
		t.Fatal(err)
	}
	tr, err := layout.GetTaskRecord(ctx, fixture.db, layout.StoredHash(fixture.taskHash))
	if err != nil {
		t.Fatal(err)
	}
	if rec.DeadlineHeight != 60 || rec.WorkerRevealDeadlineHeight != 40 {
		t.Fatalf("Nexus control fields overwrote Keeper state: %#v", rec)
	}
	// A refused frame writes nothing at all, including the BuilderSet reference
	// it carried: an envelope whose body was rejected has not established that
	// this task belongs to that group.
	if tr.TaskBuilderSetID != "" || len(tr.TaskBuilderSetHash) != 0 {
		t.Fatalf("refused frame stored a BuilderSet reference %q/%x", tr.TaskBuilderSetID, tr.TaskBuilderSetHash)
	}
}

func TestTaskRunnerAppliesKeeperRetentionTerminalAndChallengeEffectsToEvidence(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	taskHash := codec.HashBytes([]byte("retained-task"))
	runner := NewTaskRunner(TaskRunnerConfig{Store: db})
	effects := []ReconcilerEffect{
		{TaskHash: taskHash, TaskID: "retained", Type: ReconcilerEffectEvidenceRetention, FinalityHeight: 100, Event: chainclient.KeeperEvent{Type: chainclient.KeeperEventSettlementFinalityUpdated}},
		{TaskHash: taskHash, TaskID: "retained", Type: ReconcilerEffectEvidenceRetention, CleanupHeight: 140, Event: chainclient.KeeperEvent{Type: chainclient.KeeperEventEvidenceCleanupDue}},
		{TaskHash: taskHash, TaskID: "retained", Type: ReconcilerEffectChallengeOpened, Event: chainclient.KeeperEvent{ChallengeID: "challenge-1", Height: 1}},
		{TaskHash: taskHash, TaskID: "retained", Type: ReconcilerEffectTaskTerminal},
	}
	if err := runner.ApplyReconcilerEffects(ctx, effects); err != nil {
		t.Fatal(err)
	}
	metadata, err := layout.GetEvidenceRecord(ctx, db, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatalf("Evidence: %v", err)
	}
	if metadata.FinalityHeight != 100 || metadata.CleanupHeight != 140 || !metadata.TerminalOrSettled {
		t.Fatalf("evidence metadata = %#v, want retention/terminal/open challenge effects", metadata)
	}
	challenge, err := layout.GetChallengeLifecycle(ctx, db, layout.StoredHash(taskHash), "challenge-1")
	if err != nil || !challenge.Open {
		t.Fatalf("challenge lifecycle = (%#v, %v), want open", challenge, err)
	}
	if err := runner.ApplyReconcilerEffects(ctx, []ReconcilerEffect{{TaskHash: taskHash, TaskID: "retained", Type: ReconcilerEffectChallengeClosed, Event: chainclient.KeeperEvent{ChallengeID: "challenge-1", Height: 2}}}); err != nil {
		t.Fatal(err)
	}
	challenge, err = layout.GetChallengeLifecycle(ctx, db, layout.StoredHash(taskHash), "challenge-1")
	if err != nil || challenge.Open {
		t.Fatalf("closed challenge metadata = (%#v, %v)", challenge, err)
	}
}

func TestRunOnceRestoresIndependentActiveDocuments(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "cortex.kv")
	db, _ := store.Open(ctx, path)
	inferHash, verifyHash := codec.HashBytes([]byte("infer")), codec.HashBytes([]byte("verify"))
	seedInferTask(ctx, t, db, inferHash, store.InferTask{TaskID: "infer"})
	seedVerifyTask(ctx, t, db, verifyHash, store.VerifyTask{TaskID: "verify"})
	r := NewTaskRunner(TaskRunnerConfig{Store: db})
	if err := r.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	infer, verify := r.ActiveTasks()
	if infer[inferHash].TaskID != "infer" || verify[verifyHash].TaskID != "verify" {
		t.Fatalf("infer=%#v verify=%#v", infer, verify)
	}
}

func TestRunOnceCheckpointsActiveTasksAndRemovesTerminalEntries(t *testing.T) {
	ctx := context.Background()
	db, _ := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	t.Cleanup(func() { _ = db.Close() })
	inferHash, verifyHash := codec.HashBytes([]byte("infer-terminal")), codec.HashBytes([]byte("verify-active"))
	seedInferTask(ctx, t, db, inferHash, store.InferTask{TaskID: "infer", Stage: "queued"})
	seedVerifyTask(ctx, t, db, verifyHash, store.VerifyTask{TaskID: "verify", Stage: "queued"})
	r := NewTaskRunner(TaskRunnerConfig{Store: db, InferExecutor: inferExecutorFunc(func(context.Context, codec.Hash, store.InferTask) (store.InferTask, bool, error) {
		return store.InferTask{}, true, nil
	}), VerifyExecutor: verifyExecutorFunc(func(_ context.Context, _ codec.Hash, task store.VerifyTask) (store.VerifyTask, bool, error) {
		task.Stage = "succeeded"
		return task, false, nil
	})})
	if err := r.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	inferRec, err := layout.GetInferRecord(ctx, db, layout.StoredHash(inferHash))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if inferRec.TaskID != "" {
		t.Fatalf("terminal infer task survived: %#v", inferRec)
	}
	verifyRec, err := layout.GetVerifyRecord(ctx, db, layout.StoredHash(verifyHash))
	if err != nil {
		t.Fatal(err)
	}
	if verifyRec.Stage != layout.StageSucceeded {
		t.Fatalf("verify checkpoint=%#v", verifyRec)
	}
}

func TestRunOnceHonorsRetryDeadlineAttemptsConcurrencyAndDoesNotHoldManagerLock(t *testing.T) {
	ctx := context.Background()
	db, _ := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	t.Cleanup(func() { _ = db.Close() })
	blockedHash, delayedHash, expiredHash, exhaustedHash := codec.HashBytes([]byte("blocked")), codec.HashBytes([]byte("delayed")), codec.HashBytes([]byte("expired")), codec.HashBytes([]byte("exhausted"))
	seedInferTask(ctx, t, db, blockedHash, store.InferTask{TaskID: "blocked", Stage: "queued", DeadlineHeight: 20})
	seedInferTask(ctx, t, db, delayedHash, store.InferTask{TaskID: "delayed", Stage: "queued", RetryAtUnixMilli: time.Now().Add(time.Hour).UnixMilli()})
	seedInferTask(ctx, t, db, expiredHash, store.InferTask{TaskID: "expired", Stage: "queued", DeadlineHeight: 5})
	seedInferTask(ctx, t, db, exhaustedHash, store.InferTask{TaskID: "exhausted", Stage: "queued", RetryCount: 2})
	started, release := make(chan struct{}), make(chan struct{})
	trace := &collectTrace{}
	var running, peak int
	var countMu sync.Mutex
	executor := inferExecutorFunc(func(_ context.Context, _ codec.Hash, task store.InferTask) (store.InferTask, bool, error) {
		countMu.Lock()
		running++
		if running > peak {
			peak = running
		}
		countMu.Unlock()
		close(started)
		<-release
		countMu.Lock()
		running--
		countMu.Unlock()
		task.Stage = "succeeded"
		return task, false, nil
	})
	r := NewTaskRunner(TaskRunnerConfig{Store: db, InferExecutor: executor, MaxConcurrency: 1, MaxRetryAttempts: 2, ChainStatus: fixedChainStatus{height: 10}, Trace: trace.trace()})
	done := make(chan error, 1)
	go func() { done <- r.RunOnce(ctx) }()
	<-started
	activeReturned := make(chan struct{})
	go func() { _, _ = r.ActiveTasks(); close(activeReturned) }()
	select {
	case <-activeReturned:
	case <-time.After(time.Second):
		t.Fatal("ActiveTasks blocked while model I/O was running")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	delayedRec, _ := layout.GetInferRecord(ctx, db, layout.StoredHash(delayedHash))
	if delayedRec.Stage != layout.StageQueued {
		t.Fatalf("retry-delayed task ran: %#v", delayedRec)
	}
	expiredRec, _ := layout.GetInferRecord(ctx, db, layout.StoredHash(expiredHash))
	if expiredRec.Stage != layout.StageFailed {
		t.Fatalf("expired task = %#v", expiredRec)
	}
	// A task that stopped without ever running still has to say why: LastError
	// is the only record an operator gets, and the execution merge does not
	// carry it.
	if !strings.Contains(expiredRec.LastError, "deadline height 5") {
		t.Fatalf("expired task LastError = %q, want the deadline named", expiredRec.LastError)
	}
	exhaustedRec, _ := layout.GetInferRecord(ctx, db, layout.StoredHash(exhaustedHash))
	if exhaustedRec.Stage != layout.StageFailed {
		t.Fatalf("exhausted task = %#v", exhaustedRec)
	}
	var stopped int
	for _, record := range trace.allRecords() {
		if strings.HasPrefix(record.Message, "task trace event=responsibility_stopped ") {
			stopped++
			if record.Level != slog.LevelError {
				t.Fatalf("responsibility_stopped level = %s, want ERROR: %s", record.Level, record.Message)
			}
		}
	}
	if stopped != 2 {
		t.Fatalf("responsibility_stopped records = %d, want deadline and retry-bound records: %#v", stopped, trace.allRecords())
	}
	if peak != 1 {
		t.Fatalf("peak concurrency = %d, want 1", peak)
	}
}

type fixedChainStatus struct {
	height  uint64
	chainID string
}

func (s fixedChainStatus) ChainStatus(context.Context) (uint64, string, error) {
	return s.height, s.chainID, nil
}

func TestTaskRunnerOwnsReconcilerEffectDocuments(t *testing.T) {
	ctx := context.Background()
	db, _ := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	t.Cleanup(func() { _ = db.Close() })
	taskHash := codec.HashBytes([]byte("assigned-task"))
	snapshot := chainclient.TaskSnapshot{Assignment: chainclient.AssignmentSnapshot{
		TaskID: "task-1", SessionID: "session-1", OrderSequence: chainclient.NewUint64String(1),
		SelectedWorker: "worker-1", ModelID: testModelID, ProfileVersion: chainclient.NewProfileVersion(1),
		InferDeadlineHeight: chainclient.NewUint64String(100), AcceptedOrderPayloadHash: chainclient.HexHash(codec.HashBytes([]byte("input"))),
	}}
	r := NewTaskRunner(TaskRunnerConfig{Store: db, LocalWorkerAddress: "worker-1"})
	a := snapshot.Assignment
	if err := layout.InferAssignmentBatch(ctx, db, layout.StoredHash(taskHash),
		layout.TaskRecord{SessionID: a.SessionID, OrderSequence: a.OrderSequence.Uint64(), ModelID: a.ModelID, ProfileVersion: a.ProfileVersion.Uint32(), WorkerAddress: a.SelectedWorker},
		layout.InferRecord{TaskID: "task-1", Stage: layout.StageQueued, DeadlineHeight: a.InferDeadlineHeight.Uint64()}); err != nil {
		t.Fatal(err)
	}
	infer, err := layout.GetInferRecord(ctx, db, layout.StoredHash(taskHash))
	if err != nil || infer.Stage != layout.StageQueued {
		t.Fatalf("infer record = %#v, %v", infer, err)
	}
	if err := r.ApplyReconcilerEffects(ctx, []ReconcilerEffect{{Type: ReconcilerEffectTaskTerminal, TaskHash: taskHash}}); err != nil {
		t.Fatal(err)
	}
	if _, err := layout.GetInferRecord(ctx, db, layout.StoredHash(taskHash)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("terminal infer record error = %v, want ErrNotFound", err)
	}
}

// A merge conflict belongs to exactly one task, but ApplyReconcilerEffects is
// called from the poller's effect sink and poller.Run stops on any error it
// cannot retry. Returning the conflict would therefore cost the node its whole
// chain view over one task - and because the consumed height never advances past
// the offending event, a restart re-reads it and stops again. So the conflicting
// effect is skipped and reported, and the effects behind it still apply.
func TestConflictingReconcilerEffectIsQuarantinedSoLaterEffectsStillApply(t *testing.T) {
	ctx := context.Background()
	db, _ := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	t.Cleanup(func() { _ = db.Close() })

	poisoned := codec.HashBytes([]byte("poisoned-task"))
	// Claim the write-once SessionID with a different value, so the assignment
	// below contradicts a durable record instead of merely replaying it.
	if err := layout.MergeTask(ctx, db, layout.StoredHash(poisoned), layout.TaskRecord{SessionID: "other-session"}); err != nil {
		t.Fatal(err)
	}
	healthy := codec.HashBytes([]byte("healthy-task"))
	assignment := func(taskID string) chainclient.TaskSnapshot {
		return chainclient.TaskSnapshot{Assignment: chainclient.AssignmentSnapshot{
			TaskID: taskID, SessionID: "session-1", OrderSequence: chainclient.NewUint64String(1),
			SelectedWorker: "worker-1", ModelID: testModelID, ProfileVersion: chainclient.NewProfileVersion(1),
			InferDeadlineHeight: chainclient.NewUint64String(100), AcceptedOrderPayloadHash: chainclient.HexHash(codec.HashBytes([]byte("input"))),
		}, VerifierAssignment: chainclient.VerifierAssignmentSnapshot{
			TaskID: taskID, VerifyRound: chainclient.NewUint64String(1), FormalVerifierSet: chainclient.CSVStrings{"verifier-1"},
			OpenVerifyHeight: chainclient.NewUint64String(20), CommitDeadlineHeight: chainclient.NewUint64String(30), VerifyDeadlineHeight: chainclient.NewUint64String(60),
		}}
	}

	var quarantined []ReconcilerEffect
	r := NewTaskRunner(TaskRunnerConfig{
		Store: db, LocalVerifierAddress: "verifier-1",
		OnQuarantinedEffect: func(effect ReconcilerEffect, err error) {
			quarantined = append(quarantined, effect)
			if !errors.Is(err, layout.ErrConflict) {
				t.Errorf("quarantined error = %v, want a merge-boundary conflict", err)
			}
		},
	})
	if err := r.ApplyReconcilerEffects(ctx, []ReconcilerEffect{
		{Type: ReconcilerEffectVerifyReady, TaskHash: poisoned, TaskID: "task-poisoned", Snapshot: assignment("task-poisoned")},
		{Type: ReconcilerEffectVerifyReady, TaskHash: healthy, TaskID: "task-healthy", Snapshot: assignment("task-healthy")},
	}); err != nil {
		t.Fatalf("ApplyReconcilerEffects() error = %v, want the conflict quarantined so the cursor advances", err)
	}
	if len(quarantined) != 1 || quarantined[0].TaskID != "task-poisoned" {
		t.Fatalf("quarantined = %#v, want exactly the conflicting effect reported", quarantined)
	}
	if verify, err := layout.GetVerifyRecord(ctx, db, layout.StoredHash(healthy)); err != nil || verify.Stage != layout.StageQueued {
		t.Fatalf("verify record behind the conflict = %#v, %v, want it applied", verify, err)
	}
	// The refused batch is atomic, so the poisoned task must not be half-written.
	if _, err := layout.GetVerifyRecord(ctx, db, layout.StoredHash(poisoned)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("poisoned verify record error = %v, want ErrNotFound", err)
	}
}

// A task-terminal effect carries no finality height when nothing ever settled -
// a refusal or a deadline expiry produces exactly that - so the retention clock
// has to come from the finalized Keeper cursor that carried the effect. Leaving
// it at zero is what retained the evidence forever.
func TestTaskTerminalEffectRecordsTheRetentionClockFromTheCursor(t *testing.T) {
	ctx := context.Background()
	db, _ := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	t.Cleanup(func() { _ = db.Close() })
	taskHash := codec.HashBytes([]byte("terminal-without-settlement"))
	r := NewTaskRunner(TaskRunnerConfig{Store: db})

	if err := r.ApplyReconcilerEffects(ctx, []ReconcilerEffect{{
		Type: ReconcilerEffectTaskTerminal, TaskHash: taskHash, TaskID: "task-1",
		Event: chainclient.KeeperEvent{Height: 40},
	}}); err != nil {
		t.Fatalf("ApplyReconcilerEffects() error = %v", err)
	}
	record, err := layout.GetEvidenceRecord(ctx, db, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	if record.FinalityHeight != 0 {
		t.Fatalf("FinalityHeight = %d, want none for a terminal with no settlement", record.FinalityHeight)
	}
	if record.RetentionStartHeight != 40 {
		t.Fatalf("RetentionStartHeight = %d, want the cursor height that carried the effect", record.RetentionStartHeight)
	}

	// A later finality is authoritative and advances the clock.
	if err := r.ApplyReconcilerEffects(ctx, []ReconcilerEffect{{
		Type: ReconcilerEffectEvidenceRetention, TaskHash: taskHash, TaskID: "task-1",
		FinalityHeight: 55, CleanupHeight: 60, Event: chainclient.KeeperEvent{Height: 55},
	}}); err != nil {
		t.Fatalf("ApplyReconcilerEffects() error = %v", err)
	}
	record, err = layout.GetEvidenceRecord(ctx, db, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	if record.FinalityHeight != 55 || record.RetentionStartHeight != 55 {
		t.Fatalf("finality=%d retention=%d, want the finality to advance both", record.FinalityHeight, record.RetentionStartHeight)
	}
}

// A cleanup-due event announces that cleanup is due. It carries no finality
// height, so falling back to the Keeper cursor would set the retention clock to
// that event's own height - and because the merge never regresses, every such
// event would push eligibility out by another full retention window. The
// evidence would be retained forever, which is the leak the field exists to
// close.
func TestCleanupSchedulingEventsDoNotMoveTheRetentionClock(t *testing.T) {
	ctx := context.Background()
	db, _ := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	t.Cleanup(func() { _ = db.Close() })
	taskHash := codec.HashBytes([]byte("cleanup-scheduling"))
	r := NewTaskRunner(TaskRunnerConfig{Store: db})

	// Terminal observed at cursor height 40: that is the clock.
	if err := r.ApplyReconcilerEffects(ctx, []ReconcilerEffect{{
		Type: ReconcilerEffectTaskTerminal, TaskHash: taskHash, TaskID: "task-1",
		Event: chainclient.KeeperEvent{Height: 40},
	}}); err != nil {
		t.Fatalf("terminal effect: %v", err)
	}

	// A cleanup-due event much later carries a cleanup height and no finality.
	if err := r.ApplyReconcilerEffects(ctx, []ReconcilerEffect{{
		Type: ReconcilerEffectEvidenceRetention, TaskHash: taskHash, TaskID: "task-1",
		CleanupHeight: 90,
		Event:         chainclient.KeeperEvent{Type: chainclient.KeeperEventEvidenceCleanupDue, Height: 900},
	}}); err != nil {
		t.Fatalf("cleanup-due effect: %v", err)
	}

	record, err := layout.GetEvidenceRecord(ctx, db, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	if record.RetentionStartHeight != 40 {
		t.Fatalf("RetentionStartHeight = %d, want it held at the terminal cursor 40; a cleanup-due event postponed its own cleanup", record.RetentionStartHeight)
	}
	if record.CleanupHeight != 90 {
		t.Fatalf("CleanupHeight = %d, want the scheduled 90", record.CleanupHeight)
	}
}

func TestTaskRunnerListsAndRequeuesActiveDocumentsThroughSingleOwner(t *testing.T) {
	ctx := context.Background()
	db, _ := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.db"))
	t.Cleanup(func() { _ = db.Close() })
	hash := codec.HashBytes([]byte("failed-infer"))
	if err := layout.MergeInfer(ctx, db, layout.StoredHash(hash), layout.InferRecord{TaskID: "task-1", Stage: layout.StageFailed, RetryCount: 7, LastError: "offline", DeadlineHeight: 99}); err != nil {
		t.Fatal(err)
	}
	r := NewTaskRunner(TaskRunnerConfig{Store: db})
	rows, err := r.ListActiveTasks(ctx)
	if err != nil || len(rows) != 1 || rows[0].Role != "worker" || rows[0].Stage != "infer" || rows[0].Status != "failed" {
		t.Fatalf("ListActiveTasks = %#v, %v", rows, err)
	}
	retryAt := time.Now().UTC().Add(time.Minute)
	row, err := r.RequeueActiveTask(ctx, rows[0].QueueID, "operator retry", retryAt)
	if err != nil || row.Status != "queued" || row.RetryCount != 0 || row.LastError != "operator retry" {
		t.Fatalf("RequeueActiveTask = %#v, %v", row, err)
	}
	record, err := layout.GetInferRecord(ctx, db, layout.StoredHash(hash))
	if err != nil || record.Stage != layout.StageQueued || record.RetryAtUnixMilli != retryAt.UnixMilli() {
		t.Fatalf("requeued record = %#v, %v", record, err)
	}
}

type inferExecutorFunc func(context.Context, codec.Hash, store.InferTask) (store.InferTask, bool, error)

func (f inferExecutorFunc) RunInfer(ctx context.Context, hash codec.Hash, task store.InferTask) (store.InferTask, bool, error) {
	return f(ctx, hash, task)
}

type verifyExecutorFunc func(context.Context, codec.Hash, store.VerifyTask) (store.VerifyTask, bool, error)

func (f verifyExecutorFunc) RunVerify(ctx context.Context, hash codec.Hash, task store.VerifyTask) (store.VerifyTask, bool, error) {
	return f(ctx, hash, task)
}

type staticEligibility struct {
	verifierInput policy.VerifierPrecheckInput
	err           error
}

func (e staticEligibility) Verifier(context.Context, VerifierHandraiseCandidate) (policy.VerifierPrecheckInput, error) {
	return e.verifierInput, e.err
}

// taskRunnerTaskDataAuth is the committed current-binding reader: the outbound
// handraise's service_authorization_nonce comes from one committed read of this
// node's own ServiceKey binding, so a runner that raises a hand cannot have a
// nil one.
func taskRunnerTaskDataAuth(t *testing.T) *taskdataauth.Authenticator {
	t.Helper()
	signing, binding := localInputServiceSigner(t)
	auth, err := taskdataauth.New(taskdataauth.Config{
		ServiceKeys: &inputServiceKeys{binding: binding}, Signer: signing,
		ChainID: "chain", OperatorAddress: inputTestOperator,
		ServiceAddress: binding.ServiceAddress, ServicePubkey: binding.ServicePubkey,
		ServiceKeyRef: inputTestKeyRef, ExpiryBlocks: inputTestExpiry,
	})
	if err != nil {
		t.Fatalf("taskdataauth.New: %v", err)
	}
	return auth
}

type outputAdmissionBuilder struct {
	pkg builderclient.OutputPackage
}

func (b *outputAdmissionBuilder) ValidateOutputPackage(context.Context, builderclient.OutputPackage) error {
	return nil
}

// recordingOutputConfirmer keeps the commitments it was handed so a test can
// assert where they came from -- the whole question this issue turns on. Every
// entry in received is a task-data-plane call, and a candidate must produce
// none: only a selected Verifier is authorised to reach the plane at all.
type recordingOutputConfirmer struct {
	pkg      builderclient.OutputPackage
	received []OutputCommitments
	err      error
}

func (c *recordingOutputConfirmer) ConfirmOutput(_ context.Context, commitments OutputCommitments) (builderclient.OutputPackage, error) {
	c.received = append(c.received, commitments)
	return c.pkg, c.err
}

const freshnessTestModelID = "ad410b3157d13dbfb8263e92914cfe5a75868ce68fd722d2f73c75ff8cc7378b"

// V3 touches nothing off-node and V7a is the download. data-plane-and-evidence-transfer.md §6:
// candidate metadata arrives on ORDER_BROADCAST / OPEN_VERIFY and is "not obtained
// through the data query interface"; GetTaskDataMetadata "is not a prerequisite
// step of the normal Task flow". nexus enforces the same rule from the other side
// -- its plane admits a selected Worker, a selected Verifier or the original User
// -- so the metadata round trip this handraise used to make was refused
// NEXUS_DATA_UNAUTHORIZED and no handraise was ever sent.
func TestVerifierHandraiseReachesTheTaskDataPlaneNotAtAll(t *testing.T) {
	fixture := newOpenVerifyFixture(t)

	if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err != nil {
		t.Fatalf("OpenVerify was refused: %v", err)
	}
	fixture.assertHandraised(t)
	if len(fixture.confirmer.received) != 0 {
		t.Fatalf("task-data plane calls = %#v, want none: a candidate is not authorised to make any",
			fixture.confirmer.received)
	}
}

// A node with no output confirmer at all still raises a hand. This is the shape
// of the rule, not an optimisation: the confirmer is the task-data client, and
// if a handraise needed one then §6's "candidate metadata does not come from the
// data plane" would not be true of this code.
func TestVerifierHandraiseNeedsNoOutputConfirmer(t *testing.T) {
	fixture := newOpenVerifyFixture(t)
	fixture.runner.cfg.OutputConfirmer = nil

	if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err != nil {
		t.Fatalf("handraise without an output confirmer was refused: %v", err)
	}
	if len(fixture.sender.handraises) != 1 {
		t.Fatalf("published = %#v, want one verifier handraise", fixture.sender.handraises)
	}
}

// The real chain deleted canonical_output_package_hash from InferReceiptState
// (proto/CHAIN_BINDINGS.md:265) and cortex-detailed-design.md:1032 forbids Cortex from
// generating a replacement. Demanding it here is what refused every real-mode
// OPEN_VERIFY with "output confirmation requires committed output and package
// hashes", so no Cortex node could ever raise a Verifier hand.
func TestVerifierHandraiseSucceedsWhenKeeperCommitsNoPackageHash(t *testing.T) {
	fixture := newOpenVerifyFixture(t)
	chain := fixture.snapshot
	chain.InferReceipt.CanonicalOutputPackageHash = chainclient.HexHash{}
	fixture.runner.cfg.TaskReader = staticKeeperTaskReader{snapshot: chain}

	if err := fixture.deliverOpenVerify(t, fixture.openVerifyCall()); err != nil {
		t.Fatalf("OPEN_VERIFY with no committed package hash was refused: %v", err)
	}
	if len(fixture.sender.handraises) != 1 {
		t.Fatalf("published = %#v, want one verifier handraise", fixture.sender.handraises)
	}
}

// The precheck's mutual-exclusion skip has to come before any fetch (the
// cortex-detailed-design.md timing red line). The winning Worker receiving its own task's
// OPEN_VERIFY is the normal case, so this path runs once per task. It used to
// pull the node's own output back from the Builder in full before the L1 mutual
// exclusion refused it; and even refusing early, returning an error would only
// make the Builder retry it.
func TestVerifierHandraiseAcknowledgesTheWinningWorkerBeforeAnyConfirmation(t *testing.T) {
	fixture := newOpenVerifyFixture(t)
	fixture.runner.cfg.LocalVerifierAddress = fixture.snapshot.Assignment.SelectedWorker

	err := fixture.deliverOpenVerify(t, fixture.openVerifyCall())

	if err != nil {
		t.Fatalf("self-winner OPEN_VERIFY error = %v, want nil", err)
	}
	if len(fixture.confirmer.received) != 0 {
		t.Fatalf("task-data plane calls = %#v, want none: the skip precedes every fetch", fixture.confirmer.received)
	}
	if len(fixture.sender.handraises) != 0 {
		t.Fatalf("published = %#v, want nothing", fixture.sender.handraises)
	}
	requireTraceFields(t, fixture.trace.event(t, "verifier_trigger_skipped"),
		`kind="OpenVerify"`, `task="`+fixture.taskID+`"`,
		`worker="worker-1"`, `reason="self_winner"`)
	requireTraceLevel(t, fixture.trace, "verifier_trigger_skipped", slog.LevelInfo)
}

// testModelID is the Hash32 model id, as canonical hex, the daemon tests run.
const testModelID = "0101010101010101010101010101010101010101010101010101010101010101"

// seedAssignedInfer records the Worker responsibility an assignment snapshot
// describes, the way the retired Keeper assignment effect did, and wakes the
// runner so the next pass picks it up.
func seedAssignedInfer(ctx context.Context, t *testing.T, runner *TaskRunner, effect ReconcilerEffect) {
	t.Helper()
	a := effect.Snapshot.Assignment
	task := layout.TaskRecord{
		SessionID: a.SessionID, OrderSequence: a.OrderSequence.Uint64(), ModelID: a.ModelID, ProfileVersion: a.ProfileVersion.Uint32(),
		AssignmentOrderDigest: layout.StoredHashFromCodec(codec.Hash(a.AcceptedOrderPayloadHash)),
		AcceptedInputHash:     layout.StoredHashFromCodec(codec.Hash(a.AcceptedOrderPayloadHash)),
		InputDigest:           layout.StoredHashFromCodec(codec.Hash(a.AcceptedOrderPayloadHash)),
		WorkerAddress:         a.SelectedWorker,
	}
	infer := layout.InferRecord{
		TaskID: effect.TaskID, WinnerConfirmHeight: a.WinnerConfirmHeight.Uint64(), InferDeadlineHeight: a.InferDeadlineHeight.Uint64(),
		Stage: layout.StageQueued, DeadlineHeight: a.InferDeadlineHeight.Uint64(),
	}
	if err := layout.InferAssignmentBatch(ctx, runner.cfg.Store, layout.StoredHash(effect.TaskHash), task, infer); err != nil {
		t.Fatal(err)
	}
	runner.Wake()
}
