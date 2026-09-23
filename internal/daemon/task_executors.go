package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/tasktrace"
	"github.com/TrueOpen/cortex/internal/txclient"
	"github.com/TrueOpen/cortex/internal/verifier"
	"github.com/TrueOpen/cortex/internal/worker"
)

type productionInferExecutor struct {
	cfg     TaskRunnerConfig
	persist func(context.Context, codec.Hash, store.InferTask, layout.Evidence) error
}
type productionVerifyExecutor struct{ cfg TaskRunnerConfig }

func newProductionInferExecutor(cfg TaskRunnerConfig, persist func(context.Context, codec.Hash, store.InferTask, layout.Evidence) error) InferExecutor {
	return &productionInferExecutor{cfg: cfg, persist: persist}
}
func newProductionVerifyExecutor(cfg TaskRunnerConfig) VerifyExecutor {
	return &productionVerifyExecutor{cfg: cfg}
}

func (e *productionInferExecutor) RunInfer(ctx context.Context, taskHash codec.Hash, task store.InferTask) (store.InferTask, bool, error) {
	if task.Stage == "succeeded" {
		return task, false, nil
	}
	var evidenceSchemaHash string
	var requirements []builderclient.InferEvidenceRequirement
	var err error
	if e.cfg.ProfileReader == nil {
		if !e.cfg.FakeOutput {
			return task, false, builderclient.Retryable(fmt.Errorf("Keeper profile reader is required"))
		}
		fakeHash := codec.HashWithDomain("CORTEX_FAKE_EVIDENCE_SCHEMA_V1", []byte(task.ModelID), codec.Uint64Bytes(uint64(task.ProfileVersion)))
		evidenceSchemaHash = hex.EncodeToString(fakeHash[:])
		requirements = []builderclient.InferEvidenceRequirement{{
			EvidenceKind: nodewire.EvidenceKindWorkerValueOpening, CommitmentSchemaVersion: nodewire.WorkerValueCommitmentSchemaVersionV2, MaxEncodedSizeBytes: 1 << 30,
		}}
	} else {
		profile, err := e.cfg.ProfileReader.CurrentModelProfile(ctx, task.ModelID, fmt.Sprintf("%d", task.ProfileVersion))
		if err != nil {
			return task, false, builderclient.Retryable(fmt.Errorf("query locked model profile: %w", err))
		}
		evidenceSchemaHash = profile.Profile.VerificationProfile.EvidenceSchemaHash.Hex()
		requirements = make([]builderclient.InferEvidenceRequirement, len(profile.Profile.VerificationProfile.EvidenceSchema.RequiredInferEvidence))
		for index, requirement := range profile.Profile.VerificationProfile.EvidenceSchema.RequiredInferEvidence {
			requirements[index] = builderclient.InferEvidenceRequirement{
				EvidenceKind:            nodewire.EvidenceKind(requirement.EvidenceKind),
				CommitmentSchemaVersion: requirement.CommitmentSchemaVersion,
				MaxEncodedSizeBytes:     requirement.MaxEncodedSizeBytes.Uint64(),
			}
		}
	}
	persistence := &evidenceWorkerPersistence{taskHash: taskHash, task: &task, evidence: e.cfg.Evidence, store: e.cfg.Store, builder: e.cfg.Builder, persist: e.persist}
	signerAddress, signerPubkey := resolveSigningIdentity(e.cfg, e.cfg.LocalWorkerAddress)
	wcfg := worker.Config{WorkerAddress: e.cfg.LocalWorkerAddress, ModelServiceID: e.cfg.ModelServiceID, Model: e.cfg.Model, Builder: e.cfg.Builder, TaskData: e.cfg.TaskData, TaskDataAuth: e.cfg.TaskDataAuth, Tx: e.cfg.Tx, Persistence: persistence, InferDeadlineDeltaHeights: e.cfg.InferDeadlineDeltaHeights, ChainID: e.cfg.ChainID, SignerAddress: signerAddress, SignerKeyRef: e.cfg.SignerKeyRef, SignerPubkey: signerPubkey, Signer: e.cfg.Signer, FakeOutput: e.cfg.FakeOutput, TrustedNATSDev: e.cfg.TrustedNATSDev || e.cfg.FakeBus, PackageStore: e.cfg.OutputPackages, NexusEnvelopeSigner: e.cfg.NexusEnvelopeSigner, EnvelopeTTL: e.cfg.EnvelopeTTL, ReceivingBuilder: e.cfg.ReceivingBuilder, TaskFacts: e.cfg.TaskFacts, EvidenceSchemaHash: evidenceSchemaHash, ProfileEvidenceRequirements: requirements, CrashHook: e.cfg.CrashHook, SnapshotReader: newTaskSnapshotReader(e.cfg.TaskReader, task.SessionID), Trace: e.cfg.Trace}
	wcfg.GenerationReader = persistedGenerationReader{store: e.cfg.Store, chainID: e.cfg.ChainID}
	wcfg.MaxOutputBytes = e.cfg.MaxOutputBytes
	event := chainclient.AssignmentFinalized{TaskID: task.TaskID, SessionID: task.SessionID, OrderSequence: task.OrderSequence, OrderDigest: task.OrderDigest, Winner: firstNonEmpty(task.WorkerAddress, e.cfg.LocalWorkerAddress), WinnerConfirmHeight: task.WinnerConfirmHeight, InferDeadlineHeight: task.DeadlineHeight, ModelID: task.ModelID, ProfileVersion: task.ProfileVersion, Capability: task.Capability, BuilderOperatorAddress: task.BuilderOperatorAddress}
	if e.cfg.InputResolver == nil {
		return task, false, builderclient.Retryable(fmt.Errorf("task input resolver is not available"))
	}
	// Prefer a locally persisted input so retries (and process restart) do not
	// re-download the same bytes from the Builder. The evidence store is
	// content-addressed, so re-writing the same input is idempotent.
	input, readErr := persistence.ReadArtifact(ctx, task.TaskID, "task-input")
	if readErr == nil && len(input) > 0 && codec.HashBytes(input) == task.InputDigest {
		event.Input = input
	} else {
		event.Input, err = e.cfg.InputResolver.ResolveTaskInput(ctx, TaskInputRef{SessionID: task.SessionID, TaskID: task.TaskID, TaskHash: taskHash, PayloadCID: task.InputCID, PayloadHash: chainclient.HexHash(task.InputDigest), BuilderOperatorAddress: task.BuilderOperatorAddress, InputSizeBytes: task.InputSizeBytes})
		if err == nil && codec.HashBytes(event.Input) != task.InputDigest {
			err = fmt.Errorf("resolved task input hash does not match Keeper accepted payload hash")
		}
		if err == nil {
			if cpErr := persistence.WriteEvidence(ctx, worker.EvidenceRecord{TaskID: task.TaskID, Kind: "task-input", Data: event.Input}); cpErr != nil {
				return task, false, fmt.Errorf("persist resolved task input: %w", cpErr)
			}
			if e.cfg.CrashHook != nil {
				if crashErr := e.cfg.CrashHook(worker.CrashPointInputCommit); crashErr != nil {
					return task, false, crashErr
				}
			}
		}
	}
	traceInferStarted := e.cfg.Trace.Event
	if err != nil {
		traceInferStarted = e.cfg.Trace.ErrorEvent
	}
	traceInferStarted("infer_started",
		tasktrace.Str("task", task.TaskID), tasktrace.Hash("task_hash", taskHash),
		tasktrace.Str("session", task.SessionID), tasktrace.Str("model", task.ModelID),
		tasktrace.Uint("profile_version", uint64(task.ProfileVersion)),
		tasktrace.Hash("input_digest", task.InputDigest), tasktrace.Int("input_bytes", len(event.Input)),
		tasktrace.Hex("evidence_schema_hash", evidenceSchemaHash),
		tasktrace.Int("evidence_requirements", len(requirements)),
		tasktrace.Str("builder", task.BuilderOperatorAddress),
		tasktrace.Uint("infer_deadline_height", task.DeadlineHeight),
		tasktrace.Err("input_error", err))
	var result worker.InferResult
	if err == nil {
		if reader, ok := e.cfg.TaskReader.(chainclient.OutputStreamLimitsReader); ok {
			var limits chainclient.OutputStreamLimitsSnapshot
			limits, err = reader.OutputStreamLimits(ctx)
			wcfg.StreamLimits = &limits
		} else if e.cfg.FakeBus {
			wcfg.StreamLimits = &chainclient.OutputStreamLimitsSnapshot{MinOutputStreamFrameBytes: 16, MaxOutputMMRLeaves: 65536}
		} else {
			err = fmt.Errorf("Keeper output stream limits reader is required")
		}
		if err == nil {
			result, err = worker.New(wcfg).HandleAssignmentFinalized(ctx, event)
		}
	}
	if err != nil {
		return task, false, err
	}
	// Every digest this node just produced for the task, in one line: these are
	// the values the on-chain receipt and the Verifier's confirmation are checked
	// against, so a disagreement with Keeper or with Nexus is a diff between this
	// line and theirs rather than a re-derivation.
	e.cfg.Trace.Event("infer_completed",
		tasktrace.Str("task", task.TaskID), tasktrace.Hash("task_hash", taskHash),
		tasktrace.Hash("output_hash", result.Receipt.OutputHash),
		tasktrace.Hash("package_hash", result.PackageHash),
		tasktrace.Hash("receipt_package_hash", result.Receipt.PackageHash),
		tasktrace.Hash("receipt_result_hash", result.Receipt.ReceiptResultHash),
		tasktrace.Str("output_ref", result.Receipt.OutputRef), tasktrace.Str("output_cid", result.OutputCID),
		tasktrace.Hex("task_data_receipt_output_hash", result.TaskDataReceipt.OutputHash),
		tasktrace.Uint("task_data_receipt_output_size_bytes", result.TaskDataReceipt.OutputSizeBytes),
		tasktrace.Uint("infer_deadline_height", result.InferDeadlineHeight))
	task.Stage = "succeeded"
	task.LastError = ""
	task.RetryAtUnixMilli = 0
	// The same value the infer checkpoint writes. Writing result.OutputRef would
	// collide with the output package address the checkpoint writes, on a write-once
	// field, and the whole daemon would exit with it.
	task.OutputCID = result.OutputCID
	task.OutputDigest = result.Receipt.OutputHash
	task.ReceiptDigest = result.Receipt.ReceiptResultHash
	return task, false, nil
}

// confirmWorkerValueEvidence downloads and binds the opening material for one
// verify round.
//
// A nil confirmer is not an error: it is the fake model transport's deployment,
// where the Worker and the Verifier share a model service and the confirmed
// package carries usable artifact refs. Returning empty evidence there leaves
// verifier.HandleOpenVerifyAccepted on its ref path, which is the only path that
// can serve those refs. On a real chain the confirmer is always built alongside
// OutputConfirmer, and RunVerify has already refused above if that one is nil.
func (e *productionVerifyExecutor) confirmWorkerValueEvidence(
	ctx context.Context,
	task store.VerifyTask,
	pkg builderclient.OutputPackage,
) (WorkerValueEvidence, error) {
	if e.cfg.EvidenceConfirmer == nil {
		return WorkerValueEvidence{}, nil
	}
	if pkg.SignedInferReceipt == nil {
		return WorkerValueEvidence{}, fmt.Errorf(
			"confirmed output for task %s carries no signed infer receipt, so the required evidence commitment is unknown; "+
				"the receipt is the only chain-bound source of required_evidence_commitments", task.TaskID)
	}
	// evidence_schema_hash is the one commitment input the receipt does not carry.
	// It is read from the locked Profile the assignment names, exactly as the
	// Worker read it when it built the commitment; a reader that resolves a
	// different profile version cannot reproduce the digest, which is a refusal
	// rather than a value to substitute.
	if e.cfg.ProfileReader == nil {
		return WorkerValueEvidence{}, builderclient.Retryable(fmt.Errorf(
			"Keeper profile reader is required to confirm worker value evidence for task %s", task.TaskID))
	}
	profile, err := e.cfg.ProfileReader.CurrentModelProfile(ctx, task.ModelID, fmt.Sprintf("%d", task.ProfileVersion))
	if err != nil {
		return WorkerValueEvidence{}, builderclient.Retryable(fmt.Errorf("query locked model profile: %w", err))
	}
	requirements := profile.Profile.VerificationProfile.EvidenceSchema.RequiredInferEvidence
	if len(requirements) != 1 || requirements[0].CommitmentSchemaVersion != 2 || nodewire.EvidenceKind(requirements[0].EvidenceKind) != nodewire.EvidenceKindWorkerValueOpening {
		return WorkerValueEvidence{}, fmt.Errorf("locked profile must require the V2 Worker opening")
	}
	return e.cfg.EvidenceConfirmer.ConfirmWorkerValueEvidence(ctx, EvidenceCommitments{
		SessionID:              task.SessionID,
		TaskID:                 task.TaskID,
		BuilderOperatorAddress: task.BuilderOperatorAddress,
		Receipt:                *pkg.SignedInferReceipt,
		Output:                 pkg.Output,
		EvidenceSchemaHash:     profile.Profile.VerificationProfile.EvidenceSchemaHash.Hex(),
		OutputChunkLengths:     pkg.OutputChunkLengths,
		MaxEncodedSizeBytes:    requirements[0].MaxEncodedSizeBytes.Uint64(),
	})
}

// RunVerify runs whichever of the verify responsibility's two halves is owed.
//
// They are two because the chain makes them two. The commit is signed and
// self-submitted as soon as the verification is done; the reveal may only be
// submitted after EventRevealPhaseStarted (Task-04-Verification-flow.md), which
// cannot have happened yet while the commit is being signed. StageCommitted is
// the durable boundary between them, so a process that restarts in between finds
// the reveal still owed rather than starting the whole verification again.
func (e *productionVerifyExecutor) RunVerify(ctx context.Context, taskHash codec.Hash, task store.VerifyTask) (store.VerifyTask, bool, error) {
	if task.Stage == "succeeded" {
		return task, false, nil
	}
	if task.Stage == string(layout.StageCommitted) {
		return e.runReveal(ctx, taskHash, task)
	}
	if e.cfg.OutputConfirmer == nil {
		return task, false, fmt.Errorf("verify requires a Nexus output confirmer: it is built only when the node uses real dependencies (mode real or integration) and carries a task-data client, a task-data authenticator and a Builder directory; the receiving Builder is resolved per task from its on-chain service descriptor, never from configuration")
	}
	commitments, err := verifyTaskCommitments(task)
	if err != nil {
		return task, false, err
	}
	commitments.TaskHash = taskHash
	e.cfg.Trace.Event("verify_started",
		tasktrace.Str("task", task.TaskID), tasktrace.Hash("task_hash", taskHash),
		tasktrace.Str("session", task.SessionID), tasktrace.Uint("verify_round", task.VerifyRound),
		tasktrace.Hash("committed_output_hash", commitments.OutputHash),
		tasktrace.Hash("committed_package_hash", commitments.PackageHash),
		tasktrace.Hash("infer_receipt_digest", task.InferReceiptDigest),
		tasktrace.Hash("verification_sample_seed", task.VerificationSampleSeed),
		tasktrace.Str("worker", task.WorkerAddress), tasktrace.Str("builder", task.BuilderOperatorAddress),
		tasktrace.Bool("keeper_receipt", commitments.KeeperReceipt != nil),
		tasktrace.Uint("open_verify_height", task.OpenVerifyHeight),
		tasktrace.Uint("commit_deadline_height", task.CommitDeadlineHeight),
		tasktrace.Uint("reveal_deadline_height", task.RevealDeadlineHeight),
		tasktrace.Uint("verify_deadline_height", task.DeadlineHeight))
	pkg, err := e.cfg.OutputConfirmer.ConfirmOutput(ctx, commitments)
	if err != nil {
		e.cfg.Trace.ErrorEvent("output_confirm_failed",
			tasktrace.Str("kind", "verify"), tasktrace.Str("task", task.TaskID),
			tasktrace.Hash("committed_output_hash", commitments.OutputHash),
			tasktrace.Hash("committed_package_hash", commitments.PackageHash),
			tasktrace.Str("builder", commitments.BuilderOperatorAddress), tasktrace.Err("error", err))
		return task, false, fmt.Errorf("confirm output before verify: %w", err)
	}
	e.cfg.Trace.Event("output_confirmed", traceConfirmedPackage("verify", pkg)...)
	// The evidence the locked Profile requires. It is a second download and not a
	// detail of the first: the OUTPUT object is the inference result, the
	// WORKER_VALUE_OPENING artifacts are the opening material local
	// re-verification runs against, and they are separate objects under separate
	// signed selectors on the task-data plane.
	//
	// This is where the verify path used to die on a real chain. The artifact refs
	// a confirmed package carries are Worker-local model-service addresses that no
	// wire transports, so on every real-transport node they are empty and
	// FetchArtifact refused with "empty ref" -- for 100k blocks, until the commit
	// deadline passed.
	workerValueEvidence, err := e.confirmWorkerValueEvidence(ctx, task, pkg)
	if err != nil {
		e.cfg.Trace.ErrorEvent("evidence_confirm_failed",
			tasktrace.Str("kind", "verify"), tasktrace.Str("task", task.TaskID),
			tasktrace.Str("builder", commitments.BuilderOperatorAddress), tasktrace.Err("error", err))
		return task, false, fmt.Errorf("confirm worker value evidence before verify: %w", err)
	}
	persistence := &evidenceVerifierPersistence{taskHash: taskHash, task: &task, evidence: e.cfg.Evidence, builder: e.cfg.Builder}
	identity, err := e.verifyRoundIdentity(ctx, taskHash, task)
	if err != nil {
		return task, false, err
	}
	signerAddress, authorizationNonce := identity.signerAddress, identity.authorizationNonce
	member, inferReceiptHash, expiryHeight := identity.member, identity.inferReceiptHash, identity.handraiseExpiryHeight
	// The commit exit. The relay is the receiving Builder's nexus
	// SubmitVerifyCommit (nexus#70, phase-one trusted Builder): asked first, and only a
	// deterministic refusal falls through to self-submission. The submitter is
	// built per verify rather than once, because the tx client and the service
	// address it must sign as are only known after the Keeper confirms this
	// node's service key.
	//
	// The relay is resolved before the submitter so that its presence can answer
	// the submitter's fail-closed question. A relay-only node is a legal
	// configuration -- deliverCommit already treats a nil submitter as "the relay
	// is the only route" -- and refusing one here meant the relay was never asked
	// at all.
	commitRelay := taskCommitRelayFor(e.cfg.VerifyCommitRelay, task)
	commitSubmitter, err := e.commitSubmitter(signerAddress, commitRelay != nil)
	if err != nil {
		return task, false, err
	}
	v := verifier.New(verifier.Config{VerifierAddress: e.cfg.LocalVerifierAddress, ModelServiceID: e.cfg.ModelServiceID, Model: e.cfg.Model, Builder: e.cfg.Builder, Persistence: persistence, ChainID: e.cfg.ChainID, SignerAddress: signerAddress, SignerKeyRef: e.cfg.SignerKeyRef, Signer: e.cfg.Signer, VerifyDeadlineDeltaHeight: e.cfg.VerifyDeadlineDeltaHeight, FakeOutput: e.cfg.FakeOutput, TrustedNATSDev: e.cfg.TrustedNATSDev || e.cfg.FakeBus, NexusEnvelopeSigner: e.cfg.NexusEnvelopeSigner, EnvelopeTTL: e.cfg.EnvelopeTTL, TaskFacts: e.cfg.TaskFacts, ServiceAuthorizationNonce: authorizationNonce, ProfileReader: e.cfg.ProfileReader, MaxOutputBytes: e.cfg.MaxOutputBytes, Trace: e.cfg.Trace, CommitSubmitter: commitSubmitter, CommitRelay: commitRelay})
	state := verifier.TaskState{TaskID: task.TaskID, SessionID: task.SessionID, OrderSequence: task.OrderSequence, OrderDigest: task.OrderDigest, VerifyRound: task.VerifyRound, InferReceiptHash: inferReceiptHash, Member: member, ModelID: task.ModelID, ProfileVersion: task.ProfileVersion, Capability: task.Capability, WorkerAddress: task.WorkerAddress, OutputPackage: outputPackageSummary(pkg), ConfirmedOutput: pkg.Output, ConfirmedTrace: workerValueEvidence.Trace, ConfirmedCheckpoint: workerValueEvidence.Checkpoint, OutputConfirmed: true, OpenVerifyAccepted: true, AssignedVerifiers: append([]string(nil), task.AssignedVerifiers...), OpenVerifyHeight: task.OpenVerifyHeight, HandraiseExpiryHeight: expiryHeight, CurrentHeight: task.CurrentHeight, CommitDeadlineHeight: task.CommitDeadlineHeight, WorkerRevealDeadlineHeight: task.WorkerRevealDeadlineHeight, RevealDeadlineHeight: task.RevealDeadlineHeight, VerifyDeadlineHeight: task.DeadlineHeight, VerificationSampleSeed: task.VerificationSampleSeed}
	state.ConfirmedFinishReason = workerValueEvidence.FinishReason
	state.ConfirmedOutputChunkLengths = pkg.OutputChunkLengths
	state.ConfirmedInputTokenIDs = workerValueEvidence.InputTokenIDs
	state.ConfirmedGeneratedTokenIDs = workerValueEvidence.GeneratedTokenIDs
	state.ConfirmedInferReceipt = pkg.SignedInferReceipt
	result, err := v.HandleOpenVerifyAccepted(ctx, state)
	if err != nil {
		return task, false, err
	}
	e.cfg.Trace.Event("verify_completed",
		tasktrace.Str("task", task.TaskID), tasktrace.Hash("task_hash", taskHash),
		tasktrace.Uint("verify_round", task.VerifyRound),
		tasktrace.Hash("output_hash", pkg.OutputHash), tasktrace.Hash("package_hash", pkg.PackageHash),
		tasktrace.Hash("infer_receipt_hash", inferReceiptHash),
		tasktrace.Hash("result_digest", result.ResultDigest), tasktrace.Hash("commit_hash", result.CommitHash),
		tasktrace.Hash("verification_sample_seed", result.VerificationSampleSeed),
		// The reveal is framed bytes, so the trace prints its length and its
		// digest rather than the blob: result_digest above is what identifies it,
		// and result_reveal_bytes is what tells an operator it is non-empty.
		tasktrace.Int("result_reveal_bytes", len(result.ResultReveal)),
		tasktrace.Int("main_mismatch_count", result.MainMismatchCount),
		tasktrace.Str("sample_value_sequence_ref", result.SampleValueSequenceRef),
		tasktrace.Bool("started", result.Started))
	// StageCommitted, not "succeeded": the commit is on chain and the reveal is
	// still owed. Marking the responsibility finished here is what let the reveal
	// disappear -- the record would be dropped from the active set and the
	// EventRevealPhaseStarted that opens the reveal would have nothing to land on.
	task.Stage = string(layout.StageCommitted)
	task.LastError = ""
	task.RetryAtUnixMilli = 0
	task.ReceiptDigest = result.ResultDigest
	return task, false, nil
}

// verifyRoundIdentity is the per-round identity both halves of the verify
// responsibility sign under: this node's current service binding, its frozen
// membership in the verifier window, and the handraise expiry that membership
// was granted with.
//
// It is read once per attempt rather than carried across the commit/reveal
// boundary on purpose. The service-key binding and its nonce are committed chain
// state that can be rotated between the two, and a reveal signed under a
// superseded nonce is a body the Keeper compares and rejects.
type verifyRoundIdentity struct {
	signerAddress         string
	authorizationNonce    uint64
	member                builderclient.CandidateMemberRefMessage
	inferReceiptHash      codec.Hash
	handraiseExpiryHeight uint64
}

func (e *productionVerifyExecutor) verifyRoundIdentity(ctx context.Context, taskHash codec.Hash, task store.VerifyTask) (verifyRoundIdentity, error) {
	signerAddress, _ := resolveSigningIdentity(e.cfg, e.cfg.LocalVerifierAddress)
	// TRUEOPEN_BUS_ENVELOPE_V1 field 7, and preimage field 6 of every frozen §5.14
	// verifier stage wire: one committed read of this node's current ServiceKey
	// binding serves both (interface-and-topic-list.md §5.2 field 7).
	authorizationNonce, _, err := e.cfg.TaskDataAuth.CommittedBusEnvelopeIdentity(ctx)
	if err != nil {
		return verifyRoundIdentity{}, builderclient.Retryable(fmt.Errorf("read current Cortex service binding for the verifier envelopes: %w", err))
	}
	member := builderclient.CandidateMemberRefMessage{}
	// InferReceiptDigest is the Keeper-accepted Worker receipt. ReceiptDigest is
	// this Verifier's own result and is necessarily empty before verification.
	inferReceiptHash := task.InferReceiptDigest
	expiryHeight := task.OpenVerifyHeight + e.cfg.VerifyDeadlineDeltaHeight
	if e.cfg.VerifierMemberReader != nil {
		// The frozen-set read, not the handraise one. A selected Verifier only
		// starts here after handraise_close_height has passed, so the handraise
		// question is already answered "no" and asking it turned every verify into
		// a retry that re-downloaded the output and could never succeed.
		candidate, err := e.cfg.VerifierMemberReader.FrozenVerifierWindowMember(ctx, task.TaskID, uint32(task.VerifyRound), e.cfg.LocalVerifierAddress)
		if err != nil {
			return verifyRoundIdentity{}, builderclient.Retryable(fmt.Errorf("query frozen verifier window member: %w", err))
		}
		member = builderclient.CandidateMemberRefMessage{
			CandidatePoolSnapshotID: candidate.CandidatePoolSnapshotID.Hex(), Slot: candidate.Slot,
			SlotVersion: candidate.SlotVersion, OperatorAddress: candidate.OperatorAddress,
		}
		if inferReceiptHash == (codec.Hash{}) || inferReceiptHash != codec.Hash(candidate.InferReceiptHash) {
			return verifyRoundIdentity{}, fmt.Errorf("verifier candidate window infer_receipt_hash does not match responsibility")
		}
		inferReceiptHash = codec.Hash(candidate.InferReceiptHash)
		expiryHeight = candidate.ExpiryHeight
	} else if e.cfg.FakeBus {
		member = builderclient.CandidateMemberRefMessage{
			CandidatePoolSnapshotID: hex.EncodeToString(taskHash[:]), Slot: 1, SlotVersion: 1,
			OperatorAddress: "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe",
		}
	} else {
		return verifyRoundIdentity{}, builderclient.Retryable(fmt.Errorf("verifier candidate member reader is required"))
	}
	if inferReceiptHash == (codec.Hash{}) || expiryHeight == 0 {
		return verifyRoundIdentity{}, fmt.Errorf("verifier responsibility lacks infer receipt hash or handraise expiry")
	}
	return verifyRoundIdentity{
		signerAddress: signerAddress, authorizationNonce: authorizationNonce,
		member: member, inferReceiptHash: inferReceiptHash, handraiseExpiryHeight: expiryHeight,
	}, nil
}

// runReveal is the second half of the verify responsibility: the frozen
// ResultReceiptV1 for a task whose commit is on chain and whose reveal phase the
// chain has opened.
//
// It confirms no output and runs no model. Every input the frozen result body
// needs is either chain state the reveal deadline effect already recorded or a
// Keeper read, and the verification itself happened in the commit half — its
// evidence is on disk. Re-confirming the output here would re-download it from
// the Builder once per retry for nothing.
//
// It also builds no commit submitter. The reveal travels the bus as VERIFY_RESULT
// (interface-and-topic-list.md §5.3), so requiring the direct transaction path here would
// fail a node closed for a route this half never takes.
func (e *productionVerifyExecutor) runReveal(ctx context.Context, taskHash codec.Hash, task store.VerifyTask) (store.VerifyTask, bool, error) {
	if task.RevealDeadlineHeight == 0 {
		// The runner does not schedule this case (awaitingRevealPhase skips it),
		// so reaching it means a caller bypassed that gate. Refusing here keeps
		// the fail-closed reading of a zero reveal deadline true wherever the
		// reveal is entered from.
		return task, false, fmt.Errorf("%w: task %s", verifier.ErrRevealPhaseNotStarted, task.TaskID)
	}
	e.cfg.Trace.Event("verify_reveal_started",
		tasktrace.Str("task", task.TaskID), tasktrace.Hash("task_hash", taskHash),
		tasktrace.Str("session", task.SessionID), tasktrace.Uint("verify_round", task.VerifyRound),
		tasktrace.Uint("commit_deadline_height", task.CommitDeadlineHeight),
		tasktrace.Uint("reveal_deadline_height", task.RevealDeadlineHeight),
		tasktrace.Uint("verify_deadline_height", task.DeadlineHeight))
	identity, err := e.verifyRoundIdentity(ctx, taskHash, task)
	if err != nil {
		return task, false, err
	}
	persistence := &evidenceVerifierPersistence{taskHash: taskHash, task: &task, evidence: e.cfg.Evidence, builder: e.cfg.Builder}
	v := verifier.New(verifier.Config{VerifierAddress: e.cfg.LocalVerifierAddress, ModelServiceID: e.cfg.ModelServiceID, Model: e.cfg.Model, Builder: e.cfg.Builder, Persistence: persistence, ChainID: e.cfg.ChainID, SignerAddress: identity.signerAddress, SignerKeyRef: e.cfg.SignerKeyRef, Signer: e.cfg.Signer, VerifyDeadlineDeltaHeight: e.cfg.VerifyDeadlineDeltaHeight, FakeOutput: e.cfg.FakeOutput, TrustedNATSDev: e.cfg.TrustedNATSDev || e.cfg.FakeBus, NexusEnvelopeSigner: e.cfg.NexusEnvelopeSigner, EnvelopeTTL: e.cfg.EnvelopeTTL, TaskFacts: e.cfg.TaskFacts, ServiceAuthorizationNonce: identity.authorizationNonce, ProfileReader: e.cfg.ProfileReader, MaxOutputBytes: e.cfg.MaxOutputBytes, Trace: e.cfg.Trace, EvidencePublisher: nexusVerifierEvidencePublisher{cfg: e.cfg, builderOperator: task.BuilderOperatorAddress}})
	state := verifier.TaskState{TaskID: task.TaskID, SessionID: task.SessionID, OrderSequence: task.OrderSequence, OrderDigest: task.OrderDigest, VerifyRound: task.VerifyRound, InferReceiptHash: identity.inferReceiptHash, Member: identity.member, ModelID: task.ModelID, ProfileVersion: task.ProfileVersion, Capability: task.Capability, WorkerAddress: task.WorkerAddress, OpenVerifyAccepted: true, AssignedVerifiers: append([]string(nil), task.AssignedVerifiers...), OpenVerifyHeight: task.OpenVerifyHeight, HandraiseExpiryHeight: identity.handraiseExpiryHeight, CurrentHeight: task.CurrentHeight, CommitDeadlineHeight: task.CommitDeadlineHeight, WorkerRevealDeadlineHeight: task.WorkerRevealDeadlineHeight, RevealDeadlineHeight: task.RevealDeadlineHeight, VerifyDeadlineHeight: task.DeadlineHeight, VerificationSampleSeed: task.VerificationSampleSeed}
	reveal, err := v.HandleRevealPhaseStarted(ctx, state)
	if err != nil {
		return task, false, err
	}
	e.cfg.Trace.Event("verify_reveal_completed",
		tasktrace.Str("task", task.TaskID), tasktrace.Hash("task_hash", taskHash),
		tasktrace.Uint("verify_round", task.VerifyRound),
		tasktrace.Hash("result_signing_digest", reveal.ResultSigningDigest),
		tasktrace.Uint("expiry_height", reveal.ExpiryHeight),
		tasktrace.Bool("published", reveal.Published))
	task.Stage = "succeeded"
	task.LastError = ""
	task.RetryAtUnixMilli = 0
	return task, false, nil
}

// commitSubmitter builds the direct commit submitter for one verify round.
//
// serviceAddress is the Keeper-confirmed current Cortex service address, the
// only legal outer Cosmos Tx signer for a self-submitted MsgSubmitVerifyCommit
// (keeper §10.6 rule 6). It is passed in rather than re-read so that the
// submitter's identity and the identity the commit body names as its submitter
// are the same value: SettlementManager rejects the pair if they ever differ.
//
// relayWired says whether this round has a relay to ask first. When it does, a
// node with no direct transaction path is a complete configuration rather than a
// broken one: nexus#70 relays the commit, and the order -- relay first,
// self-submission only on a deterministic refusal -- belongs to
// verifier.deliverCommit, which already treats a nil submitter as "the relay is
// the only route" and fails closed with ErrCommitExitUnavailable if that route
// refuses. Returning an error here instead is what kept the relay from ever
// being asked: commitSubmitter runs before the Verifier is even constructed, so
// on devnet three selected Verifiers signed nothing and retried
// "verifier commit exit requires a workload tx client" every 30s until the
// commit deadline, with the relay wired and idle beside them.
//
// Both refusals below stay fail-closed for the relay-less case. A missing tx
// client or an inactive workload then means the commit this verify is about to
// sign has nowhere to go, and finding that out after signing would leave the
// signature in a local evidence file and the chain with no CommitState -- the
// exact silence this exit closes.
func (e *productionVerifyExecutor) commitSubmitter(serviceAddress string, relayWired bool) (verifier.CommitSubmitter, error) {
	tx := resolveWorkloadTx(e.cfg)
	if tx == nil {
		if relayWired {
			return nil, nil
		}
		return nil, builderclient.Retryable(fmt.Errorf("verifier commit exit requires a workload tx client: the signed commit has no relay to travel on, so a node without a direct transaction path cannot put a commit on chain"))
	}
	if strings.TrimSpace(serviceAddress) == "" {
		return nil, builderclient.Retryable(fmt.Errorf("verifier commit exit requires the Keeper-confirmed current Cortex service address as the outer transaction signer"))
	}
	feeCap := e.cfg.CommitExitFeeCap
	if feeCap == (txclient.Coin{}) {
		feeCap = e.cfg.TxFeeCap
	}
	return verifier.NewSettlementManager(verifier.SettlementConfig{
		VerifierAddress: e.cfg.LocalVerifierAddress,
		WorkerAddress:   e.cfg.LocalWorkerAddress,
		// The submitter and the gas payer are the same current service address:
		// txclient.Broadcaster refuses a gas payer that is not the address its
		// signer resolves to, so naming anything else here fails closed.
		SubmitterAddress: serviceAddress,
		GasPayer:         serviceAddress,
		Tx:               tx,
		FeeCap:           e.cfg.TxFeeCap,
		CommitFeeCap:     feeCap,
	}), nil
}

// verifyTaskCommitments are the facts a verify responsibility carries into
// output confirmation. Every one of them was copied out of the Keeper snapshot
// when the chain admitted the responsibility, so a task admitted from
// OPEN_VERIFY alone confirms exactly as well as one whose OUTPUT_AVAILABLE hint
// arrived: the hint contributes nothing to this set.
func verifyTaskCommitments(task store.VerifyTask) (OutputCommitments, error) {
	var keeperReceipt *chainclient.InferReceiptSnapshot
	if len(task.KeeperReceiptJSON) > 0 {
		var receipt chainclient.InferReceiptSnapshot
		if err := json.Unmarshal(task.KeeperReceiptJSON, &receipt); err != nil {
			return OutputCommitments{}, fmt.Errorf("decode Keeper infer receipt: %w", err)
		}
		keeperReceipt = &receipt
	}
	return OutputCommitments{
		SessionID: task.SessionID, TaskID: task.TaskID,
		BuilderOperatorAddress: task.BuilderOperatorAddress,
		WorkerOperatorAddress:  task.WorkerAddress,
		OutputHash:             task.OutputDigest, PackageHash: task.PackageDigest,
		KeeperReceipt: keeperReceipt,
	}, nil
}

// inferReceiptRef holds only the metadata of a persisted infer receipt; the
// actual signed receipt bytes live in the evidence store under
// worker-infer-receipt:<material_digest>.
type inferReceiptRef struct {
	TaskID         string    `json:"task_id"`
	MaterialDigest string    `json:"material_digest"`
	CreatedAt      time.Time `json:"created_at"`
}

// builderMessageRef holds only the metadata of an outbox message; the payload
// lives in the evidence store under worker-outbox:<key>.
type builderMessageRef struct {
	Digest  string `json:"digest"`
	TaskID  string `json:"task_id"`
	Subject string `json:"subject"`
	Status  string `json:"status"`
}

// storageConfirmationRef holds only the metadata of a storage confirmation; the
// signature bytes live in the evidence store under
// worker-confirmation:<key>.
// evidenceWorkerPersistence persists worker artifacts in the evidence store and
// commits their references through the provided persist callback. It keeps no
// phase field; presence of an artifact in the store is the state.
type evidenceWorkerPersistence struct {
	taskHash    codec.Hash
	task        *store.InferTask
	evidence    *evidence.Store
	store       *store.Store
	builder     builderclient.Client
	persist     func(context.Context, codec.Hash, store.InferTask, layout.Evidence) error
	evidenceRef map[string]layout.EvidenceArtifact
}

func (p *evidenceWorkerPersistence) commitManifest(ctx context.Context) error {
	if p.persist == nil {
		return fmt.Errorf("infer checkpoint persistence is required")
	}
	artifacts := make([]layout.EvidenceArtifact, 0, len(p.evidenceRef))
	for _, a := range p.evidenceRef {
		artifacts = append(artifacts, a)
	}
	ev := layout.Evidence{TaskID: p.task.TaskID, SessionID: p.task.SessionID, Artifacts: artifacts}
	// An orphaned checkpoint is a success with nothing to write: the artifact
	// bytes are already durable in the evidence store, and the manifest they
	// would have been referenced from was deleted by a terminal Keeper effect.
	// Reporting it would abort the step the caller is in the middle of, which is
	// how a relayed-and-uploaded round used to lose its OUTPUT_AVAILABLE.
	if err := p.persist(ctx, p.taskHash, *p.task, ev); err != nil && !errors.Is(err, errInferCheckpointOrphaned) {
		return err
	}
	return nil
}

func (p *evidenceWorkerPersistence) trackArtifact(kind string, data []byte) {
	if p.evidenceRef == nil {
		p.evidenceRef = make(map[string]layout.EvidenceArtifact)
	}
	var ak layout.ArtifactKind
	switch {
	case kind == "task-input":
		ak = layout.ArtifactTaskInput
	case kind == "worker-output":
		ak = layout.ArtifactWorkerOutput
	case kind == "worker-trace":
		ak = layout.ArtifactWorkerTrace
	case kind == "worker-checkpoint":
		ak = layout.ArtifactWorkerCheckpoint
	case kind == "worker-batch-log":
		ak = layout.ArtifactWorkerBatchLog
	case kind == "worker-output-descriptor":
		ak = layout.ArtifactWorkerOutputDescriptor
	case kind == "worker-result":
		ak = layout.ArtifactWorkerResult
	case kind == "worker-infer-receipt", strings.HasPrefix(kind, "worker-infer-receipt:"):
		ak = layout.ArtifactInferReceipt
	default:
		// Operational artifacts such as outbox payloads and storage confirmations
		// are durable in the evidence store but are not part of the evidence manifest.
		return
	}
	p.evidenceRef[kind] = layout.EvidenceArtifact{Kind: ak, Digest: layout.StoredHash(codec.HashBytes(data)), Size: uint64(len(data))}
}

func (p *evidenceWorkerPersistence) WriteEvidence(ctx context.Context, r worker.EvidenceRecord) error {
	if err := writeTaskEvidence(ctx, p.evidence, p.taskHash, p.task.SessionID, p.task.TaskID, r.Kind, r.Data); err != nil {
		return err
	}
	p.trackArtifact(r.Kind, r.Data)
	return p.commitManifest(ctx)
}

// CheckpointInferOutput writes the output, trace, checkpoint and output
// descriptor artifacts and commits their references, the InferRecord finish
// reason, and the output CID/digest in a single MergeInferWithEvidence batch.
func (p *evidenceWorkerPersistence) CheckpointInferOutput(ctx context.Context, taskID string, output, trace, checkpoint []byte, cp worker.InferOutputCheckpoint) error {
	if p.store == nil {
		return fmt.Errorf("infer checkpoint store is required")
	}
	// Write the artifact bytes to the evidence store first. Their digests are
	// then included in the evidence manifest below.
	artifacts := []struct {
		kind string
		data []byte
	}{
		{kind: "worker-output", data: output},
		{kind: "worker-trace", data: trace},
		{kind: "worker-checkpoint", data: checkpoint},
		{kind: "worker-output-descriptor", data: cp.DescriptorJSON},
	}
	for _, a := range artifacts {
		if err := writeTaskEvidence(ctx, p.evidence, p.taskHash, p.task.SessionID, taskID, a.kind, a.data); err != nil {
			return err
		}
	}
	var evidenceArtifacts []layout.EvidenceArtifact
	for _, a := range artifacts {
		var ak layout.ArtifactKind
		switch a.kind {
		case "worker-output":
			ak = layout.ArtifactWorkerOutput
		case "worker-trace":
			ak = layout.ArtifactWorkerTrace
		case "worker-checkpoint":
			ak = layout.ArtifactWorkerCheckpoint
		case "worker-output-descriptor":
			ak = layout.ArtifactWorkerOutputDescriptor
		}
		evidenceArtifacts = append(evidenceArtifacts, layout.EvidenceArtifact{
			Kind:   ak,
			Digest: layout.StoredHash(codec.HashBytes(a.data)),
			Size:   uint64(len(a.data)),
		})
	}
	rec, err := layout.GetInferRecord(ctx, p.store, layout.StoredHash(p.taskHash))
	if err != nil {
		// Same race, same answer as commitManifest: the artifacts above are
		// already durable and the record this would merge into is gone.
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}
	rec.FinishReason = toLayoutFinishReason(cp.FinishReason)
	if cp.OutputCID != "" {
		rec.OutputCID = cp.OutputCID
	}
	rec.OutputDigest = layout.StoredHash(cp.OutputHash)
	ev := layout.Evidence{
		TaskID:    p.task.TaskID,
		SessionID: p.task.SessionID,
		Artifacts: evidenceArtifacts,
	}
	return layout.MergeInferWithEvidence(ctx, p.store, layout.StoredHash(p.taskHash), rec, ev)
}

func (p *evidenceWorkerPersistence) ReadArtifact(ctx context.Context, taskID, kind string) ([]byte, error) {
	if p.evidence == nil {
		return nil, fmt.Errorf("evidence store is unavailable")
	}
	data, err := p.evidence.ReadTaskKind(ctx, p.taskHash, kind)
	if errors.Is(err, evidence.ErrArtifactNotFound) {
		return nil, fmt.Errorf("%w: %w", worker.ErrCheckpointNotFound, err)
	}
	return data, err
}

func (p *evidenceWorkerPersistence) OutputStreamFrames(ctx context.Context, taskID string) ([]builderclient.OutputChunk, error) {
	if p.evidence == nil || p.task.TaskID != taskID {
		return nil, fmt.Errorf("output stream journal identity mismatch or evidence unavailable")
	}
	artifacts, err := p.evidence.TaskArtifacts(ctx, p.taskHash)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var frames []builderclient.OutputChunk
	for _, artifact := range artifacts {
		kind := string(artifact.Kind)
		if !strings.HasPrefix(kind, worker.OutputStreamFramePrefix) {
			continue
		}
		data, err := p.evidence.ReadTaskKind(ctx, p.taskHash, kind)
		if err != nil {
			return nil, err
		}
		var frame builderclient.OutputChunk
		if err := json.Unmarshal(data, &frame); err != nil {
			return nil, err
		}
		if kind != worker.OutputStreamFrameKind(frame.Seq) {
			return nil, fmt.Errorf("output stream journal frame key mismatch")
		}
		frames = append(frames, frame)
	}
	sort.Slice(frames, func(i, j int) bool { return frames[i].Seq < frames[j].Seq })
	for i, frame := range frames {
		if frame.Seq != uint64(i) {
			return nil, fmt.Errorf("output stream journal has a gap or duplicate")
		}
	}
	return frames, nil
}

func (p *evidenceWorkerPersistence) WriteBuilderOutbox(ctx context.Context, r worker.OutboxRecord) error {
	if p.evidence == nil {
		return fmt.Errorf("evidence store is required to persist outbox payload")
	}
	key := strings.TrimSpace(r.DedupID)
	if key == "" {
		key = hex.EncodeToString(r.Digest[:])
	}
	if err := writeTaskEvidence(ctx, p.evidence, p.taskHash, p.task.SessionID, r.TaskID, "worker-outbox:"+key, r.Payload); err != nil {
		return err
	}
	if r.Status == "pending" && p.builder != nil {
		if err := p.builder.Publish(ctx, builderclient.PublishRequest{Subject: r.Subject, TaskID: r.TaskID, Payload: r.Payload, DedupID: key}); err != nil {
			return builderclient.Retryable(err)
		}
	}
	return nil
}

func (p *evidenceWorkerPersistence) CheckpointModelJob(context.Context, worker.ModelJobCheckpoint) error {
	return nil
}

func (p *evidenceWorkerPersistence) CheckpointInferReceipt(ctx context.Context, r worker.InferReceiptCheckpoint) error {
	if r.MaterialDigest == "" {
		return fmt.Errorf("infer receipt checkpoint for %s requires a material digest", r.TaskID)
	}
	if p.evidence == nil {
		return fmt.Errorf("evidence store is required to persist infer receipt payload")
	}
	if err := writeTaskEvidence(ctx, p.evidence, p.taskHash, p.task.SessionID, r.TaskID, "worker-infer-receipt:"+r.MaterialDigest, r.Payload); err != nil {
		return err
	}
	p.trackArtifact("worker-infer-receipt:"+r.MaterialDigest, r.Payload)
	return p.commitManifest(ctx)
}

func (p *evidenceWorkerPersistence) InferReceipts(ctx context.Context, _ string) ([]worker.InferReceiptCheckpoint, error) {
	artifacts, err := p.evidence.TaskArtifacts(ctx, p.taskHash)
	if err != nil {
		return nil, err
	}
	var out []worker.InferReceiptCheckpoint
	for _, a := range artifacts {
		kind := string(a.Kind)
		if !strings.HasPrefix(kind, "worker-infer-receipt:") {
			continue
		}
		digest := strings.TrimPrefix(kind, "worker-infer-receipt:")
		payload, err := p.evidence.ReadTaskKind(ctx, p.taskHash, kind)
		if err != nil {
			return nil, fmt.Errorf("infer receipt payload missing for %s: %w", digest, err)
		}
		out = append(out, worker.InferReceiptCheckpoint{TaskID: p.task.TaskID, MaterialDigest: digest, Payload: payload})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MaterialDigest < out[j].MaterialDigest })
	return out, nil
}

func (p *evidenceWorkerPersistence) CheckpointStorageConfirmation(ctx context.Context, r worker.StorageConfirmationCheckpoint) error {
	if p.evidence == nil {
		return fmt.Errorf("evidence store is required to persist storage confirmation")
	}
	key := storageConfirmationKey(r)
	meta := storageConfirmationMeta{
		TaskID: r.TaskID, DataKind: r.DataKind, EvidenceType: r.EvidenceType, EvidenceArtifactID: r.EvidenceArtifactID,
		BuilderOperator: r.BuilderOperator, MaterialDigest: r.MaterialDigest,
		SemanticHash: r.SemanticHash, SizeBytes: r.SizeBytes, RetentionUntilHeight: r.RetentionUntilHeight,
		BuilderServicePubkey: r.BuilderServicePubkey, VerifiedAt: r.VerifiedAt,
		Confirmation: r.Confirmation,
		Signature:    append([]byte(nil), r.Signature...),
	}
	kind := "worker-confirmation-meta:" + key
	artifacts, err := p.evidence.TaskArtifacts(ctx, p.taskHash)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	for _, artifact := range artifacts {
		if string(artifact.Kind) != kind {
			continue
		}
		previous, err := p.evidence.ReadTaskKind(ctx, p.taskHash, kind)
		if err != nil {
			return err
		}
		var saved storageConfirmationMeta
		if err := json.Unmarshal(previous, &saved); err != nil {
			return err
		}
		// Preserve the first verified timestamp when Nexus returns the same receipt.
		meta.VerifiedAt = saved.VerifiedAt
		current, err := json.Marshal(meta)
		if err != nil {
			return err
		}
		if !bytes.Equal(current, previous) {
			return fmt.Errorf("storage confirmation checkpoint conflicts with persisted material")
		}
		return p.commitManifest(ctx)
	}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("encode storage confirmation metadata: %w", err)
	}
	if err := writeTaskEvidence(ctx, p.evidence, p.taskHash, p.task.SessionID, r.TaskID, kind, metaBytes); err != nil {
		return err
	}
	return p.commitManifest(ctx)
}

func storageConfirmationKey(r worker.StorageConfirmationCheckpoint) string {
	return r.DataKind + ":" + r.BuilderOperator + ":" + r.MaterialDigest
}

func (p *evidenceWorkerPersistence) StorageConfirmations(ctx context.Context, _ string) ([]worker.StorageConfirmationCheckpoint, error) {
	artifacts, err := p.evidence.TaskArtifacts(ctx, p.taskHash)
	if err != nil {
		return nil, err
	}
	var records []worker.StorageConfirmationCheckpoint
	for _, a := range artifacts {
		kind := string(a.Kind)
		if !strings.HasPrefix(kind, "worker-confirmation-meta:") {
			continue
		}
		key := strings.TrimPrefix(kind, "worker-confirmation-meta:")
		metaBytes, err := p.evidence.ReadTaskKind(ctx, p.taskHash, kind)
		if err != nil {
			return nil, fmt.Errorf("storage confirmation metadata missing for %s: %w", key, err)
		}
		var meta storageConfirmationMeta
		if err := json.Unmarshal(metaBytes, &meta); err != nil {
			return nil, fmt.Errorf("decode storage confirmation metadata: %w", err)
		}
		sig := meta.Signature
		if len(sig) == 0 && meta.Confirmation != nil {
			sig = meta.Confirmation.Signature
		}
		if len(sig) == 0 {
			sig, err = p.evidence.ReadTaskKind(ctx, p.taskHash, "worker-confirmation:"+key)
			if err != nil {
				return nil, fmt.Errorf("storage confirmation signature missing for %s: %w", key, err)
			}
		}
		records = append(records, worker.StorageConfirmationCheckpoint{
			TaskID: meta.TaskID, DataKind: meta.DataKind, EvidenceType: meta.EvidenceType,
			EvidenceArtifactID: meta.EvidenceArtifactID,
			BuilderOperator:    meta.BuilderOperator, MaterialDigest: meta.MaterialDigest,
			SemanticHash: meta.SemanticHash, SizeBytes: meta.SizeBytes, RetentionUntilHeight: meta.RetentionUntilHeight,
			BuilderServicePubkey: meta.BuilderServicePubkey, VerifiedAt: meta.VerifiedAt, Signature: sig,
			Confirmation: meta.Confirmation,
		})
	}
	sort.Slice(records, func(i, j int) bool { return storageConfirmationKey(records[i]) < storageConfirmationKey(records[j]) })
	return records, nil
}

func (p *evidenceWorkerPersistence) CheckpointInferInput(ctx context.Context, r worker.InferInputCheckpoint) error {
	if p.evidence == nil {
		return fmt.Errorf("evidence store is required to persist infer input")
	}
	if err := writeTaskEvidence(ctx, p.evidence, p.taskHash, p.task.SessionID, p.task.TaskID, "worker-input", r.Payload); err != nil {
		return err
	}
	p.trackArtifact("worker-input", r.Payload)
	return p.commitManifest(ctx)
}

func (p *evidenceWorkerPersistence) InferInput(ctx context.Context, _ string) (worker.InferInputCheckpoint, error) {
	if p.evidence == nil {
		return worker.InferInputCheckpoint{}, worker.ErrCheckpointNotFound
	}
	data, err := p.evidence.ReadTaskKind(ctx, p.taskHash, "worker-input")
	if err != nil {
		return worker.InferInputCheckpoint{}, worker.ErrCheckpointNotFound
	}
	return worker.InferInputCheckpoint{TaskID: p.task.TaskID, Payload: data}, nil
}

func (p *evidenceWorkerPersistence) BuilderMessage(ctx context.Context, digest string) (worker.BuilderMessageCheckpoint, error) {
	if p.evidence == nil {
		return worker.BuilderMessageCheckpoint{}, fmt.Errorf("evidence store is required to read outbox payload")
	}
	payload, err := p.evidence.ReadTaskKind(ctx, p.taskHash, "worker-outbox:"+digest)
	if err != nil {
		return worker.BuilderMessageCheckpoint{}, worker.ErrCheckpointNotFound
	}
	return worker.BuilderMessageCheckpoint{Digest: digest, TaskID: p.task.TaskID, Payload: payload, Status: "sent"}, nil
}

// storageConfirmationMeta is the durable metadata for a storage confirmation.
type storageConfirmationMeta struct {
	Signature            []byte                             `json:"signature"`
	Confirmation         *builderclient.StorageConfirmation `json:"confirmation,omitempty"`
	TaskID               string                             `json:"task_id"`
	DataKind             string                             `json:"data_kind"`
	EvidenceType         string                             `json:"evidence_type,omitempty"`
	EvidenceArtifactID   string                             `json:"evidence_artifact_id,omitempty"`
	BuilderOperator      string                             `json:"builder_operator"`
	MaterialDigest       string                             `json:"material_digest"`
	SemanticHash         string                             `json:"semantic_hash"`
	SizeBytes            uint64                             `json:"size_bytes"`
	RetentionUntilHeight uint64                             `json:"retention_until_height"`
	BuilderServicePubkey string                             `json:"builder_service_pubkey"`
	VerifiedAt           time.Time                          `json:"verified_at"`
}

func toLayoutFinishReason(r nodewire.FinishReasonV1) layout.FinishReasonV1 {
	switch r {
	case nodewire.FinishReasonV1EosToken:
		return layout.FinishReasonEOS
	case nodewire.FinishReasonV1StopSequence:
		return layout.FinishReasonStopSequence
	case nodewire.FinishReasonV1MaxOutputTokens:
		return layout.FinishReasonMaxOutputTokens
	case nodewire.FinishReasonV1MaxOutputDuration:
		return layout.FinishReasonMaxOutputDuration
	default:
		return layout.FinishReasonUnknown
	}
}

// evidenceVerifierPersistence persists verifier artifacts in the evidence store.
type evidenceVerifierPersistence struct {
	taskHash codec.Hash
	task     *store.VerifyTask
	evidence *evidence.Store
	builder  builderclient.Client
}

func (p *evidenceVerifierPersistence) WriteEvidence(ctx context.Context, r verifier.EvidenceRecord) error {
	return writeTaskEvidence(ctx, p.evidence, p.taskHash, p.task.SessionID, p.task.TaskID, r.Kind, r.Data)
}
func (p *evidenceVerifierPersistence) WriteSettleMaterial(ctx context.Context, r verifier.SettleMaterial) error {
	return writeTaskEvidence(ctx, p.evidence, p.taskHash, p.task.SessionID, p.task.TaskID, "settlement-"+r.Kind, r.Payload)
}
func (p *evidenceVerifierPersistence) ReadVerifierEvidence(ctx context.Context, kind string) ([]byte, error) {
	return p.evidence.ReadTaskKind(ctx, p.taskHash, kind)
}
func (p *evidenceVerifierPersistence) CheckpointModelJob(context.Context, verifier.ModelJobCheckpoint) error {
	return nil
}
func (p *evidenceVerifierPersistence) WriteVerifierBuilderOutbox(ctx context.Context, r verifier.OutboxRecord) error {
	if p.builder == nil {
		return errors.New("builder client is required")
	}
	return p.builder.Publish(ctx, builderclient.PublishRequest{Subject: r.Subject, TaskID: r.TaskID, Payload: r.Payload, DedupID: r.DedupID})
}

func writeTaskEvidence(ctx context.Context, s *evidence.Store, taskHash codec.Hash, sessionID, taskID, kind string, data []byte) error {
	if s == nil {
		return fmt.Errorf("task runner evidence store is required")
	}
	_, err := s.Write(ctx, evidence.WriteRequest{TaskHash: taskHash, SessionID: sessionID, TaskID: taskID, Kind: kind, Data: data})
	return err
}

var _ worker.Persistence = (*evidenceWorkerPersistence)(nil)
var _ verifier.Persistence = (*evidenceVerifierPersistence)(nil)
