package worker

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

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
	"github.com/TrueOpen/cortex/internal/tasktrace"
	"github.com/TrueOpen/cortex/internal/txclient"
	busv1 "github.com/TrueOpen/cortex/proto/bus/v1"
)

type Config struct {
	WorkerAddress             string
	ModelServiceID            string
	Model                     modelservice.Client
	Builder                   builderclient.Client
	TaskData                  builderclient.TaskDataClient
	TaskDataAuth              *taskdataauth.Authenticator
	Tx                        txclient.Client
	Persistence               Persistence
	InferDeadlineDeltaHeights uint64
	ChainID                   string
	SessionID                 string
	OrderSequence             uint64
	SignerAddress             string
	SignerKeyRef              string
	// SignerPubkey is the compressed secp256k1 public key of the online service
	// key, lower hex. Nexus derives the signer address from it, so a submission
	// cannot be authenticated without it.
	SignerPubkey        string
	Signer              signer.DigestSigner
	FakeOutput          bool
	TrustedNATSDev      bool
	PackageStore        builderclient.OutputPackageStore
	NexusEnvelopeSigner builderclient.BusEnvelopeSigner
	// EnvelopeTTL is the lifetime stamped on outbound envelopes. Zero keeps the
	// envelope default.
	EnvelopeTTL time.Duration
	// ReceivingBuilder resolves the receiving Builder's endpoint and service
	// key at one pinned chain height for output relay and confirmation
	// verification.
	ReceivingBuilder ReceivingBuilderProvider
	// TaskFacts reads TaskCoreState.accepted_task_hash and
	// TaskAssignmentViewV1.generation_params_digest for the assignment being
	// worked. Both are signed fields of the frozen InferReceiptV3 that no local
	// derivation can produce, so the receipt path refuses without this reader.
	TaskFacts        taskfacts.Reader
	GenerationReader GenerationReader
	// EvidenceSchemaHash and ProfileEvidenceRequirements are copied from the
	// locked Query/Profile typed evidence schema for this task's model/profile.
	// They are immutable receipt inputs and are never locally defaulted.
	EvidenceSchemaHash          string
	ProfileEvidenceRequirements []builderclient.InferEvidenceRequirement
	// RequiredTopK is the locked Profile's required_top_k: every normal
	// worker_values leaf carries exactly this many top-k entries.
	RequiredTopK uint32
	// TaskBuilderSet is the BuilderSet reference this task's outbound bus
	// envelopes carry in fields 11 and 12 (interface-and-topic-list.md §5.2 fields 11-12).
	//
	// A Worker instance is constructed per task responsibility
	// (daemon.productionInferExecutor.RunInfer), so this is per-task state, not a
	// process-wide setting. It is Task state on the chain, not something Cortex
	// derives: the daemon copies it out of the admitted task record, which took it
	// from the authenticated frame that opened the task. Absent, it is a refusal -
	// §5.2 forbids an empty builder_set_id on a task-control message.
	// CrashHook, if non-nil, is called at named durable-handoff points. Returning
	// an error aborts the current pass and surfaces it to the caller. Tests use
	// it to simulate a crash between durable writes.
	CrashHook func(point string) error
	// SnapshotReader re-reads the on-chain task assignment before the worker
	// begins (and while building the receipt) so that event spoofing or a stale
	// assignment cannot be turned into a signed receipt.
	SnapshotReader SnapshotReader
	// Trace reports the digests this Worker derives -- the receipt's own signing
	// digest, the evidence commitment, the output and package hashes, the relay
	// and upload licences -- as they are produced. Every one of them is a value
	// some peer derives independently, so a disagreement is diagnosable only if
	// both sides can be read. Nil is silent.
	Trace          *tasktrace.Trace
	StreamLimits   *chainclient.OutputStreamLimitsSnapshot
	MaxOutputBytes uint64
}

// SnapshotReader reads the current canonical task state from the chain.
type SnapshotReader interface {
	TaskSnapshot(ctx context.Context, taskID string) (chainclient.TaskSnapshot, error)
}

// workerValueEvidenceInputs are the two Worker evidence commitment inputs the
// receipt wire does not carry.
type workerValueEvidenceInputs struct {
	// EvidenceSchemaHash is the locked Profile's
	// verification_profile.evidence_schema_hash, canonical lowercase 64-hex.
	EvidenceSchemaHash string `json:"evidence_schema_hash"`
	// FinishReason is the Worker's committed successful termination outcome.
	FinishReason nodewire.FinishReasonV1 `json:"finish_reason"`
}

type Worker struct {
	outputStream       builderclient.TaskOutputStream
	outputStreamTaskID string
	cfg                Config
	receipts           map[string]ReceiptState
	results            map[string]InferResult
	reveals            map[string]WorkerRevealResult
	snapshot           chainclient.TaskSnapshot
}

// producedOutput holds the material produced by a single inference run.
type producedOutput struct {
	event                   chainclient.AssignmentFinalized
	jobID                   string
	output                  []byte
	tokenIDs                []byte
	positionValues          []byte
	batchLog                []byte
	canonicalReceiptPayload []byte
	canonicalReceiptDigest  codec.Hash
	receipt                 builderclient.SignedInferReceipt
	workerValueEvidence     workerValueEvidenceInputs
	subject                 string
	outputCID               string
	availablePayload        []byte
	result                  InferResult
}

// outputDescriptor captures the immutable identities produced by one inference
// pass. It is written as a separate artifact so that receipt construction and
// the output-availability message can each be retried after a crash without
// re-running the model.
type outputDescriptor struct {
	JobID               string                  `json:"job_id"`
	OutputRef           string                  `json:"output_ref"`
	TokenIDsRef         string                  `json:"token_ids_ref"`
	PositionValuesRef   string                  `json:"position_values_ref"`
	OutputHash          codec.Hash              `json:"output_hash"`
	PackageHash         codec.Hash              `json:"package_hash"`
	OutputCID           string                  `json:"output_cid"`
	FinishReason        nodewire.FinishReasonV1 `json:"finish_reason"`
	GeneratedTokenCount uint64                  `json:"generated_token_count"`
	OutputChunkLengths  []uint64                `json:"output_chunk_lengths"`
}

// InferOutputCheckpoint carries the durable identities produced by one
// inference pass so that the persistence layer can commit the artifact refs and
// InferRecord finish reason in a single batch.
type InferOutputCheckpoint struct {
	JobID             string
	OutputRef         string
	TokenIDsRef       string
	PositionValuesRef string
	OutputHash        codec.Hash
	PackageHash       codec.Hash
	OutputCID         string
	FinishReason      nodewire.FinishReasonV1
	DescriptorJSON    []byte
}
type Persistence interface {
	WriteEvidence(context.Context, EvidenceRecord) error
	ReadArtifact(context.Context, string, string) ([]byte, error)
	WriteBuilderOutbox(context.Context, OutboxRecord) error
	CheckpointModelJob(context.Context, ModelJobCheckpoint) error
	CheckpointInferReceipt(context.Context, InferReceiptCheckpoint) error
	InferReceipts(context.Context, string) ([]InferReceiptCheckpoint, error)
	CheckpointStorageConfirmation(context.Context, StorageConfirmationCheckpoint) error
	CheckpointInferInput(context.Context, InferInputCheckpoint) error
	InferInput(context.Context, string) (InferInputCheckpoint, error)
	StorageConfirmations(context.Context, string) ([]StorageConfirmationCheckpoint, error)
	OutputStreamFrames(context.Context, string) ([]builderclient.OutputChunk, error)
	BuilderMessage(context.Context, string) (BuilderMessageCheckpoint, error)
	// CheckpointInferOutput persists the output, the model token-id and
	// position-value material and the output
	// descriptor for an inference pass together with the InferRecord finish reason
	// in a single durable batch. The descriptor is also stored as an artifact.
	CheckpointInferOutput(context.Context, string, []byte, []byte, []byte, InferOutputCheckpoint) error
	// PublishWorkerBundle publishes one Worker evidence bundle write-once: its
	// canonical manifest and every artifact the manifest references.
	PublishWorkerBundle(ctx context.Context, taskID string, kind nodewire.EvidenceKind, manifest []byte, artifacts [][]byte) error
	// WorkerBundle reads a published Worker bundle back: the exact manifest
	// bytes and its artifacts keyed by artifact id.
	WorkerBundle(ctx context.Context, taskID string, kind nodewire.EvidenceKind) ([]byte, map[string][]byte, error)
}

var ErrCheckpointNotFound = errors.New("worker checkpoint not found")

type ModelJobCheckpoint struct{ JobID, TaskID, Role, ModelServiceID, Status, Intent string }
type InferReceiptCheckpoint struct {
	TaskID, MaterialDigest string
	Payload                []byte
	CreatedAt              time.Time
}
type InferInputCheckpoint struct {
	TaskID    string
	Payload   []byte
	CreatedAt time.Time
}
type BuilderMessageCheckpoint struct {
	Digest, TaskID, Subject, Status string
	Payload                         []byte
}

// StorageConfirmationCheckpoint is the durable record of one verified Builder
// storage confirmation. SemanticHash is the content commitment for whichever
// kind DataKind names, so it is the value an EVIDENCE resume matches on.
// EvidenceType and EvidenceArtifactID are EVIDENCE-only and empty for OUTPUT;
// they are recorded so an operator can tell which artifact a record belongs to
// without re-hashing the artifact.
type StorageConfirmationCheckpoint struct {
	Confirmation                                                    *builderclient.StorageConfirmation `json:"confirmation,omitempty"`
	TaskID, DataKind, BuilderOperator, MaterialDigest, SemanticHash string
	EvidenceType, EvidenceArtifactID                                string
	SizeBytes, RetentionUntilHeight                                 uint64
	Signature                                                       []byte
	BuilderServicePubkey                                            string
	VerifiedAt                                                      time.Time
}

type EvidenceRecord struct {
	TaskID string
	Kind   string
	Data   []byte
	Ref    string
}

type OutboxRecord struct {
	TaskID  string
	Subject string
	Payload []byte
	Digest  codec.Hash
	Status  string
	// DedupID is a stable per-logical-event identifier used for transport-level
	// deduplication. It must survive envelope regeneration.
	DedupID string
}

type InferReceipt struct {
	TaskID              string
	OutputRef           string
	OutputHash          codec.Hash
	PackageHash         codec.Hash
	ReceiptResultHash   codec.Hash
	ActualOutputSummary string
}

type InferResult struct {
	Started             bool
	InferDeadlineHeight uint64
	OutputRef           string
	// OutputCID is the address of the output in the package store and is not the same
	// value as OutputRef (the model artifact address). The daemon's checkpoint and its
	// execution result both write to the same write-once InferRecord.OutputCID, so both
	// sides have to take this one value.
	OutputCID       string
	PackageHash     codec.Hash
	Receipt         InferReceipt
	SignedReceipt   identity.SignedEnvelope
	TaskDataReceipt builderclient.SignedInferReceipt
}

type ReceiptState struct {
	TaskID string
	// SessionID is local routing context only. The frozen receipt wire locates a
	// task by task_id alone, but the vendored Keeper Query still keys by
	// (session_id, task_id), so the confirmer needs it on the request envelope.
	SessionID            string
	InferReceiptAccepted bool
	OpenVerifyAccepted   bool
	WorkerRevealDeadline uint64
	SelfRescueMargin     uint64
	// ReceiptOnlyRescue is the frozen task.v1.MsgSubmitInferReceipt body the
	// selected worker self-submits when the Task Builder relay is late.
	ReceiptOnlyRescue   txclient.SubmitInferReceiptMessage
	SelfRescueSubmitted bool
	SelfRescueTx        txclient.Observation
}

type WorkerHandraiseRequest struct {
	TaskID                    string
	SessionID                 string
	OrderSequence             uint64
	TaskHash                  codec.Hash
	ModelID                   string
	ProfileVersion            uint32
	Member                    builderclient.CandidateMemberRefMessage
	CurrentHeight             uint64
	HandraiseExpireHeight     uint64
	BuilderSelectionDigest    codec.Hash
	ServiceAuthorizationNonce uint64
	Precheck                  policy.WorkerPrecheckInput
}

type WorkerHandraiseResult struct {
	Signed   bool
	Decision policy.WorkerDecision
	Payload  []byte
	// DedupID is the stable transport dedup ID for this handraise. It survives
	// envelope regeneration and must be used by any caller that republishes.
	DedupID string
}

type WorkerRevealTrigger struct {
	SessionID                  string
	TaskID                     string
	VerifyRound                uint64
	InferReceiptHash           codec.Hash
	VerificationSampleSeed     codec.Hash
	SelectedPositions          []uint64
	SampledValueSet            [][]byte
	OpeningMaterial            []byte
	SampleEncodingProfile      string
	SourceRootKind             string
	EvidenceSchemaVersion      string
	WorkerRevealDeadlineHeight uint64
}

type WorkerRevealReceipt struct {
	TaskID                 string
	VerifyRound            uint64
	WorkerAddress          string
	InferReceiptHash       codec.Hash
	VerificationSampleSeed codec.Hash
	SelectedPositions      []uint64
	SampledValueSetHash    codec.Hash
	SampleEncodingProfile  string
	SourceRootKind         string
	EvidenceSchemaVersion  string
	WorkerSignature        []byte
}

type WorkerRevealResult struct {
	Receipt WorkerRevealReceipt
	Payload []byte
}

// crashAt invokes the configured crash hook, if any. It is a no-op in
// production and returns any error the hook produces so the caller aborts.
func (w *Worker) crashAt(point string) error {
	if w.cfg.CrashHook == nil {
		return nil
	}
	return w.cfg.CrashHook(point)
}

func New(cfg Config) *Worker {
	return &Worker{
		cfg: cfg, receipts: make(map[string]ReceiptState), results: make(map[string]InferResult),
		reveals: make(map[string]WorkerRevealResult),
	}
}

func (w *Worker) HandleAssignmentAccepted(_ context.Context, _ chainclient.AssignmentAccepted) error {
	return nil
}

func (w *Worker) EvaluateAndHandraise(ctx context.Context, req WorkerHandraiseRequest) (WorkerHandraiseResult, error) {
	if err := validateWorkerHandraiseRequest(req); err != nil {
		return WorkerHandraiseResult{Decision: policy.WorkerDecision{Accepted: false, RejectCode: canonicalTaskRejectCode(err)}}, nil
	}
	decision := policy.EvaluateWorkerPrecheck(req.Precheck)
	if !decision.Accepted {
		return WorkerHandraiseResult{Decision: decision}, nil
	}
	taskID, err := builderclient.CanonicalWireHash(req.TaskID, "task_id")
	if err != nil {
		return WorkerHandraiseResult{}, err
	}
	member, err := req.Member.Nodewire()
	if err != nil {
		return WorkerHandraiseResult{}, err
	}
	modelID, err := identity.ModelIDBytes(req.ModelID)
	if err != nil {
		return WorkerHandraiseResult{}, err
	}
	handraise := nodewire.WorkerHandraiseV1{
		SchemaVersion: builderclient.WorkerHandraiseSchemaV1, ChainID: w.cfg.ChainID,
		TaskID: taskID[:], TaskHash: append([]byte(nil), req.TaskHash[:]...),
		ModelID: modelID, ProfileVersion: req.ProfileVersion, Member: member,
		Duty:                      nodewire.DutyWorker,
		ServiceAuthorizationNonce: req.ServiceAuthorizationNonce, ExpiryHeight: req.HandraiseExpireHeight,
	}
	wireDigest, err := nodewire.WorkerHandraiseSigningDigest(handraise)
	if err != nil {
		return WorkerHandraiseResult{}, err
	}
	serviceSignature, err := w.signDigest(ctx, wireDigest)
	if err != nil {
		return WorkerHandraiseResult{}, err
	}
	handraise.ServiceSignature = serviceSignature
	message, err := builderclient.WorkerHandraiseProto(handraise)
	if err != nil {
		return WorkerHandraiseResult{}, err
	}
	subject := builderclient.NATSWorkerHandraiseSubject(req.TaskID)
	payload, err := w.encodeNexusMessage(builderclient.UnsignedEnvelopeInput{
		Kind: builderclient.KindWorkerHandraise, ChainID: w.cfg.ChainID, Subject: subject,
		SenderOperatorAddress: w.cfg.WorkerAddress, SenderParticipantType: builderclient.ParticipantCortex,
		ServiceAuthorizationNonce: req.ServiceAuthorizationNonce,
	}, message)
	if err != nil {
		return WorkerHandraiseResult{}, err
	}
	handraiseDedupID := builderclient.WorkerHandraiseDedupID(req.TaskID, hex.EncodeToString(wireDigest[:]))
	if err := w.persistWorkerHandraise(ctx, req.TaskID, subject, payload, handraiseDedupID); err != nil {
		return WorkerHandraiseResult{}, err
	}
	return WorkerHandraiseResult{Signed: true, Decision: decision, Payload: payload, DedupID: handraiseDedupID}, nil
}

func (w *Worker) HandleAssignmentFinalized(ctx context.Context, event chainclient.AssignmentFinalized) (InferResult, error) {
	defer w.closeOutputStream()
	return w.handleAssignmentFinalized(ctx, event)
}

// handleAssignmentFinalized processes an assignment using presence-driven recovery.
func (w *Worker) handleAssignmentFinalized(ctx context.Context, event chainclient.AssignmentFinalized) (InferResult, error) {
	if event.Winner != w.cfg.WorkerAddress {
		return InferResult{}, nil
	}
	if err := validateAssignmentIdentity(event); err != nil {
		return InferResult{}, err
	}
	if !w.cfg.FakeOutput {
		if _, _, err := w.taskGeneration(ctx, event); err != nil {
			return InferResult{}, err
		}
	}
	if result, ok := w.results[event.TaskID]; ok {
		return result, nil
	}
	if w.cfg.Persistence == nil {
		return InferResult{}, fmt.Errorf("worker output persistence is required")
	}
	if err := w.requireInferDependencies(); err != nil {
		return InferResult{}, err
	}
	snapshot, err := w.cfg.SnapshotReader.TaskSnapshot(ctx, event.TaskID)
	if err != nil {
		return InferResult{}, fmt.Errorf("read task snapshot: %w", err)
	}
	if err := w.validateSnapshot(event, snapshot); err != nil {
		return InferResult{}, err
	}
	w.snapshot = snapshot

	// Ensure input: fetch if not present.
	input, err := w.ensureInput(ctx, event)
	if err != nil {
		return InferResult{}, err
	}

	// Ensure output: run inference if worker-output artifact is missing.
	output, tokenIDs, positionValues, err := w.ensureOutput(ctx, event, input)
	if err != nil {
		return InferResult{}, err
	}
	// Ensure descriptor and receipt from committed artifacts.
	_, result, err := w.ensureReceiptAndResult(ctx, event, output, tokenIDs, positionValues)
	if err != nil {
		return InferResult{}, err
	}

	// Ensure output is available to the Builder.
	if err := w.ensureOutputAvailable(ctx, event, output, result); err != nil {
		return InferResult{}, err
	}

	w.results[event.TaskID] = result
	return result, nil
}

func (w *Worker) prepareOutput(ctx context.Context, event chainclient.AssignmentFinalized) (*producedOutput, error) {
	if err := w.requireInferDependencies(); err != nil {
		return nil, err
	}
	output, tokenIDs, positionValues, descriptor, err := w.runInferenceAndPersistArtifacts(ctx, event)
	if err != nil {
		return nil, err
	}
	receipt, result, err := w.buildAndPersistReceipt(ctx, event, descriptor, output, tokenIDs, positionValues)
	if err != nil {
		return nil, err
	}
	if err := w.persistModelServiceJob(ctx, descriptor.JobID, event.TaskID, "succeeded", "infer"); err != nil {
		return nil, err
	}
	availablePayload, err := w.buildOutputAvailablePayload(ctx, event, descriptor.OutputHash)
	if err != nil {
		return nil, err
	}
	return &producedOutput{
		event: event, jobID: descriptor.JobID, output: append([]byte(nil), output...),
		tokenIDs: append([]byte(nil), tokenIDs...), positionValues: append([]byte(nil), positionValues...),
		receipt: receipt, workerValueEvidence: workerValueEvidenceInputs{
			EvidenceSchemaHash: w.cfg.EvidenceSchemaHash,
			FinishReason:       descriptor.FinishReason,
		},
		subject:          builderclient.NATSOutputAvailableSubject(event.TaskID),
		outputCID:        descriptor.OutputCID,
		availablePayload: availablePayload,
		result:           result,
	}, nil
}

func (w *Worker) requireInferDependencies() error {
	switch {
	case w.cfg.Model == nil:
		return fmt.Errorf("model client is required")
	case w.cfg.Builder == nil:
		return fmt.Errorf("builder client is required")
	case w.cfg.TaskData == nil:
		return fmt.Errorf("task data client is required")
	case w.cfg.TaskDataAuth == nil:
		return fmt.Errorf("task data authenticator is required")
	case w.cfg.Persistence == nil:
		return fmt.Errorf("worker output persistence is required")
	case w.cfg.ReceivingBuilder == nil:
		return fmt.Errorf("receiving Builder provider is required")
	case w.cfg.TaskFacts == nil:
		return fmt.Errorf("Keeper task facts reader is required")
	case w.cfg.SnapshotReader == nil:
		return fmt.Errorf("task snapshot reader is required")
	}
	return nil
}

func (w *Worker) runInferenceAndPersistArtifacts(ctx context.Context, event chainclient.AssignmentFinalized) (output, tokenIDs, positionValues []byte, descriptor outputDescriptor, err error) {
	profileVersion := fmt.Sprintf("%d", event.ProfileVersion)
	generation, generationDigest, err := w.taskGeneration(ctx, event)
	if err != nil {
		return nil, nil, nil, outputDescriptor{}, err
	}
	requestDigest := codec.HashWithDomain(
		"TRUEOPEN_INFER_REQUEST_V1", []byte(event.TaskID), []byte(event.ModelID), []byte(profileVersion), event.Input,
	)
	if generation != nil {
		requestDigest = codec.HashWithDomain("CORTEX_INFER_REQUEST_V2", requestDigest[:], generationDigest)
	}
	jobID := "worker-infer-" + event.TaskID
	if err := w.persistModelServiceJob(ctx, jobID, event.TaskID, "running", "infer"); err != nil {
		return nil, nil, nil, outputDescriptor{}, err
	}
	var recorder *outputStreamRecorder
	var resp modelservice.InferResponse
	savedData, savedErr := w.cfg.Persistence.ReadArtifact(ctx, event.TaskID, "worker-model-result")
	if savedErr == nil {
		var saved completedModelInference
		if err := json.Unmarshal(savedData, &saved); err != nil {
			return nil, nil, nil, outputDescriptor{}, err
		}
		if saved.RequestDigest != requestDigest {
			return nil, nil, nil, outputDescriptor{}, fmt.Errorf("completed model response request differs from current assignment")
		}
		recorder, err = w.resumeOutputRecorder(ctx, event, saved)
		resp = saved.Response
	} else {
		recorder, err = w.newOutputRecorder(ctx, event)
	}
	if err != nil {
		return nil, nil, nil, outputDescriptor{}, err
	}
	defer func() {
		if recorder.stream != nil {
			_ = recorder.stream.Close()
		}
	}()
	if savedErr != nil {
		resp, err = w.cfg.Model.Infer(modelservice.WithInferStreamObserver(ctx, recorder), modelservice.InferRequest{
			RequestID: "infer-" + event.TaskID, ModelServiceID: w.cfg.ModelServiceID, JobID: jobID,
			TaskID: event.TaskID, ModelID: event.ModelID, ProfileVersion: profileVersion,
			RequestDigest: requestDigest[:], Capability: event.Capability, Input: append([]byte(nil), event.Input...),
			Generation: generation, GenerationParamsDigest: generationDigest,
		})
	}
	if err != nil {
		_ = w.persistModelServiceJob(ctx, jobID, event.TaskID, "failed", "infer")
		return nil, nil, nil, outputDescriptor{}, err
	}
	if resp.Error != nil {
		_ = w.persistModelServiceJob(ctx, jobID, event.TaskID, "failed", "infer")
		return nil, nil, nil, outputDescriptor{}, fmt.Errorf("model infer failed: %s", resp.Error.Code)
	}
	if recorder.err != nil {
		return nil, nil, nil, outputDescriptor{}, recorder.err
	}
	if generation != nil {
		if !bytes.Equal(resp.GenerationParamsDigest, generationDigest) {
			return nil, nil, nil, outputDescriptor{}, fmt.Errorf("model infer generation_params_digest missing or mismatched")
		}
		if resp.GeneratedTokenCount > generation.Params.MaxOutputTokens {
			// The same budget the evidence check re-derives, caught one step
			// earlier off the response itself, and classified the same way: the
			// engine answered this request with more tokens than the order
			// authorised, and asking it again is not the remedy.
			over := modelservice.Deterministic(modelservice.FaultCodeTokenBudgetExceeded,
				fmt.Errorf("model generated %d tokens above order limit %d", resp.GeneratedTokenCount, generation.Params.MaxOutputTokens),
				modelservice.FaultUint("generated_token_count", resp.GeneratedTokenCount),
				modelservice.FaultUint("max_output_tokens", generation.Params.MaxOutputTokens),
				modelservice.FaultInt("finish_reason", int(resp.FinishReason)),
				modelservice.FaultStr("source", "infer_response"))
			w.traceGenerationRefusal(event.TaskID, over)
			return nil, nil, nil, outputDescriptor{}, over
		}
	}
	if savedErr != nil {
		completed, err := json.Marshal(completedModelInference{RequestDigest: requestDigest, TaskHash: recorder.taskHash, Response: resp, FrameCount: uint64(len(recorder.frames)), Pending: append([]byte(nil), recorder.pending...), ObservedBytes: recorder.total})
		if err != nil {
			return nil, nil, nil, outputDescriptor{}, err
		}
		if err := w.cfg.Persistence.WriteEvidence(ctx, EvidenceRecord{TaskID: event.TaskID, Kind: "worker-model-result", Data: completed}); err != nil {
			return nil, nil, nil, outputDescriptor{}, err
		}
	}
	outputArtifact, err := w.fetchInferArtifact(ctx, event.TaskID, "output", resp.OutputRef)
	if err != nil {
		return nil, nil, nil, outputDescriptor{}, err
	}
	tokenIDsArtifact, err := w.fetchInferArtifact(ctx, event.TaskID, "token_ids", resp.TokenIDsRef)
	if err != nil {
		return nil, nil, nil, outputDescriptor{}, err
	}
	positionValuesArtifact, err := w.fetchInferArtifact(ctx, event.TaskID, "position_values", resp.PositionValuesRef)
	if err != nil {
		return nil, nil, nil, outputDescriptor{}, err
	}
	output = append([]byte(nil), outputArtifact.Data...)
	tokenIDs = append([]byte(nil), tokenIDsArtifact.Data...)
	positionValues = append([]byte(nil), positionValuesArtifact.Data...)
	if generation != nil {
		ids, values, err := decodeMaterial(tokenIDs, positionValues)
		if err != nil {
			return nil, nil, nil, outputDescriptor{}, fmt.Errorf("model generation material: %w", err)
		}
		count, err := modelservice.ValidateGenerationMaterial(generation, generationDigest, ids, values)
		if err != nil {
			// The numbers that decided this refusal, on their own line, bound to
			// the task. Nothing here is model input.
			w.traceGenerationRefusal(event.TaskID, err,
				tasktrace.Hex("generation_params_digest", hex.EncodeToString(generationDigest)),
				tasktrace.Uint("order_max_output_tokens", generation.Params.MaxOutputTokens),
				tasktrace.Int("output_size_bytes", len(output)),
				tasktrace.Int("generated_token_ids", len(ids.Generated)),
				tasktrace.Int("position_values", len(values)))
			return nil, nil, nil, outputDescriptor{}, fmt.Errorf("model generation material: %w", err)
		}
		if count != resp.GeneratedTokenCount {
			// Deterministic for the same reason every check above it is: both
			// sides of the comparison are values this node already holds.
			mismatch := modelservice.Deterministic(modelservice.FaultCodeResponseEvidenceDisagreement,
				fmt.Errorf("model generated token count disagrees with its token material"),
				modelservice.FaultUint("response_generated_token_count", resp.GeneratedTokenCount),
				modelservice.FaultUint("material_generated_token_count", count))
			w.traceGenerationRefusal(event.TaskID, mismatch)
			return nil, nil, nil, outputDescriptor{}, mismatch
		}
		w.cfg.Trace.Event("generation_parameters_applied",
			tasktrace.Str("task", event.TaskID),
			tasktrace.Hex("generation_params_digest", hex.EncodeToString(generationDigest)),
			tasktrace.Uint("max_output_tokens", generation.Params.MaxOutputTokens),
			tasktrace.Uint("generated_token_count", count),
			tasktrace.Int("output_size_bytes", len(output)), tasktrace.Int("finish_reason", int(resp.FinishReason)))
	}

	lengths, err := recorder.finish(ctx, output)
	if err != nil {
		return nil, nil, nil, outputDescriptor{}, err
	}
	outputHash, err := codec.OutputMMRRootFromLengths(output, lengths)
	if err != nil {
		return nil, nil, nil, outputDescriptor{}, err
	}
	packageHash := outputPackageHash(event.TaskID, resp.OutputRef, resp.TokenIDsRef, resp.PositionValuesRef, outputHash)
	// The fake output path stores a canonical package whose hash covers
	// session/model/profile, which is not the same as the one above. package_hash has to
	// be fixed **before** the receipt material takes shape: the package_hash in the
	// receipt is compared field by field against the output, so signing with the old
	// value first and then changing the package to the canonical hash guarantees a
	// mismatch.
	fakePkg := builderclient.OutputPackage{
		SessionID: event.SessionID, TaskID: event.TaskID, ModelID: event.ModelID,
		ProfileVersion: profileVersion, OutputRef: resp.OutputRef, TokenIDsRef: resp.TokenIDsRef,
		PositionValuesRef: resp.PositionValuesRef, OutputHash: outputHash,
		OutputChunkLengths: append([]uint64(nil), lengths...),
	}
	if w.cfg.FakeOutput {
		if w.cfg.PackageStore == nil {
			return nil, nil, nil, outputDescriptor{}, fmt.Errorf("fake output package store is required")
		}
		canonical, err := builderclient.CanonicalOutputPackageHash(fakePkg)
		if err != nil {
			return nil, nil, nil, outputDescriptor{}, err
		}
		packageHash = canonical
	}
	receiptCommitHash := codec.HashWithDomain(
		"TRUEOPEN_INFER_RECEIPT_RESULT_V1", []byte(event.TaskID), outputHash[:], packageHash[:],
	)
	legacyReceipt := InferReceipt{
		TaskID: event.TaskID, OutputRef: resp.OutputRef, OutputHash: outputHash, PackageHash: packageHash,
		ReceiptResultHash: receiptCommitHash, ActualOutputSummary: fmt.Sprintf("%d bytes output", len(output)),
	}
	legacyPayload, err := receiptPayload(legacyReceipt)
	if err != nil {
		return nil, nil, nil, outputDescriptor{}, err
	}

	outputCID := resp.OutputRef
	// The fake output store canonicalizes the package and therefore needs a
	// signature before it can compute the fixture package hash. The real builder
	// validation is the only durable handoff that must wait until after the
	// artifacts are persisted, so we sign here only in the fake-output path.
	var validationPkg builderclient.OutputPackage
	if w.cfg.FakeOutput {
		fakeSigned, err := w.signReceipt(ctx, event, legacyReceipt, legacyPayload)
		if err != nil {
			return nil, nil, nil, outputDescriptor{}, err
		}
		pkg := fakePkg
		pkg.PackageHash = packageHash
		pkg.ReceiptHash = receiptCommitHash
		pkg.ReceiptPayload = legacyPayload
		pkg.WorkerSignature = append([]byte(nil), fakeSigned.Signature...)
		_, savedCID, err := w.cfg.PackageStore.SaveOutputPackage(ctx, pkg)
		if err != nil {
			return nil, nil, nil, outputDescriptor{}, err
		}
		if err := w.crashAt(CrashPointBuilderSaveOutputPackage); err != nil {
			return nil, nil, nil, outputDescriptor{}, err
		}
		outputCID = savedCID
		validationPkg = pkg
	}

	descriptor = outputDescriptor{
		JobID: jobID, OutputRef: resp.OutputRef, TokenIDsRef: resp.TokenIDsRef,
		PositionValuesRef: resp.PositionValuesRef, OutputHash: outputHash,
		PackageHash: packageHash, OutputCID: outputCID,
		FinishReason: resp.FinishReason, GeneratedTokenCount: resp.GeneratedTokenCount,
		OutputChunkLengths: lengths,
	}
	descriptorJSON, err := json.Marshal(descriptor)
	if err != nil {
		return nil, nil, nil, outputDescriptor{}, fmt.Errorf("encode output descriptor: %w", err)
	}
	checkpointData := InferOutputCheckpoint{
		JobID: jobID, OutputRef: resp.OutputRef, TokenIDsRef: resp.TokenIDsRef,
		PositionValuesRef: resp.PositionValuesRef, OutputHash: outputHash,
		PackageHash: packageHash, OutputCID: outputCID,
		FinishReason: resp.FinishReason, DescriptorJSON: descriptorJSON,
	}
	if err := w.cfg.Persistence.CheckpointInferOutput(ctx, event.TaskID, output, tokenIDs, positionValues, checkpointData); err != nil {
		return nil, nil, nil, outputDescriptor{}, err
	}
	if err := w.crashAt(CrashPointOutputFsync); err != nil {
		return nil, nil, nil, outputDescriptor{}, err
	}

	if !w.cfg.FakeOutput {
		legacySigned, err := w.signReceipt(ctx, event, legacyReceipt, legacyPayload)
		if err != nil {
			return nil, nil, nil, outputDescriptor{}, err
		}
		validationPkg = builderclient.OutputPackage{
			TaskID: event.TaskID, OutputRef: resp.OutputRef, TokenIDsRef: resp.TokenIDsRef,
			PositionValuesRef: resp.PositionValuesRef, OutputHash: outputHash,
			OutputChunkLengths: append([]uint64(nil), lengths...),
			PackageHash:        packageHash, ReceiptHash: receiptCommitHash, ReceiptPayload: legacyPayload,
			WorkerSignature: append([]byte(nil), legacySigned.Signature...),
		}
	}
	if err := w.cfg.Builder.ValidateOutputPackage(ctx, validationPkg); err != nil {
		return nil, nil, nil, outputDescriptor{}, err
	}
	return output, tokenIDs, positionValues, descriptor, nil
}

func (w *Worker) loadOutputDescriptor(ctx context.Context, taskID string) (outputDescriptor, error) {
	data, err := w.cfg.Persistence.ReadArtifact(ctx, taskID, "worker-output-descriptor")
	if err != nil {
		return outputDescriptor{}, err
	}
	var descriptor outputDescriptor
	if err := json.Unmarshal(data, &descriptor); err != nil {
		return outputDescriptor{}, fmt.Errorf("decode output descriptor: %w", err)
	}
	return descriptor, nil
}

func (w *Worker) buildAndPersistReceipt(ctx context.Context, event chainclient.AssignmentFinalized, descriptor outputDescriptor, output, tokenIDs, positionValues []byte) (builderclient.SignedInferReceipt, InferResult, error) {
	if err := w.validateGenerationOutput(ctx, event, output, tokenIDs, positionValues, descriptor); err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, err
	}
	outputHash, err := codec.OutputMMRRootFromLengths(output, descriptor.OutputChunkLengths)
	if err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, err
	}
	if outputHash != descriptor.OutputHash {
		return builderclient.SignedInferReceipt{}, InferResult{}, fmt.Errorf("output hash does not match descriptor")
	}
	packageHash := descriptor.PackageHash
	receiptCommitHash := codec.HashWithDomain(
		"TRUEOPEN_INFER_RECEIPT_RESULT_V1", []byte(event.TaskID), outputHash[:], packageHash[:],
	)
	legacyReceipt := InferReceipt{
		TaskID: event.TaskID, OutputRef: descriptor.OutputRef, OutputHash: outputHash, PackageHash: packageHash,
		ReceiptResultHash: receiptCommitHash, ActualOutputSummary: fmt.Sprintf("%d bytes output", len(output)),
	}
	legacyPayload, err := receiptPayload(legacyReceipt)
	if err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, err
	}
	legacySigned, err := w.signReceipt(ctx, event, legacyReceipt, legacyPayload)
	if err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, err
	}
	if err := w.crashAt(CrashPointReceiptSigned); err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, err
	}

	serviceAuthorizationNonce, _, err := w.cfg.TaskDataAuth.CommittedBusEnvelopeIdentity(ctx)
	if err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, err
	}
	if descriptor.FinishReason == nodewire.FinishReasonV1Unspecified {
		return builderclient.SignedInferReceipt{}, InferResult{}, fmt.Errorf("model service returned an unspecified finish reason")
	}
	workerValueEvidence := workerValueEvidenceInputs{
		EvidenceSchemaHash: w.cfg.EvidenceSchemaHash,
		FinishReason:       descriptor.FinishReason,
	}
	facts, err := w.taskFacts(ctx, event.TaskID)
	if err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, err
	}
	if w.cfg.EvidenceSchemaHash == "" {
		return builderclient.SignedInferReceipt{}, InferResult{}, fmt.Errorf("%w: evidence_schema_hash requires the locked Profile's verification_profile.evidence_schema_hash from hub.v1.Query/Profile", builderclient.ErrInferReceiptInputUnavailable)
	}
	generationParams, generation, err := w.generationParamsArtifact(ctx, event, facts.GenerationParamsDigest)
	if err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, err
	}
	derived, err := w.deriveWorkerEvidence(event.TaskID, facts.AcceptedTaskHash, generationParams, tokenIDs, positionValues)
	if err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, err
	}
	// The finish reason must agree with the generated tokens
	// under the task's parameters before this node signs it, whichever
	// transport produced the generation.
	generated, err := nodewire.DecodeTokenIDs(derived.generatedTokenIDs)
	if err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, err
	}
	if err := modelservice.ValidateFinishReason(generation, generated, descriptor.FinishReason); err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, err
	}
	if derived.generatedCount != descriptor.GeneratedTokenCount {
		return builderclient.SignedInferReceipt{}, InferResult{}, fmt.Errorf("generated token artifact count differs from model response")
	}
	inputs := preparedReceiptInputs{
		event:                     event,
		facts:                     facts,
		local:                     workerValueEvidence,
		serviceAuthorizationNonce: serviceAuthorizationNonce,
		outputHash:                outputHash,
		outputSizeBytes:           uint64(len(output)),
		outputLeafCount:           uint64(len(descriptor.OutputChunkLengths)),
		evidence:                  derived,
	}
	if err := builderclient.ValidateWorkerEvidenceRequirementsV3(w.cfg.ProfileEvidenceRequirements); err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, err
	}
	if err := w.publishWorkerBundles(ctx, event, facts.AcceptedTaskHash.Hex(), derived); err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, err
	}
	evidence, err := builderclient.WorkerEvidenceCommitments(w.workerEvidenceFacts(inputs))
	if err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, err
	}
	receipt, signingDigest, err := builderclient.BuildInferReceipt(
		w.inferReceiptFacts(inputs, evidence, w.cfg.ProfileEvidenceRequirements),
	)
	if err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, err
	}
	serviceSignature, err := w.signDigest(ctx, signingDigest)
	if err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, err
	}
	if err := signer.VerifyDigestSignature(w.cfg.SignerPubkey, signingDigest, serviceSignature); err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, fmt.Errorf("locally verify infer receipt service signature: %w", err)
	}
	receipt.ServiceSignature = hex.EncodeToString(serviceSignature)
	canonicalPayload, err := codec.CanonicalJSON(receipt)
	if err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, fmt.Errorf("encode canonical infer receipt: %w", err)
	}
	canonicalDigest := codec.HashBytes(canonicalPayload)
	// Every digest of the receipt this node just signed, at the one point where
	// all of them exist. signing_digest and evidence_commitment_root are the two
	// a conforming peer must reproduce from the same facts, and evidence_schema
	// framing has already been wrong once in a way that only a peer's value
	// exposed (TRUEOPEN_INFER_EVIDENCE_COMMITMENTS_V1), so they are printed rather
	// than assumed.
	listItems := make([]nodewire.EvidenceCommitmentV1, len(evidence))
	for i, item := range evidence {
		root := item.EvidenceHashOrRoot
		listItems[i] = nodewire.EvidenceCommitmentV1{EvidenceKind: item.EvidenceKind, EvidenceHashOrRoot: root[:], EncodedSizeBytes: item.EncodedSizeBytes}
	}
	evidenceListRoot, err := nodewire.EvidenceCommitmentsHash(listItems)
	if err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, err
	}
	w.cfg.Trace.Event("infer_receipt_built",
		tasktrace.Str("task", event.TaskID), tasktrace.Str("session", event.SessionID),
		tasktrace.Hash("output_hash", outputHash), tasktrace.Hash("package_hash", packageHash),
		tasktrace.Hash("receipt_result_hash", receiptCommitHash),
		tasktrace.Hash("signing_digest", signingDigest),
		tasktrace.Hash("evidence_commitment_root", evidenceListRoot),
		tasktrace.Hash("canonical_receipt_digest", canonicalDigest),
		tasktrace.Hex("receipt_task_hash", receipt.TaskHash),
		tasktrace.Hex("generation_params_digest", receipt.GenerationParamsDigest),
		tasktrace.Hex("evidence_schema_hash", w.cfg.EvidenceSchemaHash),
		tasktrace.Hash("worker_value_commitment", evidence[0].EvidenceHashOrRoot),
		tasktrace.Uint("worker_values_encoded_size_bytes", evidence[0].EncodedSizeBytes),
		tasktrace.Hash("worker_token_commitment", evidence[1].EvidenceHashOrRoot),
		tasktrace.Uint("worker_token_ids_encoded_size_bytes", evidence[1].EncodedSizeBytes),
		tasktrace.Hash("worker_value_root", derived.valueRoot),
		tasktrace.Uint("output_size_bytes", uint64(len(output))),
		tasktrace.Int("finish_reason", int(descriptor.FinishReason)),
		tasktrace.Uint("service_authorization_nonce", serviceAuthorizationNonce),
		tasktrace.Uint("expiry_height", receipt.ExpiryHeight),
		tasktrace.Str("output_ref", descriptor.OutputRef), tasktrace.Str("output_cid", descriptor.OutputCID))

	produced := &producedOutput{
		event: event, jobID: descriptor.JobID, output: append([]byte(nil), output...),
		tokenIDs: append([]byte(nil), tokenIDs...), positionValues: append([]byte(nil), positionValues...),
		canonicalReceiptPayload: canonicalPayload,
		canonicalReceiptDigest:  canonicalDigest, receipt: receipt,
		workerValueEvidence: workerValueEvidence,
		result: InferResult{
			Started: true, InferDeadlineHeight: event.InferDeadlineHeight, OutputRef: descriptor.OutputRef,
			OutputCID:   descriptor.OutputCID,
			PackageHash: packageHash, Receipt: legacyReceipt, SignedReceipt: legacySigned, TaskDataReceipt: receipt,
		},
	}
	if err := w.persistCanonicalReceipt(ctx, produced); err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, err
	}
	if err := w.crashAt(CrashPointReceiptCommitted); err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, err
	}
	resultBytes, err := json.Marshal(produced.result)
	if err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, fmt.Errorf("encode worker result: %w", err)
	}
	if err := w.cfg.Persistence.WriteEvidence(ctx, EvidenceRecord{
		TaskID: event.TaskID, Kind: "worker-result", Data: resultBytes,
	}); err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, err
	}
	return receipt, produced.result, nil
}

func (w *Worker) buildOutputAvailablePayload(ctx context.Context, event chainclient.AssignmentFinalized, outputHash codec.Hash) ([]byte, error) {
	facts, err := w.taskFacts(ctx, event.TaskID)
	if err != nil {
		return nil, err
	}
	serviceAuthorizationNonce, _, err := w.cfg.TaskDataAuth.CommittedBusEnvelopeIdentity(ctx)
	if err != nil {
		return nil, err
	}
	subject := builderclient.NATSOutputAvailableSubject(event.TaskID)
	taskID, err := builderclient.CanonicalWireHash(event.TaskID, "task_id")
	if err != nil {
		return nil, err
	}
	// The availability hint proves nothing: output and task facts remain Keeper
	// and task-data authorities the receiver reads for itself. task_hash binds
	// the accepted order version this output belongs to.
	available := &busv1.OutputAvailableV1{
		TaskId:                taskID[:],
		TaskHash:              append([]byte(nil), facts.AcceptedTaskHash...),
		OutputHash:            append([]byte(nil), outputHash[:]...),
		WorkerOperatorAddress: w.cfg.WorkerAddress,
		PublishedAtUnixMs:     uint64(time.Now().UTC().UnixMilli()),
	}
	return w.encodeNexusMessage(builderclient.UnsignedEnvelopeInput{
		Kind: builderclient.KindOutputAvailable, ChainID: w.cfg.ChainID, Subject: subject,
		SenderOperatorAddress: w.cfg.WorkerAddress, SenderParticipantType: builderclient.ParticipantCortex,
		ServiceAuthorizationNonce: serviceAuthorizationNonce,
	}, available)
}

// traceGenerationRefusal prints one refused generation as a single greppable
// line: the task, the fault class and code, every scalar the refusal measured,
// and whatever extra the call site supplies.
//
// It carries measurements only. modelservice.FaultField is documented as scalars
// only for exactly this reason -- this line reaches the operator's log and a
// durable halt reason, and the model's prompt and output must not.
func (w *Worker) traceGenerationRefusal(taskID string, err error, extra ...tasktrace.Field) {
	fields := make([]tasktrace.Field, 0, len(extra)+4)
	fields = append(fields,
		tasktrace.Str("task", taskID),
		tasktrace.Str("class", modelservice.ClassOf(err).String()),
		tasktrace.Str("code", modelservice.FaultCode(err)))
	for _, field := range modelservice.FaultFields(err) {
		fields = append(fields, tasktrace.Str(field.Key, field.Value))
	}
	fields = append(fields, extra...)
	w.cfg.Trace.ErrorEvent("generation_evidence_refused", fields...)
}

func (w *Worker) fetchInferArtifact(ctx context.Context, taskID, kind, ref string) (modelservice.Artifact, error) {
	if strings.TrimSpace(ref) == "" {
		return modelservice.Artifact{}, fmt.Errorf("model infer %s artifact ref is required", kind)
	}
	artifact, err := w.cfg.Model.FetchArtifact(ctx, modelservice.FetchArtifactRequest{
		RequestID: "fetch-" + kind + "-" + taskID, ModelServiceID: w.cfg.ModelServiceID, Ref: ref,
		// Empty output text, and the empty PositionValuesV1 of a generation
		// with no generated token, are both legal material.
		AllowEmpty: kind == "output" || kind == "position_values",
	})
	if err != nil {
		return modelservice.Artifact{}, err
	}
	if len(artifact.Data) == 0 && kind != "output" && kind != "position_values" {
		return modelservice.Artifact{}, fmt.Errorf("model infer %s artifact is empty", kind)
	}
	return artifact, nil
}

func (w *Worker) persistCanonicalReceipt(ctx context.Context, prepared *producedOutput) error {
	if err := w.cfg.Persistence.WriteEvidence(ctx, EvidenceRecord{
		TaskID: prepared.event.TaskID, Kind: "worker-infer-receipt",
		Data: append([]byte(nil), prepared.canonicalReceiptPayload...),
		Ref:  "sha256:" + hex.EncodeToString(prepared.canonicalReceiptDigest[:]),
	}); err != nil {
		return err
	}
	return w.cfg.Persistence.CheckpointInferReceipt(ctx, InferReceiptCheckpoint{
		TaskID: prepared.event.TaskID, MaterialDigest: hex.EncodeToString(prepared.canonicalReceiptDigest[:]),
		Payload: append([]byte(nil), prepared.canonicalReceiptPayload...), CreatedAt: time.Now().UTC(),
	})
}

// relayReceiptAndUpload puts this task's result in every Task Builder's hands.
//
// Steps that happen once for the task are separated from steps that happen once
// per Builder, because only the first kind is genuinely shared. data-ready is a
// per-Builder judgement made from that Builder's own complete local copy
// (04-任务/02 §257), so a Builder that never received the evidence never becomes
// data-ready, never sends OPEN_VERIFY and never proposes a Verifier, no matter
// what the other two hold. Uploading to one Builder therefore made the task
// depend on it and left the 2-of-3 redundancy the data plane assumes absent.
//
// Once per task: the Fin that terminates the output stream (already fanned out,
// see openOutputStream) and the receipt relay, which only has to reach the chain
// once -- a second relay of the same signed receipt is a duplicate submission,
// not a second guarantee. Every Builder still receives the receipt itself: it
// travels inside the FinalizeTaskResult request that needs it.
//
// Once per Builder: the evidence artifacts, the bundle manifests, and one
// FinalizeTaskResult per Worker evidence kind.
//
// One Builder failing does not stop the others, and the relay succeeds as long
// as one Builder finalized. That floor is what the single-Builder path already
// required -- exactly one -- so nothing that completes today stops completing,
// while the normal case leaves all three able to drive the task. A Builder that
// failed leaves no storage confirmation behind, so confirmedBuilders makes a
// later re-entry retry precisely those and skip the rest.
func (w *Worker) relayReceiptAndUpload(ctx context.Context, event chainclient.AssignmentFinalized, output []byte, receipt builderclient.SignedInferReceipt) error {
	ref := receivingBuilderRef(event)
	descriptor, err := w.loadOutputDescriptor(ctx, event.TaskID)
	if err != nil {
		return err
	}
	bundles, err := w.readWorkerBundles(ctx, event, receipt, descriptor)
	if err != nil {
		return err
	}
	// The Fin goes out before the receipt, in that order, because ADR-0027
	// decision three makes a receipt imply a Fin: a Builder holding a receipt
	// must already hold the signed Fin that terminates its output stream.
	//
	// Submitted the other way round, a Fin the Builder refuses -- a signature it
	// cannot verify, a finish_reason outside the closed set -- leaves the receipt
	// already in its hands with no Fin behind it, and nothing downstream can
	// distinguish that from a Worker that never finished. Failing here instead
	// leaves the receipt unsubmitted, which a retry or a restart resumes cleanly:
	// both re-enter through this function.
	//
	// Only the submission moves. The receipt is still built and persisted first,
	// because building it is local and observable to nobody; it is the relay that
	// the ordering is about.
	if err := w.ensureOutputStreamStored(ctx, event, receipt); err != nil {
		return err
	}
	// The relay target is the seam's single-Builder answer, not a member picked
	// out of the list: which Builder relays a receipt onward is exactly the
	// question ResolveReceivingBuilder exists to answer, and a provider that
	// redirects it has to keep being obeyed.
	relay, err := w.receivingBuilder(ctx, ref)
	if err != nil {
		return err
	}
	if err := w.submitInferReceipt(ctx, ref, receipt, relay); err != nil {
		return err
	}
	// Resolved after the relay, not before: a relay that hit a stale fingerprint
	// has just re-read the descriptor, and resolving earlier would send every
	// upload to the pin that was already known to be wrong.
	builders, err := w.receivingBuilders(ctx, ref)
	if err != nil {
		return err
	}
	confirmations, err := w.cfg.Persistence.StorageConfirmations(ctx, event.TaskID)
	if err != nil {
		return err
	}
	done, err := w.confirmedBuilders(ctx, event, receipt, builders, confirmations)
	if err != nil {
		return err
	}
	var (
		finalized []string
		failures  []error
	)
	for _, builder := range builders {
		if done[builder.OperatorAddress] {
			finalized = append(finalized, builder.OperatorAddress)
			continue
		}
		if err := w.finalizeOnBuilder(ctx, event, output, receipt, ref, builder, bundles); err != nil {
			failures = append(failures, fmt.Errorf("finalize task result on Task Builder %s: %w", builder.OperatorAddress, err))
			continue
		}
		finalized = append(finalized, builder.OperatorAddress)
	}
	if len(finalized) == 0 {
		return errors.Join(failures...)
	}
	for _, failure := range failures {
		// Reported, not returned: the task can proceed on the Builders that did
		// finalize, and an operator still has to be able to see that this node
		// left a Builder without the material it needs to become data-ready.
		w.cfg.Trace.Event("task_result_finalize_refused", tasktrace.Str("task", event.TaskID), tasktrace.Str("error", failure.Error()))
	}
	w.cfg.Trace.Event("task_result_finalized", tasktrace.Str("task", event.TaskID), tasktrace.Hex("output_hash", receipt.OutputHash),
		tasktrace.Hash("worker_value_manifest_hash", evidencebundle.Hash(bundles[0].manifest)), tasktrace.Hash("worker_token_manifest_hash", evidencebundle.Hash(bundles[1].manifest)),
		tasktrace.Uint("output_size_bytes", receipt.OutputSizeBytes),
		tasktrace.Str("task_builders", strings.Join(finalized, ",")),
		tasktrace.Int("task_builders_finalized", len(finalized)), tasktrace.Int("task_builders_total", len(builders)))
	return nil
}

// submitInferReceipt relays the signed receipt through the one Builder that
// carries it to the chain, retrying once past the descriptor cache when that
// Builder has rotated its certificate (ADR-0015).
func (w *Worker) submitInferReceipt(ctx context.Context, ref ReceivingBuilderRef, receipt builderclient.SignedInferReceipt, relay BuilderEndpoint) error {
	submit := func(endpoint BuilderEndpoint) error {
		return w.cfg.TaskData.SubmitInferReceipt(
			builderclient.WithTLSPubkeyHash(ctx, endpoint.TLSPubkeyHash), endpoint.Endpoint,
			builderclient.SubmitInferReceiptRequest{Receipt: receipt})
	}
	err := submit(relay)
	if !errors.Is(err, builderclient.ErrTLSPubkeyMismatch) {
		return err
	}
	fresh, refreshErr := w.refreshReceivingBuilder(ctx, ref)
	if refreshErr != nil || fresh.TLSPubkeyHash == relay.TLSPubkeyHash {
		return err
	}
	return submit(fresh)
}

// finalizeOnBuilder stages and finalizes this task's evidence on one Task
// Builder, retrying once past the descriptor cache when that Builder has
// rotated its certificate (ADR-0015).
func (w *Worker) finalizeOnBuilder(ctx context.Context, event chainclient.AssignmentFinalized, output []byte, receipt builderclient.SignedInferReceipt, ref ReceivingBuilderRef, builder BuilderEndpoint, bundles []workerBundle) error {
	err := w.finalizeOnBuilderAt(ctx, event, output, receipt, ref, builder, bundles)
	if !errors.Is(err, builderclient.ErrTLSPubkeyMismatch) {
		return err
	}
	fresh, refreshErr := w.refreshReceivingBuilderFor(ctx, ref, builder.OperatorAddress)
	if refreshErr != nil || fresh.TLSPubkeyHash == builder.TLSPubkeyHash {
		return err
	}
	return w.finalizeOnBuilderAt(ctx, event, output, receipt, ref, fresh, bundles)
}

// finalizeOnBuilderAt uploads the evidence to one already-resolved Task Builder
// and closes each Worker evidence kind on it; dialCtx checks the certificate
// against that Builder's fingerprint.
func (w *Worker) finalizeOnBuilderAt(ctx context.Context, event chainclient.AssignmentFinalized, output []byte, receipt builderclient.SignedInferReceipt, ref ReceivingBuilderRef, endpoint BuilderEndpoint, bundles []workerBundle) error {
	dialCtx := builderclient.WithTLSPubkeyHash(ctx, endpoint.TLSPubkeyHash)
	outputKey := builderclient.TaskDataKey{TaskHash: receipt.TaskHash, SessionID: event.SessionID, TaskID: event.TaskID, Kind: builderclient.DataKindOutput, ContentHash: receipt.OutputHash}
	// Each bundle is staged and finalized on its own: a finalize closes exactly
	// one Worker evidence kind, and the Builder re-derives that kind's
	// commitment from what it holds before it confirms.
	var records []StorageConfirmationCheckpoint
	for _, bundle := range bundles {
		for _, artifact := range bundle.decoded.Artifacts {
			key := builderclient.EvidenceObjectKey(receipt.TaskHash, event.SessionID, event.TaskID, builderclient.DataKindEvidenceArtifact, artifact.ContentHash, builderclient.EvidenceProducerWorker, 1, w.cfg.WorkerAddress, bundle.kind)
			if err := w.stageObject(dialCtx, endpoint, key, "", bundle.artifacts[artifact.ID]); err != nil {
				return err
			}
		}
		bundleKey, err := workerBundleKey(receipt, event.SessionID, event.TaskID, bundle.kind)
		if err != nil {
			return err
		}
		if err := w.stageObject(dialCtx, endpoint, bundleKey, "", bundle.manifest); err != nil {
			return err
		}
		request := builderclient.FinalizeTaskResultRequest{TaskHash: receipt.TaskHash, SessionID: event.SessionID, TaskID: event.TaskID, Receipt: receipt, EvidenceKind: bundle.kind}
		digest, err := builderclient.TaskDataFinalizeResultBodyDigest(request)
		if err != nil {
			return err
		}
		request.Auth, err = w.cfg.TaskDataAuth.SignRequest(dialCtx, "FinalizeTaskResult", outputKey, endpoint.OperatorAddress, digest)
		if err != nil {
			return err
		}
		finalized, err := w.cfg.TaskData.FinalizeTaskResult(dialCtx, endpoint.Endpoint, request)
		if err != nil {
			return err
		}
		// Resolved by operator rather than by "the assigned Builder": this
		// confirmation was signed by the Builder the loop is on, and verifying it
		// against another member's service key would reject every honest
		// confirmation the other two return.
		current, err := w.currentReceivingBuilder(ctx, ref, endpoint.OperatorAddress)
		if err != nil {
			return err
		}
		if len(finalized.EvidenceBundleConfirmations) != 1 {
			return fmt.Errorf("finalization must confirm exactly one Worker bundle")
		}
		for i, c := range []builderclient.StorageConfirmation{finalized.OutputConfirmation, finalized.EvidenceBundleConfirmations[0]} {
			key, size, total := outputKey, uint64(len(output)), uint64(0)
			if i == 1 {
				key, size, total = bundleKey, uint64(len(bundle.manifest)), bundle.decoded.TotalSize()
			}
			// Every confirmation is verified, including the output one each
			// later finalize repeats; only its first copy is recorded. "First"
			// is per Builder: records is this Builder's alone, so each of them
			// still contributes its own output confirmation.
			hash, err := verifyStorageConfirmation(c, w.cfg.ChainID, key, key.ContentHash, size, current)
			if err != nil {
				return err
			}
			if c.ArtifactTotalSizeBytes != total {
				return fmt.Errorf("storage confirmation artifact total differs from manifest")
			}
			if i == 0 && len(records) > 0 {
				continue
			}
			records = append(records, StorageConfirmationCheckpoint{TaskID: event.TaskID, DataKind: key.Kind.String(), BuilderOperator: c.BuilderOperator, MaterialDigest: hash.String(), SemanticHash: key.ContentHash, SizeBytes: size, RetentionUntilHeight: c.RetentionUntilHeight, Signature: append([]byte(nil), c.Signature...), BuilderServicePubkey: current.ServicePubkey, VerifiedAt: time.Now().UTC(), Confirmation: &c})
		}
	}
	// Persisted only once this Builder's whole set verified. A half-written set
	// would read back as a Builder that still owes material, which is the same
	// thing a failure reads as, and re-uploading to it is harmless.
	for _, record := range records {
		if err := w.cfg.Persistence.CheckpointStorageConfirmation(ctx, record); err != nil {
			return err
		}
	}
	return nil
}

func (w *Worker) stageObject(ctx context.Context, endpoint BuilderEndpoint, key builderclient.TaskDataKey, media string, data []byte) error {
	digest, err := builderclient.TaskDataUploadBodyDigest(key, uint64(len(data)), media)
	if err != nil {
		return err
	}
	auth, err := w.cfg.TaskDataAuth.SignRequest(ctx, "UploadTaskResultObject", key, endpoint.OperatorAddress, digest)
	if err != nil {
		return err
	}
	metadata, err := w.cfg.TaskData.UploadTaskResultObject(ctx, endpoint.Endpoint, builderclient.UploadTaskResultRequest{Key: key, SizeBytes: uint64(len(data)), MediaType: media, Auth: auth, Data: data})
	if err != nil {
		return err
	}
	if metadata.Key != key || metadata.SizeBytes != uint64(len(data)) || (metadata.Readiness != builderclient.TaskDataStored && metadata.Readiness != builderclient.TaskDataReady) {
		return fmt.Errorf("uploaded object metadata does not match its signed header")
	}
	return nil
}

func verifyStorageConfirmation(c builderclient.StorageConfirmation, chainID string, key builderclient.TaskDataKey, semanticHash string, sizeBytes uint64, builder BuilderEndpoint) (codec.Hash, error) {
	if c.SchemaVersion != 1 || c.ChainID != chainID || c.Key != key || key.ContentHash != semanticHash || c.SizeBytes != sizeBytes || c.BuilderOperator != builder.OperatorAddress || c.ServiceAuthorizationNonce == 0 || c.ServiceAuthorizationNonce != builder.AuthorizationNonce {
		return codec.Hash{}, fmt.Errorf("Builder confirmation does not match object/current binding")
	}
	if c.RetentionUntilHeight <= builder.CurrentHeight {
		return codec.Hash{}, fmt.Errorf("Builder storage confirmation retention expired")
	}
	digest, err := builderclient.StorageConfirmationSigningHash(c)
	if err != nil {
		return codec.Hash{}, err
	}
	if err := signer.VerifyDigestSignature(builder.ServicePubkey, digest, c.Signature); err != nil {
		return codec.Hash{}, err
	}
	return digest, nil
}

func (w *Worker) encodeNexusMessage(input builderclient.UnsignedEnvelopeInput, payload proto.Message) ([]byte, error) {
	// The configured TTL is what the peer accepts, so it has to be stamped here
	// rather than left to the envelope default: a deployment agreeing a shorter
	// window with its Nexus would otherwise keep emitting the default lifetime.
	if input.ExpiresAt.IsZero() && w.cfg.EnvelopeTTL > 0 {
		issuedAt := input.IssuedAt
		if issuedAt.IsZero() {
			issuedAt = time.Now().UTC()
			input.IssuedAt = issuedAt
		}
		input.ExpiresAt = issuedAt.Add(w.cfg.EnvelopeTTL)
	}
	// Only a trusted transport posture may emit unsigned envelopes. FakeOutput
	// says the inference output is synthetic; it says nothing about whether this
	// node's identity is real. A fake-inference node still signs with its own
	// current service key, and the receiver still verifies under
	// TRUEOPEN_BUS_ENVELOPE_V2. Folding it into this condition made every
	// fake-inference deployment emit unsigned envelopes that a strict Nexus
	// drops outright, so a Worker on fake inference could never be assigned.
	if w.cfg.TrustedNATSDev {
		return builderclient.EncodeUnsignedBusMessage(input, payload, true)
	}
	return builderclient.EncodeAuthenticatedBusMessage(input, payload, w.cfg.NexusEnvelopeSigner)
}

func (w *Worker) persistModelServiceJob(ctx context.Context, jobID, taskID, status, intent string) error {
	if w.cfg.Persistence == nil {
		return nil
	}
	return w.cfg.Persistence.CheckpointModelJob(ctx, ModelJobCheckpoint{
		JobID:          jobID,
		TaskID:         taskID,
		Role:           "worker",
		ModelServiceID: w.cfg.ModelServiceID,
		Status:         status,
		Intent:         intent,
	})
}

func (w *Worker) verifyReceiptSignature(ctx context.Context, receipt builderclient.SignedInferReceipt) error {
	sigHex := receipt.ServiceSignature
	if len(sigHex) == 0 {
		return fmt.Errorf("receipt has no service signature")
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("decode receipt service signature: %w", err)
	}
	digest, err := builderclient.InferReceiptSigningDigest(receipt)
	if err != nil {
		return fmt.Errorf("infer receipt signing digest: %w", err)
	}
	if err := signer.VerifyDigestSignature(w.cfg.SignerPubkey, digest, sig); err != nil {
		return fmt.Errorf("verify receipt service signature: %w", err)
	}
	return nil
}

func (w *Worker) persistBuilderOutbox(ctx context.Context, taskID string, subject string, payload []byte, status string, dedupID string) error {
	if w.cfg.Persistence == nil {
		return nil
	}
	return w.cfg.Persistence.WriteBuilderOutbox(ctx, OutboxRecord{
		TaskID:  taskID,
		Subject: subject,
		Payload: append([]byte(nil), payload...),
		Digest:  codec.HashWithDomain("TRUEOPEN_BUILDER_OUTBOX_V1", []byte(subject), []byte(taskID), payload),
		Status:  status,
		DedupID: dedupID,
	})
}

func (w *Worker) RecordReceipt(state ReceiptState) {
	w.receipts[state.TaskID] = state
}

func (w *Worker) CheckReceiptOnlySelfRescue(ctx context.Context, currentHeight uint64) (bool, error) {
	for taskID, state := range w.receipts {
		if state.SelfRescueSubmitted || !state.InferReceiptAccepted || state.OpenVerifyAccepted {
			continue
		}
		if currentHeight+state.SelfRescueMargin < state.WorkerRevealDeadline {
			continue
		}
		if w.cfg.Tx == nil {
			return false, fmt.Errorf("service-key self-rescue tx client is required")
		}
		if state.ReceiptOnlyRescue.SubmitterAddress != w.cfg.SignerAddress {
			return false, fmt.Errorf("self-rescue submitter %q does not match current service address %q", state.ReceiptOnlyRescue.SubmitterAddress, w.cfg.SignerAddress)
		}
		if state.ReceiptOnlyRescue.Receipt.WorkerOperatorAddress != w.cfg.WorkerAddress {
			return false, fmt.Errorf("self-rescue worker operator %q does not match configured operator %q", state.ReceiptOnlyRescue.Receipt.WorkerOperatorAddress, w.cfg.WorkerAddress)
		}
		payload, err := txclient.MarshalMessage(txclient.MsgSubmitInferReceipt, state.ReceiptOnlyRescue)
		if err != nil {
			return false, err
		}
		obs, err := w.cfg.Tx.Submit(ctx, txclient.Request{
			TaskID:         taskID,
			SessionID:      state.SessionID,
			Kind:           txclient.MsgSubmitInferReceipt,
			Payload:        payload,
			DeadlineHeight: state.WorkerRevealDeadline,
			MaterialDigest: codec.HashWithDomain("TRUEOPEN_INFER_RECEIPT_SELF_RESCUE_V1", []byte(taskID), payload),
		})
		if err != nil {
			return false, err
		}
		state.SelfRescueTx = obs
		state.SelfRescueSubmitted = true
		w.receipts[taskID] = state
		return true, nil
	}
	return false, nil
}

func (w *Worker) signReceipt(ctx context.Context, event chainclient.AssignmentFinalized, receipt InferReceipt, payload []byte) (identity.SignedEnvelope, error) {
	taskID := identity.TaskID(event.SessionID, event.OrderSequence)
	messageHash := codec.HashWithDomain("TRUEOPEN_INFER_RECEIPT_MESSAGE_V1", payload)
	envelope := identity.SignedEnvelope{
		Domain:                "TRUEOPEN_WORKER_INFER_RECEIPT_V1",
		ChainID:               w.cfg.ChainID,
		SessionID:             event.SessionID,
		OrderSequence:         event.OrderSequence,
		OrderDigest:           event.OrderDigest,
		TaskID:                taskID,
		Role:                  "worker",
		MessageType:           "InferReceipt",
		MessageVersion:        "v1",
		ValidFromHeight:       event.WinnerConfirmHeight,
		ValidUntilHeight:      event.InferDeadlineHeight,
		SourceSnapshotHeight:  event.WinnerConfirmHeight,
		SignerSequenceOrNonce: "worker-receipt-" + event.TaskID,
		CanonicalMessageHash:  messageHash,
		SignerAddress:         w.cfg.SignerAddress,
	}
	if err := w.signEnvelope(ctx, &envelope); err != nil {
		return identity.SignedEnvelope{}, err
	}
	return envelope, nil
}

func (w *Worker) signEnvelope(ctx context.Context, envelope *identity.SignedEnvelope) error {
	digest, err := envelope.SigningHash()
	if err != nil {
		return err
	}
	signature, err := w.signDigest(ctx, digest)
	if err != nil {
		return err
	}
	envelope.Signature = signature
	return envelope.Validate()
}

func (w *Worker) signDigest(ctx context.Context, digest codec.Hash) ([]byte, error) {
	if w.cfg.Signer == nil {
		return nil, fmt.Errorf("service key signer is required")
	}
	return w.cfg.Signer.SignDigest(ctx, signer.DigestRequest{
		KeyRef:                w.cfg.SignerKeyRef,
		ExpectedSignerAddress: w.cfg.SignerAddress, Digest: digest,
	})
}

func validateAssignmentIdentity(event chainclient.AssignmentFinalized) error {
	if event.SessionID == "" {
		return fmt.Errorf("assignment session_id is required")
	}
	if event.OrderDigest == (codec.Hash{}) {
		return fmt.Errorf("assignment order_digest is required")
	}
	if event.InferDeadlineHeight == 0 {
		return fmt.Errorf("assignment infer_deadline_height is required")
	}
	if event.ModelID == "" || event.ProfileVersion == 0 || strings.TrimSpace(event.Capability) == "" {
		return fmt.Errorf("assignment model id, profile version, and capability are required")
	}
	if event.TaskID != identity.TaskIDString(event.SessionID, event.OrderSequence) {
		return fmt.Errorf("assignment task_id %q does not match canonical task id", event.TaskID)
	}
	return nil
}

func (w *Worker) validateSnapshot(event chainclient.AssignmentFinalized, snapshot chainclient.TaskSnapshot) error {
	if snapshot.Assignment.TaskID != event.TaskID {
		return fmt.Errorf("snapshot task_id %q does not match event task_id %q", snapshot.Assignment.TaskID, event.TaskID)
	}
	if snapshot.Assignment.SessionID != event.SessionID {
		return fmt.Errorf("snapshot session_id does not match event")
	}
	if snapshot.Assignment.SelectedWorker != event.Winner {
		return fmt.Errorf("snapshot selected_worker does not match event winner")
	}
	return nil
}

func validateWorkerHandraiseRequest(req WorkerHandraiseRequest) error {
	if req.SessionID == "" {
		return fmt.Errorf("worker handraise session_id is required")
	}
	if req.TaskHash == (codec.Hash{}) {
		return fmt.Errorf("worker handraise task_hash is required")
	}
	if req.ModelID == "" || req.ProfileVersion == 0 || req.Member.CandidatePoolSnapshotID == "" ||
		req.Member.SlotVersion == 0 || req.Member.OperatorAddress == "" {
		return fmt.Errorf("worker handraise model, profile, and CandidatePool member are required")
	}
	if req.TaskID == "" {
		return fmt.Errorf("worker handraise task_id is required")
	}
	// Unconditional, including at sequence 0. The guard used to read
	// `req.OrderSequence != 0 &&`, treating zero as "the caller stated no
	// sequence" - but zero is the first order of every session, so that made the
	// session-opening order the one order whose task_id nothing checked, and a
	// task_id derived from any other sequence got signed.
	if req.TaskID != identity.TaskIDString(req.SessionID, req.OrderSequence) {
		return fmt.Errorf("worker handraise task_id %q does not match canonical task id", req.TaskID)
	}
	// There is no payload_keyring_hash clause here and no field to hold one. The
	// WorkerHandraise message and its signing preimage dropped the key: node's
	// frozen WorkerHandraiseV1 and nexus's msgbus.WorkerHandraise have no such
	// field, so a value carried on an inbound order reaches nothing this node
	// signs.
	if req.CurrentHeight == 0 || req.HandraiseExpireHeight == 0 || req.CurrentHeight > req.HandraiseExpireHeight {
		return fmt.Errorf("worker handraise height window is invalid")
	}
	return nil
}

func canonicalTaskRejectCode(err error) string {
	if err == nil {
		return ""
	}
	return "L2_TASK_IDENTITY_MISSING"
}

func (w *Worker) persistWorkerHandraise(ctx context.Context, taskID string, subject string, payload []byte, dedupID string) error {
	if w.cfg.Persistence == nil {
		return nil
	}
	payloadHash := codec.HashBytes(payload)
	if err := w.cfg.Persistence.WriteEvidence(ctx, EvidenceRecord{
		TaskID: taskID,
		Kind:   "worker-handraise",
		Data:   append([]byte(nil), payload...),
		Ref:    "sha256:" + fmt.Sprintf("%x", payloadHash[:]),
	}); err != nil {
		return err
	}
	return w.cfg.Persistence.WriteBuilderOutbox(ctx, OutboxRecord{
		TaskID:  taskID,
		Subject: subject,
		Payload: append([]byte(nil), payload...),
		Digest:  codec.HashWithDomain("TRUEOPEN_BUILDER_OUTBOX_V1", []byte(subject), []byte(taskID), payload),
		Status:  "pending",
		DedupID: dedupID,
	})
}

func outputPackageHash(taskID, outputRef, tokenIDsRef, positionValuesRef string, outputHash codec.Hash) codec.Hash {
	return codec.HashWithDomain(
		"TRUEOPEN_OUTPUT_PACKAGE_V1",
		[]byte(taskID),
		[]byte(outputRef),
		[]byte(tokenIDsRef),
		[]byte(positionValuesRef),
		outputHash[:],
	)
}

func receiptPayload(receipt InferReceipt) ([]byte, error) {
	return builderclient.EncodeInferReceiptMaterial(builderclient.InferReceiptMaterial{
		TaskID:              receipt.TaskID,
		OutputRef:           receipt.OutputRef,
		OutputHash:          receipt.OutputHash,
		PackageHash:         receipt.PackageHash,
		ReceiptResultHash:   receipt.ReceiptResultHash,
		ActualOutputSummary: receipt.ActualOutputSummary,
	})
}

func (w *Worker) ensureInput(ctx context.Context, event chainclient.AssignmentFinalized) ([]byte, error) {
	var input []byte
	if len(event.Input) > 0 {
		input = event.Input
	} else {
		read, err := w.cfg.Persistence.ReadArtifact(ctx, event.TaskID, "task-input")
		if err != nil || len(read) == 0 {
			return nil, fmt.Errorf("input not available and no resolver configured")
		}
		input = read
	}
	if !w.snapshot.Assignment.AcceptedOrderPayloadHash.IsZero() {
		inputHash := codec.HashBytes(input)
		if !bytes.Equal(inputHash[:], w.snapshot.Assignment.AcceptedOrderPayloadHash[:]) {
			return nil, fmt.Errorf("input digest does not match accepted input hash for task %s", event.TaskID)
		}
	}
	return input, nil
}

func (w *Worker) ensureOutput(ctx context.Context, event chainclient.AssignmentFinalized, input []byte) (output, tokenIDs, positionValues []byte, err error) {
	_, derr := w.loadOutputDescriptor(ctx, event.TaskID)
	if derr == nil {
		output, err = w.cfg.Persistence.ReadArtifact(ctx, event.TaskID, "worker-output")
		if err != nil {
			return nil, nil, nil, fmt.Errorf("output descriptor exists but worker-output artifact is missing for task %s: %w", event.TaskID, err)
		}
		tokenIDs, terr := w.cfg.Persistence.ReadArtifact(ctx, event.TaskID, "worker-token-ids-material")
		if terr != nil {
			return nil, nil, nil, fmt.Errorf("output descriptor exists but worker-token-ids-material artifact is missing for task %s: %w", event.TaskID, terr)
		}
		positionValues, cerr := w.cfg.Persistence.ReadArtifact(ctx, event.TaskID, "worker-position-values-material")
		if cerr != nil {
			return nil, nil, nil, fmt.Errorf("output descriptor exists but worker-position-values-material artifact is missing for task %s: %w", event.TaskID, cerr)
		}
		return output, tokenIDs, positionValues, nil
	}
	output, err = w.cfg.Persistence.ReadArtifact(ctx, event.TaskID, "worker-output")
	if err == nil {
		tokenIDs, _ = w.cfg.Persistence.ReadArtifact(ctx, event.TaskID, "worker-token-ids-material")
		positionValues, _ = w.cfg.Persistence.ReadArtifact(ctx, event.TaskID, "worker-position-values-material")
		return output, tokenIDs, positionValues, nil
	}
	event.Input = input
	produced, err := w.prepareOutput(ctx, event)
	if err != nil {
		return nil, nil, nil, err
	}
	return produced.output, produced.tokenIDs, produced.positionValues, nil
}

func (w *Worker) ensureReceiptAndResult(ctx context.Context, event chainclient.AssignmentFinalized, output, tokenIDs, positionValues []byte) (builderclient.SignedInferReceipt, InferResult, error) {
	descriptor, err := w.loadOutputDescriptor(ctx, event.TaskID)
	if err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, fmt.Errorf("output descriptor missing, cannot rebuild receipt: %w", err)
	}
	if err := w.validateGenerationOutput(ctx, event, output, tokenIDs, positionValues, descriptor); err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, err
	}
	receiptData, err := w.cfg.Persistence.ReadArtifact(ctx, event.TaskID, "worker-infer-receipt")
	resultData, _ := w.cfg.Persistence.ReadArtifact(ctx, event.TaskID, "worker-result")
	if err == nil && len(receiptData) > 0 {
		var receipt builderclient.SignedInferReceipt
		if jerr := json.Unmarshal(receiptData, &receipt); jerr == nil {
			if err := w.verifyReceiptSignature(ctx, receipt); err == nil {
				facts, err := w.taskFacts(ctx, event.TaskID)
				if err != nil {
					return builderclient.SignedInferReceipt{}, InferResult{}, err
				}
				root, rootErr := codec.OutputMMRRootFromLengths(output, descriptor.OutputChunkLengths)
				if rootErr != nil {
					return builderclient.SignedInferReceipt{}, InferResult{}, rootErr
				}
				if receipt.ChainID != w.cfg.ChainID || receipt.TaskID != event.TaskID || receipt.TaskHash != facts.AcceptedTaskHash.Hex() || receipt.WorkerOperatorAddress != w.cfg.WorkerAddress || receipt.GenerationParamsDigest != facts.GenerationParamsDigest.Hex() || receipt.OutputHash != root.String() || receipt.OutputSizeBytes != uint64(len(output)) || receipt.GeneratedTokenCount != descriptor.GeneratedTokenCount || receipt.OutputLeafCount != uint64(len(descriptor.OutputChunkLengths)) {
					return builderclient.SignedInferReceipt{}, InferResult{}, fmt.Errorf("retained receipt differs from task or output artifacts")
				}
				result, rerr := w.resultFromReceipt(ctx, event.TaskID, receipt)
				if rerr == nil {
					return receipt, result, nil
				}
			}
		}
	}
	// Receipt or result missing: rebuild from the durable artifacts and descriptor.
	receipt, result, err := w.buildAndPersistReceipt(ctx, event, descriptor, output, tokenIDs, positionValues)
	if err != nil {
		return builderclient.SignedInferReceipt{}, InferResult{}, err
	}
	// If an old partial result exists but could not be decoded, overwrite it.
	if resultData != nil {
		return receipt, result, nil
	}
	return receipt, result, nil
}

func (w *Worker) resultFromReceipt(ctx context.Context, taskID string, receipt builderclient.SignedInferReceipt) (InferResult, error) {
	resultData, err := w.cfg.Persistence.ReadArtifact(ctx, taskID, "worker-result")
	if err == nil && len(resultData) > 0 {
		var result InferResult
		if jerr := json.Unmarshal(resultData, &result); jerr == nil {
			result.TaskDataReceipt = receipt
			return result, nil
		}
	}
	descriptor, err := w.loadOutputDescriptor(ctx, taskID)
	if err != nil {
		return InferResult{}, fmt.Errorf("worker-result missing and descriptor unavailable: %w", err)
	}
	return InferResult{
		Started:             true,
		InferDeadlineHeight: receipt.ExpiryHeight,
		OutputRef:           descriptor.OutputRef,
		OutputCID:           descriptor.OutputCID,
		PackageHash:         descriptor.PackageHash,
		TaskDataReceipt:     receipt,
	}, nil
}

// Recovery uses the service identity verified when each confirmation arrived.
// Later key rotation does not invalidate that retained storage commitment.
// confirmedStorageObjects reports whether the relay can be skipped entirely,
// which is only true once every Task Builder holds the whole set. Anything less
// leaves at least one Builder unable to reach data-ready, and re-entering the
// relay is how it gets the rest: the Builders already done are skipped there
// too, by the same confirmedBuilders read.
func (w *Worker) confirmedStorageObjects(ctx context.Context, event chainclient.AssignmentFinalized, receipt builderclient.SignedInferReceipt, confirmations []StorageConfirmationCheckpoint) (bool, error) {
	if len(confirmations) == 0 {
		return false, nil
	}
	builders, err := w.receivingBuilders(ctx, receivingBuilderRef(event))
	if err != nil {
		// The Task Builder list cannot be read, so the relay this gate guards
		// could not have run either. Fall back to the floor the relay itself
		// applies: one Builder holding the complete set is enough for the task
		// to go on. Failing here instead would strand a node whose material is
		// already stored and verified, over a list it only needed in order to
		// find out whether anything was left to retry.
		done, doneErr := w.confirmedBuilders(ctx, event, receipt, nil, confirmations)
		if doneErr != nil {
			return false, err
		}
		return len(done) > 0, nil
	}
	done, err := w.confirmedBuilders(ctx, event, receipt, builders, confirmations)
	if err != nil {
		return false, err
	}
	return len(done) == len(builders), nil
}

// confirmedBuilders reports which Task Builders already hold a complete set of
// signed storage confirmations that still verifies under their retained service
// identity.
//
// It is both the resume gate and the per-Builder skip inside the relay. A
// Builder whose upload failed left no confirmation behind, so it is absent here
// and is exactly the one a re-entry retries; a Builder that succeeded is not
// uploaded to twice.
//
// A nil builders list means "do not filter by membership" and is only for the
// caller that could not read the list at all; every other caller passes the
// task's frozen selection.
func (w *Worker) confirmedBuilders(ctx context.Context, event chainclient.AssignmentFinalized, receipt builderclient.SignedInferReceipt, builders []BuilderEndpoint, confirmations []StorageConfirmationCheckpoint) (map[string]bool, error) {
	done := map[string]bool{}
	if len(confirmations) == 0 {
		return done, nil
	}
	_, currentHeight, err := w.cfg.TaskDataAuth.CommittedBusEnvelopeIdentity(ctx)
	if err != nil {
		return nil, fmt.Errorf("read committed height for retained storage confirmation: %w", err)
	}
	descriptor, err := w.loadOutputDescriptor(ctx, event.TaskID)
	if err != nil {
		return nil, err
	}
	bundles, err := w.readWorkerBundles(ctx, event, receipt, descriptor)
	if err != nil {
		return nil, err
	}
	outputKey := builderclient.TaskDataKey{TaskHash: receipt.TaskHash, SessionID: event.SessionID, TaskID: event.TaskID, Kind: builderclient.DataKindOutput, ContentHash: receipt.OutputHash}
	type expected struct {
		key         builderclient.TaskDataKey
		size, total uint64
	}
	want := []expected{{key: outputKey, size: receipt.OutputSizeBytes}}
	for _, bundle := range bundles {
		key, err := workerBundleKey(receipt, event.SessionID, event.TaskID, bundle.kind)
		if err != nil {
			return nil, err
		}
		want = append(want, expected{key: key, size: uint64(len(bundle.manifest)), total: bundle.decoded.TotalSize()})
	}
	// Only members of the task's frozen selection count. A retained confirmation
	// from an operator no longer in it proves nothing about the Builders that
	// have to become data-ready, and must not stand in for one of them.
	var member map[string]struct{}
	if builders != nil {
		member = make(map[string]struct{}, len(builders))
		for _, builder := range builders {
			member[builder.OperatorAddress] = struct{}{}
		}
	}
	confirmed := map[string][]bool{}
	for _, confirmation := range confirmations {
		if confirmation.Confirmation == nil || confirmation.VerifiedAt.IsZero() || confirmation.BuilderServicePubkey == "" {
			continue
		}
		if member != nil {
			if _, ok := member[confirmation.BuilderOperator]; !ok {
				continue
			}
		}
		c := *confirmation.Confirmation
		endpoint := BuilderEndpoint{OperatorAddress: confirmation.BuilderOperator, ServicePubkey: confirmation.BuilderServicePubkey, AuthorizationNonce: c.ServiceAuthorizationNonce, CurrentHeight: currentHeight}
		for i, expect := range want {
			if c.Key != expect.key {
				continue
			}
			digest, err := verifyStorageConfirmation(c, w.cfg.ChainID, expect.key, expect.key.ContentHash, expect.size, endpoint)
			if err != nil || digest.String() != confirmation.MaterialDigest || !bytes.Equal(c.Signature, confirmation.Signature) || c.ArtifactTotalSizeBytes != expect.total || confirmation.TaskID != event.TaskID || confirmation.DataKind != expect.key.Kind.String() || confirmation.SemanticHash != expect.key.ContentHash || confirmation.SizeBytes != expect.size || confirmation.RetentionUntilHeight != c.RetentionUntilHeight {
				continue
			}
			got, ok := confirmed[confirmation.BuilderOperator]
			if !ok {
				got = make([]bool, len(want))
				confirmed[confirmation.BuilderOperator] = got
			}
			got[i] = true
		}
	}
	for operator, got := range confirmed {
		complete := true
		for _, ok := range got {
			if !ok {
				complete = false
				break
			}
		}
		if complete {
			done[operator] = true
		}
	}
	return done, nil
}

func (w *Worker) ensureOutputAvailable(ctx context.Context, event chainclient.AssignmentFinalized, output []byte, result InferResult) error {
	switch {
	case w.cfg.Builder == nil:
		return fmt.Errorf("builder client is required")
	case w.cfg.TaskData == nil:
		return fmt.Errorf("task data client is required")
	case w.cfg.TaskDataAuth == nil:
		return fmt.Errorf("task data authenticator is required")
	case w.cfg.ReceivingBuilder == nil:
		return fmt.Errorf("receiving Builder provider is required")
	}

	descriptor, err := w.loadOutputDescriptor(ctx, event.TaskID)
	if err != nil {
		return fmt.Errorf("output descriptor missing, cannot make output available: %w", err)
	}
	outputHash, err := codec.OutputMMRRootFromLengths(output, descriptor.OutputChunkLengths)
	if err != nil {
		return err
	}
	if outputHash != descriptor.OutputHash {
		return fmt.Errorf("output hash does not match descriptor")
	}

	availablePayload, err := w.buildOutputAvailablePayload(ctx, event, descriptor.OutputHash)
	if err != nil {
		return err
	}
	subject := builderclient.NATSOutputAvailableSubject(event.TaskID)
	stableDedupID := event.SessionID + "|" + event.TaskID + "|" + hex.EncodeToString(outputHash[:])

	// Repeat staging and finalization idempotently unless both complete signed
	// confirmations still verify under their retained service identities.
	confirmations, err := w.cfg.Persistence.StorageConfirmations(ctx, event.TaskID)
	if err != nil {
		return err
	}
	confirmed, err := w.confirmedStorageObjects(ctx, event, result.TaskDataReceipt, confirmations)
	if err != nil {
		return err
	}
	if !confirmed {
		if err := w.relayReceiptAndUpload(ctx, event, output, result.TaskDataReceipt); err != nil {
			return err
		}
	}

	// Hold: the first time this step runs, persist an outbox record. On a
	// restart the record already exists and we skip the durable hold.
	_, err = w.cfg.Persistence.BuilderMessage(ctx, stableDedupID)
	if errors.Is(err, ErrCheckpointNotFound) {
		if err := w.persistBuilderOutbox(ctx, event.TaskID, subject, availablePayload, "pending", stableDedupID); err != nil {
			return err
		}
		if err := w.crashAt(CrashPointOutputAvailableHeld); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	// Publish the OUTPUT_AVAILABLE message. The outbox record itself is the
	// durable guard against duplicate publication; the Builder transport is
	// expected to deduplicate on DedupID.
	if err := w.cfg.Builder.Publish(ctx, builderclient.PublishRequest{
		Subject: subject,
		TaskID:  event.TaskID,
		Payload: availablePayload,
		DedupID: stableDedupID,
	}); err != nil {
		return err
	}

	w.cfg.Trace.Event("output_available_published",
		tasktrace.Str("task", event.TaskID), tasktrace.Str("session", event.SessionID),
		tasktrace.Hash("output_hash", outputHash),
		tasktrace.Hex("task_hash", result.TaskDataReceipt.TaskHash),
		tasktrace.Str("subject", subject), tasktrace.Str("dedup_id", stableDedupID),
		tasktrace.Int("payload_bytes", len(availablePayload)))
	if err := w.crashAt(CrashPointOutputAvailableReleased); err != nil {
		return err
	}
	return nil
}
