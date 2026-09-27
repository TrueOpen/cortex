package verifier

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

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
	"github.com/TrueOpen/cortex/internal/tasktrace"
	"github.com/TrueOpen/cortex/internal/txclient"
)

type Config struct {
	VerifierAddress           string
	ModelServiceID            string
	Model                     modelservice.Client
	Builder                   builderclient.Client
	Persistence               Persistence
	ChainID                   string
	SignerAddress             string
	SignerKeyRef              string
	Signer                    signer.DigestSigner
	VerifyDeadlineDeltaHeight uint64
	FakeOutput                bool
	TrustedNATSDev            bool
	NexusEnvelopeSigner       builderclient.BusEnvelopeSigner
	// ServiceAuthorizationNonce is the current ServiceKey binding's
	// service_authorization_nonce. Every frozen §5.14 verifier stage wire carries
	// it as preimage field 6, so a commit or result credential cannot be built
	// without it.
	ServiceAuthorizationNonce uint64
	// EnvelopeTTL is the lifetime stamped on outbound envelopes. Zero keeps the
	// envelope default.
	EnvelopeTTL time.Duration
	// TaskFacts reads the accepted task hash, generation digest and execution
	// snapshot hash bound by the result payload and V2 credential.
	TaskFacts taskfacts.Reader
	// ProfileReader reads the locked model profile so the verifier can derive
	// the required evidence set from the Profile's evidence_schema instead of
	// hard-coding it. A nil reader is only allowed in fake/dev mode.
	ProfileReader ProfileReader
	// MaxOutputBytes bounds the output artifact fetch. The output is not evidence,
	// so no profile field sizes it, and the fetch happens before the output hash
	// can reject anything - so without a bound a model service that streams
	// arbitrarily many individually valid chunks makes this node buffer all of
	// them. Zero means the default, never unbounded.
	MaxOutputBytes uint64
	// Trace reports the digests this Verifier derives -- the sample seed and
	// what went into it, the trace root, the commit hash and the digest actually
	// signed, the result credential -- as they are produced. Nil is silent.
	Trace *tasktrace.Trace
	// CommitRelay is the Task Builder relay for the signed verify commit. Nil is
	// the normal configuration and means this round has no relay channel at all;
	// see commit_exit.go for why that is the shipped state and what happens next.
	CommitRelay CommitRelay
	// CommitSubmitter puts the signed commit on chain itself when the relay
	// cannot carry it. Without it a signed commit has no exit and the verify
	// path refuses rather than leaving it as a local file, so real-mode wiring
	// must supply it.
	CommitSubmitter   CommitSubmitter
	EvidencePublisher EvidencePublisher
}

// EvidencePublisher finalizes the committed verifier bundle before its receipt
// can be delivered to the Builder.
type EvidencePublisher interface {
	PublishVerifierEvidence(context.Context, TaskState, nodewire.ResultReceiptV3, []byte, []byte) error
}

// ProfileReader reads the locked model profile for a task.
type ProfileReader interface {
	CurrentModelProfile(ctx context.Context, modelID, profileVersion string) (chainclient.CurrentModelProfileSnapshot, error)
}

type Verifier struct {
	cfg     Config
	results map[string]VerifyResult
	// commits records, per Keeper commit_key scope, the commit this process
	// already landed on chain. It is keyed by the scope rather than by the
	// result identity because that is what the Keeper keys CommitState by: a
	// retry that re-derives a different commit_hash for the same task and round
	// would be a duplicate noop, and this is what stops it paying gas to find
	// that out. See commitKeyScope.
	commits map[string]CommitDelivery
}

var (
	errTaskIdentityMissing  = errors.New("task identity is required")
	errTaskIdentityMismatch = errors.New("task identity does not match canonical task id")
	errPackageTaskMismatch  = errors.New("output package task id does not match canonical task id")
)

type Persistence interface {
	WriteEvidence(context.Context, EvidenceRecord) error
	WriteSettleMaterial(context.Context, SettleMaterial) error
	CheckpointModelJob(context.Context, ModelJobCheckpoint) error
}

type ModelJobCheckpoint struct{ JobID, TaskID, Role, ModelServiceID, Status, Intent string }

type EvidenceRecord struct {
	TaskID string
	Kind   string
	Data   []byte
	Ref    string
}

type SettleMaterial struct {
	TaskID  string
	Kind    string
	Payload []byte
	Digest  codec.Hash
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

type outboxPersistence interface {
	WriteVerifierBuilderOutbox(context.Context, OutboxRecord) error
}

type verifierEvidenceReader interface {
	ReadVerifierEvidence(context.Context, string) ([]byte, error)
}

type TaskState struct {
	TaskID           string
	SessionID        string
	OrderSequence    uint64
	OrderDigest      codec.Hash
	VerifyRound      uint64
	InferReceiptHash codec.Hash
	Member           builderclient.CandidateMemberRefMessage
	ModelID          string
	ProfileVersion   uint32
	Capability       string
	WorkerAddress    string
	OutputPackage    policy.OutputPackageSummary
	// OutputConfirmed says the caller proved the receiving Builder holds the
	// committed output. At handraise (V3) that proof is metadata-only and
	// ConfirmedOutput is empty; at verify (V7a) the body came with it.
	OutputConfirmed bool
	// ConfirmedOutput is the output body the caller already proved against the
	// Keeper-committed output hash while confirming the package. When it is
	// present the verify path uses it instead of asking the local model service
	// for OutputPackage.OutputRef -- a ref only the Worker's model service can
	// resolve, which on any node that is not the Worker fails outright
	// (modelservice.LocalService.FetchArtifact refuses a foreign service id).
	ConfirmedOutput             []byte
	ConfirmedOutputChunkLengths []uint64
	ConfirmedInferReceipt       *builderclient.SignedInferReceipt
	// The token-id artifacts are bound by the receipt's
	// TRUEOPEN_WORKER_TOKEN_COMMITMENT_V1 and worker_values by its
	// TRUEOPEN_WORKER_VALUE_COMMITMENT_V3. The daemon confirms them after
	// download and the Verifier rechecks them before scoring.
	ConfirmedInputTokenIDs     []byte
	ConfirmedGeneratedTokenIDs []byte
	ConfirmedWorkerValues      []byte
	// ConfirmedGenerationParams is the A-level generation_params artifact, the
	// task's exact canonical_generation_params_json and the only source of the
	// parameters the prefill runs under.
	ConfirmedGenerationParams []byte
	// ConfirmedFinishReason is recovered from the receipt-bound
	// WORKER_TOKEN_OPENING commitment.
	ConfirmedFinishReason      nodewire.FinishReasonV1
	OpenVerifyAccepted         bool
	AssignedVerifiers          []string
	OpenVerifyHeight           uint64
	HandraiseExpiryHeight      uint64
	CurrentHeight              uint64
	FutureBeaconID             string
	BatchLogRoot               codec.Hash
	CommitDeadlineHeight       uint64
	WorkerRevealDeadlineHeight uint64
	RevealDeadlineHeight       uint64
	VerifyDeadlineHeight       uint64
	VerificationSampleSeed     codec.Hash
	HandraisePrecheck          *policy.VerifierPrecheckInput
}

type HandraiseResult struct {
	Signed   bool
	Decision policy.VerifierDecision
}

type VerifyResult struct {
	Started                bool
	VerificationSampleSeed codec.Hash
	ResultDigest           codec.Hash
	// ResultReveal stores the canonical 18-field VerifierResultPayloadV2 bytes.
	// The commit binds verifier_value_root and the salt, not this payload.
	ResultReveal     []byte
	EvidenceManifest []byte
	CommitHash       codec.Hash
	// CommitWire is the frozen task.v1.VerifyCommitV1 body, signature
	// included. It is the value whose TRUEOPEN_COMMIT_V1 digest was signed and the
	// only source commitPayload marshals from, so the submitted body and the
	// signed body cannot drift apart.
	CommitWire             nodewire.VerifyCommitV1
	Salt                   codec.Hash
	MainMismatchCount      int
	SampleValueSequenceRef string
	// MetricMaterial is metric_root, the typed MetricSummaryV1 and the
	// aggregate proof this run produced. It is derived at verify time and
	// consumed at reveal time, so it is persisted beside the compact reveal
	// rather than only returned here; see metric_material.go.
	MetricMaterial metric.Material
	// CommitDelivery is what happened to the signed commit: which exit carried
	// it, and whether the chain confirmed it. It is filled in before the result
	// credential is attempted, so a caller that only reaches the frozen
	// result-body gap still learns whether the commit landed.
	CommitDelivery CommitDelivery
}

func New(cfg Config) *Verifier {
	// Defaulted here rather than at each call site so that a wiring path which
	// forgets the field still gets a bound. An unbounded output fetch must not be
	// reachable by omission.
	if cfg.MaxOutputBytes == 0 {
		cfg.MaxOutputBytes = DefaultMaxOutputBytes
	}
	return &Verifier{cfg: cfg, results: make(map[string]VerifyResult), commits: make(map[string]CommitDelivery)}
}

// DefaultMaxOutputBytes bounds an output artifact when no deployment value is
// configured. 64 MiB is far above any inference output this node produces and far
// below what it takes to exhaust a node, which is the only job of a default here.
const DefaultMaxOutputBytes = 64 << 20

func (v *Verifier) EvaluateAndHandraise(ctx context.Context, state TaskState) (HandraiseResult, error) {
	if err := validateCanonicalTaskState(state); err != nil {
		return HandraiseResult{Decision: policy.VerifierDecision{Accepted: false, RejectCode: canonicalTaskRejectCode(err)}}, nil
	}
	// The output has to be confirmed against the receiving Builder before this
	// node signs anything that commits to it. The Verifier used to be able to do
	// that itself through FetchOutputRef; the target-state task-data contract
	// deleted the OutputRef object, and confirming an output now needs the Keeper
	// snapshot and the receiving Builder's descriptor -- neither of which is in
	// TaskState. So the confirmation belongs to the caller (daemon.TaskRunner via
	// daemon.OutputConfirmer) and an unconfirmed state is refused outright rather
	// than confirmed here on weaker evidence.
	if !state.OutputConfirmed {
		return HandraiseResult{Decision: policy.VerifierDecision{Accepted: false, RejectCode: "L2_OUTPUT_PACKAGE_MISSING"}}, nil
	}
	decision := policy.EvaluateVerifierPrecheck(v.precheckInput(state, state.OpenVerifyHeight, "handraise"))
	if !decision.Accepted {
		return HandraiseResult{Decision: decision}, nil
	}
	taskID, err := builderclient.CanonicalWireHash(state.TaskID, "task_id")
	if err != nil {
		return HandraiseResult{}, err
	}
	member, err := state.Member.Nodewire()
	if err != nil {
		return HandraiseResult{}, err
	}
	modelID, err := identity.ModelIDBytes(state.ModelID)
	if err != nil {
		return HandraiseResult{}, err
	}
	handraise := nodewire.VerifierHandraiseV1{
		SchemaVersion: nodewire.VerifierHandraiseSchemaVersionV1, ChainID: v.cfg.ChainID,
		TaskID: taskID[:], VerifyRound: uint32(state.VerifyRound),
		InferReceiptHash: append([]byte(nil), state.InferReceiptHash[:]...),
		OutputHash:       append([]byte(nil), state.OutputPackage.OutputHash[:]...),
		ModelID:          modelID, ProfileVersion: state.ProfileVersion, Member: member,
		Duty:                      nodewire.DutyVerifier,
		ServiceAuthorizationNonce: v.cfg.ServiceAuthorizationNonce,
		ExpiryHeight:              state.HandraiseExpiryHeight,
	}
	wireDigest, err := nodewire.VerifierHandraiseSigningDigest(handraise)
	if err != nil {
		return HandraiseResult{}, err
	}
	serviceSignature, err := v.signDigest(ctx, wireDigest)
	if err != nil {
		return HandraiseResult{}, err
	}
	handraise.ServiceSignature = serviceSignature
	message, err := builderclient.VerifierHandraiseProto(handraise)
	if err != nil {
		return HandraiseResult{}, err
	}
	subject := builderclient.NATSVerifierHandraiseSubject(state.TaskID)
	payload, err := v.encodeNexusMessage(builderclient.UnsignedEnvelopeInput{
		Kind: builderclient.KindVerifierHandraise, ChainID: v.cfg.ChainID, Subject: subject,
		SenderOperatorAddress: v.cfg.VerifierAddress, SenderParticipantType: builderclient.ParticipantCortex,
		ServiceAuthorizationNonce: v.cfg.ServiceAuthorizationNonce,
	}, message)
	if err != nil {
		return HandraiseResult{}, err
	}
	if err := v.persistHandraise(ctx, state.TaskID, payload); err != nil {
		return HandraiseResult{}, err
	}
	var verifierRound int
	if state.VerifyRound <= uint64(int(^uint(0)>>1)) {
		verifierRound = int(state.VerifyRound)
	}
	handraiseDedupID := builderclient.VerifierHandraiseDedupID(state.TaskID, verifierRound, hex.EncodeToString(wireDigest[:]))
	persisted, err := v.persistBuilderOutbox(ctx, state.TaskID, subject, payload, handraiseDedupID)
	if err != nil {
		return HandraiseResult{}, err
	}
	if v.cfg.Builder != nil && !persisted {
		if err := v.cfg.Builder.Publish(ctx, builderclient.PublishRequest{
			Subject: subject,
			TaskID:  state.TaskID,
			Payload: payload,
			DedupID: handraiseDedupID,
		}); err != nil {
			return HandraiseResult{}, err
		}
	}
	return HandraiseResult{Signed: true, Decision: decision}, nil
}

func (v *Verifier) persistHandraise(ctx context.Context, taskID string, payload []byte) error {
	if v.cfg.Persistence == nil {
		return nil
	}
	if err := v.cfg.Persistence.WriteEvidence(ctx, EvidenceRecord{
		TaskID: taskID,
		Kind:   "verifier-handraise",
		Data:   append([]byte(nil), payload...),
		Ref:    evidenceRef(payload),
	}); err != nil {
		return err
	}
	return v.cfg.Persistence.WriteSettleMaterial(ctx, SettleMaterial{
		TaskID:  taskID,
		Kind:    "verifier-handraise",
		Payload: append([]byte(nil), payload...),
		Digest:  codec.HashWithDomain("TRUEOPEN_VERIFIER_HANDRAISE_MATERIAL_V1", payload),
	})
}

// profileEvidenceRequirement is a required evidence kind together with the
// profile's per-kind size bound. ExpectedRoot/EncodedSizeBytes are filled in
// after the artifact is fetched.
// lockedProfile reads the profile snapshot the task was assigned under, once
// per verify. Two independent consumers need it - the evidence bounds and the
// metric binding - and reading it twice would let them disagree about which
// profile this round ran under.
//
// The nil reader is the fake/dev configuration, reported as such rather than as
// an error, so the two callers can each decide what a missing profile means for
// them.
func (v *Verifier) lockedProfile(ctx context.Context, state TaskState) (chainclient.CurrentModelProfileSnapshot, bool, error) {
	if v.cfg.ProfileReader == nil {
		if v.cfg.FakeOutput {
			return chainclient.CurrentModelProfileSnapshot{}, false, nil
		}
		return chainclient.CurrentModelProfileSnapshot{}, false, fmt.Errorf("profile reader is required")
	}
	profile, err := v.cfg.ProfileReader.CurrentModelProfile(ctx, state.ModelID, fmt.Sprintf("%d", state.ProfileVersion))
	if err != nil {
		return chainclient.CurrentModelProfileSnapshot{}, false, fmt.Errorf("query locked model profile: %w", err)
	}
	return profile, true, nil
}

// profileEvidenceLimits reads the locked profile's evidence schema and returns
// each Worker evidence kind's max_encoded_size_bytes. It fails closed for an
// evidence schema that does not re-derive, and for any requirement other than
// the two v0.3.0 Worker commitments.
func (v *Verifier) profileEvidenceLimits(state TaskState, profile chainclient.CurrentModelProfileSnapshot, served bool) (map[nodewire.EvidenceKind]uint64, error) {
	if !served {
		return map[nodewire.EvidenceKind]uint64{
			nodewire.EvidenceKindWorkerValueOpening: math.MaxUint64, nodewire.EvidenceKindWorkerTokenOpening: math.MaxUint64,
		}, nil
	}
	if _, err := keepercontract.EvidenceSchemaHashFromCurrentModelProfile(profile); err != nil {
		return nil, fmt.Errorf("locked profile evidence_schema does not re-derive to evidence_schema_hash for task %s: %w", state.TaskID, err)
	}
	schema := profile.Profile.VerificationProfile.EvidenceSchema
	limits := map[nodewire.EvidenceKind]uint64{}
	for _, req := range schema.RequiredInferEvidence {
		kind := nodewire.EvidenceKind(req.EvidenceKind)
		supported := kind == nodewire.EvidenceKindWorkerValueOpening && req.CommitmentSchemaVersion == nodewire.WorkerValueCommitmentSchemaVersionV3 ||
			kind == nodewire.EvidenceKindWorkerTokenOpening && req.CommitmentSchemaVersion == nodewire.WorkerTokenCommitmentSchemaVersionV1
		if !supported {
			return nil, fmt.Errorf("locked profile requires unsupported evidence kind %d at commitment schema %d", req.EvidenceKind, req.CommitmentSchemaVersion)
		}
		limits[kind] = req.MaxEncodedSizeBytes.Uint64()
	}
	if len(limits) != 2 {
		return nil, fmt.Errorf("locked profile must require exactly the Worker value and token evidence")
	}
	return limits, nil
}

// metricBinding projects the locked profile and the Keeper-served
// generation_params_digest into the binding every metric leaf carries.
//
// It runs BEFORE the model is asked to verify anything, and that ordering is
// the point. metric.BindTask is where an unsupported verification_mode,
// numeric_scale or metric_aggregate_proof_version is refused, and discovering
// one of those after a full prefill costs the round its whole verify budget for
// an answer that was knowable from the snapshot.
//
// The second return value is false only in the fake/dev configuration that has
// no profile reader at all. Everywhere else a profile is required, because the
// alternative - deriving leaves under a guessed profile - produces a
// metric_root that no opening can reproduce.
func (v *Verifier) metricBinding(ctx context.Context, state TaskState, profile chainclient.CurrentModelProfileSnapshot, served bool) (metric.Binding, bool, error) {
	if !served {
		return metric.Binding{}, false, nil
	}
	taskID, err := hex.DecodeString(state.TaskID)
	if err != nil || len(taskID) != 32 {
		return metric.Binding{}, false, fmt.Errorf("metric binding task_id must be canonical 32-byte hex, got %q", state.TaskID)
	}
	facts, err := v.taskFacts(ctx, state.TaskID)
	if err != nil {
		return metric.Binding{}, false, fmt.Errorf("metric binding generation_params_digest: %w", err)
	}
	if state.VerifyRound == 0 || state.VerifyRound > math.MaxUint32 {
		return metric.Binding{}, false, fmt.Errorf("metric binding verify_round must fit a positive uint32")
	}
	var taskIDHash, taskHash, generationParamsDigest codec.Hash
	copy(taskIDHash[:], taskID)
	copy(taskHash[:], facts.AcceptedTaskHash)
	copy(generationParamsDigest[:], facts.GenerationParamsDigest)

	binding, err := metric.BindTask(v.cfg.ChainID, taskIDHash, taskHash, uint32(state.VerifyRound), profile.Profile, generationParamsDigest)
	if err != nil {
		return metric.Binding{}, false, err
	}
	return binding, true, nil
}

func (v *Verifier) HandleOpenVerifyAccepted(ctx context.Context, state TaskState) (VerifyResult, error) {
	if state.ModelID == "" || state.ProfileVersion == 0 || strings.TrimSpace(state.Capability) == "" {
		return VerifyResult{}, fmt.Errorf("task model id, profile version, and capability are required")
	}
	if !state.OpenVerifyAccepted || !slices.Contains(state.AssignedVerifiers, v.cfg.VerifierAddress) {
		return VerifyResult{}, nil
	}
	if _, err := selectedVerifierIndex(state, v.cfg.VerifierAddress); err != nil {
		return VerifyResult{}, err
	}
	if err := validateCanonicalTaskState(state); err != nil {
		if errors.Is(err, errPackageTaskMismatch) {
			return VerifyResult{}, fmt.Errorf("verifier precheck rejected: L2_OUTPUT_PACKAGE_TASK_MISMATCH")
		}
		return VerifyResult{}, err
	}
	if v.cfg.Model == nil {
		return VerifyResult{}, fmt.Errorf("model client is required")
	}
	decision := policy.EvaluateVerifierPrecheck(v.precheckInput(state, state.OpenVerifyHeight, "verify"))
	if !decision.Accepted {
		return VerifyResult{}, fmt.Errorf("verifier precheck rejected: %s", decision.RejectCode)
	}
	lockedProfile, profileServed, err := v.lockedProfile(ctx, state)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("verifier precheck rejected: PROFILE: %w", err)
	}
	evidenceLimits, err := v.profileEvidenceLimits(state, lockedProfile, profileServed)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("verifier precheck rejected: PROFILE evidence schema: %w", err)
	}
	// Before any model work: a profile this verifier cannot honestly compute
	// under - BATCH_SAMPLES above all - stops the round here rather than after a
	// full prefill. keeper §9.7 forbids choosing a batch aggregation semantics
	// locally, so there is nothing to fall back to.
	metricBinding, metricBound, err := v.metricBinding(ctx, state, lockedProfile, profileServed)
	if err != nil {
		if errors.Is(err, metric.ErrProfileUnsupported) {
			return VerifyResult{}, fmt.Errorf("verifier precheck rejected: PROFILE metric spec: %w", err)
		}
		return VerifyResult{}, err
	}
	output := modelservice.Artifact{Data: state.ConfirmedOutput}
	if state.ConfirmedOutput == nil && (state.ConfirmedInferReceipt == nil || state.ConfirmedInferReceipt.OutputSizeBytes != 0) {
		output, err = v.cfg.Model.FetchArtifact(ctx, modelservice.FetchArtifactRequest{
			RequestID:      "verifier-fetch-output-" + state.TaskID,
			ModelServiceID: v.cfg.ModelServiceID,
			Ref:            state.OutputPackage.OutputRef,
			SizeLimitBytes: v.cfg.MaxOutputBytes,
			Kind:           "worker-output",
		})
		if err != nil {
			return VerifyResult{}, err
		}
	} else if uint64(len(output.Data)) > v.cfg.MaxOutputBytes {
		// The confirmer applies its own bound, but this node's configured bound
		// is the one the rest of the verify path was sized against, so it is
		// re-applied rather than assumed to be the same number.
		return VerifyResult{}, fmt.Errorf("confirmed output is %d bytes, above the configured bound %d", len(output.Data), v.cfg.MaxOutputBytes)
	}
	// Re-checked on both paths. On the confirmed path this is a second reading of
	// a binding the confirmer already established; keeping it means the guarantee
	// does not depend on which caller assembled the state.
	got, err := codec.OutputMMRRootFromLengths(output.Data, state.ConfirmedOutputChunkLengths)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("output artifact chunk boundaries: %w", err)
	}
	if got != state.OutputPackage.OutputHash {
		return VerifyResult{}, fmt.Errorf("output artifact hash mismatch")
	}
	facts, err := v.taskFacts(ctx, state.TaskID)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("%w: accepted_task_hash: %w", ErrVerifyCommitInputUnavailable, err)
	}
	requiredTopK := uint32(0)
	if metricBound {
		requiredTopK = metricBinding.RequiredTopK
	}
	evidence, err := v.workerEvidence(ctx, state, evidenceLimits, requiredTopK, facts.AcceptedTaskHash)
	if err != nil {
		return VerifyResult{}, err
	}
	if !v.cfg.FakeOutput {
		if err := v.validateAcceptedWorkerEvidence(ctx, state, lockedProfile, evidenceLimits, output.Data, evidence); err != nil {
			return VerifyResult{}, err
		}
	}
	tokenIDs, err := evidence.tokenIDs()
	if err != nil {
		return VerifyResult{}, err
	}
	generation, generationDigest, err := v.taskGeneration(ctx, state, evidence.generationParams)
	if err != nil {
		return VerifyResult{}, err
	}
	seed := state.VerificationSampleSeed
	if seed == (codec.Hash{}) {
		seed = VerificationSampleSeed(SeedInput{
			ChainID:          v.cfg.ChainID,
			TaskID:           state.TaskID,
			VerifyRound:      state.VerifyRound,
			OpenVerifyHeight: state.OpenVerifyHeight,
			Profile:          fmt.Sprintf("%d", state.ProfileVersion),
			FutureBeaconID:   state.FutureBeaconID,
			PackageHash:      state.OutputPackage.PackageHash,
			OutputHash:       state.OutputPackage.OutputHash,
		})
	}
	resultKey := verifyResultKey(state, seed, v.cfg.VerifierAddress)
	if result, ok := v.results[resultKey]; ok {
		return result, nil
	}
	jobID := "verifier-verify-" + state.TaskID
	if err := v.persistModelServiceJob(ctx, jobID, state.TaskID, "running", "verify"); err != nil {
		return VerifyResult{}, err
	}
	// The prefill takes the Worker's token ids only. The Worker's values are not
	// a model-service input: this Verifier's own values, and the root it commits
	// to, must be fixed by its own prefill.
	resp, err := v.cfg.Model.Verify(ctx, modelservice.VerifyRequest{
		Generation: generation, GenerationParamsDigest: generationDigest,
		RequestID:      "verifier-verify-" + state.TaskID,
		ModelServiceID: v.cfg.ModelServiceID,
		JobID:          jobID,
		TaskID:         state.TaskID,
		ModelID:        state.ModelID,
		ProfileVersion: fmt.Sprintf("%d", state.ProfileVersion),
		RequestDigest:  seed[:],
		Capability:     state.Capability,
		Sample:         seed[:],
		TokenIDs:       tokenIDs,
	})
	if err != nil {
		_ = v.persistModelServiceJob(ctx, jobID, state.TaskID, "failed", "verify")
		return VerifyResult{}, err
	}
	if resp.Error != nil {
		_ = v.persistModelServiceJob(ctx, jobID, state.TaskID, "failed", "verify")
		return VerifyResult{}, fmt.Errorf("model verify failed: %s", resp.Error.Code)
	}
	if generation != nil && !bytes.Equal(resp.GenerationParamsDigest, generationDigest) {
		return VerifyResult{}, fmt.Errorf("model verification generation_params_digest missing or mismatched")
	}
	if len(resp.VerifierValues) != len(tokenIDs.Generated) {
		_ = v.persistModelServiceJob(ctx, jobID, state.TaskID, "failed", "verify")
		return VerifyResult{}, fmt.Errorf("model service returned %d verifier values for %d generated tokens", len(resp.VerifierValues), len(tokenIDs.Generated))
	}
	values, err := v.fetchVerificationValues(ctx, state.TaskID, resp.SampleValueSequenceRef)
	if err != nil {
		return VerifyResult{}, err
	}
	// The metric pipeline runs on the values this same Verify call produced, not
	// on a re-read of the persisted artifact: the value root, metric_root and the
	// reveal have to describe one run, and a second read is a second source that
	// can disagree with the first.
	var metricMaterial metric.Material
	if metricBound {
		verifierLeaves, verifierValueRoot, err := v.verifierValueLeaves(state, facts.AcceptedTaskHash, requiredTopK, resp.VerifierValues)
		if err != nil {
			_ = v.persistModelServiceJob(ctx, jobID, state.TaskID, "failed", "verify")
			return VerifyResult{}, err
		}
		metricMaterial, err = buildMetricMaterial(metricBinding, metricBound, verifierValueRoot, evidence.workerLeaves, verifierLeaves)
		if err != nil {
			_ = v.persistModelServiceJob(ctx, jobID, state.TaskID, "failed", "verify")
			return VerifyResult{}, err
		}
	}
	if !hasMetricMaterial(metricMaterial) {
		// Fail closed rather than reaching for a substitute. The commit binds
		// verifier_value_root and the reveal carries metric material; without a
		// locked profile neither exists, and there is no value that makes them
		// re-derivable.
		_ = v.persistModelServiceJob(ctx, jobID, state.TaskID, "failed", "verify")
		return VerifyResult{}, fmt.Errorf(
			"%w: the commit needs verifier_value_root and the reveal needs metric material, and this run "+
				"produced neither, so no commit this Keeper can re-derive at full reveal exists",
			ErrVerifyCommitInputUnavailable)
	}
	// The task identity enters the commitment as raw Hash32 bytes.
	commitTaskID, err := hex.DecodeString(state.TaskID)
	if err != nil || len(commitTaskID) != 32 {
		return VerifyResult{}, fmt.Errorf(
			"%w: commit task_id must be canonical 32-byte hex, got %q", ErrVerifyCommitInputUnavailable, state.TaskID)
	}
	if state.VerifyRound > math.MaxUint32 {
		return VerifyResult{}, fmt.Errorf(
			"%w: commit verify_round %d does not fit the frozen uint32 field",
			ErrVerifyCommitInputUnavailable, state.VerifyRound)
	}
	commitVerifyRound := uint32(state.VerifyRound)
	if metricMaterial.LeafCount < 0 || metricMaterial.LeafCount > math.MaxUint32 {
		return VerifyResult{}, fmt.Errorf(
			"%w: metric_leaf_count %d does not fit the uint32 the reveal and the receipt carry",
			ErrVerifyCommitInputUnavailable, metricMaterial.LeafCount)
	}
	salt := codec.HashWithDomain("TRUEOPEN_RESULT_COMMIT_SALT_V1", []byte(state.TaskID), []byte(v.cfg.VerifierAddress), seed[:], resp.MaterialDigest)
	manifest, err := (evidencebundle.Manifest{
		Version: 1, ChainID: v.cfg.ChainID, TaskID: state.TaskID,
		TaskHash: hex.EncodeToString(facts.AcceptedTaskHash), VerifyRound: commitVerifyRound,
		EvidenceKind: evidencebundle.KindVerifierValueOpening,
		ProducerKind: "VERIFIER", ProducerOperator: v.cfg.VerifierAddress,
		EvidenceSchemaHash: metricBinding.EvidenceSchemaHash.String(),
		Artifacts:          []evidencebundle.Artifact{evidencebundle.NewArtifact(builderclient.EvidenceArtifactAggregateProof, metricMaterial.AggregateProof.Bytes)},
	}).Encode()
	if err != nil {
		return VerifyResult{}, fmt.Errorf("build verifier evidence manifest: %w", err)
	}
	resultReveal, err := canonicalResultPayload(v.cfg, state, facts, metricMaterial, manifest)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("%w: %w", ErrVerifyCommitInputUnavailable, err)
	}
	resultDigest := codec.HashBytes(resultReveal)
	commitHash, err := nodewire.ResultCommitmentHash(nodewire.ResultCommitmentV3{
		ChainID:                 v.cfg.ChainID,
		TaskID:                  commitTaskID,
		TaskHash:                facts.AcceptedTaskHash,
		VerifyRound:             commitVerifyRound,
		VerifierOperatorAddress: v.cfg.VerifierAddress,
		VerifierValueRoot:       metricMaterial.VerifierValueRoot[:],
		Salt:                    salt[:],
	})
	if err != nil {
		return VerifyResult{}, fmt.Errorf("derive frozen commit_hash: %w", err)
	}
	// The frozen commit body is assembled BEFORE it is signed, and the value that
	// is signed is the value commitPayload marshals. Signing a digest derived
	// from a different struct than the one submitted is how the pre-freeze
	// keepercontract.Commit preimage survived the cutover: it covered five text
	// fields and left schema_version, the raw Hash32 task_id, the address codec
	// bytes, service_authorization_nonce and expiry_height unauthorized.
	commitWire, err := verifyCommitWire(v.cfg, state, commitHash)
	if err != nil {
		return VerifyResult{}, err
	}
	commitSigningDigest, err := nodewire.VerifyCommitSigningDigest(commitWire)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("derive frozen verify commit signing digest: %w", err)
	}
	commitWire.ServiceSignature, err = v.signDigest(ctx, commitSigningDigest)
	if err != nil {
		return VerifyResult{}, err
	}
	// The seed is printed with the two hashes it is derived from, because a seed
	// that disagrees with the chain's is almost always one of those two inputs
	// disagreeing -- and commit_hash is what the reveal is later checked against.
	v.cfg.Trace.Event("verify_commit_signed",
		tasktrace.Str("task", state.TaskID), tasktrace.Uint("verify_round", state.VerifyRound),
		tasktrace.Hash("output_hash", state.OutputPackage.OutputHash),
		tasktrace.Hash("package_hash", state.OutputPackage.PackageHash),
		tasktrace.Hash("infer_receipt_hash", state.InferReceiptHash),
		tasktrace.Hash("verification_sample_seed", seed),
		tasktrace.Bool("seed_from_keeper", state.VerificationSampleSeed != codec.Hash{}),
		tasktrace.Hash("worker_value_root", evidence.workerValueRoot),
		tasktrace.Hash("verifier_value_root", metricMaterial.VerifierValueRoot),
		tasktrace.Hash("salt", salt), tasktrace.Hash("result_digest", resultDigest),
		tasktrace.Hash("commit_hash", commitHash),
		tasktrace.Hash("commit_signing_digest", commitSigningDigest),
		tasktrace.Int("main_mismatch_count", resp.MainMismatchCount),
		tasktrace.Int("sample_values", len(values)),
		// The metric material, printed at the point it is produced. metric_root
		// is what a later opening is checked against, and metric_leaf_count is
		// the only place the tree's length is recorded - the tree itself carries
		// no length.
		tasktrace.Hash("metric_root", metricMaterial.Root),
		tasktrace.Int("metric_leaf_count", metricMaterial.LeafCount),
		tasktrace.Hash("aggregate_proof_hash", metricMaterial.AggregateProof.Hash),
		tasktrace.Uint("open_verify_height", state.OpenVerifyHeight),
		tasktrace.Uint("commit_deadline_height", state.CommitDeadlineHeight))
	result := VerifyResult{
		Started:                true,
		VerificationSampleSeed: seed,
		ResultDigest:           resultDigest,
		ResultReveal:           resultReveal,
		EvidenceManifest:       manifest,
		CommitHash:             commitHash,
		CommitWire:             commitWire,
		Salt:                   salt,
		MainMismatchCount:      resp.MainMismatchCount,
		SampleValueSequenceRef: resp.SampleValueSequenceRef,
		MetricMaterial:         metricMaterial,
	}
	if err := v.persistResult(ctx, state, result, values); err != nil {
		return VerifyResult{}, err
	}
	// The model job status describes the model-service job, which is finished and
	// whose evidence is persisted. Chain-credential delivery below is a separate
	// concern and must not retroactively mark the model work unfinished.
	if err := v.persistModelServiceJob(ctx, jobID, state.TaskID, "succeeded", "verify"); err != nil {
		return VerifyResult{}, err
	}
	// The commit exit runs HERE, between the local records and the result
	// credential, because those are two independent obligations and the second
	// one is still blocked. The commit is complete and signed; the result
	// receipt still has no producer for metric_root, metric_summary,
	// and aggregate_proof_hash. Delivering the commit after
	// the result credential would mean no commit ever reaches the chain until
	// those three exist, which is how a signed commit came to live only in
	// verifier-result-commit-receipt.
	//
	// The result is returned beside a delivery failure for the same reason it is
	// returned beside the credential gap: the verification really happened, its
	// evidence is stored, and the caller must be able to see it next to why the
	// commit did not land.
	delivery, err := v.deliverCommit(ctx, state, result)
	result.CommitDelivery = delivery
	// A commit that did not reach the chain is an ERROR-level milestone, not an
	// informational one: nothing downstream can complete without it, and this is
	// the line an operator greps for when the round produced no CommitState.
	traceCommitExit := v.cfg.Trace.Event
	if err != nil {
		traceCommitExit = v.cfg.Trace.ErrorEvent
	}
	traceCommitExit("verify_commit_exit",
		tasktrace.Str("task", state.TaskID), tasktrace.Uint("verify_round", state.VerifyRound),
		tasktrace.Str("exit", commitExitLabel(delivery)),
		tasktrace.Str("trigger", delivery.Reason),
		tasktrace.Hash("commit_hash", commitHash),
		tasktrace.Str("verifier_operator_address", v.cfg.VerifierAddress),
		tasktrace.Str("submitter_address", v.cfg.SignerAddress),
		tasktrace.Str("tx", delivery.TxHash),
		tasktrace.Uint("included_height", delivery.IncludedHeight),
		// keeper_confirmed is the only field here that means the chain wrote
		// CommitState. A broadcast ack does not, and neither does a relay ack
		// (nexus contract §7): both are reported as their own fields so no
		// reader can mistake one for the other.
		tasktrace.Bool("keeper_confirmed", delivery.ChainAccepted),
		tasktrace.Bool("duplicate_noop", delivery.Duplicate),
		tasktrace.Uint("commit_deadline_height", state.CommitDeadlineHeight),
		tasktrace.Err("error", err))
	if err != nil {
		return result, err
	}
	// The reveal STOPS here, and that is the whole point of this boundary.
	//
	// Task-04-Verification-flow.md admits MsgSubmitVerifyResult only after
	// EventRevealPhaseStarted, and the Keeper handler refuses any reveal that
	// arrives before the task enters REVEALING. A reveal assembled on this line
	// would be assembled at commit time by construction, so it could only ever be
	// early -- and it would also be assembled with reveal_deadline_height still
	// zero, because keeper §10.7 writes that height exactly once, inside
	// StartRevealPhase. Both facts made the reveal a tail of the commit that
	// could never succeed, and its failure buried the commit's own outcome.
	//
	// The reveal is a separate responsibility with a separate trigger:
	// HandleRevealPhaseStarted, driven by the Keeper event of that name. See
	// reveal.go.
	v.results[resultKey] = result
	return result, nil
}

func (v *Verifier) encodeNexusMessage(input builderclient.UnsignedEnvelopeInput, payload proto.Message) ([]byte, error) {
	// See Worker.encodeNexusMessage: the accepted lifetime is a deployment
	// agreement, so it is stamped rather than defaulted.
	if input.ExpiresAt.IsZero() && v.cfg.EnvelopeTTL > 0 {
		issuedAt := input.IssuedAt
		if issuedAt.IsZero() {
			issuedAt = time.Now().UTC()
			input.IssuedAt = issuedAt
		}
		input.ExpiresAt = issuedAt.Add(v.cfg.EnvelopeTTL)
	}
	// Same rule as the Worker path: only a trusted transport posture may emit
	// unsigned envelopes. Synthetic verification output does not make this
	// node's identity synthetic, and a strict Nexus drops unsigned envelopes.
	if v.cfg.TrustedNATSDev {
		return builderclient.EncodeUnsignedBusMessage(input, payload, true)
	}
	return builderclient.EncodeAuthenticatedBusMessage(input, payload, v.cfg.NexusEnvelopeSigner)
}

func (v *Verifier) persistBuilderOutbox(ctx context.Context, taskID string, subject string, payload []byte, dedupID string) (bool, error) {
	persistence, ok := v.cfg.Persistence.(outboxPersistence)
	if !ok {
		return false, nil
	}
	err := persistence.WriteVerifierBuilderOutbox(ctx, OutboxRecord{
		TaskID: taskID, Subject: subject, Payload: append([]byte(nil), payload...), Status: "pending",
		Digest:  codec.HashWithDomain("TRUEOPEN_BUILDER_OUTBOX_V1", []byte(subject), []byte(taskID), payload),
		DedupID: dedupID,
	})
	return true, err
}

func (v *Verifier) persistModelServiceJob(ctx context.Context, jobID, taskID, status, intent string) error {
	if v.cfg.Persistence == nil {
		return nil
	}
	return v.cfg.Persistence.CheckpointModelJob(ctx, ModelJobCheckpoint{
		JobID:          jobID,
		TaskID:         taskID,
		Role:           "verifier",
		ModelServiceID: v.cfg.ModelServiceID,
		Status:         status,
		Intent:         intent,
	})
}

func validateCanonicalTaskState(state TaskState) error {
	if state.SessionID == "" || state.OrderDigest == (codec.Hash{}) || state.InferReceiptHash == (codec.Hash{}) ||
		state.VerifyRound == 0 || state.VerifyRound > math.MaxUint32 || state.Member.CandidatePoolSnapshotID == "" ||
		state.Member.SlotVersion == 0 || state.Member.OperatorAddress == "" || state.HandraiseExpiryHeight == 0 {
		return errTaskIdentityMissing
	}
	canonicalTaskID := identity.TaskIDString(state.SessionID, state.OrderSequence)
	if state.TaskID != canonicalTaskID {
		return fmt.Errorf("%w: task_id %q", errTaskIdentityMismatch, state.TaskID)
	}
	if state.OutputPackage.TaskID != "" && state.OutputPackage.TaskID != canonicalTaskID {
		return fmt.Errorf("%w: output package task_id %q", errPackageTaskMismatch, state.OutputPackage.TaskID)
	}
	return nil
}

func canonicalTaskRejectCode(err error) string {
	switch {
	case errors.Is(err, errTaskIdentityMissing):
		return "L2_TASK_IDENTITY_MISSING"
	case errors.Is(err, errPackageTaskMismatch):
		return "L2_OUTPUT_PACKAGE_TASK_MISMATCH"
	default:
		return "L2_TASK_IDENTITY_MISMATCH"
	}
}

type SeedInput struct {
	ChainID          string
	TaskID           string
	VerifyRound      uint64
	OpenVerifyHeight uint64
	Profile          string
	FutureBeaconID   string
	PackageHash      codec.Hash
	OutputHash       codec.Hash
}

func VerificationSampleSeed(input SeedInput) codec.Hash {
	return codec.HashWithDomain(
		"TRUEOPEN_VERIFICATION_SAMPLE_SEED_V1",
		[]byte(input.ChainID),
		[]byte(input.TaskID),
		codec.Uint64Bytes(input.VerifyRound),
		codec.Uint64Bytes(input.OpenVerifyHeight),
		[]byte(input.Profile),
		input.PackageHash[:],
		input.OutputHash[:],
		[]byte(input.FutureBeaconID),
	)
}

func (v *Verifier) precheckInput(state TaskState, currentHeight uint64, phase string) policy.VerifierPrecheckInput {
	if phase == "handraise" && state.HandraisePrecheck != nil {
		input := *state.HandraisePrecheck
		input.Phase = phase
		input.CurrentHeight = effectiveCurrentHeight(state, input.CurrentHeight)
		input.SessionID = state.SessionID
		input.OrderDigest = state.OrderDigest
		input.ExpectedTaskID = state.TaskID
		input.VerifierAddress = v.cfg.VerifierAddress
		input.WorkerAddress = state.WorkerAddress
		input.Profile = state.Capability
		input.OutputPackage = state.OutputPackage
		input.OpenVerifyAccepted = state.OpenVerifyAccepted
		if state.VerifyDeadlineHeight != 0 {
			input.VerifyDeadlineHeight = state.VerifyDeadlineHeight
		} else if input.VerifyDeadlineHeight == 0 {
			input.VerifyDeadlineHeight = state.OpenVerifyHeight + v.cfg.VerifyDeadlineDeltaHeight
		}
		if state.CommitDeadlineHeight != 0 {
			input.CommitDeadlineHeight = state.CommitDeadlineHeight
		}
		return input
	}
	return policy.VerifierPrecheckInput{
		Phase:                      phase,
		ChainSynced:                true,
		CurrentHeight:              effectiveCurrentHeight(state, currentHeight),
		SessionID:                  state.SessionID,
		OrderDigest:                state.OrderDigest,
		ExpectedTaskID:             state.TaskID,
		VerifierAddress:            v.cfg.VerifierAddress,
		WorkerAddress:              state.WorkerAddress,
		SupportState:               policy.SupportActive,
		SupportLastConfirmedHeight: state.OpenVerifyHeight,
		SupportFreshnessWindow:     10,
		Profile:                    state.Capability,
		SupportedProfiles:          []string{state.Capability},
		OutputPackage:              state.OutputPackage,
		AvailableSlots:             1,
		VerifyDeadlineHeight:       exactOrDelta(state.VerifyDeadlineHeight, state.OpenVerifyHeight, v.cfg.VerifyDeadlineDeltaHeight),
		CommitDeadlineHeight:       state.CommitDeadlineHeight,
		BeaconDelayHeights:         1,
		OpenVerifyAccepted:         state.OpenVerifyAccepted,
	}
}

func exactOrDelta(exact uint64, base uint64, delta uint64) uint64 {
	if exact != 0 {
		return exact
	}
	return base + delta
}

func effectiveCurrentHeight(state TaskState, fallback uint64) uint64 {
	if state.CurrentHeight != 0 {
		return state.CurrentHeight
	}
	return fallback
}

func verifyResultKey(state TaskState, seed codec.Hash, verifierAddress string) string {
	return fmt.Sprintf("%s/%d/%s/%x/%x", state.TaskID, state.VerifyRound, verifierAddress, state.OutputPackage.PackageHash, seed)
}

// fetchVerificationValues is bounded because its ref is the least trustworthy
// input in the whole verify path: it arrives in the model service's own Verify
// response, so a malicious service picks both the ref and the bytes behind it.
//
// The bound is the configured artifact maximum, NOT the profile's per-kind
// evidence maximum. Those are different objects: the profile value is
// TraceEncodedSizeBytes + CheckpointEncodedSizeBytes (see
// internal/nodewire/worker_value_commitment.go), which sizes the worker's infer
// evidence. The sample-value sequence is a later, verifier-side protocol object
// that the profile does not size at all, and a small legitimate profile - say a
// 16-byte trace plus checkpoint - would reject a perfectly valid 20-byte decimal
// result value and make the task unverifiable.
func (v *Verifier) fetchVerificationValues(ctx context.Context, taskID string, ref string) ([][]byte, error) {
	artifact, err := v.cfg.Model.FetchArtifact(ctx, modelservice.FetchArtifactRequest{
		RequestID:      "verifier-fetch-values-" + taskID,
		ModelServiceID: v.cfg.ModelServiceID,
		Ref:            ref,
		SizeLimitBytes: v.cfg.MaxOutputBytes,
		Kind:           "verifier-sample-values",
	})
	if err != nil {
		return nil, err
	}
	return [][]byte{artifact.Data}, nil
}

func (v *Verifier) persistResult(ctx context.Context, state TaskState, result VerifyResult, values [][]byte) error {
	if v.cfg.Persistence == nil {
		return nil
	}
	valuePayload, err := json.Marshal(map[string]any{
		"task_id":                        state.TaskID,
		"verify_round":                   state.VerifyRound,
		"sample_value_sequence_ref":      result.SampleValueSequenceRef,
		"canonical_sample_value_records": byteStrings(values),
	})
	if err != nil {
		return err
	}
	if err := v.cfg.Persistence.WriteEvidence(ctx, EvidenceRecord{
		TaskID: state.TaskID,
		Kind:   "verifier-v-values",
		Data:   valuePayload,
		Ref:    evidenceRef(valuePayload),
	}); err != nil {
		return err
	}
	revealRecord := map[string]any{
		"task_id":                  state.TaskID,
		"verify_round":             state.VerifyRound,
		"verification_sample_seed": result.VerificationSampleSeed,
		"result_digest":            result.ResultDigest,
		// Hex rather than raw, because the reveal is framed bytes now and JSON
		// has no byte string. The reader refuses anything that is not hex, which
		// is also how a record written by the retired compact text encoding is
		// rejected instead of being turned into a credential whose commit_hash
		// was derived from different bytes entirely.
		"result_reveal":       hex.EncodeToString(result.ResultReveal),
		"salt":                result.Salt.String(),
		"commit_hash":         result.CommitHash.String(),
		"evidence_manifest":   hex.EncodeToString(result.EvidenceManifest),
		"values_evidence_ref": evidenceRef(valuePayload),
	}
	// The metric material rides in the same record as the compact reveal, under
	// the same task/round identity, because the reveal credential needs both and
	// they are one run's output. It is omitted rather than written as zeros when
	// the run produced none, so a reader can tell "this node had no locked
	// profile" from "this node measured zero".
	if hasMetricMaterial(result.MetricMaterial) {
		revealRecord["metric_material"] = projectMetricMaterial(result.MetricMaterial)
	}
	revealPayload, err := json.Marshal(revealRecord)
	if err != nil {
		return err
	}
	if err := v.cfg.Persistence.WriteEvidence(ctx, EvidenceRecord{
		TaskID: state.TaskID,
		Kind:   verifierFullResultRevealEvidenceKind,
		Data:   revealPayload,
		Ref:    evidenceRef(revealPayload),
	}); err != nil {
		return err
	}
	commitReceipt, err := commitPayload(v.cfg, result)
	if err != nil {
		return err
	}
	if err := v.cfg.Persistence.WriteEvidence(ctx, EvidenceRecord{
		TaskID: state.TaskID,
		Kind:   "verifier-result-commit-receipt",
		Data:   commitReceipt,
		Ref:    evidenceRef(commitReceipt),
	}); err != nil {
		return err
	}
	return v.cfg.Persistence.WriteSettleMaterial(ctx, SettleMaterial{
		TaskID:  state.TaskID,
		Kind:    "verifier-result-commit",
		Payload: append([]byte(nil), commitReceipt...),
		Digest:  codec.HashWithDomain("TRUEOPEN_VERIFIER_SETTLE_MATERIAL_V1", commitReceipt),
	})
}

// ErrVerifyCommitInputUnavailable marks a commit refusal as a missing protocol
// input rather than malformed caller data, the same distinction
// builderclient.ErrInferReceiptInputUnavailable draws for the infer receipt.
var ErrVerifyCommitInputUnavailable = errors.New("frozen verify commit input is unavailable")

// ErrResultReceiptInputUnavailable marks a verifier result-credential refusal as
// a missing protocol input rather than a missing derivation, the same
// distinction ErrVerifyCommitInputUnavailable draws for the commit.
//
// Every result field must be sourced before the service key signs it.
var ErrResultReceiptInputUnavailable = errors.New("frozen result receipt input is unavailable")

// verifyCommitWire assembles the unsigned frozen task.v1.VerifyCommitV1
// body whose TRUEOPEN_COMMIT_V1 digest the verifier's service key signs. Every
// preimage field is taken from a real source or refused: a zero here would be a
// guess at a consensus field, and nodewire keeps its derivations total, so it
// would hash happily and produce a digest the Keeper can never accept.
func verifyCommitWire(cfg Config, state TaskState, commitHash codec.Hash) (nodewire.VerifyCommitV1, error) {
	if cfg.ServiceAuthorizationNonce == 0 {
		return nodewire.VerifyCommitV1{}, fmt.Errorf(
			"%w: verify commit needs the current ServiceKey binding's service_authorization_nonce "+
				"(frozen preimage field 6) and no daemon path publishes it into the task plane yet",
			ErrVerifyCommitInputUnavailable)
	}
	if state.CommitDeadlineHeight == 0 {
		return nodewire.VerifyCommitV1{}, fmt.Errorf(
			"%w: verify commit expiry_height requires the Keeper commit deadline height",
			ErrVerifyCommitInputUnavailable)
	}
	// task_id enters the preimage as raw Hash32, not as the canonical hex text
	// the Cortex task plane passes around, so a malformed identity has to be
	// rejected here rather than silently truncated into 32 bytes.
	taskID, err := hex.DecodeString(state.TaskID)
	if err != nil || len(taskID) != 32 {
		return nodewire.VerifyCommitV1{}, fmt.Errorf(
			"%w: verify commit task_id must be canonical 32-byte hex, got %q",
			ErrVerifyCommitInputUnavailable, state.TaskID)
	}
	// verify_round is uint32 on the wire. Narrowing a uint64 silently would let
	// two distinct rounds share one digest, so the overflow is refused.
	if state.VerifyRound > math.MaxUint32 {
		return nodewire.VerifyCommitV1{}, fmt.Errorf(
			"%w: verify commit verify_round %d does not fit the frozen uint32 field",
			ErrVerifyCommitInputUnavailable, state.VerifyRound)
	}
	return nodewire.VerifyCommitV1{
		SchemaVersion:             nodewire.VerifyCommitSchemaVersionV1,
		ChainID:                   cfg.ChainID,
		TaskID:                    taskID,
		VerifyRound:               uint32(state.VerifyRound),
		VerifierOperatorAddress:   cfg.VerifierAddress,
		ServiceAuthorizationNonce: cfg.ServiceAuthorizationNonce,
		CommitHash:                append([]byte(nil), commitHash[:]...),
		ExpiryHeight:              state.CommitDeadlineHeight,
	}, nil
}

// commitPayload encodes the frozen task.v1.MsgSubmitVerifyCommit body. The
// same bytes are the CommitItem the Task Builder relays inside
// MsgBatchSubmitVerifyCommit and what the commit exit submits directly.
func commitPayload(cfg Config, result VerifyResult) ([]byte, error) {
	message, err := commitMessage(cfg, result)
	if err != nil {
		return nil, err
	}
	return txclient.MarshalMessage(txclient.MsgSubmitVerifyCommit, message)
}

// commitMessage assembles the typed frozen MsgSubmitVerifyCommit.
//
// Every field is projected from result.CommitWire, the exact value whose digest
// was signed. Nothing is re-read from Config or TaskState here: a second read
// would be a second chance for the submitted body to differ from the signed one.
// The local receipt and the on-chain submission therefore come from one
// assembler, so an evidence file can never describe a body the chain did not
// receive.
func commitMessage(cfg Config, result VerifyResult) (txclient.SubmitVerifyCommitMessage, error) {
	commit := result.CommitWire
	if len(commit.ServiceSignature) == 0 {
		return txclient.SubmitVerifyCommitMessage{}, fmt.Errorf("verify commit service_signature is missing: the frozen body was never signed")
	}
	return txclient.SubmitVerifyCommitMessage{
		Commit: txclient.VerifyCommitMessage{
			SchemaVersion:             txclient.ProtoUint32(commit.SchemaVersion),
			ChainID:                   commit.ChainID,
			TaskID:                    txclient.ProtoBytes32(hex.EncodeToString(commit.TaskID)),
			VerifyRound:               txclient.ProtoUint32(commit.VerifyRound),
			VerifierOperatorAddress:   commit.VerifierOperatorAddress,
			ServiceAuthorizationNonce: txclient.ProtoUint64(commit.ServiceAuthorizationNonce),
			CommitHash:                txclient.ProtoBytes32(hex.EncodeToString(commit.CommitHash)),
			ExpiryHeight:              txclient.ProtoUint64(commit.ExpiryHeight),
			ServiceSignature:          txclient.ProtoBytes(hex.EncodeToString(commit.ServiceSignature)),
		},
		SubmitterAddress: cfg.SignerAddress,
	}, nil
}

// resultReceiptWire assembles the unsigned frozen task.v1.ResultReceiptV2
// body from every preimage value Cortex can source. It is the exact counterpart
// of verifyCommitWire: a sourced value is taken from its real source or refused,
// because nodewire keeps its derivations total and would hash a guessed zero
// into a digest the Keeper can never accept.
//
// Nine of the twelve preimage fields are sourced here. generation_params_digest
// (field 7) is one of them: TaskAssignmentViewV1 serves it as field 16
// (TrueOpen/node d8792e6 proto/task/v1/query_task.proto:106),
// chainclient.KeeperABCIClient.TaskReceiptFacts reads it, and the verifier's
// TaskFacts reader is what puts it in facts. It is copied through byte for byte
// and never re-derived: the Keeper only ever compares it, so a second derivation
// could only drift.
//
// The remaining three - metric_root (8), metric_summary (9) and
// aggregate_proof_hash (10) - come from the metric material the verify run
// produced and this call is handed; see internal/metric. A run that produced
// none leaves them zero here, which is why the only caller on the signing path
// is resultReceiptCredential rather than this function.
func resultReceiptWire(
	cfg Config, state TaskState, facts taskfacts.Facts, resultReveal []byte, material metric.Material, manifest []byte, salt codec.Hash,
) (nodewire.ResultReceiptV3, error) {
	if cfg.ServiceAuthorizationNonce == 0 {
		return nodewire.ResultReceiptV3{}, fmt.Errorf(
			"%w: verify result needs the current ServiceKey binding's service_authorization_nonce "+
				"(frozen preimage field 6) and no daemon path publishes it into the task plane yet",
			ErrResultReceiptInputUnavailable)
	}
	// task_id enters the preimage as raw Hash32, not as the canonical hex text
	// the Cortex task plane passes around.
	taskID, err := hex.DecodeString(state.TaskID)
	if err != nil || len(taskID) != 32 {
		return nodewire.ResultReceiptV3{}, fmt.Errorf(
			"%w: verify result task_id must be canonical 32-byte hex, got %q",
			ErrResultReceiptInputUnavailable, state.TaskID)
	}
	// verify_round is uint32 on the wire; narrowing silently would let two
	// distinct rounds share one digest.
	if state.VerifyRound > math.MaxUint32 {
		return nodewire.ResultReceiptV3{}, fmt.Errorf(
			"%w: verify result verify_round %d does not fit the frozen uint32 field",
			ErrResultReceiptInputUnavailable, state.VerifyRound)
	}
	// The Keeper bounds the credential by the verifier assignment's reveal
	// deadline (x/task/keeper/verification_runtime.go:230), so that height
	// is the expiry_height the body must carry.
	if state.RevealDeadlineHeight == 0 {
		return nodewire.ResultReceiptV3{}, fmt.Errorf(
			"%w: verify result expiry_height requires the Keeper verifier reveal deadline height",
			ErrResultReceiptInputUnavailable)
	}
	// The served facts have to belong to the task this verify responsibility is
	// for, and an absent or all-zero generation_params_digest is refused rather
	// than signed. Validate keeps those three reasons apart.
	if err := facts.Validate(state.TaskID); err != nil {
		return nodewire.ResultReceiptV3{}, fmt.Errorf(
			"%w: verify result generation_params_digest: %w", ErrResultReceiptInputUnavailable, err)
	}
	if len(resultReveal) == 0 {
		return nodewire.ResultReceiptV3{}, fmt.Errorf(
			"%w: verify result result_reveal bytes are required for frozen preimage field 11",
			ErrResultReceiptInputUnavailable)
	}
	if len(manifest) == 0 || salt.IsZero() {
		return nodewire.ResultReceiptV3{}, fmt.Errorf("%w: verifier evidence manifest and salt are required", ErrResultReceiptInputUnavailable)
	}
	bundleHash := evidencebundle.Hash(manifest)
	receipt := nodewire.ResultReceiptV3{
		SchemaVersion:                     nodewire.ResultReceiptSchemaVersionV3,
		ChainID:                           cfg.ChainID,
		TaskID:                            taskID,
		VerifyRound:                       uint32(state.VerifyRound),
		VerifierOperatorAddress:           cfg.VerifierAddress,
		ServiceAuthorizationNonce:         cfg.ServiceAuthorizationNonce,
		GenerationParamsDigest:            append([]byte(nil), facts.GenerationParamsDigest...),
		VerifierEvidenceBundleHash:        append([]byte(nil), bundleHash[:]...),
		VerifierEvidenceManifestSizeBytes: uint64(len(manifest)),
		Salt:                              append([]byte(nil), salt[:]...),
		ExpiryHeight:                      state.RevealDeadlineHeight,
		// Plaintext results carry no verifier evidence key.
		VerifierEvidenceKeyCommitment: make([]byte, 32),
	}
	// The metric values are copied in only when the run really produced them.
	// An absent material leaves the three fields zero, and the gate below is
	// what refuses that body - the assembler stays total, so no caller can
	// accidentally sign a partially sourced credential.
	if hasMetricMaterial(material) {
		receipt.MetricRoot = append([]byte(nil), material.Root[:]...)
		receipt.MetricSummary = material.Summary
		receipt.AggregateProofHash = append([]byte(nil), material.AggregateProof.Hash[:]...)
		receipt.VerifierValueRoot = append([]byte(nil), material.VerifierValueRoot[:]...)
		receipt.MetricLeafCount = uint32(material.LeafCount)
	}
	return receipt, nil
}

// resultReceiptCredential is the only assembler the signing path may call: it
// returns a body solely when every frozen preimage value is sourced.
//
// The gate itself has not changed and must not: it reads the assembled body and
// refuses any zero, because the frozen wire gives none of these fields an absent
// encoding. What changed is that the body can now be complete.
//
// metric_root (8), metric_summary (9) and aggregate_proof_hash (10) come from
// the verify run's metric material (internal/metric), derived under the locked
// profile and persisted with the compact reveal.
//
// result_reveal_hash (field 11) is sourced from the persisted canonical reveal
// and framed with H_V1("TRUEOPEN_FULL_RESULT_REVEAL_PAYLOAD_V1", reveal). It is
// distinct from the retired compact reveal's plain SHA-256.
func resultReceiptCredential(
	cfg Config, state TaskState, facts taskfacts.Facts, resultReveal []byte, material metric.Material, manifest []byte, salt codec.Hash,
) (nodewire.ResultReceiptV3, error) {
	receipt, err := resultReceiptWire(cfg, state, facts, resultReveal, material, manifest, salt)
	if err != nil {
		return nodewire.ResultReceiptV3{}, err
	}
	if unsourced := resultReceiptUnsourced(receipt); len(unsourced) > 0 {
		return nodewire.ResultReceiptV3{}, fmt.Errorf(
			"%w: %s reached the frozen result body as zeros; the verify run produced no metric material "+
				"for this task, so metric_root, the ten typed MetricSummaryV1 members and "+
				"aggregate_proof_hash cannot be sourced",
			ErrResultReceiptInputUnavailable, strings.Join(unsourced, ", "))
	}
	return receipt, nil
}

// resultReceiptUnsourced names the frozen preimage values that reached the
// assembled body as zeros. The frozen wire gives none of them an absent
// encoding, so a zero here is a claim rather than a gap marker and must never be
// signed.
func resultReceiptUnsourced(receipt nodewire.ResultReceiptV3) []string {
	unsourced := make([]string, 0, 4)
	if isZeroHash32(receipt.MetricRoot) {
		unsourced = append(unsourced, "metric_root")
	}
	if receipt.MetricSummary == (nodewire.MetricSummaryV1{}) {
		unsourced = append(unsourced, "metric_summary")
	}
	if isZeroHash32(receipt.AggregateProofHash) {
		unsourced = append(unsourced, "aggregate_proof_hash")
	}
	if isZeroHash32(receipt.VerifierEvidenceBundleHash) || receipt.VerifierEvidenceManifestSizeBytes == 0 {
		unsourced = append(unsourced, "verifier_evidence_bundle_hash")
	}
	if isZeroHash32(receipt.Salt) {
		unsourced = append(unsourced, "salt")
	}
	if isZeroHash32(receipt.VerifierValueRoot) || receipt.MetricLeafCount == 0 {
		unsourced = append(unsourced, "verifier_value_root")
	}
	return unsourced
}

// isZeroHash32 treats an unset Hash32 and an all-zero one as the same condition,
// which is what the frozen wire forces: it frames the field unconditionally, so
// a caller with nothing to say can only send zeros.
func isZeroHash32(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

// signResultReceipt derives the TRUEOPEN_RESULT_V3 digest of the assembled body and
// writes the signature back into that same struct.
//
// Taking a pointer is the point. The commit path's retired bug was a signature
// derived from one value and attached to another, so the only body that can be
// submitted here is the body that was hashed.
func (v *Verifier) signResultReceipt(ctx context.Context, receipt *nodewire.ResultReceiptV3) error {
	digest, err := nodewire.ResultReceiptSigningDigest(*receipt)
	if err != nil {
		return fmt.Errorf("derive frozen result receipt signing digest: %w", err)
	}
	signature, err := v.signDigest(ctx, digest)
	if err != nil {
		return err
	}
	receipt.ServiceSignature = signature
	return nil
}

// resultPayload encodes the frozen task.v1.MsgSubmitVerifyResult body. The
// same bytes are the ResultItem the Task Builder relays inside
// MsgBatchSubmitVerifyResult and what verifier self-rescue submits directly.
//
// Every field is projected from the receipt whose digest was signed. Nothing is
// re-read from Config or TaskState: a second read would be a second chance for
// the submitted body to differ from the signed one. commit_key and
// metric_summary_hash are Keeper-recomputed and are deliberately absent.
func resultPayload(cfg Config, receipt nodewire.ResultReceiptV3) ([]byte, error) {
	if len(receipt.ServiceSignature) == 0 {
		return nil, fmt.Errorf("verify result service_signature is missing: the frozen body was never signed")
	}
	return txclient.MarshalMessage(txclient.MsgSubmitVerifyResult, txclient.SubmitVerifyResultMessage{
		Receipt: txclient.ResultReceiptMessage{
			SchemaVersion:                     txclient.ProtoUint32(receipt.SchemaVersion),
			ChainID:                           receipt.ChainID,
			TaskID:                            txclient.ProtoBytes32(hex.EncodeToString(receipt.TaskID)),
			VerifyRound:                       txclient.ProtoUint32(receipt.VerifyRound),
			VerifierOperatorAddress:           receipt.VerifierOperatorAddress,
			ServiceAuthorizationNonce:         txclient.ProtoUint64(receipt.ServiceAuthorizationNonce),
			GenerationParamsDigest:            txclient.ProtoBytes32(hex.EncodeToString(receipt.GenerationParamsDigest)),
			MetricRoot:                        txclient.ProtoBytes32(hex.EncodeToString(receipt.MetricRoot)),
			MetricSummary:                     metricSummaryMessage(receipt.MetricSummary),
			AggregateProofHash:                txclient.ProtoBytes32(hex.EncodeToString(receipt.AggregateProofHash)),
			VerifierEvidenceBundleHash:        txclient.ProtoBytes32(hex.EncodeToString(receipt.VerifierEvidenceBundleHash)),
			VerifierEvidenceManifestSizeBytes: txclient.ProtoUint64(receipt.VerifierEvidenceManifestSizeBytes),
			Salt:                              txclient.ProtoBytes32(hex.EncodeToString(receipt.Salt)),
			ExpiryHeight:                      txclient.ProtoUint64(receipt.ExpiryHeight),
			VerifierValueRoot:                 txclient.ProtoBytes32(hex.EncodeToString(receipt.VerifierValueRoot)),
			MetricLeafCount:                   txclient.ProtoUint32(receipt.MetricLeafCount),
			VerifierEvidenceKeyCommitment:     txclient.ProtoBytes32(hex.EncodeToString(receipt.VerifierEvidenceKeyCommitment)),
			ServiceSignature:                  txclient.ProtoBytes(hex.EncodeToString(receipt.ServiceSignature)),
		},
		SubmitterAddress: cfg.SignerAddress,
	})
}

// metricSummaryMessage projects the typed summary onto the ProtoJSON body. The
// two proto3 optionals stay pointers: a present zero must serialise as an
// explicit 0 and an absent member must be omitted entirely, because the frozen
// preimage gives those two cases different digests.
func metricSummaryMessage(summary nodewire.MetricSummaryV1) txclient.MetricSummaryMessage {
	return txclient.MetricSummaryMessage{
		FiniteCount:               txclient.ProtoUint32(summary.FiniteCount),
		MissingComparedCount:      txclient.ProtoUint32(summary.MissingComparedCount),
		MeanAbsLogprobDiffFP1e6:   txclient.ProtoUint32(summary.MeanAbsLogprobDiffFP1e6),
		AbsLogprobDiffP95FP1e6:    txclient.ProtoUint32(summary.AbsLogprobDiffP95FP1e6),
		AbsLogprobDiffP99FP1e6:    txclient.ProtoUint32(summary.AbsLogprobDiffP99FP1e6),
		RankDeltaNonzeroRateFP1e6: txclient.ProtoUint32(summary.RankDeltaNonzeroRateFP1e6),
		TopkJaccardMeanFP1e6:      optionalProtoUint32(summary.TopkJaccardMeanFP1e6),
		UnionJSP99FP1e6:           optionalProtoUint32(summary.UnionJSP99FP1e6),
		ComparedTopkCount:         txclient.ProtoUint32(summary.ComparedTopkCount),
		ComparedRankCount:         txclient.ProtoUint32(summary.ComparedRankCount),
	}
}

func optionalProtoUint32(value nodewire.OptionalUint32) *txclient.ProtoUint32 {
	if !value.Present {
		return nil
	}
	encoded := txclient.ProtoUint32(value.Value)
	return &encoded
}

func byteStrings(values [][]byte) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}

func evidenceRef(data []byte) string {
	digest := codec.HashBytes(data)
	return "sha256:" + fmt.Sprintf("%x", digest[:])
}

func (v *Verifier) signEnvelope(ctx context.Context, envelope *identity.SignedEnvelope) error {
	digest, err := envelope.SigningHash()
	if err != nil {
		return err
	}
	signature, err := v.signDigest(ctx, digest)
	if err != nil {
		return err
	}
	envelope.Signature = signature
	return envelope.Validate()
}

func (v *Verifier) signDigest(ctx context.Context, digest codec.Hash) ([]byte, error) {
	if v.cfg.Signer == nil {
		return nil, fmt.Errorf("service key signer is required")
	}
	return v.cfg.Signer.SignDigest(ctx, signer.DigestRequest{
		KeyRef:                v.cfg.SignerKeyRef,
		ExpectedSignerAddress: v.cfg.SignerAddress, Digest: digest,
	})
}
