package layout

import "github.com/SingaXYZ/cortex/internal/codec"

const (
	// Admission schema v2 marks handraises whose service_signature is canonical
	// lowercase hex. Schema v1 records contain the retired base64 wire spelling
	// and must be re-signed rather than replayed after an upgrade.
	CandidateAdmissionSchemaVersion = uint16(2)
	// Verifier admission schema v3 retains the authenticated OPEN_VERIFY sender
	// that declared its local task data ready. V2 handraises remain valid, but a
	// v2 row has no Builder to use if this node is later selected as a Verifier.
	VerifierAdmissionSchemaVersion = uint16(3)
)

// RoleStage is the local lifecycle stage of a role record. The merge boundary
// rejects any value outside the declared constants.
type RoleStage string

const (
	StageQueued RoleStage = "queued"
	// StageCommitted is a verify-only stage: this node's VerifyCommitV1 reached
	// the chain and the reveal is still owed. It is NOT a terminal stage — the
	// responsibility stays active so a restart between the commit and the reveal
	// rebuilds the reveal from Pebble instead of losing it — and it is what tells
	// the runner to take the reveal path rather than re-run the model.
	//
	// Keeping it distinct from StageQueued is what makes the crossing observable:
	// "committed, waiting for the reveal phase" and "not verified yet" used to be
	// the same row.
	StageCommitted RoleStage = "committed"
	StageFailed    RoleStage = "failed"
	StageSucceeded RoleStage = "succeeded"
)

// ArtifactKind is the canonical kind of a content-addressed artifact stored in
// the evidence manifest. The merge boundary rejects aliases and unknown kinds.
type ArtifactKind string

const (
	ArtifactTaskInput              ArtifactKind = "task-input"
	ArtifactWorkerOutput           ArtifactKind = "worker-output"
	ArtifactWorkerTrace            ArtifactKind = "worker-trace"
	ArtifactWorkerCheckpoint       ArtifactKind = "worker-checkpoint"
	ArtifactWorkerBatchLog         ArtifactKind = "worker-batch-log"
	ArtifactInferReceipt           ArtifactKind = "signed-infer-receipt"
	ArtifactWorkerOutputDescriptor ArtifactKind = "worker-output-descriptor"
	ArtifactWorkerResult           ArtifactKind = "worker-result"
)

// CandidateAdmission records a Worker's pre-assignment handraise. It is written
// only after this node decides to handraise for a pre-assignment order.
type CandidateAdmission struct {
	SchemaVersion uint16 `json:"schema_version"`

	// SignedOrder is the order_envelope carrier exactly as the OPEN_TASK frame
	// spelled it: hex-encoded proto task.v1.SignedOrderV1 from a contract-v1
	// Builder, or the legacy proto3 JSON TaskOrderV1 from the pre-contract path.
	// Storing the received document keeps Cortex from maintaining a mirror of the
	// frozen field set, which would silently compute a wrong digest on drift - and
	// keeps the stored bytes re-derivable into the same task_hash whichever
	// carrier they came in on.
	SignedOrder []byte `json:"signed_order"`

	// Signed WorkerHandraise BusEnvelope bytes. Admission schema upgrades decide
	// whether these exact bytes remain replayable or must be re-signed first.
	HandraisePayload []byte     `json:"handraise_payload"`
	HandraiseDigest  StoredHash `json:"handraise_digest"`
	PublishTS        int64      `json:"publish_ts"`

	// InputSizeBytes is the user-signed input size from the accepted TaskOrderV1.
	// Zero means the size was not available at admission time.
	InputSizeBytes uint64 `json:"input_size_bytes,omitempty"`

	// DedupID is the stable transport dedup ID for this handraise. It survives
	// envelope regeneration and must be used when republishing.
	DedupID string `json:"dedup_id,omitempty"`

	// BroadcastingBuilder is the operator address of the Builder that broadcast this
	// order, taken from the verified sender field of the ORDER_BROADCAST envelope. It
	// is the reliable answer to "who to fetch the input from": only a Builder that
	// accepted the order broadcasts it, so the sender necessarily holds that input.
	//
	// Keeper's task snapshot does not currently serve builder_operator_address, and
	// the chain has no field saying which Builder is the receiver, so without this
	// source the Worker cannot get its input.
	BroadcastingBuilder string `json:"broadcasting_builder,omitempty"`
}

// VerifierAdmission records a Verifier's pre-assignment handraise for one
// verify round. It prevents duplicate output fetches and second handraises on a
// duplicate OUTPUT_AVAILABLE hint.
type VerifierAdmission struct {
	SchemaVersion uint16 `json:"schema_version"`

	InferReceiptHash StoredHash `json:"infer_receipt_hash"`
	OutputHash       StoredHash `json:"output_hash"`
	// DataReadyBuilderOperator is the authenticated OPEN_VERIFY sender. The
	// protocol permits several fixed Task Builders to announce the same round,
	// while interface-and-topic-list.md §5.8 requires that each sender publish only when it
	// "holds the data the protocol requires locally". The first one observed
	// locally remains the single-Builder compatibility source until
	// QueryTaskBuilders and multi-Builder retrieval are available.
	DataReadyBuilderOperator string     `json:"data_ready_builder_operator,omitempty"`
	HandraisePayload         []byte     `json:"handraise_payload"`
	HandraiseDigest          StoredHash `json:"handraise_digest"`
	ExpiryHeight             uint64     `json:"expiry_height"`
	// Completed distinguishes a claim that finished from one that was merely
	// taken. Only a finished claim suppresses a duplicate: suppressing on an
	// attempt would strand the task whenever the attempt failed or crashed.
	Completed bool `json:"completed"`
}

// TaskRecord holds Keeper-authoritative facts shared by both roles. It is
// created by whichever role learns the task first and is deleted at task
// terminal.
type TaskRecord struct {
	SchemaVersion uint16 `json:"schema_version"`

	SessionID     string `json:"session_id"`
	OrderSequence uint64 `json:"order_sequence"`

	ModelID        string `json:"model_id"`
	ProfileVersion uint32 `json:"profile_version"`
	// Capability is deliberately absent. It is the deployment config's local label
	// for a (ModelID, ProfileVersion) pair, and the chain commits neither the label
	// nor anything that fixes it — so it is not part of accepted_task_hash, two
	// admissions of one task can legitimately disagree about it, and storing it in a
	// write-once field turned a config edit into a consensus conflict that lost the
	// responsibility. Derive it from ModelID and ProfileVersion at the point of use.

	AssignmentOrderDigest StoredHash `json:"assignment_order_digest"`
	AssignmentDigest      StoredHash `json:"assignment_digest"`

	// Input locator/digest from the accepted TaskOrderV1.
	InputCID    string     `json:"input_cid"`
	InputDigest StoredHash `json:"input_digest"`

	AcceptedInputHash StoredHash `json:"accepted_input_hash"`

	WorkerAddress          string `json:"worker_address"`
	BuilderOperatorAddress string `json:"builder_operator_address"`

	// Authenticated ACCEPTED_TASK control binding; first non-empty value wins.
	TaskBuilderSetID   string `json:"task_builder_set_id"`
	TaskBuilderSetHash []byte `json:"task_builder_set_hash"`

	// InputSizeBytes is the user-signed input size from the accepted TaskOrderV1.
	// Zero means the size was not available at admission time.
	InputSizeBytes uint64 `json:"input_size_bytes,omitempty"`
}

// FinishReasonV1 records why inference finished, as committed to the receipt.
// It is a string-backed type so dumps are readable; the merge boundary rejects
// unknown values.
type FinishReasonV1 string

const (
	FinishReasonEOS               FinishReasonV1 = "eos-token"
	FinishReasonStopSequence      FinishReasonV1 = "stop-sequence"
	FinishReasonMaxOutputTokens   FinishReasonV1 = "max-output-tokens"
	FinishReasonMaxOutputDuration FinishReasonV1 = "max-output-duration"
	FinishReasonUnknown           FinishReasonV1 = "unknown"
)

// InferRecord holds Worker-only facts and local scheduling for an active infer
// responsibility.
type InferRecord struct {
	SchemaVersion uint16 `json:"schema_version"`

	// TaskID mirrors the task record for diagnostics and admin listing.
	TaskID string `json:"task_id"`

	GenerationParamsDigest StoredHash `json:"generation_params_digest"`
	WinnerConfirmHeight    uint64     `json:"winner_confirm_height"`
	InferDeadlineHeight    uint64     `json:"infer_deadline_height"`

	FinishReason FinishReasonV1 `json:"finish_reason"`

	Stage            RoleStage `json:"stage"`
	RetryCount       uint32    `json:"retry_count"`
	RetryAtUnixMilli int64     `json:"retry_at_unix_milli"`
	RetryAtHeight    uint64    `json:"retry_at_height"`
	DeadlineHeight   uint64    `json:"deadline_height"`
	LastError        string    `json:"last_error"`

	AutoHalt

	// Executor outputs persisted for diagnostics and replay.
	OutputCID     string     `json:"output_cid,omitempty"`
	OutputDigest  StoredHash `json:"output_digest,omitempty"`
	ReceiptCID    string     `json:"receipt_cid,omitempty"`
	ReceiptDigest StoredHash `json:"receipt_digest,omitempty"`
}

// AutoHalt is the durable "stop calling the model for this responsibility"
// decision, and it is deliberately a third thing beside the two that already
// existed.
//
// It is NOT "the task is terminal on chain": the chain has said nothing, the
// responsibility is still owed, and every Keeper effect for this task must keep
// landing. It is NOT "the evidence may be cleaned up" either: the artifacts of
// the failed run are exactly what an operator needs to read, and retention is
// still governed by the task's own terminal/finality heights. All it says is
// that the local scheduler must stop re-entering the executor, because the
// failure it hit is one that re-running the model reproduces.
//
// Without it a deterministic refusal spent the whole retry budget --
// max_retry_attempts defaults to 120 -- and on a real vLLM node each attempt is
// a full generation holding the node's only GPU. The record is what makes the
// stop survive a restart; a process-local flag would resume the loop on the
// next boot.
//
// The three fields are absent from every record written before this landed, and
// their zero value is "not halted", so an old record decodes to the previous
// behaviour with no migration. Clearing them is deliberately not a merge: see
// mergeAutoHalt and ClearInferAutoHalt.
type AutoHalt struct {
	// AutoHalted stops the local scheduler from invoking the executor again.
	AutoHalted bool `json:"auto_halted,omitempty"`
	// HaltCode is the stable modelservice fault code that decided the halt.
	HaltCode string `json:"halt_code,omitempty"`
	// HaltReason is the operator-facing sentence, already free of model input.
	HaltReason string `json:"halt_reason,omitempty"`
}

// VerifyRecord holds Verifier-only facts and local scheduling for an active
// verify responsibility.
type VerifyRecord struct {
	SchemaVersion uint16 `json:"schema_version"`

	// TaskID mirrors the task record for diagnostics and admin listing.
	TaskID string `json:"task_id"`

	VerifyRound                uint64     `json:"verify_round"`
	OpenVerifyHeight           uint64     `json:"open_verify_height"`
	SampleSeedReadyHeight      uint64     `json:"sample_seed_ready_height"`
	CommitDeadlineHeight       uint64     `json:"commit_deadline_height"`
	WorkerRevealDeadlineHeight uint64     `json:"worker_reveal_deadline_height"`
	RevealDeadlineHeight       uint64     `json:"reveal_deadline_height"`
	VerificationSampleSeed     StoredHash `json:"verification_sample_seed"`
	AssignedVerifiers          []string   `json:"assigned_verifiers"`

	InferReceiptDigest StoredHash `json:"infer_receipt_digest"`
	KeeperReceiptJSON  string     `json:"keeper_receipt_json,omitempty"`
	OutputCID          string     `json:"output_cid,omitempty"`
	OutputDigest       StoredHash `json:"output_digest"`
	PackageDigest      StoredHash `json:"package_digest"`

	Stage            RoleStage `json:"stage"`
	RetryCount       uint32    `json:"retry_count"`
	RetryAtUnixMilli int64     `json:"retry_at_unix_milli"`
	RetryAtHeight    uint64    `json:"retry_at_height"`
	DeadlineHeight   uint64    `json:"deadline_height"`
	LastError        string    `json:"last_error"`

	AutoHalt

	// Executor outputs persisted for diagnostics and replay.
	ReceiptCID    string     `json:"receipt_cid,omitempty"`
	ReceiptDigest StoredHash `json:"receipt_digest,omitempty"`
}

// StorageConfirmation is the receiving Builder's signed confirmation for one
// uploaded material kind. It is deliberately not evidence and is deleted at task
// terminal.
type StorageConfirmation struct {
	SchemaVersion uint16 `json:"schema_version"`

	BuilderOperator      string     `json:"builder_operator"`
	MaterialDigest       StoredHash `json:"material_digest"`
	SemanticHash         StoredHash `json:"semantic_hash"`
	SizeBytes            uint64     `json:"size_bytes"`
	RetentionUntilHeight uint64     `json:"retention_until_height"`
	Signature            []byte     `json:"signature"`
	BuilderServicePubkey string     `json:"builder_service_pubkey"`
	VerifiedAtUnixMilli  int64      `json:"verified_at_unix_milli"`
}

// Evidence is the durable material manifest for one task and its retention
// window. It survives task terminal and is deleted when retention matures.
type Evidence struct {
	SchemaVersion uint16 `json:"schema_version"`

	SessionID string `json:"session_id"`
	TaskID    string `json:"task_id"`

	Artifacts []EvidenceArtifact `json:"artifacts"`
	Digest    StoredHash         `json:"digest"`
	Size      uint64             `json:"size"`

	FinalityHeight       uint64 `json:"finality_height"`
	RetentionStartHeight uint64 `json:"retention_start_height"`
	CleanupHeight        uint64 `json:"cleanup_height"`
	TerminalOrSettled    bool   `json:"terminal_or_settled"`
}

// EvidenceEntry pairs a task hash with its evidence record.
type EvidenceEntry struct {
	TaskHash codec.Hash
	Evidence Evidence
}

// EvidenceArtifact is one content-addressed file in the evidence manifest.
type EvidenceArtifact struct {
	Kind   ArtifactKind `json:"kind"`
	Digest StoredHash   `json:"digest"`
	Size   uint64       `json:"size"`
}

// ChallengeLifecycle is the per-challenge retention gate.
type ChallengeLifecycle struct {
	SchemaVersion uint16 `json:"schema_version"`

	Open         bool     `json:"open"`
	OpenedHeight uint64   `json:"opened_height"`
	LastPosition Position `json:"last_position"`
}

// Position is a Keeper event position used for ordering and deduplication.
type Position struct {
	Height     uint64 `json:"height"`
	TxIndex    uint64 `json:"tx_index"`
	MsgIndex   uint64 `json:"msg_index"`
	EventIndex uint64 `json:"event_index"`
}
