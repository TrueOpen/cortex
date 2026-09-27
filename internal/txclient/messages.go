package txclient

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type ProtoUint64 uint64

type ProtoUint32 uint32

func (v ProtoUint32) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatUint(uint64(v), 10)), nil
}

func (v *ProtoUint32) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("decode ProtoJSON uint32 into nil destination")
	}
	raw := string(data)
	if len(raw) == 0 || raw[0] == '"' {
		return fmt.Errorf("ProtoJSON uint32 must be a JSON number")
	}
	parsed, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || strconv.FormatUint(parsed, 10) != raw {
		return fmt.Errorf("ProtoJSON uint32 must be a canonical JSON number")
	}
	*v = ProtoUint32(parsed)
	return nil
}

// ProtoBytes32 stores a fixed protobuf bytes field as lowercase hex in Go and
// emits the canonical base64 string required by ProtoJSON.
type ProtoBytes32 string

func (v ProtoBytes32) MarshalJSON() ([]byte, error) {
	raw, err := hex.DecodeString(string(v))
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != string(v) {
		return nil, fmt.Errorf("ProtoJSON bytes32 must be canonical lowercase hex internally")
	}
	return json.Marshal(base64.StdEncoding.EncodeToString(raw))
}

func (v *ProtoBytes32) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("decode ProtoJSON bytes32 into nil destination")
	}
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return fmt.Errorf("ProtoJSON bytes32 must be a base64 string")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("ProtoJSON bytes32 must decode to exactly 32 bytes")
	}
	*v = ProtoBytes32(hex.EncodeToString(raw))
	return nil
}

func (v ProtoBytes32) Hex() string { return string(v) }

// ProtoBytes stores variable-length protobuf bytes as lowercase hex in Go and
// emits base64 in ProtoJSON.
type ProtoBytes string

func (v ProtoBytes) MarshalJSON() ([]byte, error) {
	raw, err := hex.DecodeString(string(v))
	if err != nil || len(raw) == 0 || hex.EncodeToString(raw) != string(v) {
		return nil, fmt.Errorf("ProtoJSON bytes must be canonical non-empty lowercase hex internally")
	}
	return json.Marshal(base64.StdEncoding.EncodeToString(raw))
}

func (v *ProtoBytes) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("decode ProtoJSON bytes into nil destination")
	}
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return fmt.Errorf("ProtoJSON bytes must be a base64 string")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) == 0 {
		return fmt.Errorf("ProtoJSON bytes must be non-empty canonical base64")
	}
	*v = ProtoBytes(hex.EncodeToString(raw))
	return nil
}

func (v ProtoBytes) Hex() string { return string(v) }

func (v ProtoUint64) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatUint(uint64(v), 10))
}

func (v *ProtoUint64) UnmarshalJSON(data []byte) error {
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return fmt.Errorf("ProtoJSON uint64 must be a decimal string")
	}
	parsed, err := strconv.ParseUint(encoded, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != encoded {
		return fmt.Errorf("ProtoJSON uint64 must be a canonical decimal string")
	}
	*v = ProtoUint64(parsed)
	return nil
}

type CoinMessage struct {
	Denom  string      `json:"denom"`
	Amount ProtoUint64 `json:"amount"`
}

// LegacyRegisterModelProfileMessage is the obsolete flat builder material.
// It remains only until the modelregistry manifest migration is complete and
// must never be marshaled as MsgRegisterModelProfile.
type LegacyRegisterModelProfileMessage struct {
	ModelID                   string      `json:"model_id"`
	ProfileVersion            string      `json:"profile_version"`
	ManifestHash              string      `json:"manifest_hash"`
	TokenizerHash             string      `json:"tokenizer_hash"`
	RuntimeVersion            string      `json:"runtime_version"`
	ResourceTier              string      `json:"resource_tier"`
	MinStake                  ProtoUint64 `json:"min_stake"`
	ChallengeOpenWindowBlocks ProtoUint64 `json:"challenge_open_window_blocks"`
	VerificationProfile       string      `json:"verification_profile"`
	PricingProfile            string      `json:"pricing_profile"`
	EpsilonParams             string      `json:"epsilon_params"`
	TimeoutBootstrapProfile   string      `json:"timeout_bootstrap_profile"`
	SchemaHash                string      `json:"schema_hash"`
	PreviousProfileVersion    string      `json:"previous_profile_version,omitempty"`
	RegistrationFee           CoinMessage `json:"registration_fee"`
	RegistrantSignature       string      `json:"registrant_signature"`
	MetadataHash              string      `json:"metadata_hash"`
	OptionalDisplayTagHash    string      `json:"optional_display_tag_hash,omitempty"`
}

type MetricSpecMessage struct {
	CompareLogprobDiff bool        `json:"compare_logprob_diff"`
	CompareRankDelta   bool        `json:"compare_rank_delta"`
	CompareTopKJaccard bool        `json:"compare_topk_jaccard"`
	CompareUnionJS     bool        `json:"compare_union_js"`
	ComparedTopK       ProtoUint32 `json:"compared_top_k"`
	NumericScale       string      `json:"numeric_scale"`
}

type InferEvidenceRequirementMessage struct {
	EvidenceKind            string      `json:"evidence_kind"`
	CommitmentSchemaVersion ProtoUint32 `json:"commitment_schema_version"`
	MaxEncodedSizeBytes     ProtoUint64 `json:"max_encoded_size_bytes"`
}

type EvidenceSchemaMessage struct {
	SchemaVersion         ProtoUint32                       `json:"schema_version"`
	RequiredInferEvidence []InferEvidenceRequirementMessage `json:"required_infer_evidence"`
}

// WorkerEvidenceSchemaV3 is the two-level Worker evidence schema of wire
// v0.3.0: the B-level value opening (kind 1, commitment V3) and the A-level
// token opening (kind 4, commitment V1), in ascending kind order.
func WorkerEvidenceSchemaV3(maxValueBytes, maxTokenBytes uint64) EvidenceSchemaMessage {
	return EvidenceSchemaMessage{
		SchemaVersion: 1,
		RequiredInferEvidence: []InferEvidenceRequirementMessage{
			{EvidenceKind: "EVIDENCE_KIND_WORKER_VALUE_OPENING", CommitmentSchemaVersion: 3, MaxEncodedSizeBytes: ProtoUint64(maxValueBytes)},
			{EvidenceKind: "EVIDENCE_KIND_WORKER_TOKEN_OPENING", CommitmentSchemaVersion: 1, MaxEncodedSizeBytes: ProtoUint64(maxTokenBytes)},
		},
	}
}

type VerificationProfileMessage struct {
	VerificationProfileID         ProtoUint32           `json:"verification_profile_id"`
	JudgmentFunctionVersion       string                `json:"judgment_function_version"`
	VerificationMode              string                `json:"verification_mode"`
	TokenScope                    string                `json:"token_scope"`
	IncludeGeneratedSpecialTokens bool                  `json:"include_generated_special_tokens"`
	IncludePromptTokens           bool                  `json:"include_prompt_tokens"`
	IncludePaddingTokens          bool                  `json:"include_padding_tokens"`
	RequireOutputTokenIDs         bool                  `json:"require_output_token_ids"`
	RequireFinishReason           bool                  `json:"require_finish_reason"`
	Metrics                       MetricSpecMessage     `json:"metrics"`
	CanonicalEncodingVersion      string                `json:"canonical_encoding_version"`
	EvidenceSchemaHash            ProtoBytes32          `json:"evidence_schema_hash"`
	MetricAggregateProofVersion   string                `json:"metric_aggregate_proof_version"`
	EvidenceSchema                EvidenceSchemaMessage `json:"evidence_schema"`
}

type VerificationThresholdsMessage struct {
	PassMinFiniteCount            ProtoUint32 `json:"pass_min_finite_count"`
	PassMaxMissingComparedCount   ProtoUint32 `json:"pass_max_missing_compared_count"`
	PassMeanAbsLogprobDiffMax     ProtoUint32 `json:"pass_mean_abs_logprob_diff_max"`
	PassAbsLogprobDiffP95Max      ProtoUint32 `json:"pass_abs_logprob_diff_p95_max"`
	PassAbsLogprobDiffP99Max      ProtoUint32 `json:"pass_abs_logprob_diff_p99_max"`
	PassRankDeltaNonzeroRateMax   ProtoUint32 `json:"pass_rank_delta_nonzero_rate_max"`
	PassTopKJaccardMeanMin        ProtoUint32 `json:"pass_topk_jaccard_mean_min"`
	PassUnionJSP99Max             ProtoUint32 `json:"pass_union_js_p99_max"`
	RejectMeanAbsLogprobDiffMin   ProtoUint32 `json:"reject_mean_abs_logprob_diff_min"`
	RejectAbsLogprobDiffP95Min    ProtoUint32 `json:"reject_abs_logprob_diff_p95_min"`
	RejectAbsLogprobDiffP99Min    ProtoUint32 `json:"reject_abs_logprob_diff_p99_min"`
	RejectRankDeltaNonzeroRateMin ProtoUint32 `json:"reject_rank_delta_nonzero_rate_min"`
	RejectTopKJaccardMeanMax      ProtoUint32 `json:"reject_topk_jaccard_mean_max"`
	RejectUnionJSP99Min           ProtoUint32 `json:"reject_union_js_p99_min"`
}

type BatchVerificationMessage struct {
	Enabled                       bool        `json:"enabled"`
	MinSampleCount                ProtoUint32 `json:"min_sample_count"`
	MinValidSampleCount           ProtoUint32 `json:"min_valid_sample_count"`
	PassMinSamplePassRatioBPS     ProtoUint32 `json:"pass_min_sample_pass_ratio_bps"`
	RejectMinSampleRejectRatioBPS ProtoUint32 `json:"reject_min_sample_reject_ratio_bps"`
}

type PricingProfileMessage struct {
	InitialOutputPrice ProtoUint64 `json:"initial_output_price"`
	VerifyRatioBPS     ProtoUint32 `json:"verify_ratio_bps"`
	MinOrderValue      ProtoUint64 `json:"min_order_value"`
}

type TimeoutBootstrapProfileMessage struct {
	InferTimeoutBootstrapBlocks  ProtoUint32 `json:"infer_timeout_bootstrap_blocks"`
	VerifyTimeoutBootstrapBlocks ProtoUint32 `json:"verify_timeout_bootstrap_blocks"`
	CommitTimeoutBootstrapBlocks ProtoUint32 `json:"commit_timeout_bootstrap_blocks"`
	BootstrapValidUntilEpoch     ProtoUint64 `json:"bootstrap_valid_until_epoch"`
}

// SourceRefMessage is shared.v1.SourceRefV1: the immutable upstream the
// profile's weights come from. provider and repo_id are also inputs of the
// model id.
type SourceRefMessage struct {
	Provider        string `json:"provider"`
	SourceURI       string `json:"source_uri"`
	Revision        string `json:"revision"`
	ResolverVersion string `json:"resolver_version"`
	RepoID          string `json:"repo_id"`
	RepoType        string `json:"repo_type"`
}

// ParserRefMessage is shared.v1.ParserRefV1. The zero value means "no parser".
type ParserRefMessage struct {
	Name    string      `json:"name,omitempty"`
	Version ProtoUint32 `json:"version,omitempty"`
}

type ModelProfileProjectionMessage struct {
	ModelID                   ProtoBytes32                   `json:"model_id"`
	ProfileVersion            ProtoUint32                    `json:"profile_version"`
	ManifestHash              ProtoBytes32                   `json:"manifest_hash"`
	TokenizerHash             ProtoBytes32                   `json:"tokenizer_hash"`
	RuntimeClass              string                         `json:"runtime_class"`
	RequiredTopK              ProtoUint32                    `json:"required_top_k"`
	TaskTypes                 []string                       `json:"task_types"`
	GenerationType            string                         `json:"generation_type"`
	ResourceTier              ProtoUint32                    `json:"resource_tier"`
	MinStake                  CoinMessage                    `json:"min_stake"`
	ChallengeOpenWindowBlocks ProtoUint64                    `json:"challenge_open_window_blocks"`
	VerificationProfile       VerificationProfileMessage     `json:"verification_profile"`
	VerificationThresholds    VerificationThresholdsMessage  `json:"verification_thresholds"`
	BatchVerification         BatchVerificationMessage       `json:"batch_verification"`
	PricingProfile            PricingProfileMessage          `json:"pricing_profile"`
	TimeoutBootstrapProfile   TimeoutBootstrapProfileMessage `json:"timeout_bootstrap_profile"`
	SchemaHash                ProtoBytes32                   `json:"schema_hash"`
	PreviousProfileVersion    ProtoUint32                    `json:"previous_profile_version"`
	RegistrationFee           CoinMessage                    `json:"registration_fee"`
	Source                    SourceRefMessage               `json:"source"`
	ToolCallParser            ParserRefMessage               `json:"tool_call_parser"`
	ReasoningParser           ParserRefMessage               `json:"reasoning_parser"`
}

type RegisterModelProfileMessage struct {
	ProposerAddress string                        `json:"proposer_address"`
	Profile         ModelProfileProjectionMessage `json:"profile"`
}

// DeclareModelSupportMessage declares support for a model. Since wire v0.3.0
// support is per model; no profile version is carried.
type DeclareModelSupportMessage struct {
	OperatorAddress        string       `json:"operator_address"`
	ModelID                ProtoBytes32 `json:"model_id"`
	InferenceCapability    bool         `json:"inference_capability"`
	VerificationCapability bool         `json:"verification_capability"`
}

type ModelSupportConfirmation struct {
	OperatorAddress           string         `json:"operator_address"`
	SupportedModels           []ProtoBytes32 `json:"supported_models"`
	ServiceAuthorizationNonce ProtoUint64    `json:"service_authorization_nonce"`
	ExpiryHeight              ProtoUint64    `json:"expiry_height"`
	ServiceSignature          ProtoBytes     `json:"service_signature"`
}

type BatchConfirmModelSupportMessage struct {
	SubmitterAddress string                     `json:"submitter_address"`
	EpochIndex       ProtoUint64                `json:"epoch_index"`
	Confirmations    []ModelSupportConfirmation `json:"confirmations"`
}

// ---------------------------------------------------------------------------
// Frozen task.v1 Task-domain wires.
//
// Every struct below mirrors one frozen message field for field, in frozen
// field-number order, using the ProtoJSON representation each scalar type
// requires (uint32 -> JSON number, uint64 -> decimal string, bytes -> base64,
// enum -> value name, oneof -> exactly one present member). Source: TrueOpen/node
// contract/proto-v1-all-domains, proto/task/v1/{tx,msg_verification,
// msg_settlement,deadline,commit,result,infer_receipt,evidence}.proto.
// ---------------------------------------------------------------------------

const (
	// InferReceiptSchemaVersionV3 is the two-commitment receipt with the
	// plaintext key slots.
	InferReceiptSchemaVersionV3 ProtoUint32 = 3
	// ResultReceiptSchemaVersionV3 binds verifier_value_root.
	ResultReceiptSchemaVersionV3 ProtoUint32 = 3
	// TaskWireSchemaVersionV1 is the first-round VerifyCommit schema version.
	TaskWireSchemaVersionV1 ProtoUint32 = 1
	// VerifyRoundV1 is the only verification round V1 accepts. The field exists
	// to stop cross-round replay and is not a caller-selectable counter
	// (node x/task/types/keys.go VerifyRoundV1).
	VerifyRoundV1 ProtoUint32 = 1
)

// Frozen task.v1.EvidenceKind value names. UNSPECIFIED is never written.
const (
	EvidenceKindWorkerValueOpening    = "EVIDENCE_KIND_WORKER_VALUE_OPENING"
	EvidenceKindVerifierValueOpening  = "EVIDENCE_KIND_VERIFIER_VALUE_OPENING"
	EvidenceKindSettlementRootOpening = "EVIDENCE_KIND_SETTLEMENT_ROOT_OPENING"
	EvidenceKindWorkerTokenOpening    = "EVIDENCE_KIND_WORKER_TOKEN_OPENING"
)

// Frozen task.v1.DeadlineKindV1 value names a MsgSweepDeadline
// TaskDeadlineLocator may carry. The four K-BLOCK-03/04 gated kinds
// (EVIDENCE_REQUEST, CHALLENGE_RESOLVE, CHALLENGE_CLOSE, EVIDENCE_CLEANUP) are
// deliberately absent: deadline.proto states no ACTIVE writer may emit them and
// the sweep executor must reject them.
const (
	DeadlineKindTaskFinality     = "DEADLINE_KIND_V1_TASK_FINALITY"
	DeadlineKindTaskSettlement   = "DEADLINE_KIND_V1_TASK_SETTLEMENT"
	DeadlineKindVerifyReveal     = "DEADLINE_KIND_V1_VERIFY_REVEAL"
	DeadlineKindVerifyCommit     = "DEADLINE_KIND_V1_VERIFY_COMMIT"
	DeadlineKindVerifyOpen       = "DEADLINE_KIND_V1_VERIFY_OPEN"
	DeadlineKindWorkerInfer      = "DEADLINE_KIND_V1_WORKER_INFER"
	DeadlineKindWorkerAssignment = "DEADLINE_KIND_V1_WORKER_ASSIGNMENT"
	DeadlineKindVerifyFinal      = "DEADLINE_KIND_V1_VERIFY_FINAL"
)

// EvidenceCommitmentMessage mirrors task.v1.EvidenceCommitmentV1.
type EvidenceCommitmentMessage struct {
	EvidenceKind       string       `json:"evidence_kind"`
	EvidenceHashOrRoot ProtoBytes32 `json:"evidence_hash_or_root"`
	EncodedSizeBytes   ProtoUint64  `json:"encoded_size_bytes"`
}

// InferReceiptMessage mirrors task.v1.InferReceiptV2. Field 12
// service_signature is outside the signing preimage; evidence_commitments_hash
// is Keeper-derived from field 10 and is not a wire field.
type InferReceiptMessage struct {
	SchemaVersion               ProtoUint32                 `json:"schema_version"`
	ChainID                     string                      `json:"chain_id"`
	TaskID                      ProtoBytes32                `json:"task_id"`
	TaskHash                    ProtoBytes32                `json:"task_hash"`
	WorkerOperatorAddress       string                      `json:"worker_operator_address"`
	ServiceAuthorizationNonce   ProtoUint64                 `json:"service_authorization_nonce"`
	GenerationParamsDigest      ProtoBytes32                `json:"generation_params_digest"`
	OutputHash                  ProtoBytes32                `json:"output_hash"`
	OutputSizeBytes             ProtoUint64                 `json:"output_size_bytes"`
	RequiredEvidenceCommitments []EvidenceCommitmentMessage `json:"required_evidence_commitments"`
	ExpiryHeight                ProtoUint64                 `json:"expiry_height"`
	ServiceSignature            ProtoBytes                  `json:"service_signature"`
	GeneratedTokenCount         ProtoUint64                 `json:"generated_token_count"`
	OutputLeafCount             ProtoUint64                 `json:"output_leaf_count"`
	// The key slots are ZERO32 in plaintext.
	OutputKeyCommitment      ProtoBytes32 `json:"output_key_commitment"`
	WorkerTokenKeyCommitment ProtoBytes32 `json:"worker_token_key_commitment"`
	WorkerValueKeyCommitment ProtoBytes32 `json:"worker_value_key_commitment"`
	CiphertextOutputRoot     ProtoBytes32 `json:"ciphertext_output_root"`
}

// SubmitInferReceiptMessage mirrors task.v1.MsgSubmitInferReceipt.
type SubmitInferReceiptMessage struct {
	Receipt          InferReceiptMessage `json:"receipt"`
	SubmitterAddress string              `json:"submitter_address"`
}

// VerifyCommitMessage mirrors task.v1.VerifyCommitV1. Field 9
// service_signature is outside the signing preimage.
type VerifyCommitMessage struct {
	SchemaVersion             ProtoUint32  `json:"schema_version"`
	ChainID                   string       `json:"chain_id"`
	TaskID                    ProtoBytes32 `json:"task_id"`
	VerifyRound               ProtoUint32  `json:"verify_round"`
	VerifierOperatorAddress   string       `json:"verifier_operator_address"`
	ServiceAuthorizationNonce ProtoUint64  `json:"service_authorization_nonce"`
	CommitHash                ProtoBytes32 `json:"commit_hash"`
	ExpiryHeight              ProtoUint64  `json:"expiry_height"`
	ServiceSignature          ProtoBytes   `json:"service_signature"`
}

// SubmitVerifyCommitMessage mirrors task.v1.MsgSubmitVerifyCommit.
type SubmitVerifyCommitMessage struct {
	Commit           VerifyCommitMessage `json:"commit"`
	SubmitterAddress string              `json:"submitter_address"`
}

// MetricSummaryMessage mirrors task.v1.MetricSummaryV1. Fields 7 and 8 are
// proto3 optional: whether they are present is decided solely by the locked
// profile MetricSpec, so they stay pointers and are omitted when unset.
type MetricSummaryMessage struct {
	FiniteCount               ProtoUint32  `json:"finite_count"`
	MissingComparedCount      ProtoUint32  `json:"missing_compared_count"`
	MeanAbsLogprobDiffFP1e6   ProtoUint32  `json:"mean_abs_logprob_diff_fp_1e6"`
	AbsLogprobDiffP95FP1e6    ProtoUint32  `json:"abs_logprob_diff_p95_fp_1e6"`
	AbsLogprobDiffP99FP1e6    ProtoUint32  `json:"abs_logprob_diff_p99_fp_1e6"`
	RankDeltaNonzeroRateFP1e6 ProtoUint32  `json:"rank_delta_nonzero_rate_fp_1e6"`
	TopkJaccardMeanFP1e6      *ProtoUint32 `json:"topk_jaccard_mean_fp_1e6,omitempty"`
	UnionJSP99FP1e6           *ProtoUint32 `json:"union_js_p99_fp_1e6,omitempty"`
	ComparedTopkCount         ProtoUint32  `json:"compared_topk_count"`
	ComparedRankCount         ProtoUint32  `json:"compared_rank_count"`
}

// ResultReceiptMessage mirrors task.v1.ResultReceiptV2. commit_key and
// metric_summary_hash are Keeper-recomputed and are not caller fields.
type ResultReceiptMessage struct {
	SchemaVersion                     ProtoUint32          `json:"schema_version"`
	ChainID                           string               `json:"chain_id"`
	TaskID                            ProtoBytes32         `json:"task_id"`
	VerifyRound                       ProtoUint32          `json:"verify_round"`
	VerifierOperatorAddress           string               `json:"verifier_operator_address"`
	ServiceAuthorizationNonce         ProtoUint64          `json:"service_authorization_nonce"`
	GenerationParamsDigest            ProtoBytes32         `json:"generation_params_digest"`
	MetricRoot                        ProtoBytes32         `json:"metric_root"`
	MetricSummary                     MetricSummaryMessage `json:"metric_summary"`
	AggregateProofHash                ProtoBytes32         `json:"aggregate_proof_hash"`
	VerifierEvidenceBundleHash        ProtoBytes32         `json:"verifier_evidence_bundle_hash"`
	VerifierEvidenceManifestSizeBytes ProtoUint64          `json:"verifier_evidence_manifest_size_bytes"`
	Salt                              ProtoBytes32         `json:"salt"`
	ExpiryHeight                      ProtoUint64          `json:"expiry_height"`
	ServiceSignature                  ProtoBytes           `json:"service_signature"`
	VerifierValueRoot                 ProtoBytes32         `json:"verifier_value_root"`
	MetricLeafCount                   ProtoUint32          `json:"metric_leaf_count"`
	VerifierEvidenceKeyCommitment     ProtoBytes32         `json:"verifier_evidence_key_commitment"`
}

// SubmitVerifyResultMessage mirrors task.v1.MsgSubmitVerifyResult.
type SubmitVerifyResultMessage struct {
	Receipt          ResultReceiptMessage `json:"receipt"`
	SubmitterAddress string               `json:"submitter_address"`
}

// SettleTaskMessage mirrors task.v1.MsgSettleTask. task_id is the only
// business locator and submitter_address exists solely for Cosmos Tx
// authorization; verdict, cluster, receipt refs, payout, refund, fault,
// evidence root, plan hash, fees and heights are all derived by the Keeper.
type SettleTaskMessage struct {
	TaskID           ProtoBytes32 `json:"task_id"`
	SubmitterAddress string       `json:"submitter_address"`
}

// TaskDeadlineLocatorMessage mirrors task.v1.TaskDeadlineLocator.
type TaskDeadlineLocatorMessage struct {
	TaskID       ProtoBytes32 `json:"task_id"`
	DeadlineKind string       `json:"deadline_kind"`
}

// DeadlineLocatorMessage mirrors task.v1.DeadlineLocatorV1. Only the
// task-scoped member exists here: the challenge and evidence_request members
// are K-BLOCK-03/04 gated with no ACTIVE writer, and session lifecycle sweeps
// are a Session-domain runner Cortex never drives.
type TaskRoundDeadlineLocatorMessage struct {
	TaskID       ProtoBytes32 `json:"task_id"`
	VerifyRound  ProtoUint32  `json:"verify_round"`
	DeadlineKind string       `json:"deadline_kind"`
}
type DeadlineLocatorMessage struct {
	Task      *TaskDeadlineLocatorMessage      `json:"task,omitempty"`
	TaskRound *TaskRoundDeadlineLocatorMessage `json:"task_round,omitempty"`
}

// SweepDeadlineMessage mirrors task.v1.MsgSweepDeadline.
type SweepDeadlineMessage struct {
	Locator          DeadlineLocatorMessage `json:"locator"`
	SubmitterAddress string                 `json:"submitter_address"`
}

func MarshalMessage(kind Kind, value any) ([]byte, error) {
	if !kind.Valid() {
		return nil, fmt.Errorf("unsupported Keeper message type URL %q", kind)
	}
	if err := validateMessageType(kind, value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func ValidateMessagePayload(kind Kind, payload []byte) error {
	var target any
	switch kind {
	case MsgRegisterModelProfile:
		target = &RegisterModelProfileMessage{}
	case MsgDeclareModelSupport:
		target = &DeclareModelSupportMessage{}
	case MsgBatchConfirmModelSupport:
		target = &BatchConfirmModelSupportMessage{}
	case MsgSubmitInferReceipt:
		target = &SubmitInferReceiptMessage{}
	case MsgSubmitVerifyCommit:
		target = &SubmitVerifyCommitMessage{}
	case MsgSubmitVerifyResult:
		target = &SubmitVerifyResultMessage{}
	case MsgSettleTask:
		target = &SettleTaskMessage{}
	case MsgSweepDeadline:
		target = &SweepDeadlineMessage{}
	default:
		return fmt.Errorf("unsupported Keeper message type URL %q", kind)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid %s ProtoJSON payload: %w", kind, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("invalid %s ProtoJSON payload: trailing data", kind)
	}
	switch value := target.(type) {
	case *RegisterModelProfileMessage:
		return validateMessageType(kind, *value)
	case *DeclareModelSupportMessage:
		return validateMessageType(kind, *value)
	case *BatchConfirmModelSupportMessage:
		return validateMessageType(kind, *value)
	case *SubmitInferReceiptMessage:
		return validateMessageType(kind, *value)
	case *SubmitVerifyCommitMessage:
		return validateMessageType(kind, *value)
	case *SubmitVerifyResultMessage:
		return validateMessageType(kind, *value)
	case *SettleTaskMessage:
		return validateMessageType(kind, *value)
	case *SweepDeadlineMessage:
		return validateMessageType(kind, *value)
	default:
		return fmt.Errorf("unsupported Keeper message type URL %q", kind)
	}
}

func validateMessageType(kind Kind, value any) error {
	switch kind {
	case MsgRegisterModelProfile:
		m, ok := value.(RegisterModelProfileMessage)
		if !ok {
			return messageTypeMismatch(kind)
		}
		return validateRegisterModelProfile(m)
	case MsgDeclareModelSupport:
		m, ok := value.(DeclareModelSupportMessage)
		if !ok {
			return messageTypeMismatch(kind)
		}
		if err := requireStrings(m.OperatorAddress, string(m.ModelID)); err != nil {
			return err
		}
		if !m.InferenceCapability && !m.VerificationCapability {
			return fmt.Errorf("at least one capability is required")
		}
		return nil
	case MsgBatchConfirmModelSupport:
		m, ok := value.(BatchConfirmModelSupportMessage)
		if !ok {
			return messageTypeMismatch(kind)
		}
		if err := requireStrings(m.SubmitterAddress); err != nil {
			return err
		}
		if len(m.Confirmations) == 0 {
			return fmt.Errorf("daily support confirmations are required")
		}
		var previousNode string
		for index, item := range m.Confirmations {
			if err := requireStrings(item.OperatorAddress); err != nil || len(item.SupportedModels) == 0 {
				return fmt.Errorf("model support confirmation fields are required")
			}
			if index > 0 && item.OperatorAddress <= previousNode {
				return fmt.Errorf("model support confirmations must be sorted and unique by operator_address")
			}
			previousNode = item.OperatorAddress
			for modelIndex, model := range item.SupportedModels {
				if err := requireStrings(string(model)); err != nil {
					return fmt.Errorf("model support model ids are required")
				}
				// Fixed-width lowercase hex orders exactly like the raw bytes.
				if modelIndex > 0 && model <= item.SupportedModels[modelIndex-1] {
					return fmt.Errorf("supported models must be sorted and unique")
				}
			}
			if item.ServiceAuthorizationNonce == 0 || item.ExpiryHeight == 0 {
				return fmt.Errorf("model support confirmation nonce and expiry height are required")
			}
			if err := validateSignatureHex(item.ServiceSignature.Hex()); err != nil {
				return err
			}
		}
		return nil
	case MsgSubmitInferReceipt:
		m, ok := value.(SubmitInferReceiptMessage)
		if !ok {
			return messageTypeMismatch(kind)
		}
		return validateSubmitInferReceipt(m)
	case MsgSubmitVerifyCommit:
		m, ok := value.(SubmitVerifyCommitMessage)
		if !ok {
			return messageTypeMismatch(kind)
		}
		return validateSubmitVerifyCommit(m)
	case MsgSubmitVerifyResult:
		m, ok := value.(SubmitVerifyResultMessage)
		if !ok {
			return messageTypeMismatch(kind)
		}
		return validateSubmitVerifyResult(m)
	case MsgSettleTask:
		m, ok := value.(SettleTaskMessage)
		if !ok {
			return messageTypeMismatch(kind)
		}
		return validateSettleTask(m)
	case MsgSweepDeadline:
		m, ok := value.(SweepDeadlineMessage)
		if !ok {
			return messageTypeMismatch(kind)
		}
		return validateSweepDeadline(m)
	default:
		return fmt.Errorf("typed message encoder is not implemented for %q", kind)
	}
}

// ErrGenerationParamsDigestUnavailable is the single fail-closed reason for
// every frozen wire that carries generation_params_digest. The field is preimage
// field 7 of both TRUEOPEN_INFER_RECEIPT_V1 and TRUEOPEN_RESULT_V1. Its one source is
// task.v1.TaskAssignmentViewV1 field 16 (TrueOpen/node d8792e6
// proto/task/v1/query_task.proto:106), which
// chainclient.KeeperABCIClient.TaskReceiptFacts reads and the Worker receipt and
// verifier result paths call. A message that reaches this encoder without it was
// built without that read, and substituting a lookalike value -- an all-zero
// hash included -- would produce a signature no Keeper can ever accept.
var ErrGenerationParamsDigestUnavailable = errors.New(
	"generation_params_digest is required by the frozen wire and this message does not carry it: " +
		"task.v1.TaskAssignmentViewV1 field 16 carries it and " +
		"chainclient.KeeperABCIClient.TaskReceiptFacts reads it, so build the message from that read")

// ErrTaskHashUnavailable is the fail-closed reason for the frozen wires that
// carry task_hash. The value is TaskCoreState.accepted_task_hash, which
// chainclient.KeeperABCIClient.TaskReceiptFacts reads and the Worker receipt
// path calls; order_digest is not a substitute because it commits the order
// envelope rather than canonical TaskOrderV1, and neither is a zero hash. The
// upstream handler compares the submitted task_hash against
// core.AcceptedTaskHash, so a placeholder is a guaranteed rejection.
var ErrTaskHashUnavailable = errors.New(
	"task_hash is required by the frozen wire and this message does not carry it: " +
		"chainclient.KeeperABCIClient.TaskReceiptFacts reads TaskCoreState.accepted_task_hash, " +
		"and neither order_digest nor a zero hash is a substitute")

// unavailableHash32 treats an unset ProtoBytes32 and an all-zero one as the same
// condition. The frozen wire frames a Hash32 unconditionally, so it has no
// "absent" encoding: a caller with nothing to send either leaves the field empty
// or writes 32 zero bytes, and the second is shape-valid all the way onto the
// chain. validateSignatureHex already refuses the all-zero signature for the
// same reason; these fields are held to the same rule.
//
// It guards only the two fields whose value comes from a chain read rather than
// from local derivation -- task_hash and generation_params_digest. Both reads
// exist now: chainclient.KeeperABCIClient.TaskReceiptFacts serves them and the
// Worker receipt path and the Verifier result path both perform it, so an empty
// or all-zero value here means that read did not reach the message, which is
// still exactly the fault this reports. task_id and output_hash are derived
// locally, so zeros there would be a Cortex bug rather than a missing input, and
// mislabelling one as "unavailable" would send an operator looking upstream.
func unavailableHash32(value ProtoBytes32) bool {
	if value == "" {
		return true
	}
	decoded, err := hex.DecodeString(value.Hex())
	if err != nil {
		return false
	}
	for _, b := range decoded {
		if b != 0 {
			return false
		}
	}
	return true
}

// ErrRequiredEvidenceKindsUnavailable is the fail-closed reason for an empty
// InferReceiptV2.required_evidence_commitments. The list must exactly equal the
// locked Profile's evidence_schema.required_infer_evidence, which
// hub.v1.Query/Profile serves and Cortex has no reader for; no Profile
// requires the empty set, so an empty list can never be that set. The frozen
// handler rejects it at the same boundary, on the requirement count
// (x/task/keeper/msg_server_receipt.go:296-298).
// zeroHash32Hex is ZERO32, the plaintext value of every key slot.
var zeroHash32Hex = strings.Repeat("00", 32)

var ErrRequiredEvidenceKindsUnavailable = errors.New(
	"required_evidence_commitments must exactly equal the locked Profile's " +
		"evidence_schema.required_infer_evidence and the list is empty: no Profile requires the empty set, " +
		"and hub.v1.Query/Profile, which serves that set, has no Cortex reader")

func validateSubmitInferReceipt(m SubmitInferReceiptMessage) error {
	if err := requireStrings(m.SubmitterAddress); err != nil {
		return err
	}
	r := m.Receipt
	if r.SchemaVersion != InferReceiptSchemaVersionV3 {
		return fmt.Errorf("infer receipt schema_version must be %d", InferReceiptSchemaVersionV3)
	}
	for _, slot := range []struct {
		name  string
		value ProtoBytes32
	}{
		{"output_key_commitment", r.OutputKeyCommitment}, {"worker_token_key_commitment", r.WorkerTokenKeyCommitment},
		{"worker_value_key_commitment", r.WorkerValueKeyCommitment}, {"ciphertext_output_root", r.CiphertextOutputRoot},
	} {
		if slot.value.Hex() != zeroHash32Hex {
			return fmt.Errorf("infer receipt %s must be ZERO32 in plaintext", slot.name)
		}
	}
	if len(r.RequiredEvidenceCommitments) != 2 || r.RequiredEvidenceCommitments[0].EvidenceKind != EvidenceKindWorkerValueOpening ||
		r.RequiredEvidenceCommitments[1].EvidenceKind != EvidenceKindWorkerTokenOpening {
		return fmt.Errorf("infer receipt must commit exactly the Worker value and token openings, in that order")
	}
	if err := requireStrings(r.ChainID, r.WorkerOperatorAddress); err != nil {
		return err
	}
	if unavailableHash32(r.GenerationParamsDigest) {
		return ErrGenerationParamsDigestUnavailable
	}
	if unavailableHash32(r.TaskHash) {
		return ErrTaskHashUnavailable
	}
	for _, field := range []struct{ name, hex string }{
		{"task_id", r.TaskID.Hex()},
		{"task_hash", r.TaskHash.Hex()},
		{"generation_params_digest", r.GenerationParamsDigest.Hex()},
		{"output_hash", r.OutputHash.Hex()},
	} {
		if err := validateHashHex(field.hex); err != nil {
			return fmt.Errorf("infer receipt %s: %w", field.name, err)
		}
	}
	if r.ServiceAuthorizationNonce == 0 || r.ExpiryHeight == 0 || r.OutputLeafCount == 0 {
		return fmt.Errorf("infer receipt service_authorization_nonce, expiry_height and output_leaf_count are required")
	}
	if r.OutputSizeBytes == 0 && r.OutputLeafCount != 1 {
		return fmt.Errorf("empty infer output must have exactly one leaf")
	}
	if err := validateEvidenceCommitments(r.RequiredEvidenceCommitments); err != nil {
		return err
	}
	return validateSignatureHex(r.ServiceSignature.Hex())
}

// validateEvidenceCommitments enforces the frozen list rule: strictly ascending
// by evidence_kind, unique kinds, canonical Hash32 per element and a non-zero
// encoded size. The list is never re-sorted; a reordered list is rejected.
func validateEvidenceCommitments(items []EvidenceCommitmentMessage) error {
	if len(items) == 0 {
		return ErrRequiredEvidenceKindsUnavailable
	}
	previous := -1
	for index, item := range items {
		rank, ok := evidenceKindRank(item.EvidenceKind)
		if !ok {
			return fmt.Errorf("required_evidence_commitments[%d]: evidence_kind %q is not a frozen EvidenceKind value", index, item.EvidenceKind)
		}
		if rank <= previous {
			return fmt.Errorf("required_evidence_commitments must be strictly ascending and unique by evidence_kind")
		}
		previous = rank
		if err := validateHashHex(item.EvidenceHashOrRoot.Hex()); err != nil {
			return fmt.Errorf("required_evidence_commitments[%d]: evidence_hash_or_root: %w", index, err)
		}
		if item.EncodedSizeBytes == 0 {
			return fmt.Errorf("required_evidence_commitments[%d]: encoded_size_bytes is required", index)
		}
	}
	return nil
}

func evidenceKindRank(name string) (int, bool) {
	switch name {
	case EvidenceKindWorkerValueOpening:
		return 1, true
	case EvidenceKindVerifierValueOpening:
		return 2, true
	case EvidenceKindSettlementRootOpening:
		return 3, true
	case EvidenceKindWorkerTokenOpening:
		return 4, true
	default:
		return 0, false
	}
}

func validateSubmitVerifyCommit(m SubmitVerifyCommitMessage) error {
	if err := requireStrings(m.SubmitterAddress); err != nil {
		return err
	}
	c := m.Commit
	if c.SchemaVersion != TaskWireSchemaVersionV1 {
		return fmt.Errorf("verify commit schema_version must be %d", TaskWireSchemaVersionV1)
	}
	if c.VerifyRound < 1 || c.VerifyRound > 2 {
		return fmt.Errorf("verify commit verify_round must be %d", VerifyRoundV1)
	}
	if err := requireStrings(c.ChainID, c.VerifierOperatorAddress); err != nil {
		return err
	}
	if err := validateHashHex(c.TaskID.Hex()); err != nil {
		return fmt.Errorf("verify commit task_id: %w", err)
	}
	if err := validateHashHex(c.CommitHash.Hex()); err != nil {
		return fmt.Errorf("verify commit commit_hash: %w", err)
	}
	if c.ServiceAuthorizationNonce == 0 || c.ExpiryHeight == 0 {
		return fmt.Errorf("verify commit service_authorization_nonce and expiry_height are required")
	}
	return validateSignatureHex(c.ServiceSignature.Hex())
}

func validateSubmitVerifyResult(m SubmitVerifyResultMessage) error {
	if err := requireStrings(m.SubmitterAddress); err != nil {
		return err
	}
	r := m.Receipt
	if r.SchemaVersion != ResultReceiptSchemaVersionV3 {
		return fmt.Errorf("verify result schema_version must be %d", ResultReceiptSchemaVersionV3)
	}
	if r.VerifierEvidenceKeyCommitment.Hex() != zeroHash32Hex {
		return fmt.Errorf("verify result verifier_evidence_key_commitment must be ZERO32 in plaintext")
	}
	// metric_leaf_count 0 is a legal zero-token output (05 empty-F case 1).
	if r.VerifyRound < 1 || r.VerifyRound > 2 {
		return fmt.Errorf("verify result verify_round must be %d", VerifyRoundV1)
	}
	if err := requireStrings(r.ChainID, r.VerifierOperatorAddress); err != nil {
		return err
	}
	if unavailableHash32(r.GenerationParamsDigest) {
		return ErrGenerationParamsDigestUnavailable
	}
	for _, field := range []struct{ name, hex string }{
		{"task_id", r.TaskID.Hex()},
		{"generation_params_digest", r.GenerationParamsDigest.Hex()},
		{"metric_root", r.MetricRoot.Hex()},
		{"aggregate_proof_hash", r.AggregateProofHash.Hex()},
		{"verifier_evidence_bundle_hash", r.VerifierEvidenceBundleHash.Hex()},
		{"salt", r.Salt.Hex()},
		{"verifier_value_root", r.VerifierValueRoot.Hex()},
	} {
		if err := validateHashHex(field.hex); err != nil {
			return fmt.Errorf("verify result %s: %w", field.name, err)
		}
	}
	if r.ServiceAuthorizationNonce == 0 || r.ExpiryHeight == 0 || r.VerifierEvidenceManifestSizeBytes == 0 {
		return fmt.Errorf("verify result service_authorization_nonce and expiry_height are required")
	}
	return validateSignatureHex(r.ServiceSignature.Hex())
}

func validateSettleTask(m SettleTaskMessage) error {
	if err := requireStrings(m.SubmitterAddress); err != nil {
		return err
	}
	if err := validateHashHex(m.TaskID.Hex()); err != nil {
		return fmt.Errorf("settle task task_id: %w", err)
	}
	return nil
}

func validateSweepDeadline(m SweepDeadlineMessage) error {
	if err := requireStrings(m.SubmitterAddress); err != nil {
		return err
	}
	if (m.Locator.Task == nil) == (m.Locator.TaskRound == nil) {
		return fmt.Errorf("sweep deadline locator must set exactly one member")
	}
	if round := m.Locator.TaskRound; round != nil {
		if err := validateHashHex(round.TaskID.Hex()); err != nil {
			return err
		}
		if round.VerifyRound < 1 || round.VerifyRound > 2 || round.DeadlineKind != "DEADLINE_KIND_V1_VERIFY_ROUND_CLOSE" {
			return fmt.Errorf("invalid round deadline locator")
		}
		return nil
	}
	if err := validateHashHex(m.Locator.Task.TaskID.Hex()); err != nil {
		return err
	}
	if !registeredDeadlineKind(m.Locator.Task.DeadlineKind) {
		return fmt.Errorf("unsupported task deadline kind %q", m.Locator.Task.DeadlineKind)
	}
	return nil
}

// registeredDeadlineKind reports whether a name is a DeadlineKindV1 value an
// ACTIVE writer may emit. The four K-BLOCK-03/04 gated kinds are excluded:
// deadline.proto states no ACTIVE writer may emit them and the sweep executor
// must reject them until those blockers close.
func registeredDeadlineKind(name string) bool {
	switch name {
	case DeadlineKindTaskFinality, DeadlineKindTaskSettlement, DeadlineKindVerifyReveal,
		DeadlineKindVerifyCommit, DeadlineKindVerifyOpen, DeadlineKindWorkerInfer,
		DeadlineKindWorkerAssignment, DeadlineKindVerifyFinal, "DEADLINE_KIND_V1_CHALLENGE_WINDOW_CLOSE", "DEADLINE_KIND_V1_EVIDENCE_CLEANUP":
		return true
	default:
		return false
	}
}

func validateRegisterModelProfile(message RegisterModelProfileMessage) error {
	if err := requireStrings(message.ProposerAddress); err != nil {
		return err
	}
	if err := ValidateModelProfileProjection(message.Profile); err != nil {
		return err
	}

	return nil
}

// ValidateModelProfileProjection validates every consensus field that Cortex
// must preserve before calculating Node's registration digest.
func ValidateModelProfileProjection(profile ModelProfileProjectionMessage) error {
	if err := requireStrings(string(profile.ModelID), profile.RuntimeClass); err != nil {
		return err
	}
	if err := validateHashHex(string(profile.ModelID)); err != nil {
		return fmt.Errorf("model_id must be a Hash32: %w", err)
	}
	source := profile.Source
	if source.Provider != "HUGGINGFACE" {
		return fmt.Errorf("model profile source provider must be HUGGINGFACE")
	}
	if err := requireStrings(source.SourceURI, source.Revision, source.ResolverVersion, source.RepoID, source.RepoType); err != nil {
		return fmt.Errorf("model profile source reference is incomplete: %w", err)
	}
	for name, parser := range map[string]ParserRefMessage{"tool_call_parser": profile.ToolCallParser, "reasoning_parser": profile.ReasoningParser} {
		if (parser.Name == "") != (parser.Version == 0) {
			return fmt.Errorf("model profile %s must set both name and version, or neither", name)
		}
	}
	if profile.ProfileVersion == 0 || profile.ResourceTier == 0 || profile.RequiredTopK == 0 || profile.VerificationProfile.Metrics.ComparedTopK != profile.RequiredTopK {
		return fmt.Errorf("model profile numeric identity, resource tier, and matching top-k are required")
	}
	if profile.ProfileVersion == 1 && profile.PreviousProfileVersion != 0 || profile.ProfileVersion > 1 && profile.PreviousProfileVersion+1 != profile.ProfileVersion {
		return fmt.Errorf("model profile version must immediately follow previous_profile_version")
	}
	for _, hash := range []string{
		profile.ManifestHash.Hex(), profile.TokenizerHash.Hex(), profile.SchemaHash.Hex(), profile.VerificationProfile.EvidenceSchemaHash.Hex(),
	} {
		if err := validateHashHex(hash); err != nil {
			return err
		}
	}
	if profile.RuntimeClass != "CAUSAL_LM_PREFILL_LOGPROBS_V1" {
		return fmt.Errorf("unsupported model profile runtime_class")
	}
	if len(profile.TaskTypes) == 0 {
		return fmt.Errorf("model profile task_types are required")
	}
	taskTypeNumbers := map[string]uint32{
		"TASK_TYPE_TEXT_GENERATION": 1, "TASK_TYPE_CHAT": 2,
	}
	previousTaskType := uint32(0)
	for index, taskType := range profile.TaskTypes {
		number := taskTypeNumbers[taskType]
		if number == 0 || index > 0 && number <= previousTaskType {
			return fmt.Errorf("model profile task_types must be known, sorted, and unique")
		}
		previousTaskType = number
	}
	if profile.GenerationType != "GENERATION_TYPE_DETERMINISTIC" && profile.GenerationType != "GENERATION_TYPE_SAMPLED" {
		return fmt.Errorf("model profile generation_type is unsupported")
	}
	verification := profile.VerificationProfile
	if verification.VerificationProfileID == 0 || verification.VerificationMode != "VERIFICATION_MODE_SINGLE_SAMPLE" || verification.TokenScope != "TOKEN_SCOPE_ALL_GENERATED_OUTPUT_TOKENS" || verification.Metrics.NumericScale != "NUMERIC_SCALE_FP_1E6" {
		return fmt.Errorf("model profile verification identity, mode, token scope, and scale are required")
	}
	if verification.JudgmentFunctionVersion != "PREFILL_GENERATED_TOKEN_METRICS_V1" || verification.CanonicalEncodingVersion != "CANONICAL_OUTPUT_TEXT_V1" || verification.MetricAggregateProofVersion != "PREFILL_METRIC_AGGREGATE_PROOF_V1" {
		return fmt.Errorf("unsupported model profile verification wire identifiers")
	}
	if verification.EvidenceSchema.SchemaVersion != 1 || len(verification.EvidenceSchema.RequiredInferEvidence) == 0 {
		return fmt.Errorf("model profile typed evidence schema is required")
	}
	evidenceKindNumbers := map[string]uint32{
		"EVIDENCE_KIND_WORKER_VALUE_OPENING":    1,
		"EVIDENCE_KIND_VERIFIER_VALUE_OPENING":  2,
		"EVIDENCE_KIND_SETTLEMENT_ROOT_OPENING": 3,
		"EVIDENCE_KIND_WORKER_TOKEN_OPENING":    4,
	}
	previousEvidenceKind := uint32(0)
	for index, requirement := range verification.EvidenceSchema.RequiredInferEvidence {
		number := evidenceKindNumbers[requirement.EvidenceKind]
		if number == 0 || index > 0 && number <= previousEvidenceKind ||
			requirement.CommitmentSchemaVersion == 0 || requirement.MaxEncodedSizeBytes == 0 || requirement.MaxEncodedSizeBytes > 1<<40 {
			return fmt.Errorf("model profile evidence requirements must be known, sorted, unique, and bounded")
		}
		if number == 1 && requirement.CommitmentSchemaVersion != 3 {
			return fmt.Errorf("model profile Worker value commitment schema version must be 3")
		}
		if number == 4 && requirement.CommitmentSchemaVersion != 1 {
			return fmt.Errorf("model profile Worker token commitment schema version must be 1")
		}
		previousEvidenceKind = number
	}
	batch := profile.BatchVerification
	if batch.Enabled || batch.MinSampleCount != 0 || batch.MinValidSampleCount != 0 || batch.PassMinSamplePassRatioBPS != 0 || batch.RejectMinSampleRejectRatioBPS != 0 {
		return fmt.Errorf("only disabled single-sample batch verification is supported")
	}
	pricing := profile.PricingProfile
	if pricing.InitialOutputPrice == 0 || pricing.MinOrderValue == 0 || pricing.VerifyRatioBPS > 10_000 {
		return fmt.Errorf("invalid model profile pricing configuration")
	}
	if profile.MinStake.Denom == "" || profile.RegistrationFee.Denom != profile.MinStake.Denom || profile.MinStake.Amount == 0 || profile.RegistrationFee.Amount == 0 {
		return fmt.Errorf("model profile stake and registration fee require positive amounts in the same denomination")
	}
	if profile.ChallengeOpenWindowBlocks == 0 {
		return fmt.Errorf("model profile challenge window is required")
	}
	return nil
}

func messageTypeMismatch(kind Kind) error {
	return fmt.Errorf("message value does not match type URL %q", kind)
}

func requireStrings(values ...string) error {
	for _, value := range values {
		if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value {
			return fmt.Errorf("message required string field is missing or non-canonical")
		}
	}
	return nil
}

func validateHashHex(value string) error {
	if len(value) != 64 || value != strings.ToLower(value) || strings.HasPrefix(value, "0x") {
		return fmt.Errorf("message hash must be 32-byte lowercase hex")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("message hash must be 32-byte lowercase hex")
	}
	return nil
}

func validateSignatureHex(value string) error {
	if len(value) != 128 || value != strings.ToLower(value) || strings.HasPrefix(value, "0x") {
		return fmt.Errorf("message signature must be 64-byte lowercase hex")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return fmt.Errorf("message signature must be 64-byte lowercase hex")
	}
	allZero := true
	for _, b := range decoded {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("message signature must not be zero")
	}
	return nil
}
