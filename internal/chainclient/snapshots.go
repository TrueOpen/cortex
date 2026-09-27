package chainclient

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/codec"
)

type ParamsSnapshot struct {
	ServiceUnbondingPeriodBlocks Uint64String `json:"service_unbonding_period_blocks"`
	DailySupportWindowBlocks     Uint64String `json:"daily_support_window_blocks"`
}

type CortexNodeSnapshot struct {
	OperatorAddress          string       `json:"operator_address"`
	CurrentServiceAddress    string       `json:"current_service_address"`
	CurrentServicePubkey     string       `json:"current_service_pubkey"`
	AuthorizationNonce       Uint64String `json:"service_authorization_nonce"`
	Status                   string       `json:"status"`
	RegisteredHeight         Uint64String `json:"registered_height"`
	UpdatedHeight            Uint64String `json:"updated_height"`
	CurrentDescriptorVersion Uint64String `json:"current_descriptor_version"`
}

func (s CortexNodeSnapshot) Validate() error {
	if s.OperatorAddress == "" {
		return fmt.Errorf("Keeper Cortex node operator address is required")
	}
	if s.Status == "" {
		return fmt.Errorf("Keeper Cortex node status is required")
	}
	if s.CurrentServiceAddress == "" || s.CurrentServicePubkey == "" {
		return fmt.Errorf("Keeper Cortex node current service key is required")
	}
	if s.AuthorizationNonce.Uint64() == 0 {
		return fmt.Errorf("Keeper Cortex node service authorization nonce is required")
	}
	return nil
}

type ServiceBondSnapshot struct {
	OperatorAddress       string       `json:"operator_address"`
	ActiveBond            Uint64String `json:"active_bond"`
	ReservedLiability     Uint64String `json:"reserved_liability"`
	PendingUnbondingTotal Uint64String `json:"pending_unbonding_total"`
	BondVersion           Uint64String `json:"bond_version"`
	EffectiveBondEpoch    Uint64String `json:"effective_bond_epoch"`
	Status                string       `json:"status"`
	NodeJailCount         Uint64String `json:"node_jail_count"`
}

func (s ServiceBondSnapshot) Validate() error {
	if s.OperatorAddress == "" || s.Status == "" {
		return fmt.Errorf("Keeper service bond identity and status are required")
	}
	if s.BondVersion.Uint64() == 0 {
		return fmt.Errorf("Keeper service bond version is required")
	}
	return nil
}

// candidateEligibleBondStatuses mirrors the chain's IsCandidateEligibleBondStatus
// (node x/hub/types/service_support.go): the live statuses REGISTERED and ACTIVE,
// plus JAILED.
//
// REGISTERED is the one that matters. A freshly staked bond is REGISTERED, and it
// only becomes ACTIVE once a model support activates, which needs ActivationKind
// set, which is only set when the node completes a first duty. Requiring ACTIVE
// before working is therefore not a stricter version of the same rule, it is a
// cycle: the node can never reach the state its own gate demands. The spec names
// this and carves it out -- 04-任务/03 §"REGISTERED 冷启动例外" admits a node with
// fresh declared_support and sufficient stake into the first candidate set
// precisely 为避免首单死锁.
//
// JAILED is admissible for a different reason, and deliberately: the candidate
// selection hard filter tests jail_count against the pool-ejection threshold
// rather than the status, so the chain has already excluded a node that jailed
// too often. The same spec section forbids rejecting a node 仅因
// ServiceBond.status=JAILED. A narrower local test would only refuse work the
// chain would have accepted.
//
// UNBONDING, EXITED and TOMBSTONED stay out: those are exits, not starts.
var candidateEligibleBondStatuses = []string{"REGISTERED", "ACTIVE", "JAILED"}

// CandidateEligible reports whether this bond's status admits taking on work.
// It exists so the readiness gate and the handraise gate cannot drift apart or
// from the chain; see candidateEligibleBondStatuses for why the set is what it is.
func (s ServiceBondSnapshot) CandidateEligible() bool {
	for _, status := range candidateEligibleBondStatuses {
		if strings.EqualFold(s.Status, status) {
			return true
		}
	}
	return false
}

// CandidateEligibleBondStatuses is the admissible set, for an error message that
// tells an operator which statuses would have worked.
func CandidateEligibleBondStatuses() string {
	return strings.Join(candidateEligibleBondStatuses, ", ")
}

type ServiceKeySnapshot struct {
	CurrentDescriptorVersion Uint64String `json:"current_descriptor_version"`
	ParticipantType          string       `json:"participant_type"`
	OperatorAddress          string       `json:"operator_address"`
	ServiceAddress           string       `json:"service_address"`
	ServicePubkey            string       `json:"service_pubkey"`
	AuthorizationNonce       Uint64String `json:"authorization_nonce"`
	RevokedHeight            Uint64String `json:"revoked_height"`
	Status                   string       `json:"status"`
}

type TaskLiabilitySnapshot struct {
	SessionID         string         `json:"session_id"`
	TaskID            string         `json:"task_id"`
	OperatorAddress   string         `json:"operator_address"`
	Duty              string         `json:"duty"`
	BondVersion       Uint64String   `json:"bond_version"`
	CapabilityVersion Uint64String   `json:"capability_version"`
	ReservedAmount    Uint64String   `json:"reserved_amount"`
	Status            string         `json:"status"`
	CreatedHeight     Uint64String   `json:"created_height"`
	ReleasedHeight    Uint64String   `json:"released_height"`
	ConsumedAmount    Uint64String   `json:"consumed_amount"`
	ModelID           string         `json:"model_id"`
	ProfileVersion    ProfileVersion `json:"profile_version"`
}

func (s TaskLiabilitySnapshot) Validate() error {
	for _, field := range []struct{ name, value string }{
		{name: "session id", value: s.SessionID}, {name: "task id", value: s.TaskID},
		{name: "operator address", value: s.OperatorAddress},
		{name: "model id", value: s.ModelID},
	} {
		if field.value == "" || field.value != strings.TrimSpace(field.value) {
			return fmt.Errorf("Keeper task liability %s must be canonical", field.name)
		}
	}
	if s.Duty != "WORKER" && s.Duty != "VERIFIER" {
		return fmt.Errorf("Keeper task liability duty must be WORKER or VERIFIER")
	}
	if s.ProfileVersion.Uint32() == 0 || s.BondVersion.Uint64() == 0 || s.CapabilityVersion.Uint64() == 0 || s.ReservedAmount.Uint64() == 0 || s.CreatedHeight.Uint64() == 0 {
		return fmt.Errorf("Keeper task liability profile, bond/capability versions, amount, and creation height are required")
	}
	if s.ConsumedAmount.Uint64() > s.ReservedAmount.Uint64() {
		return fmt.Errorf("Keeper task liability consumed amount exceeds reservation")
	}
	switch s.Status {
	case "RESERVED":
		if s.ReleasedHeight.Uint64() != 0 || s.ConsumedAmount.Uint64() == s.ReservedAmount.Uint64() {
			return fmt.Errorf("Keeper reserved task liability must remain open")
		}
	case "RELEASED":
		if s.ReleasedHeight.Uint64() < s.CreatedHeight.Uint64() || s.ConsumedAmount.Uint64() == s.ReservedAmount.Uint64() {
			return fmt.Errorf("Keeper released task liability is inconsistent")
		}
	case "CONSUMED":
		if s.ReleasedHeight.Uint64() < s.CreatedHeight.Uint64() || s.ConsumedAmount.Uint64() != s.ReservedAmount.Uint64() {
			return fmt.Errorf("Keeper consumed task liability is inconsistent")
		}
	default:
		return fmt.Errorf("Keeper task liability status %q is unsupported", s.Status)
	}
	return nil
}

type ModelSnapshot struct {
	ModelID                  string       `json:"model_id"`
	Status                   string       `json:"status"`
	RegisteredHeight         Uint64String `json:"registered_height"`
	TotalRegistrationFeePaid Uint64String `json:"total_registration_fee_paid"`
	ConfirmedWorkerCount     Uint64String `json:"confirmed_worker_count"`
	LastStatusChangeHeight   Uint64String `json:"last_status_change_height"`
	ActiveProfileCount       Uint64String `json:"active_profile_count"`
	StatusSource             string       `json:"status_source"`
}

func (s ModelSnapshot) Validate() error {
	if s.ModelID == "" || s.Status == "" || s.RegisteredHeight.Uint64() == 0 {
		return fmt.Errorf("Keeper model identity, status, and registered height are required")
	}
	return nil
}

type ProfileSnapshot struct {
	ModelID                   string         `json:"model_id"`
	ProfileVersion            ProfileVersion `json:"profile_version"`
	Status                    string         `json:"status"`
	RegisteredHeight          Uint64String   `json:"registered_height"`
	HardwareTierFloor         Uint64String   `json:"hardware_tier_floor"`
	TokenizerHash             HexHash        `json:"tokenizer_hash"`
	RuntimeHash               HexHash        `json:"runtime_hash"`
	QuantHash                 HexHash        `json:"quant_hash"`
	LastStatusChangeHeight    Uint64String   `json:"last_status_change_height"`
	ResourceTier              Uint64String   `json:"resource_tier"`
	MinStake                  Uint64String   `json:"min_stake"`
	ChallengeOpenWindowBlocks Uint64String   `json:"challenge_open_window_blocks"`
	ActiveSupporterCount      Uint64String   `json:"active_supporter_count"`
	ActiveSupportStake        Uint64String   `json:"active_support_stake"`
	RegistrationFeePaid       Uint64String   `json:"registration_fee_paid"`
	PreviousProfileVersion    ProfileVersion `json:"previous_profile_version"`
	EligibleWorkerStake       Uint64String   `json:"eligible_worker_stake"`
	StatusSource              string         `json:"status_source"`
}

func (s ProfileSnapshot) Validate() error {
	if s.ModelID == "" || s.ProfileVersion.Uint32() == 0 || s.Status == "" || s.RegisteredHeight.Uint64() == 0 {
		return fmt.Errorf("Keeper profile identity, status, and registered height are required")
	}
	if s.TokenizerHash == (HexHash{}) || s.RuntimeHash == (HexHash{}) || s.QuantHash == (HexHash{}) {
		return fmt.Errorf("Keeper profile execution hashes are required")
	}
	return nil
}

type ModelProfileSnapshot struct {
	Model   ModelSnapshot   `json:"model"`
	Profile ProfileSnapshot `json:"profile"`
}

// CurrentModelSnapshot is the current Node model aggregate state. It is kept
// separate from the legacy snapshot until every registry consumer migrates.
type CurrentModelSnapshot struct {
	ModelID              string         `json:"model_id"`
	ProposerAddress      string         `json:"proposer_address"`
	Status               string         `json:"status"`
	ActiveProfileCount   uint32         `json:"active_profile_count"`
	LatestProfileVersion ProfileVersion `json:"latest_profile_version"`
	StatusSource         string         `json:"status_source"`
	RegistrationFeePaid  Uint64String   `json:"registration_fee_paid"`
	CreatedHeight        Uint64String   `json:"created_height"`
	UpdatedHeight        Uint64String   `json:"updated_height"`
}

func (s CurrentModelSnapshot) Validate() error {
	if s.ModelID == "" || s.ProposerAddress == "" || s.Status == "" || s.StatusSource == "" || s.LatestProfileVersion.Uint32() == 0 || s.CreatedHeight.Uint64() == 0 || s.UpdatedHeight.Uint64() < s.CreatedHeight.Uint64() {
		return fmt.Errorf("current Keeper model identity, status, proposer, and heights are required")
	}
	return nil
}

type CurrentMetricSpecSnapshot struct {
	CompareLogprobDiff bool   `json:"compare_logprob_diff"`
	CompareRankDelta   bool   `json:"compare_rank_delta"`
	CompareTopKJaccard bool   `json:"compare_topk_jaccard"`
	CompareUnionJS     bool   `json:"compare_union_js"`
	ComparedTopK       uint32 `json:"compared_top_k"`
	NumericScale       string `json:"numeric_scale"`
}

type CurrentInferEvidenceRequirementSnapshot struct {
	EvidenceKind            int32        `json:"evidence_kind"`
	CommitmentSchemaVersion uint32       `json:"commitment_schema_version"`
	MaxEncodedSizeBytes     Uint64String `json:"max_encoded_size_bytes"`
}

type CurrentEvidenceSchemaSnapshot struct {
	SchemaVersion         uint32                                    `json:"schema_version"`
	RequiredInferEvidence []CurrentInferEvidenceRequirementSnapshot `json:"required_infer_evidence"`
}

func (s CurrentEvidenceSchemaSnapshot) Validate() error {
	if s.SchemaVersion != 1 || len(s.RequiredInferEvidence) == 0 {
		return fmt.Errorf("current Keeper evidence schema version and requirements are required")
	}
	var previous int32
	for index, requirement := range s.RequiredInferEvidence {
		if requirement.EvidenceKind <= 0 || (index > 0 && requirement.EvidenceKind <= previous) ||
			requirement.CommitmentSchemaVersion == 0 || requirement.MaxEncodedSizeBytes.Uint64() == 0 {
			return fmt.Errorf("current Keeper evidence requirement %d is invalid", index)
		}
		previous = requirement.EvidenceKind
	}
	return nil
}

type CurrentVerificationProfileSnapshot struct {
	VerificationProfileID         uint32                        `json:"verification_profile_id"`
	JudgmentFunctionVersion       string                        `json:"judgment_function_version"`
	VerificationMode              string                        `json:"verification_mode"`
	TokenScope                    string                        `json:"token_scope"`
	IncludeGeneratedSpecialTokens bool                          `json:"include_generated_special_tokens"`
	IncludePromptTokens           bool                          `json:"include_prompt_tokens"`
	IncludePaddingTokens          bool                          `json:"include_padding_tokens"`
	RequireOutputTokenIDs         bool                          `json:"require_output_token_ids"`
	RequireFinishReason           bool                          `json:"require_finish_reason"`
	Metrics                       CurrentMetricSpecSnapshot     `json:"metrics"`
	CanonicalEncodingVersion      string                        `json:"canonical_encoding_version"`
	EvidenceSchemaHash            ProtoBytes32                  `json:"evidence_schema_hash"`
	MetricAggregateProofVersion   string                        `json:"metric_aggregate_proof_version"`
	EvidenceSchema                CurrentEvidenceSchemaSnapshot `json:"evidence_schema"`
}

type CurrentVerificationThresholdsSnapshot struct {
	PassMinFiniteCount            uint32 `json:"pass_min_finite_count"`
	PassMaxMissingComparedCount   uint32 `json:"pass_max_missing_compared_count"`
	PassMeanAbsLogprobDiffMax     uint32 `json:"pass_mean_abs_logprob_diff_max"`
	PassAbsLogprobDiffP95Max      uint32 `json:"pass_abs_logprob_diff_p95_max"`
	PassAbsLogprobDiffP99Max      uint32 `json:"pass_abs_logprob_diff_p99_max"`
	PassRankDeltaNonzeroRateMax   uint32 `json:"pass_rank_delta_nonzero_rate_max"`
	PassTopKJaccardMeanMin        uint32 `json:"pass_topk_jaccard_mean_min"`
	PassUnionJSP99Max             uint32 `json:"pass_union_js_p99_max"`
	RejectMeanAbsLogprobDiffMin   uint32 `json:"reject_mean_abs_logprob_diff_min"`
	RejectAbsLogprobDiffP95Min    uint32 `json:"reject_abs_logprob_diff_p95_min"`
	RejectAbsLogprobDiffP99Min    uint32 `json:"reject_abs_logprob_diff_p99_min"`
	RejectRankDeltaNonzeroRateMin uint32 `json:"reject_rank_delta_nonzero_rate_min"`
	RejectTopKJaccardMeanMax      uint32 `json:"reject_topk_jaccard_mean_max"`
	RejectUnionJSP99Min           uint32 `json:"reject_union_js_p99_min"`
}

type CurrentBatchVerificationSnapshot struct {
	Enabled                       bool   `json:"enabled"`
	MinSampleCount                uint32 `json:"min_sample_count"`
	MinValidSampleCount           uint32 `json:"min_valid_sample_count"`
	PassMinSamplePassRatioBPS     uint32 `json:"pass_min_sample_pass_ratio_bps"`
	RejectMinSampleRejectRatioBPS uint32 `json:"reject_min_sample_reject_ratio_bps"`
}

type CurrentPricingProfileSnapshot struct {
	InitialOutputPrice Uint64String `json:"initial_output_price"`
	VerifyRatioBPS     uint32       `json:"verify_ratio_bps"`
	MinOrderValue      Uint64String `json:"min_order_value"`
}

type CurrentTimeoutBootstrapProfileSnapshot struct {
	InferTimeoutBootstrapBlocks  uint32       `json:"infer_timeout_bootstrap_blocks"`
	VerifyTimeoutBootstrapBlocks uint32       `json:"verify_timeout_bootstrap_blocks"`
	CommitTimeoutBootstrapBlocks uint32       `json:"commit_timeout_bootstrap_blocks"`
	BootstrapValidUntilEpoch     Uint64String `json:"bootstrap_valid_until_epoch"`
}

type CurrentProfileSnapshot struct {
	ModelID                   string                                 `json:"model_id"`
	ProfileVersion            ProfileVersion                         `json:"profile_version"`
	ManifestHash              ProtoBytes32                           `json:"manifest_hash"`
	TokenizerHash             ProtoBytes32                           `json:"tokenizer_hash"`
	RuntimeClass              string                                 `json:"runtime_class"`
	RequiredTopK              uint32                                 `json:"required_top_k"`
	TaskTypes                 []string                               `json:"task_types"`
	GenerationType            string                                 `json:"generation_type"`
	ResourceTier              uint32                                 `json:"resource_tier"`
	MinStake                  Uint64String                           `json:"min_stake"`
	ChallengeOpenWindowBlocks Uint64String                           `json:"challenge_open_window_blocks"`
	VerificationProfile       CurrentVerificationProfileSnapshot     `json:"verification_profile"`
	VerificationThresholds    CurrentVerificationThresholdsSnapshot  `json:"verification_thresholds"`
	BatchVerification         CurrentBatchVerificationSnapshot       `json:"batch_verification"`
	PricingProfile            CurrentPricingProfileSnapshot          `json:"pricing_profile"`
	TimeoutBootstrapProfile   CurrentTimeoutBootstrapProfileSnapshot `json:"timeout_bootstrap_profile"`
	SchemaHash                ProtoBytes32                           `json:"schema_hash"`
	Status                    string                                 `json:"status"`
	ActiveSupportStake        Uint64String                           `json:"active_support_stake"`
	EligibleSupportStake      Uint64String                           `json:"eligible_support_stake"`
	ActiveSupporterCount      uint32                                 `json:"active_supporter_count"`
	StatusSource              string                                 `json:"status_source"`
	RegistrationFeePaid       Uint64String                           `json:"registration_fee_paid"`
	PreviousProfileVersion    ProfileVersion                         `json:"previous_profile_version"`
	ProposerAddress           string                                 `json:"proposer_address"`
	RegistrationDigest        ProtoBytes32                           `json:"registration_digest"`
	CreatedHeight             Uint64String                           `json:"created_height"`
	UpdatedHeight             Uint64String                           `json:"updated_height"`
}

func (s CurrentProfileSnapshot) Validate() error {
	if s.ModelID == "" || s.ProfileVersion.Uint32() == 0 || s.ProposerAddress == "" || s.Status == "" || s.StatusSource == "" || s.CreatedHeight.Uint64() == 0 || s.UpdatedHeight.Uint64() < s.CreatedHeight.Uint64() {
		return fmt.Errorf("current Keeper profile identity, status, proposer, and heights are required")
	}
	for _, field := range []ProtoBytes32{s.ManifestHash, s.TokenizerHash, s.SchemaHash, s.RegistrationDigest, s.VerificationProfile.EvidenceSchemaHash} {
		if !field.IsSet() {
			return fmt.Errorf("current Keeper profile bytes32 fields are required")
		}
	}
	if err := s.VerificationProfile.EvidenceSchema.Validate(); err != nil {
		return err
	}
	if s.RuntimeClass == "" || s.RequiredTopK == 0 || s.RequiredTopK != s.VerificationProfile.Metrics.ComparedTopK || len(s.TaskTypes) == 0 || s.GenerationType == "" || s.ResourceTier == 0 || s.MinStake.Uint64() == 0 || s.ChallengeOpenWindowBlocks.Uint64() == 0 {
		return fmt.Errorf("current Keeper profile execution projection is incomplete")
	}
	return nil
}

type CurrentModelProfileSnapshot struct {
	Model   CurrentModelSnapshot   `json:"model"`
	Profile CurrentProfileSnapshot `json:"profile"`
}

func (s CurrentModelProfileSnapshot) Validate() error {
	if err := s.Model.Validate(); err != nil {
		return err
	}
	if err := s.Profile.Validate(); err != nil {
		return err
	}
	if s.Model.ModelID != s.Profile.ModelID || s.Model.ProposerAddress != s.Profile.ProposerAddress {
		return fmt.Errorf("current Keeper model/profile identities do not match")
	}
	return nil
}

func (s ModelProfileSnapshot) Validate() error {
	if err := s.Model.Validate(); err != nil {
		return err
	}
	if err := s.Profile.Validate(); err != nil {
		return err
	}
	if s.Model.ModelID != s.Profile.ModelID {
		return fmt.Errorf("Keeper model/profile identity mismatch")
	}
	return nil
}

type ModelCapabilitySnapshot struct {
	OperatorAddress        string         `json:"operator_address"`
	ModelID                string         `json:"model_id"`
	ProfileVersion         ProfileVersion `json:"profile_version"`
	InferenceCapability    bool           `json:"inference_capability"`
	VerificationCapability bool           `json:"verification_capability"`
	CapabilityVersion      Uint64String   `json:"capability_version"`
}

func (s ModelCapabilitySnapshot) Validate() error {
	if s.OperatorAddress == "" || s.ModelID == "" || s.ProfileVersion.Uint32() == 0 {
		return fmt.Errorf("Keeper model capability identity is required")
	}
	if !s.InferenceCapability && !s.VerificationCapability {
		return fmt.Errorf("Keeper model capability must enable inference or verification")
	}
	if s.CapabilityVersion.Uint64() == 0 {
		return fmt.Errorf("Keeper model capability version is required")
	}
	return nil
}

type ModelSupportSnapshot struct {
	OperatorAddress              string         `json:"operator_address"`
	ModelID                      string         `json:"model_id"`
	ProfileVersion               ProfileVersion `json:"profile_version"`
	DeclaredSupport              bool           `json:"declared_support"`
	SupportActive                bool           `json:"support_active"`
	ActivationKind               int32          `json:"activation_kind"`
	FirstActivationDuty          int32          `json:"first_activation_duty"`
	FirstSupportTaskID           ProtoBytes32   `json:"first_support_task_id"`
	FirstSupportOrderValue       Uint64String   `json:"first_support_order_value"`
	P30CutoffEpoch               *Uint64String  `json:"p30_cutoff_epoch,omitempty"`
	P30Bootstrap                 *bool          `json:"p30_bootstrap,omitempty"`
	SupportFreshUntilEpoch       Uint64String   `json:"support_fresh_until_epoch"`
	LastRefreshTaskID            ProtoBytes32   `json:"last_refresh_task_id"`
	LastRefreshHeight            Uint64String   `json:"last_refresh_height"`
	ActiveSupportStakeSnapshot   Uint64String   `json:"active_support_stake_snapshot"`
	EligibleSupportStakeSnapshot Uint64String   `json:"eligible_support_stake_snapshot"`
	SupportVersion               Uint64String   `json:"support_version"`
}

func (s ModelSupportSnapshot) Validate() error {
	if s.OperatorAddress == "" || s.ModelID == "" || s.ProfileVersion.Uint32() == 0 {
		return fmt.Errorf("Keeper model support identity is required")
	}
	if s.SupportVersion.Uint64() == 0 {
		return fmt.Errorf("Keeper model support version is required")
	}
	if s.SupportActive && !s.DeclaredSupport {
		return fmt.Errorf("Keeper active model support must remain declared")
	}
	if s.P30CutoffEpoch != nil && s.P30Bootstrap != nil || s.P30Bootstrap != nil && !*s.P30Bootstrap {
		return fmt.Errorf("Keeper model support P30 source must be an epoch or true bootstrap flag")
	}
	if s.ActivationKind == 2 && s.P30CutoffEpoch == nil && s.P30Bootstrap == nil {
		return fmt.Errorf("Keeper Worker model support P30 source is required")
	}
	return nil
}

func (s ServiceKeySnapshot) Validate() error {
	if s.ParticipantType == "" || s.OperatorAddress == "" {
		return fmt.Errorf("Keeper current service key participant is required")
	}
	if s.ServiceAddress == "" || s.ServicePubkey == "" || s.Status == "" {
		return fmt.Errorf("Keeper service key material and status are required")
	}
	if len(s.ServicePubkey) != 66 || s.ServicePubkey != strings.ToLower(s.ServicePubkey) || (s.ServicePubkey[:2] != "02" && s.ServicePubkey[:2] != "03") {
		return fmt.Errorf("Keeper service key public key must be lowercase compressed secp256k1 hex")
	}
	if decoded, err := hex.DecodeString(s.ServicePubkey); err != nil || len(decoded) != 33 {
		return fmt.Errorf("Keeper service key public key must be lowercase compressed secp256k1 hex")
	}
	if s.AuthorizationNonce.Uint64() == 0 {
		return fmt.Errorf("Keeper service key authorization nonce is required")
	}
	return nil
}

type AssignmentSnapshot struct {
	SessionID                string         `json:"session_id"`
	TaskID                   string         `json:"task_id"`
	OrderSequence            Uint64String   `json:"order_sequence"`
	OrderDigest              HexHash        `json:"order_digest"`
	SelectedWorker           string         `json:"selected_worker"`
	InferDeadlineHeight      Uint64String   `json:"infer_deadline_height"`
	WinnerConfirmHeight      Uint64String   `json:"winner_confirm_height"`
	ModelID                  string         `json:"model_id"`
	ProfileVersion           ProfileVersion `json:"profile_version"`
	AcceptedOrderPayloadHash HexHash        `json:"accepted_order_payload_hash"`
	// BuilderOperatorAddress is the Builder that received the Task and therefore
	// holds its input. BuilderSet rotation never moves it. Keeper builds that
	// predate the field omit it, so it is required at the point of use rather
	// than here; what is enforced here is that a present value is canonical.
	BuilderOperatorAddress string `json:"builder_operator_address"`
	// TaskReceiptFactsSnapshot is embedded, so accepted_task_hash and
	// generation_params_digest are promoted fields here and inline keys in this
	// snapshot's JSON. The pre-freeze Query/Task response that Task() reads
	// carries neither, so on that path both stay absent; their producer is
	// KeeperABCIClient.TaskReceiptFacts, which reads them from the frozen
	// section 16.2 views. They are therefore required at the point of use rather
	// than here, exactly like BuilderOperatorAddress above; what is enforced at
	// decode is that a present value is exactly 32 bytes.
	//
	// Both json tags carry omitempty so an absent fact stays absent through a
	// round trip: ProtoBytes32.MarshalJSON refuses a value that is not 32 bytes,
	// and the reconciler hashes json.Marshal of this snapshot as the
	// authoritative task material. With omitempty an unpopulated snapshot
	// marshals to exactly the bytes it did before these fields existed.
	TaskReceiptFactsSnapshot
}

type InferReceiptSnapshot struct {
	OutputLeafCount        Uint64String `json:"output_leaf_count"`
	GeneratedTokenCount    Uint64String `json:"generated_token_count"`
	SessionID              string       `json:"session_id"`
	TaskID                 string       `json:"task_id"`
	WinnerWorker           string       `json:"winner_worker"`
	InferReceiptCommitHash HexHash      `json:"infer_receipt_commit_hash"`
	InferReceiptHash       HexHash      `json:"infer_receipt_hash"`
	OutputHash             HexHash      `json:"output_hash"`
	// OutputSizeBytes is task.v1.InferReceiptState.output_size_bytes, the
	// size the Worker signed for. It is a first-class field because the chain
	// carries it: it used to be smuggled into TokenCount and WorkUnit, two
	// columns the frozen receipt deleted, which made a deleted fact look
	// populated and left the live one with nowhere to land. Nothing signs it --
	// output_hash is V1's only output content commitment -- but it is what a
	// candidate Verifier reports at V3 and what V7a's range fetch is judged
	// against.
	OutputSizeBytes            Uint64String `json:"output_size_bytes,omitempty"`
	TraceCommitRoot            HexHash      `json:"trace_commit_root"`
	CheckpointCommitRoot       HexHash      `json:"checkpoint_commit_root"`
	BatchLogRoot               HexHash      `json:"batch_log_root"`
	TokenCount                 Uint64String `json:"token_count"`
	WorkUnit                   Uint64String `json:"work_unit"`
	WorkerSignature            string       `json:"worker_signature"`
	CanonicalOutputPackageHash HexHash      `json:"canonical_output_package_hash"`
	OutputDeliveryCommitment   HexHash      `json:"output_delivery_commitment"`
	OpenVerifyHeight           Uint64String `json:"open_verify_height"`
	ReceiptMode                string       `json:"receipt_mode"`
	ReceiptHeight              Uint64String `json:"receipt_height"`
	VerifyOpenDeadlineHeight   Uint64String `json:"verify_open_deadline_height"`
}

type VerifierAssignmentSnapshot struct {
	VerifyRound                       Uint64String      `json:"verify_round"`
	SelectedVerifierIndexes           map[string]uint32 `json:"selected_verifier_indexes,omitempty"`
	SessionID                         string            `json:"session_id"`
	TaskID                            string            `json:"task_id"`
	OpenVerifyHeight                  Uint64String      `json:"open_verify_height"`
	FormalVerifierSet                 CSVStrings        `json:"formal_verifier_set"`
	SampleSeedReadyHeight             Uint64String      `json:"sample_seed_ready_height"`
	VerificationSampleSeed            HexHash           `json:"verification_sample_seed"`
	CommitDeadlineHeight              Uint64String      `json:"commit_deadline_height"`
	WorkerRevealDeadlineHeight        Uint64String      `json:"worker_reveal_deadline_height"`
	RevealDeadlineHeight              Uint64String      `json:"reveal_deadline_height"`
	VerifyDeadlineHeight              Uint64String      `json:"verify_deadline_height"`
	SampleSeedStatus                  string            `json:"sample_seed_status"`
	VerifierCandidateWindowHash       HexHash           `json:"verifier_candidate_window_hash"`
	ParamVersion                      string            `json:"param_version"`
	SampleRandomnessAggregationBlocks Uint64String      `json:"sample_randomness_aggregation_blocks"`
	WorkerRevealWindowBlocks          Uint64String      `json:"worker_reveal_window_blocks"`
	RevealWindowBlocks                Uint64String      `json:"reveal_window_blocks"`
	Stage3BuilderGraceBlocks          Uint64String      `json:"stage3_builder_grace_blocks"`
}

type SettlementSnapshot struct {
	TaskVerdict      string       `json:"task_verdict"`
	SettlementHeight Uint64String `json:"settlement_height"`
}

type TaskFailureClassSnapshot struct {
	SessionID               string       `json:"session_id"`
	TaskID                  string       `json:"task_id"`
	SettlementID            string       `json:"settlement_id"`
	FailureClass            string       `json:"failure_class"`
	FreezeSignalEligible    bool         `json:"freeze_signal_eligible"`
	ClassificationSource    string       `json:"classification_source"`
	ClassifiedHeight        Uint64String `json:"classified_height"`
	SupersededByChallengeID string       `json:"superseded_by_challenge_id"`
	EvidenceDigest          string       `json:"evidence_digest"`
}

func (s TaskFailureClassSnapshot) Validate() error {
	if s.SessionID == "" || s.TaskID == "" || s.FailureClass == "" || s.ClassificationSource == "" || s.ClassifiedHeight.Uint64() == 0 {
		return fmt.Errorf("Keeper task failure classification is incomplete")
	}
	return nil
}

type SettlementFinalitySnapshot struct {
	OptimisticFinalityStatus          string       `json:"optimistic_finality_status"`
	ChallengeCloseHeight              Uint64String `json:"challenge_close_height"`
	MaxChallengeResolveDeadlineHeight Uint64String `json:"max_challenge_resolve_deadline_height"`
	TaskFinalityHeight                Uint64String `json:"task_finality_height"`
	ClaimableAfterHeight              Uint64String `json:"claimable_after_height"`
	ChallengeRefsHash                 string       `json:"challenge_refs_hash"`
}

type CommitSnapshot struct {
	TaskID          string       `json:"task_id"`
	VerifyRound     Uint64String `json:"verify_round"`
	VerifierAddress string       `json:"verifier_address"`
	CommitHash      HexHash      `json:"commit_hash"`
	CommitHeight    Uint64String `json:"commit_height"`
	Status          string       `json:"status"`
}

func (s CommitSnapshot) Validate() error {
	if s.TaskID == "" || s.VerifyRound.Uint64() == 0 || s.VerifierAddress == "" || s.CommitHash.IsZero() || s.CommitHeight.Uint64() == 0 || s.Status == "" {
		return fmt.Errorf("Keeper commit is incomplete")
	}
	return nil
}

type ResultReceiptSnapshot struct {
	TaskID           string       `json:"task_id"`
	VerifyRound      Uint64String `json:"verify_round"`
	VerifierAddress  string       `json:"verifier_address"`
	ResultRevealHash HexHash      `json:"result_reveal_hash"`
	AcceptedHeight   Uint64String `json:"accepted_height"`
	Status           string       `json:"status"`
}

func (s ResultReceiptSnapshot) Validate() error {
	if s.TaskID == "" || s.VerifyRound.Uint64() == 0 || s.VerifierAddress == "" || s.ResultRevealHash.IsZero() || s.AcceptedHeight.Uint64() == 0 || s.Status == "" {
		return fmt.Errorf("Keeper result receipt is incomplete")
	}
	return nil
}

type FullResultRevealSnapshot struct {
	SessionID       string       `json:"session_id"`
	TaskID          string       `json:"task_id"`
	VerifyRound     Uint64String `json:"verify_round"`
	VerifierAddress string       `json:"verifier_address"`
	ResultDigest    HexHash      `json:"result_digest"`
	AcceptedHeight  Uint64String `json:"accepted_height"`
	Source          string       `json:"source"`
	Status          string       `json:"status"`
}

func (s FullResultRevealSnapshot) Validate() error {
	if s.SessionID == "" || s.TaskID == "" || s.VerifyRound.Uint64() == 0 || s.VerifierAddress == "" || s.ResultDigest.IsZero() || s.AcceptedHeight.Uint64() == 0 || s.Source == "" || s.Status == "" {
		return fmt.Errorf("Keeper full result reveal is incomplete")
	}
	return nil
}

type WorkerRevealReceiptSnapshot struct {
	TaskID                string       `json:"task_id"`
	VerifyRound           Uint64String `json:"verify_round"`
	WorkerAddress         string       `json:"worker_address"`
	SampledValueSetHash   HexHash      `json:"sampled_value_set_hash"`
	EvidenceSchemaVersion string       `json:"evidence_schema_version"`
	AcceptedHeight        Uint64String `json:"accepted_height"`
	Status                string       `json:"status"`
}

func (s WorkerRevealReceiptSnapshot) Validate() error {
	if s.TaskID == "" || s.VerifyRound.Uint64() == 0 || s.WorkerAddress == "" || s.SampledValueSetHash.IsZero() || s.EvidenceSchemaVersion == "" || s.AcceptedHeight.Uint64() == 0 || s.Status == "" {
		return fmt.Errorf("Keeper worker reveal receipt is incomplete")
	}
	return nil
}

type TaskSettlementSnapshot struct {
	SessionID          string       `json:"session_id"`
	TaskID             string       `json:"task_id"`
	SettlementID       string       `json:"settlement_id"`
	Verdict            string       `json:"task_verdict"`
	SettlementHeight   Uint64String `json:"settlement_height"`
	TaskFinalityHeight Uint64String `json:"task_finality_height"`
}

func (s TaskSettlementSnapshot) Validate() error {
	if s.TaskID == "" || s.SettlementID == "" || s.Verdict == "" || s.SettlementHeight.Uint64() == 0 {
		return fmt.Errorf("Keeper settlement is incomplete")
	}
	return nil
}

type ChallengeCommitSnapshot struct {
	ChallengeID     string       `json:"challenge_id"`
	VerifierAddress string       `json:"verifier_address"`
	CommitHash      HexHash      `json:"commit_hash"`
	CommitHeight    Uint64String `json:"commit_height"`
	Status          string       `json:"status"`
}

func (s ChallengeCommitSnapshot) Validate() error {
	if s.ChallengeID == "" || s.VerifierAddress == "" || s.CommitHash.IsZero() || s.CommitHeight.Uint64() == 0 || s.Status == "" {
		return fmt.Errorf("Keeper challenge commit is incomplete")
	}
	return nil
}

type ChallengeResultReceiptSnapshot struct {
	ChallengeID      string       `json:"challenge_id"`
	VerifierAddress  string       `json:"verifier_address"`
	ResultRevealHash HexHash      `json:"result_reveal_hash"`
	AcceptedHeight   Uint64String `json:"accepted_height"`
	Status           string       `json:"status"`
}

func (s ChallengeResultReceiptSnapshot) Validate() error {
	if s.ChallengeID == "" || s.VerifierAddress == "" || s.ResultRevealHash.IsZero() || s.AcceptedHeight.Uint64() == 0 || s.Status == "" {
		return fmt.Errorf("Keeper challenge result receipt is incomplete")
	}
	return nil
}

type ChallengeFullResultRevealSnapshot struct {
	ChallengeID     string       `json:"challenge_id"`
	VerifierAddress string       `json:"verifier_address"`
	ResultDigest    HexHash      `json:"result_digest"`
	AcceptedHeight  Uint64String `json:"accepted_height"`
	Source          string       `json:"source"`
	Status          string       `json:"status"`
}

type ChallengeSnapshot struct {
	ChallengeID                       string       `json:"challenge_id"`
	SessionID                         string       `json:"session_id"`
	TaskID                            string       `json:"task_id"`
	ChallengerAddress                 string       `json:"challenger_address"`
	ChallengeKind                     string       `json:"challenge_kind"`
	Status                            string       `json:"status"`
	OpenedHeight                      Uint64String `json:"opened_height"`
	ChallengeDeadlineHeight           Uint64String `json:"challenge_deadline_height"`
	BondAmount                        Uint64String `json:"bond_amount"`
	EvidenceDigest                    HexHash      `json:"evidence_digest"`
	SettlementID                      string       `json:"settlement_id"`
	ChallengeOutcome                  string       `json:"challenge_outcome"`
	AffectsSettlementVerdict          bool         `json:"affects_settlement_verdict"`
	AffectsRewardEligibility          bool         `json:"affects_reward_eligibility"`
	ChallengeCloseHeightSnapshot      Uint64String `json:"challenge_close_height_snapshot"`
	OpenEvidenceRequestCount          Uint64String `json:"open_evidence_request_count"`
	MaxEvidenceResponseDeadlineHeight Uint64String `json:"max_evidence_response_deadline_height"`
	ResolveDeadlineHeight             Uint64String `json:"resolve_deadline_height"`
	BondLockedAmount                  Uint64String `json:"bond_locked_amount"`
	BondSource                        string       `json:"bond_source"`
	BondStatus                        string       `json:"bond_status"`
	ProofID                           string       `json:"proof_id"`
	RecomputedVerdict                 string       `json:"recomputed_verdict"`
	AffectedAddresses                 []string     `json:"affected_addresses"`
	EconomicEffectRoot                HexHash      `json:"economic_effect_root"`
	SummaryApplied                    bool         `json:"summary_applied"`
	EconomicEffectStatus              string       `json:"economic_effect_status"`
	ChallengeEffectPoolAmount         Uint64String `json:"challenge_effect_pool_amount"`
	ClosedHeight                      Uint64String `json:"closed_height"`
	DebugRuleVersion                  string       `json:"debug_rule_version"`
}

type TaskChallengeSummarySnapshot struct {
	SessionID          string `json:"session_id"`
	TaskID             string `json:"task_id"`
	OpenChallengeCount uint64 `json:"open_challenge_count"`
}

func (s ChallengeSnapshot) Validate() error {
	if s.ChallengeID == "" || s.SessionID == "" || s.TaskID == "" || s.ChallengerAddress == "" || s.ChallengeKind == "" || s.Status == "" {
		return fmt.Errorf("Keeper challenge identity and status are required")
	}
	if s.OpenedHeight.Uint64() == 0 || s.ChallengeDeadlineHeight.Uint64() == 0 || s.ResolveDeadlineHeight.Uint64() == 0 {
		return fmt.Errorf("Keeper challenge deadlines are required")
	}
	return nil
}

type ChallengeAssignmentSnapshot struct {
	ChallengeID               string       `json:"challenge_id"`
	ChallengeVerifiers        []string     `json:"challenge_verifiers"`
	ChallengeSampleSeed       HexHash      `json:"challenge_sample_seed"`
	ChallengeSeedHeight       Uint64String `json:"challenge_seed_height"`
	ChallengeSampleSeedStatus string       `json:"challenge_sample_seed_status"`
	OriginalCheckpointRefHash HexHash      `json:"original_checkpoint_ref_hash"`
	OriginalVerifierSetHash   HexHash      `json:"original_verifier_set_hash"`
	ExcludedVerifierSetHash   HexHash      `json:"excluded_verifier_set_hash"`
	CommitDeadlineHeight      Uint64String `json:"commit_deadline_height"`
	RevealDeadlineHeight      Uint64String `json:"reveal_deadline_height"`
	ParamVersion              string       `json:"param_version"`
	ChallengeVerifierCount    Uint64String `json:"challenge_verifier_count"`
	SeedRetryDelayBlocks      Uint64String `json:"seed_retry_delay_blocks"`
	CommitWindowBlocks        Uint64String `json:"commit_window_blocks"`
	RevealWindowBlocks        Uint64String `json:"reveal_window_blocks"`
}

func (s ChallengeAssignmentSnapshot) Validate() error {
	if s.ChallengeID == "" || s.ChallengeSampleSeedStatus == "" || s.ParamVersion == "" {
		return fmt.Errorf("Keeper challenge assignment identity and parameter snapshot are required")
	}
	if s.OriginalCheckpointRefHash.IsZero() || s.OriginalVerifierSetHash.IsZero() || s.ExcludedVerifierSetHash.IsZero() {
		return fmt.Errorf("Keeper challenge assignment source hashes are required")
	}
	if s.ChallengeSeedHeight.Uint64() == 0 || s.ChallengeVerifierCount.Uint64() == 0 || s.SeedRetryDelayBlocks.Uint64() == 0 || s.CommitWindowBlocks.Uint64() == 0 || s.RevealWindowBlocks.Uint64() == 0 {
		return fmt.Errorf("Keeper challenge assignment parameter values are required")
	}
	switch s.ChallengeSampleSeedStatus {
	case "PENDING":
		if len(s.ChallengeVerifiers) != 0 || !s.ChallengeSampleSeed.IsZero() || s.CommitDeadlineHeight.Uint64() != 0 || s.RevealDeadlineHeight.Uint64() != 0 {
			return fmt.Errorf("Keeper pending challenge assignment contains ready-only fields")
		}
	case "READY":
		if s.ChallengeVerifierCount.Uint64() != uint64(len(s.ChallengeVerifiers)) {
			return fmt.Errorf("Keeper challenge verifier count does not match assignment")
		}
		if s.ChallengeSampleSeed.IsZero() || s.CommitDeadlineHeight.Uint64() == 0 || s.RevealDeadlineHeight.Uint64() < s.CommitDeadlineHeight.Uint64() {
			return fmt.Errorf("Keeper ready challenge assignment is incomplete")
		}
	default:
		return fmt.Errorf("Keeper challenge sample seed status %q is unsupported", s.ChallengeSampleSeedStatus)
	}
	return nil
}

func (s ChallengeFullResultRevealSnapshot) Validate() error {
	if s.ChallengeID == "" || s.VerifierAddress == "" || s.ResultDigest.IsZero() || s.AcceptedHeight.Uint64() == 0 || s.Source == "" || s.Status == "" {
		return fmt.Errorf("Keeper challenge full result reveal is incomplete")
	}
	return nil
}

func (s SettlementFinalitySnapshot) Validate() error {
	if s.OptimisticFinalityStatus == "" {
		return fmt.Errorf("Keeper settlement finality status is required")
	}
	return nil
}

type TaskSnapshot struct {
	Status             string                     `json:"status"`
	UpdatedHeight      Uint64String               `json:"updated_height"`
	Assignment         AssignmentSnapshot         `json:"assignment"`
	InferReceipt       InferReceiptSnapshot       `json:"infer_receipt"`
	VerifierAssignment VerifierAssignmentSnapshot `json:"verifier_assignment"`
	Settlement         SettlementSnapshot         `json:"settlement"`
	CurrentContract    bool                       `json:"-"`
}

// TaskStatusTerminal is the status a settled task reports. The Keeper compacts
// such a task into TaskTerminalSummaryState, so the snapshot built from it
// (snapshotFromTerminalTask) carries the settlement and the assignment identity
// and nothing else: no verifier assignment, no infer deadline. Those fields
// read zero because the chain no longer holds them, not because anyone
// disagrees about their value, and every reader that cross-checks them has to
// make that allowance -- Validate below does, and so does the Keeper event
// enrichment in internal/daemon.
const TaskStatusTerminal = "TERMINAL"

// Validate does not require a non-zero order_sequence. Keeper creates a
// session's StreamState without assigning NextExpectedSequence, so the first
// order of every session is sequence 0 and the Keeper answers Query/Task with
// exactly that; requiring non-zero failed the authority read for every
// session-opening task. Nothing is lost - the sequence carries no completeness
// signal of its own, and task_id, which is required here, already commits to it
// through H_FIELDS_V1(TRUEOPEN_TASK_ID_V1, session_id, order_sequence).
func (s TaskSnapshot) Validate() error {
	if s.Status == TaskStatusTerminal {
		if s.Assignment.SessionID == "" || s.Assignment.TaskID == "" ||
			!s.Assignment.AcceptedTaskHash.IsSet() ||
			s.Assignment.ModelID == "" || s.Assignment.ProfileVersion.Uint32() == 0 || s.Settlement.TaskVerdict == "" {
			return fmt.Errorf("Keeper terminal task authority is incomplete")
		}
		return nil
	}
	if s.CurrentContract {
		if s.Status == "" || s.Assignment.SessionID == "" || s.Assignment.TaskID == "" ||
			!s.Assignment.AcceptedTaskHash.IsSet() ||
			s.Assignment.AcceptedOrderPayloadHash.IsZero() || s.Assignment.ModelID == "" ||
			s.Assignment.ProfileVersion.Uint32() == 0 {
			return fmt.Errorf("Keeper current task authority is incomplete")
		}
		if !s.InferReceipt.OutputHash.IsZero() {
			if s.InferReceipt.TaskID != s.Assignment.TaskID || s.InferReceipt.WinnerWorker != s.Assignment.SelectedWorker ||
				s.InferReceipt.InferReceiptHash.IsZero() || s.InferReceipt.ReceiptHeight.Uint64() == 0 {
				return fmt.Errorf("Keeper current infer receipt is incomplete")
			}
		}
		if len(s.VerifierAssignment.FormalVerifierSet) > 0 {
			if s.VerifierAssignment.TaskID != s.Assignment.TaskID || s.VerifierAssignment.OpenVerifyHeight.Uint64() == 0 ||
				s.VerifierAssignment.SampleSeedReadyHeight.Uint64() == 0 || s.VerifierAssignment.VerificationSampleSeed.IsZero() ||
				s.VerifierAssignment.CommitDeadlineHeight.Uint64() == 0 || s.VerifierAssignment.VerifyDeadlineHeight.Uint64() == 0 {
				return fmt.Errorf("Keeper current verifier assignment is incomplete")
			}
		}
		return nil
	}
	if s.Status == "" || s.Assignment.SessionID == "" || s.Assignment.TaskID == "" || s.Assignment.SelectedWorker == "" {
		return fmt.Errorf("Keeper task status and assignment identity are required")
	}
	if s.Assignment.AcceptedOrderPayloadHash.IsZero() {
		return fmt.Errorf("Keeper task accepted payload digest is required")
	}
	if s.Assignment.ModelID == "" || s.Assignment.ProfileVersion.Uint32() == 0 {
		return fmt.Errorf("Keeper task model and profile are required")
	}
	if s.Assignment.InferDeadlineHeight.Uint64() == 0 {
		return fmt.Errorf("Keeper task infer deadline is required")
	}
	if !s.InferReceipt.OutputHash.IsZero() {
		if s.InferReceipt.SessionID != s.Assignment.SessionID || s.InferReceipt.TaskID != s.Assignment.TaskID || s.InferReceipt.WinnerWorker != s.Assignment.SelectedWorker {
			return fmt.Errorf("Keeper infer receipt identity does not match assignment")
		}
		// canonical_output_package_hash and output_delivery_commitment are NOT in
		// this set. Node deleted both from task.v1.InferReceiptState
		// (proto/CHAIN_BINDINGS.md:265) and cortex-detailed-design.md:1032 puts "a parallel
		// commitment such as a package hash or a delivery hash" among the §13 hard
		// boundaries: output_hash is V1's only output content commitment. Demanding a
		// deleted parallel commitment here refused the authority read for every task
		// that reached this branch.
		if s.InferReceipt.InferReceiptCommitHash.IsZero() || s.InferReceipt.InferReceiptHash.IsZero() || s.InferReceipt.TraceCommitRoot.IsZero() || s.InferReceipt.CheckpointCommitRoot.IsZero() {
			return fmt.Errorf("Keeper infer receipt commitments are required")
		}
		if s.InferReceipt.TokenCount.Uint64() == 0 || s.InferReceipt.WorkUnit.Uint64() == 0 || s.InferReceipt.WorkerSignature == "" || s.InferReceipt.ReceiptMode == "" || s.InferReceipt.ReceiptHeight.Uint64() == 0 {
			return fmt.Errorf("Keeper infer receipt audit facts are required")
		}
	}
	if len(s.VerifierAssignment.FormalVerifierSet) > 0 {
		if s.VerifierAssignment.SessionID != s.Assignment.SessionID || s.VerifierAssignment.TaskID != s.Assignment.TaskID {
			return fmt.Errorf("Keeper verifier assignment identity does not match task")
		}
		if s.VerifierAssignment.OpenVerifyHeight.Uint64() == 0 || s.VerifierAssignment.SampleSeedReadyHeight.Uint64() == 0 || s.VerifierAssignment.CommitDeadlineHeight.Uint64() == 0 || s.VerifierAssignment.VerifyDeadlineHeight.Uint64() == 0 {
			return fmt.Errorf("Keeper verifier assignment base heights are required")
		}
		if s.VerifierAssignment.SampleSeedStatus == "" || s.VerifierAssignment.VerifierCandidateWindowHash.IsZero() || s.VerifierAssignment.ParamVersion == "" || s.VerifierAssignment.SampleRandomnessAggregationBlocks.Uint64() == 0 || s.VerifierAssignment.WorkerRevealWindowBlocks.Uint64() == 0 || s.VerifierAssignment.RevealWindowBlocks.Uint64() == 0 || s.VerifierAssignment.Stage3BuilderGraceBlocks.Uint64() == 0 {
			return fmt.Errorf("Keeper verifier assignment parameter snapshot is required")
		}
		workerRevealDeadline := s.VerifierAssignment.WorkerRevealDeadlineHeight.Uint64()
		revealDeadline := s.VerifierAssignment.RevealDeadlineHeight.Uint64()
		switch s.VerifierAssignment.SampleSeedStatus {
		case "PENDING":
			if !s.VerifierAssignment.VerificationSampleSeed.IsZero() || workerRevealDeadline != 0 || revealDeadline != 0 {
				return fmt.Errorf("Keeper pending verifier assignment contains ready-only fields")
			}
		case "READY":
			if s.VerifierAssignment.VerificationSampleSeed.IsZero() {
				return fmt.Errorf("Keeper ready verifier assignment is missing its sample seed")
			}
			if (workerRevealDeadline == 0) != (revealDeadline == 0) || (workerRevealDeadline != 0 && (workerRevealDeadline >= revealDeadline || revealDeadline >= s.VerifierAssignment.VerifyDeadlineHeight.Uint64())) {
				return fmt.Errorf("Keeper verifier reveal deadlines are inconsistent")
			}
		default:
			return fmt.Errorf("Keeper verifier sample seed status %q is unsupported", s.VerifierAssignment.SampleSeedStatus)
		}
	}
	return nil
}

type AssignmentAccepted struct {
	TaskID string `json:"task_id"`
	Height uint64 `json:"height"`
}

type AssignmentFinalized struct {
	TaskID              string     `json:"task_id"`
	SessionID           string     `json:"session_id"`
	OrderSequence       uint64     `json:"order_sequence"`
	OrderDigest         codec.Hash `json:"order_digest"`
	Winner              string     `json:"winner"`
	WinnerConfirmHeight uint64     `json:"winner_confirm_height"`
	InferDeadlineHeight uint64     `json:"infer_deadline_height"`
	ModelID             string     `json:"model_id"`
	ProfileVersion      uint32     `json:"profile_version"`
	Capability          string     `json:"capability"`
	Input               []byte     `json:"input"`
	// BuilderOperatorAddress is the Builder that received the Task. Its Nexus
	// holds the input and must receive the output.
	BuilderOperatorAddress string `json:"builder_operator_address"`
}
