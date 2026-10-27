package chainclient

// profileVerificationDomain is the H_FIELDS_V1 domain of the snapshot digest.
// TRUEOPEN_FRAME_V1 is gone with the JSON payload it used to wrap: H_FIELDS_V1
// frames nested values itself, so there is no outer frame domain any more.
const profileVerificationDomain = "TRUEOPEN_PROFILE_VERIFICATION_SNAPSHOT_V1"

// SettlementProfileExecutionSnapshot is the immutable execution policy copied
// by Node into TaskAssignment. It must be verified against the adjacent
// profile_verification_snapshot_hash before any settlement judgment uses it.
type SettlementProfileExecutionSnapshot struct {
	ManifestHash           ProtoBytes32                          `json:"manifest_hash"`
	TokenizerHash          ProtoBytes32                          `json:"tokenizer_hash"`
	RuntimeClass           string                                `json:"runtime_class"`
	RequiredTopK           uint32                                `json:"required_top_k"`
	GenerationType         string                                `json:"generation_type"`
	VerificationProfile    CurrentVerificationProfileSnapshot    `json:"verification_profile"`
	VerificationThresholds CurrentVerificationThresholdsSnapshot `json:"verification_thresholds"`
	BatchVerification      CurrentBatchVerificationSnapshot      `json:"batch_verification"`
	SchemaHash             ProtoBytes32                          `json:"schema_hash"`
}

// The frozen enum numbers the snapshot's string fields project onto. Keeper
// serves the prefixed proto names; the preimage frames the numbers.
var (
	profileGenerationTypeNumbers = map[string]uint32{
		"GENERATION_TYPE_DETERMINISTIC": 1, "GENERATION_TYPE_SAMPLED": 2,
	}
	profileVerificationModeNumbers = map[string]uint32{"VERIFICATION_MODE_SINGLE_SAMPLE": 1}
	profileTokenScopeNumbers       = map[string]uint32{"TOKEN_SCOPE_ALL_GENERATED_OUTPUT_TOKENS": 1}
	profileNumericScaleNumbers     = map[string]uint32{"NUMERIC_SCALE_FP_1E6": 1}
)
