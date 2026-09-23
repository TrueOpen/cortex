package chainclient

import (
	"fmt"
	"math"

	"github.com/TrueOpen/cortex/internal/hfields"
)

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

func (s SettlementProfileExecutionSnapshot) Validate() error {
	if !s.ManifestHash.IsSet() || !s.TokenizerHash.IsSet() || !s.SchemaHash.IsSet() || !s.VerificationProfile.EvidenceSchemaHash.IsSet() {
		return fmt.Errorf("Keeper settlement profile execution bytes32 fields are required")
	}
	profile := s.VerificationProfile
	if s.RuntimeClass == "" || s.RequiredTopK == 0 || s.GenerationType == "" ||
		profile.VerificationProfileID == 0 || profile.JudgmentFunctionVersion == "" ||
		profile.VerificationMode == "" || profile.TokenScope == "" ||
		profile.CanonicalEncodingVersion == "" || profile.MetricAggregateProofVersion == "" ||
		profile.Metrics.ComparedTopK == 0 || profile.Metrics.NumericScale == "" {
		return fmt.Errorf("Keeper settlement profile execution policy is incomplete")
	}
	if s.RequiredTopK != profile.Metrics.ComparedTopK {
		return fmt.Errorf("Keeper settlement profile top-k snapshot is inconsistent")
	}
	return nil
}

// verificationHash derives TRUEOPEN_PROFILE_VERIFICATION_SNAPSHOT_V1, the digest
// Keeper publishes as TaskAssignment.profile_verification_snapshot_hash and
// which settlement material is refused without agreeing with.
//
// The framing is H_FIELDS_V1 with typed fields and nested frames, per
// github.com/TrueOpen/wire's published vector
// (testdata/v1/hub/hub_domains_v1.json, profile_verification_snapshot_v1, whose
// "producer" key names this function). This repository previously hashed a
// canonical-JSON payload under TRUEOPEN_FRAME_V1 instead -- an entirely different
// preimage, which additionally omitted evidence_schema. Nothing about that
// could ever agree with the chain, so every settlement build carrying a real
// Keeper snapshot was refused with "profile execution snapshot hash mismatch".
//
// Field order is the frozen one and is not alphabetical at the top level, so do
// not "tidy" it: manifest_hash, tokenizer_hash, runtime_class, required_top_k,
// generation_type, verification_profile, verification_thresholds,
// batch_verification, schema_hash.
func (s SettlementProfileExecutionSnapshot) verificationHash() (ProtoBytes32, error) {
	fields, err := s.verificationFields()
	if err != nil {
		return nil, err
	}
	digest, err := hfields.Digest(profileVerificationDomain, fields...)
	if err != nil {
		return nil, err
	}
	return ProtoBytes32(digest[:]), nil
}

// verificationPreimage returns the framed bytes verificationHash digests. It
// exists so the agreement test can compare against wire's published preimage
// and localise a drift to a field, instead of only learning that two digests
// differ.
func (s SettlementProfileExecutionSnapshot) verificationPreimage() ([]byte, error) {
	fields, err := s.verificationFields()
	if err != nil {
		return nil, err
	}
	return hfields.Preimage(profileVerificationDomain, fields...)
}

func (s SettlementProfileExecutionSnapshot) verificationFields() ([]hfields.Field, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	generationType, ok := profileGenerationTypeNumbers[s.GenerationType]
	if !ok {
		return nil, fmt.Errorf("Keeper settlement profile generation_type %q is not a frozen enum value", s.GenerationType)
	}
	verificationMode, ok := profileVerificationModeNumbers[s.VerificationProfile.VerificationMode]
	if !ok {
		return nil, fmt.Errorf("Keeper settlement profile verification_mode %q is not a frozen enum value", s.VerificationProfile.VerificationMode)
	}
	tokenScope, ok := profileTokenScopeNumbers[s.VerificationProfile.TokenScope]
	if !ok {
		return nil, fmt.Errorf("Keeper settlement profile token_scope %q is not a frozen enum value", s.VerificationProfile.TokenScope)
	}
	numericScale, ok := profileNumericScaleNumbers[s.VerificationProfile.Metrics.NumericScale]
	if !ok {
		return nil, fmt.Errorf("Keeper settlement profile numeric_scale %q is not a frozen enum value", s.VerificationProfile.Metrics.NumericScale)
	}
	evidenceSchema, err := s.evidenceSchemaFrame()
	if err != nil {
		return nil, err
	}
	metrics := s.VerificationProfile.Metrics
	thresholds := s.VerificationThresholds
	batch := s.BatchVerification
	return []hfields.Field{
		hfields.Bytes(s.ManifestHash), hfields.Bytes(s.TokenizerHash),
		hfields.String(s.RuntimeClass), hfields.Uint32(s.RequiredTopK), hfields.Uint32(generationType),
		hfields.Frame(
			hfields.Uint32(s.VerificationProfile.VerificationProfileID),
			hfields.String(s.VerificationProfile.JudgmentFunctionVersion),
			hfields.Uint32(verificationMode), hfields.Uint32(tokenScope),
			hfields.Bool(s.VerificationProfile.IncludeGeneratedSpecialTokens),
			hfields.Bool(s.VerificationProfile.IncludePromptTokens),
			hfields.Bool(s.VerificationProfile.IncludePaddingTokens),
			hfields.Bool(s.VerificationProfile.RequireOutputTokenIDs),
			hfields.Bool(s.VerificationProfile.RequireFinishReason),
			hfields.Frame(
				hfields.Bool(metrics.CompareLogprobDiff), hfields.Bool(metrics.CompareRankDelta),
				hfields.Bool(metrics.CompareTopKJaccard), hfields.Bool(metrics.CompareUnionJS),
				hfields.Uint32(metrics.ComparedTopK), hfields.Uint32(numericScale),
			),
			hfields.String(s.VerificationProfile.CanonicalEncodingVersion),
			hfields.Bytes(s.VerificationProfile.EvidenceSchemaHash),
			hfields.String(s.VerificationProfile.MetricAggregateProofVersion),
			evidenceSchema,
		),
		// The threshold and batch frames are in the frozen order, which here does
		// coincide with alphabetical; wire's vector is the authority, not the
		// coincidence.
		hfields.Frame(
			hfields.Uint32(thresholds.PassAbsLogprobDiffP95Max), hfields.Uint32(thresholds.PassAbsLogprobDiffP99Max),
			hfields.Uint32(thresholds.PassMaxMissingComparedCount), hfields.Uint32(thresholds.PassMeanAbsLogprobDiffMax),
			hfields.Uint32(thresholds.PassMinFiniteCount), hfields.Uint32(thresholds.PassRankDeltaNonzeroRateMax),
			hfields.Uint32(thresholds.PassTopKJaccardMeanMin), hfields.Uint32(thresholds.PassUnionJSP99Max),
			hfields.Uint32(thresholds.RejectAbsLogprobDiffP95Min), hfields.Uint32(thresholds.RejectAbsLogprobDiffP99Min),
			hfields.Uint32(thresholds.RejectMeanAbsLogprobDiffMin), hfields.Uint32(thresholds.RejectRankDeltaNonzeroRateMin),
			hfields.Uint32(thresholds.RejectTopKJaccardMeanMax), hfields.Uint32(thresholds.RejectUnionJSP99Min),
		),
		hfields.Frame(
			hfields.Bool(batch.Enabled), hfields.Uint32(batch.MinSampleCount), hfields.Uint32(batch.MinValidSampleCount),
			hfields.Uint32(batch.PassMinSamplePassRatioBPS), hfields.Uint32(batch.RejectMinSampleRejectRatioBPS),
		),
		hfields.Bytes(s.SchemaHash),
	}, nil
}

// evidenceSchemaFrame builds verification_profile.evidence_schema: the schema
// version, then ONE nested frame over required_infer_evidence carrying its own
// element_count and a frame per requirement.
func (s SettlementProfileExecutionSnapshot) evidenceSchemaFrame() (hfields.Field, error) {
	schema := s.VerificationProfile.EvidenceSchema
	if err := schema.Validate(); err != nil {
		return hfields.Field{}, err
	}
	if uint64(len(schema.RequiredInferEvidence)) > uint64(math.MaxUint32) {
		return hfields.Field{}, fmt.Errorf("required_infer_evidence count %d overflows uint32", len(schema.RequiredInferEvidence))
	}
	elements := make([]hfields.Field, 0, len(schema.RequiredInferEvidence)+1)
	elements = append(elements, hfields.Uint32(uint32(len(schema.RequiredInferEvidence))))
	for _, requirement := range schema.RequiredInferEvidence {
		elements = append(elements, hfields.Frame(
			hfields.Int32(requirement.EvidenceKind),
			hfields.Uint32(requirement.CommitmentSchemaVersion),
			hfields.Uint64(requirement.MaxEncodedSizeBytes.Uint64()),
		))
	}
	return hfields.Frame(hfields.Uint32(schema.SchemaVersion), hfields.Frame(elements...)), nil
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
