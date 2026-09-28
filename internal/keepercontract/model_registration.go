package keepercontract

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/txclient"
)

const (
	modelChainProjectionDomain = "TRUEOPEN_MODEL_CHAIN_PROJECTION_V3"
	modelRegistrationDomain    = "TRUEOPEN_MODEL_REGISTRATION_DIGEST_V3"
	modelFrameDomain           = "TRUEOPEN_FRAME_V1"
	evidenceSchemaDomain       = "TRUEOPEN_EVIDENCE_SCHEMA_V1"
)

// CanonicalModelProfileProjection matches Node's frozen JSON projection used
// for model registration signatures. This is deliberately different from
// ProtoJSON: uint64 values are JSON numbers and enum prefixes are removed.
func CanonicalModelProfileProjection(profile txclient.ModelProfileProjectionMessage) ([]byte, error) {
	evidenceHash, err := EvidenceSchemaHash(profile)
	if err != nil {
		return nil, err
	}
	if profile.VerificationProfile.EvidenceSchemaHash.Hex() != hex.EncodeToString(evidenceHash[:]) {
		return nil, fmt.Errorf("evidence_schema_hash does not match typed evidence_schema")
	}
	taskTypes := make([]string, len(profile.TaskTypes))
	for index, value := range profile.TaskTypes {
		taskTypes[index] = trimRegistrationEnum(value, "TASK_TYPE_")
	}
	projection := map[string]any{
		"batch_verification": map[string]any{
			"enabled":                            profile.BatchVerification.Enabled,
			"min_sample_count":                   uint32(profile.BatchVerification.MinSampleCount),
			"min_valid_sample_count":             uint32(profile.BatchVerification.MinValidSampleCount),
			"pass_min_sample_pass_ratio_bps":     uint32(profile.BatchVerification.PassMinSamplePassRatioBPS),
			"reject_min_sample_reject_ratio_bps": uint32(profile.BatchVerification.RejectMinSampleRejectRatioBPS),
		},
		"challenge_open_window_blocks": uint64(profile.ChallengeOpenWindowBlocks),
		"generation_type":              trimRegistrationEnum(profile.GenerationType, "GENERATION_TYPE_"),
		"manifest_hash":                registrationHashHex(profile.ManifestHash.Hex()),
		"manifest_uri":                 profile.ManifestURI,
		"min_stake": map[string]any{
			"amount": json.Number(strconv.FormatUint(uint64(profile.MinStake.Amount), 10)),
			"denom":  profile.MinStake.Denom,
		},
		"model_id":                 registrationHashHex(profile.ModelID.Hex()),
		"previous_profile_version": uint32(profile.PreviousProfileVersion),
		"pricing_profile": map[string]any{
			"min_order_value":      uint64(profile.PricingProfile.MinOrderValue),
			"initial_output_price": uint64(profile.PricingProfile.InitialOutputPrice),
			"verify_ratio_bps":     uint32(profile.PricingProfile.VerifyRatioBPS),
		},
		"profile_version": uint32(profile.ProfileVersion),
		"registration_fee": map[string]any{
			"amount": json.Number(strconv.FormatUint(uint64(profile.RegistrationFee.Amount), 10)),
			"denom":  profile.RegistrationFee.Denom,
		},
		"required_top_k": profile.RequiredTopK,
		"resource_tier":  profile.ResourceTier,
		"runtime_class":  profile.RuntimeClass,
		"schema_hash":    registrationHashHex(profile.SchemaHash.Hex()),
		"task_types":     taskTypes,
		"timeout_bootstrap_profile": map[string]any{
			"bootstrap_valid_until_epoch":     uint64(profile.TimeoutBootstrapProfile.BootstrapValidUntilEpoch),
			"commit_timeout_bootstrap_blocks": uint32(profile.TimeoutBootstrapProfile.CommitTimeoutBootstrapBlocks),
			"infer_timeout_bootstrap_blocks":  uint32(profile.TimeoutBootstrapProfile.InferTimeoutBootstrapBlocks),
			"verify_timeout_bootstrap_blocks": uint32(profile.TimeoutBootstrapProfile.VerifyTimeoutBootstrapBlocks),
		},
		"tokenizer_hash": registrationHashHex(profile.TokenizerHash.Hex()),
		"verification_profile": map[string]any{
			"canonical_encoding_version":       profile.VerificationProfile.CanonicalEncodingVersion,
			"evidence_schema_hash":             registrationHashHex(profile.VerificationProfile.EvidenceSchemaHash.Hex()),
			"evidence_schema":                  canonicalRegistrationEvidenceSchema(profile.VerificationProfile.EvidenceSchema),
			"include_generated_special_tokens": profile.VerificationProfile.IncludeGeneratedSpecialTokens,
			"include_padding_tokens":           profile.VerificationProfile.IncludePaddingTokens,
			"include_prompt_tokens":            profile.VerificationProfile.IncludePromptTokens,
			"judgment_function_version":        profile.VerificationProfile.JudgmentFunctionVersion,
			"metric_aggregate_proof_version":   profile.VerificationProfile.MetricAggregateProofVersion,
			"metrics": map[string]any{
				"compare_logprob_diff": profile.VerificationProfile.Metrics.CompareLogprobDiff,
				"compare_rank_delta":   profile.VerificationProfile.Metrics.CompareRankDelta,
				"compare_topk_jaccard": profile.VerificationProfile.Metrics.CompareTopKJaccard,
				"compare_union_js":     profile.VerificationProfile.Metrics.CompareUnionJS,
				"compared_top_k":       uint32(profile.VerificationProfile.Metrics.ComparedTopK),
				"numeric_scale":        trimRegistrationEnum(profile.VerificationProfile.Metrics.NumericScale, "NUMERIC_SCALE_"),
			},
			"require_finish_reason":    profile.VerificationProfile.RequireFinishReason,
			"require_output_token_ids": profile.VerificationProfile.RequireOutputTokenIDs,
			"token_scope":              trimRegistrationEnum(profile.VerificationProfile.TokenScope, "TOKEN_SCOPE_"),
			"verification_mode":        trimRegistrationEnum(profile.VerificationProfile.VerificationMode, "VERIFICATION_MODE_"),
			"verification_profile_id":  uint32(profile.VerificationProfile.VerificationProfileID),
		},
		"verification_thresholds": canonicalRegistrationThresholds(profile.VerificationThresholds),
		"source": map[string]any{
			"provider":         profile.Source.Provider,
			"repo_id":          profile.Source.RepoID,
			"repo_type":        profile.Source.RepoType,
			"resolver_version": profile.Source.ResolverVersion,
			"revision":         profile.Source.Revision,
			"source_uri":       profile.Source.SourceURI,
		},
		"tool_call_parser": canonicalRegistrationParser(profile.ToolCallParser),
		"reasoning_parser": canonicalRegistrationParser(profile.ReasoningParser),
	}
	return codec.CanonicalJSON(projection)
}

func ModelRegistrationDigest(chainID, proposer string, profile txclient.ModelProfileProjectionMessage) (codec.Hash, []byte, error) {
	if chainID == "" || strings.TrimSpace(chainID) != chainID || proposer == "" || strings.TrimSpace(proposer) != proposer {
		return codec.Hash{}, nil, fmt.Errorf("chain id and proposer are required without surrounding whitespace")
	}
	projection, err := CanonicalModelProfileProjection(profile)
	if err != nil {
		return codec.Hash{}, nil, err
	}
	projectionHash := framedRegistrationHash(modelChainProjectionDomain, projection)
	payload, err := codec.CanonicalJSON(map[string]any{
		"chain_id":              chainID,
		"chain_projection_hash": "0x" + hex.EncodeToString(projectionHash[:]),
		"manifest_hash":         registrationHashHex(profile.ManifestHash.Hex()),
		"profile_version":       uint32(profile.ProfileVersion),

		"proposer_address": proposer,
	})
	if err != nil {
		return codec.Hash{}, nil, err
	}
	return framedRegistrationHash(modelRegistrationDomain, payload), projection, nil
}

// evidenceSchemaProfile holds the subset of a model profile that contributes to
// the TRUEOPEN_EVIDENCE_SCHEMA_V1 digest. It is intentionally a plain struct so that
// both the registration DTO and the chain snapshot can feed the same producer.
type evidenceSchemaProfile struct {
	SchemaVersion                 uint32
	ModelID                       string
	ProfileVersion                uint32
	SchemaHash                    []byte
	TokenizerHash                 []byte
	GenerationType                string
	RequiredTopK                  uint32
	BatchVerification             evidenceSchemaBatch
	VerificationProfileID         uint32
	JudgmentFunctionVersion       string
	CanonicalEncodingVersion      string
	MetricAggregateProofVersion   string
	VerificationMode              string
	TokenScope                    string
	IncludeGeneratedSpecialTokens bool
	IncludePromptTokens           bool
	IncludePaddingTokens          bool
	RequireOutputTokenIDs         bool
	RequireFinishReason           bool
	Metrics                       evidenceSchemaMetrics
	RequiredInferEvidence         []evidenceSchemaRequirement
}

type evidenceSchemaBatch struct {
	Enabled                       bool
	MinSampleCount                uint32
	MinValidSampleCount           uint32
	PassMinSamplePassRatioBPS     uint32
	RejectMinSampleRejectRatioBPS uint32
}

type evidenceSchemaMetrics struct {
	CompareLogprobDiff bool
	CompareRankDelta   bool
	CompareTopKJaccard bool
	CompareUnionJS     bool
	ComparedTopK       uint32
	NumericScale       string
}

type evidenceSchemaRequirement struct {
	Kind                    string
	CommitmentSchemaVersion uint32
	MaxEncodedSizeBytes     uint64
}

func evidenceSchemaHash(profile evidenceSchemaProfile) (codec.Hash, error) {
	if len(profile.SchemaHash) != 32 {
		return codec.Hash{}, fmt.Errorf("schema_hash must be Hash32")
	}
	if len(profile.TokenizerHash) != 32 {
		return codec.Hash{}, fmt.Errorf("tokenizer_hash must be Hash32")
	}
	generationType := map[string]uint32{"GENERATION_TYPE_DETERMINISTIC": 1, "GENERATION_TYPE_SAMPLED": 2}[profile.GenerationType]
	verificationMode := map[string]uint32{"VERIFICATION_MODE_SINGLE_SAMPLE": 1}[profile.VerificationMode]
	tokenScope := map[string]uint32{"TOKEN_SCOPE_ALL_GENERATED_OUTPUT_TOKENS": 1}[profile.TokenScope]
	numericScale := map[string]uint32{"NUMERIC_SCALE_FP_1E6": 1}[profile.Metrics.NumericScale]
	if generationType == 0 || verificationMode == 0 || tokenScope == 0 || numericScale == 0 {
		return codec.Hash{}, fmt.Errorf("profile evidence schema scope enums are invalid")
	}
	batch := profile.BatchVerification
	metrics := profile.Metrics
	modelID, err := identity.ModelIDBytes(profile.ModelID)
	if err != nil {
		return codec.Hash{}, err
	}
	fields := []hfields.Field{
		hfields.Uint32(profile.SchemaVersion),
		hfields.Bytes(modelID), hfields.Uint32(profile.ProfileVersion),
		hfields.Bytes(profile.SchemaHash), hfields.Bytes(profile.TokenizerHash), hfields.Uint32(generationType), hfields.Uint32(profile.RequiredTopK),
		hfields.Frame(
			hfields.Bool(batch.Enabled), hfields.Uint32(batch.MinSampleCount), hfields.Uint32(batch.MinValidSampleCount),
			hfields.Uint32(batch.PassMinSamplePassRatioBPS), hfields.Uint32(batch.RejectMinSampleRejectRatioBPS),
		),
		hfields.Uint32(profile.VerificationProfileID), hfields.String(profile.JudgmentFunctionVersion),
		hfields.String(profile.CanonicalEncodingVersion), hfields.String(profile.MetricAggregateProofVersion),
		hfields.Uint32(verificationMode), hfields.Uint32(tokenScope),
		hfields.Bool(profile.IncludeGeneratedSpecialTokens), hfields.Bool(profile.IncludePromptTokens),
		hfields.Bool(profile.IncludePaddingTokens), hfields.Bool(profile.RequireOutputTokenIDs), hfields.Bool(profile.RequireFinishReason),
		hfields.Frame(
			hfields.Bool(metrics.CompareLogprobDiff), hfields.Bool(metrics.CompareRankDelta), hfields.Bool(metrics.CompareTopKJaccard),
			hfields.Bool(metrics.CompareUnionJS), hfields.Uint32(metrics.ComparedTopK), hfields.Uint32(numericScale),
		),
		hfields.Uint32(uint32(len(profile.RequiredInferEvidence))),
	}
	// The repeated field is ONE nested frame -- u64_be(4)||uint32_be(element_count)
	// followed by one frame per element -- and not one top-level field per
	// element. This repository used to flatten the elements into the outer list,
	// which produced a different preimage for every non-empty requirement set.
	//
	// It is the same mistake internal/nodewire already corrected for
	// TRUEOPEN_INFER_EVIDENCE_COMMITMENTS_V1, and it is settled the same way: by
	// github.com/TrueOpen/wire's published vector
	// (testdata/v1/hub/hub_domains_v1.json, evidence_schema_v1), whose
	// "requirements" field is a frame carrying its own element_count. The
	// flattened form reached a digest this node signs -- evidence_schema_hash is
	// inside the canonical model-profile projection, so it moved
	// chain_projection_hash and registration_digest with it, and every model
	// registration this node signed was rejected by the chain's own derivation.
	//
	// Note that requirement_count above and the frame's element_count below are
	// two separate fields carrying the same number; wire's vector lists both.
	elements := make([]hfields.Field, 0, len(profile.RequiredInferEvidence)+1)
	elements = append(elements, hfields.Uint32(uint32(len(profile.RequiredInferEvidence))))
	previous := uint32(0)
	for index, requirement := range profile.RequiredInferEvidence {
		kind := map[string]uint32{
			"EVIDENCE_KIND_WORKER_VALUE_OPENING": 1, "EVIDENCE_KIND_VERIFIER_VALUE_OPENING": 2,
			"EVIDENCE_KIND_SETTLEMENT_ROOT_OPENING": 3, "EVIDENCE_KIND_WORKER_TOKEN_OPENING": 4,
		}[requirement.Kind]
		if kind == 0 || index > 0 && kind <= previous || requirement.CommitmentSchemaVersion == 0 ||
			requirement.MaxEncodedSizeBytes == 0 || requirement.MaxEncodedSizeBytes > 1<<40 {
			return codec.Hash{}, fmt.Errorf("required_infer_evidence must be known, sorted, unique, and bounded")
		}
		previous = kind
		elements = append(elements, hfields.Frame(
			hfields.Uint32(kind), hfields.Uint32(requirement.CommitmentSchemaVersion),
			hfields.Uint64(requirement.MaxEncodedSizeBytes),
		))
	}
	fields = append(fields, hfields.Frame(elements...))
	return hfields.Digest(evidenceSchemaDomain, fields...)
}

// EvidenceSchemaHash re-derives the typed evidence_schema under
// TRUEOPEN_EVIDENCE_SCHEMA_V1 and checks it against the supplied
// evidence_schema_hash. It returns the computed hash on success.
func EvidenceSchemaHash(profile txclient.ModelProfileProjectionMessage) (codec.Hash, error) {
	schemaHash, err := hex.DecodeString(profile.SchemaHash.Hex())
	if err != nil || len(schemaHash) != 32 {
		return codec.Hash{}, fmt.Errorf("schema_hash must be Hash32")
	}
	tokenizerHash, err := hex.DecodeString(profile.TokenizerHash.Hex())
	if err != nil || len(tokenizerHash) != 32 {
		return codec.Hash{}, fmt.Errorf("tokenizer_hash must be Hash32")
	}
	requirements := make([]evidenceSchemaRequirement, len(profile.VerificationProfile.EvidenceSchema.RequiredInferEvidence))
	for i, req := range profile.VerificationProfile.EvidenceSchema.RequiredInferEvidence {
		requirements[i] = evidenceSchemaRequirement{
			Kind:                    req.EvidenceKind,
			CommitmentSchemaVersion: uint32(req.CommitmentSchemaVersion),
			MaxEncodedSizeBytes:     uint64(req.MaxEncodedSizeBytes),
		}
	}
	batch := profile.BatchVerification
	metrics := profile.VerificationProfile.Metrics
	hash, err := evidenceSchemaHash(evidenceSchemaProfile{
		SchemaVersion:                 uint32(profile.VerificationProfile.EvidenceSchema.SchemaVersion),
		ModelID:                       profile.ModelID.Hex(),
		ProfileVersion:                uint32(profile.ProfileVersion),
		SchemaHash:                    schemaHash,
		TokenizerHash:                 tokenizerHash,
		GenerationType:                profile.GenerationType,
		RequiredTopK:                  uint32(profile.RequiredTopK),
		BatchVerification:             evidenceSchemaBatch{Enabled: batch.Enabled, MinSampleCount: uint32(batch.MinSampleCount), MinValidSampleCount: uint32(batch.MinValidSampleCount), PassMinSamplePassRatioBPS: uint32(batch.PassMinSamplePassRatioBPS), RejectMinSampleRejectRatioBPS: uint32(batch.RejectMinSampleRejectRatioBPS)},
		VerificationProfileID:         uint32(profile.VerificationProfile.VerificationProfileID),
		JudgmentFunctionVersion:       profile.VerificationProfile.JudgmentFunctionVersion,
		CanonicalEncodingVersion:      profile.VerificationProfile.CanonicalEncodingVersion,
		MetricAggregateProofVersion:   profile.VerificationProfile.MetricAggregateProofVersion,
		VerificationMode:              profile.VerificationProfile.VerificationMode,
		TokenScope:                    profile.VerificationProfile.TokenScope,
		IncludeGeneratedSpecialTokens: profile.VerificationProfile.IncludeGeneratedSpecialTokens,
		IncludePromptTokens:           profile.VerificationProfile.IncludePromptTokens,
		IncludePaddingTokens:          profile.VerificationProfile.IncludePaddingTokens,
		RequireOutputTokenIDs:         profile.VerificationProfile.RequireOutputTokenIDs,
		RequireFinishReason:           profile.VerificationProfile.RequireFinishReason,
		Metrics: evidenceSchemaMetrics{
			CompareLogprobDiff: metrics.CompareLogprobDiff,
			CompareRankDelta:   metrics.CompareRankDelta,
			CompareTopKJaccard: metrics.CompareTopKJaccard,
			CompareUnionJS:     metrics.CompareUnionJS,
			ComparedTopK:       uint32(metrics.ComparedTopK),
			NumericScale:       metrics.NumericScale,
		},
		RequiredInferEvidence: requirements,
	})
	return hash, err
}

// ComputeEvidenceSchemaHashFromCurrentModelProfile re-derives the typed
// evidence_schema under TRUEOPEN_EVIDENCE_SCHEMA_V1 for a chain snapshot and
// returns the computed hash without checking it against the stored hash.
func ComputeEvidenceSchemaHashFromCurrentModelProfile(profile chainclient.CurrentModelProfileSnapshot) (codec.Hash, error) {
	p, err := evidenceSchemaProfileFromCurrentModelProfile(profile)
	if err != nil {
		return codec.Hash{}, err
	}
	return evidenceSchemaHash(p)
}

// EvidenceSchemaHashFromCurrentModelProfile re-derives the typed evidence_schema
// under TRUEOPEN_EVIDENCE_SCHEMA_V1 for a chain snapshot and checks it against the
// snapshot's evidence_schema_hash. It returns the computed hash on success.
func EvidenceSchemaHashFromCurrentModelProfile(profile chainclient.CurrentModelProfileSnapshot) (codec.Hash, error) {
	if len(profile.Profile.SchemaHash) != 32 {
		return codec.Hash{}, fmt.Errorf("schema_hash must be Hash32")
	}
	if len(profile.Profile.VerificationProfile.EvidenceSchemaHash) != 32 {
		return codec.Hash{}, fmt.Errorf("evidence_schema_hash must be Hash32")
	}
	hash, err := ComputeEvidenceSchemaHashFromCurrentModelProfile(profile)
	if err != nil {
		return codec.Hash{}, err
	}
	if profile.Profile.VerificationProfile.EvidenceSchemaHash.Hex() != hex.EncodeToString(hash[:]) {
		return codec.Hash{}, fmt.Errorf("evidence_schema_hash does not match typed evidence_schema: computed %s, profile %s",
			hex.EncodeToString(hash[:]), profile.Profile.VerificationProfile.EvidenceSchemaHash.Hex())
	}
	return hash, nil
}

func evidenceSchemaProfileFromCurrentModelProfile(profile chainclient.CurrentModelProfileSnapshot) (evidenceSchemaProfile, error) {
	schema := profile.Profile.VerificationProfile.EvidenceSchema
	requirements := make([]evidenceSchemaRequirement, len(schema.RequiredInferEvidence))
	for i, req := range schema.RequiredInferEvidence {
		requirements[i] = evidenceSchemaRequirement{
			Kind:                    evidenceKindStringFromInt32(req.EvidenceKind),
			CommitmentSchemaVersion: req.CommitmentSchemaVersion,
			MaxEncodedSizeBytes:     req.MaxEncodedSizeBytes.Uint64(),
		}
	}
	return evidenceSchemaProfile{
		SchemaVersion:                 schema.SchemaVersion,
		ModelID:                       profile.Profile.ModelID,
		ProfileVersion:                profile.Profile.ProfileVersion.Uint32(),
		SchemaHash:                    profile.Profile.SchemaHash,
		TokenizerHash:                 profile.Profile.TokenizerHash,
		GenerationType:                profile.Profile.GenerationType,
		RequiredTopK:                  profile.Profile.RequiredTopK,
		BatchVerification:             evidenceSchemaBatch(profile.Profile.BatchVerification),
		VerificationProfileID:         profile.Profile.VerificationProfile.VerificationProfileID,
		JudgmentFunctionVersion:       profile.Profile.VerificationProfile.JudgmentFunctionVersion,
		CanonicalEncodingVersion:      profile.Profile.VerificationProfile.CanonicalEncodingVersion,
		MetricAggregateProofVersion:   profile.Profile.VerificationProfile.MetricAggregateProofVersion,
		VerificationMode:              profile.Profile.VerificationProfile.VerificationMode,
		TokenScope:                    profile.Profile.VerificationProfile.TokenScope,
		IncludeGeneratedSpecialTokens: profile.Profile.VerificationProfile.IncludeGeneratedSpecialTokens,
		IncludePromptTokens:           profile.Profile.VerificationProfile.IncludePromptTokens,
		IncludePaddingTokens:          profile.Profile.VerificationProfile.IncludePaddingTokens,
		RequireOutputTokenIDs:         profile.Profile.VerificationProfile.RequireOutputTokenIDs,
		RequireFinishReason:           profile.Profile.VerificationProfile.RequireFinishReason,
		Metrics: evidenceSchemaMetrics{
			CompareLogprobDiff: profile.Profile.VerificationProfile.Metrics.CompareLogprobDiff,
			CompareRankDelta:   profile.Profile.VerificationProfile.Metrics.CompareRankDelta,
			CompareTopKJaccard: profile.Profile.VerificationProfile.Metrics.CompareTopKJaccard,
			CompareUnionJS:     profile.Profile.VerificationProfile.Metrics.CompareUnionJS,
			ComparedTopK:       profile.Profile.VerificationProfile.Metrics.ComparedTopK,
			NumericScale:       profile.Profile.VerificationProfile.Metrics.NumericScale,
		},
		RequiredInferEvidence: requirements,
	}, nil
}

func evidenceKindStringFromInt32(kind int32) string {
	switch kind {
	case 1:
		return "EVIDENCE_KIND_WORKER_VALUE_OPENING"
	case 2:
		return "EVIDENCE_KIND_VERIFIER_VALUE_OPENING"
	case 3:
		return "EVIDENCE_KIND_SETTLEMENT_ROOT_OPENING"
	case 4:
		return "EVIDENCE_KIND_WORKER_TOKEN_OPENING"
	}
	return ""
}

func canonicalRegistrationEvidenceSchema(value txclient.EvidenceSchemaMessage) map[string]any {
	requirements := make([]map[string]any, len(value.RequiredInferEvidence))
	for index, requirement := range value.RequiredInferEvidence {
		requirements[index] = map[string]any{
			"commitment_schema_version": uint32(requirement.CommitmentSchemaVersion),
			"evidence_kind":             strings.TrimPrefix(requirement.EvidenceKind, "EVIDENCE_KIND_"),
			"max_encoded_size_bytes":    uint64(requirement.MaxEncodedSizeBytes),
		}
	}
	return map[string]any{
		"required_infer_evidence": requirements,
		"schema_version":          uint32(value.SchemaVersion),
	}
}
func canonicalRegistrationThresholds(value txclient.VerificationThresholdsMessage) map[string]any {
	return map[string]any{
		"pass_abs_logprob_diff_p95_max":      uint32(value.PassAbsLogprobDiffP95Max),
		"pass_abs_logprob_diff_p99_max":      uint32(value.PassAbsLogprobDiffP99Max),
		"pass_max_missing_compared_count":    uint32(value.PassMaxMissingComparedCount),
		"pass_mean_abs_logprob_diff_max":     uint32(value.PassMeanAbsLogprobDiffMax),
		"pass_min_finite_count":              uint32(value.PassMinFiniteCount),
		"pass_rank_delta_nonzero_rate_max":   uint32(value.PassRankDeltaNonzeroRateMax),
		"pass_topk_jaccard_mean_min":         uint32(value.PassTopKJaccardMeanMin),
		"pass_union_js_p99_max":              uint32(value.PassUnionJSP99Max),
		"reject_abs_logprob_diff_p95_min":    uint32(value.RejectAbsLogprobDiffP95Min),
		"reject_abs_logprob_diff_p99_min":    uint32(value.RejectAbsLogprobDiffP99Min),
		"reject_mean_abs_logprob_diff_min":   uint32(value.RejectMeanAbsLogprobDiffMin),
		"reject_rank_delta_nonzero_rate_min": uint32(value.RejectRankDeltaNonzeroRateMin),
		"reject_topk_jaccard_mean_max":       uint32(value.RejectTopKJaccardMeanMax),
		"reject_union_js_p99_min":            uint32(value.RejectUnionJSP99Min),
	}
}

func framedRegistrationHash(domain string, payload []byte) codec.Hash {
	frame := make([]byte, 0, len(modelFrameDomain)+4+len(domain)+8+len(payload))
	frame = append(frame, modelFrameDomain...)
	var length [8]byte
	binary.BigEndian.PutUint32(length[:4], uint32(len(domain)))
	frame = append(frame, length[:4]...)
	frame = append(frame, domain...)
	binary.BigEndian.PutUint64(length[:], uint64(len(payload)))
	frame = append(frame, length[:]...)
	frame = append(frame, payload...)
	return sha256.Sum256(frame)
}

func registrationHashHex(value string) string { return "0x" + value }

// canonicalRegistrationParser renders an absent parser as {} and a present one
// with both of its fields, which is how the V3 projection vector spells them.
func canonicalRegistrationParser(parser txclient.ParserRefMessage) map[string]any {
	if parser.Name == "" && parser.Version == 0 {
		return map[string]any{}
	}
	return map[string]any{"name": parser.Name, "version": uint32(parser.Version)}
}

func trimRegistrationEnum(value, prefix string) string { return strings.TrimPrefix(value, prefix) }
