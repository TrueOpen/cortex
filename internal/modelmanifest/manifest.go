// Package modelmanifest obtains and verifies another operator's
// ModelProfileManifestV4: the full off-chain document whose hash a registered
// profile carries on chain as manifest_hash.
//
// The chain projection is authoritative. A manifest is usable only when its
// bytes hash to the chain's manifest_hash, parse strictly as a V4 manifest,
// are exactly their own canonical encoding, and project onto the same field
// values the chain's ProfileState holds. Anything else is treated as not
// obtained, never as a source of truth.
package modelmanifest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/TrueOpen/cortex/internal/codec"
)

const (
	// ManifestVersion is the only manifest_version this package accepts.
	ManifestVersion = 4
	// HashDomain frames manifest_hash = H_V1(HashDomain, canonical bytes).
	HashDomain = "TRUEOPEN_MODEL_MANIFEST_V4"
	// MaxManifestBytes is the protocol constant max_manifest_bytes (4 MiB).
	// It is not a governance parameter.
	MaxManifestBytes = 4 << 20
)

// Manifest is ModelProfileManifestV4. Every field is required; the strict
// parser rejects unknown fields and the canonical round trip rejects missing,
// null, duplicate or reordered ones.
type Manifest struct {
	Artifacts               Artifacts               `json:"artifacts"`
	BatchVerification       BatchVerification       `json:"batch_verification"`
	Identity                Identity                `json:"identity"`
	ManifestVersion         uint32                  `json:"manifest_version"`
	Metadata                Metadata                `json:"metadata"`
	ModelConfigSummary      ModelConfigSummary      `json:"model_config_summary"`
	OutputDecoding          OutputDecoding          `json:"output_decoding"`
	PricingProfile          PricingProfile          `json:"pricing_profile"`
	ProfileSpec             ProfileSpec             `json:"profile_spec"`
	ReasoningParsing        ReasoningParsing        `json:"reasoning_parsing"`
	RuntimeRequirements     RuntimeRequirements     `json:"runtime_requirements"`
	Source                  Source                  `json:"source"`
	TimeoutBootstrapProfile TimeoutBootstrapProfile `json:"timeout_bootstrap_profile"`
	ToolCalling             ToolCalling             `json:"tool_calling"`
	VerificationProfile     VerificationProfile     `json:"verification_profile"`
	VerificationThresholds  VerificationThresholds  `json:"verification_thresholds"`
}

type Artifacts struct {
	ChatTemplateHash     string         `json:"chat_template_hash"`
	FileManifestHash     string         `json:"file_manifest_hash"`
	Files                []ArtifactFile `json:"files"`
	GenerationConfigHash string         `json:"generation_config_hash"`
	ModelConfigHash      string         `json:"model_config_hash"`
	ModelWeightDigest    string         `json:"model_weight_digest"`
	QuantConfigHash      string         `json:"quant_config_hash"`
	TokenizerConfigHash  string         `json:"tokenizer_config_hash"`
	TokenizerHash        string         `json:"tokenizer_hash"`
}

type ArtifactFile struct {
	Digest    string `json:"digest"`
	Path      string `json:"path"`
	Role      string `json:"role"`
	SizeBytes uint64 `json:"size_bytes"`
}

type BatchVerification struct {
	Enabled                       bool   `json:"enabled"`
	MinSampleCount                uint32 `json:"min_sample_count"`
	MinValidSampleCount           uint32 `json:"min_valid_sample_count"`
	PassMinSamplePassRatioBPS     uint32 `json:"pass_min_sample_pass_ratio_bps"`
	RejectMinSampleRejectRatioBPS uint32 `json:"reject_min_sample_reject_ratio_bps"`
}

type Identity struct {
	DisplayName            string `json:"display_name"`
	ModelID                string `json:"model_id"`
	PreviousProfileVersion uint32 `json:"previous_profile_version"`
	ProfileVersion         uint32 `json:"profile_version"`
}

type Metadata struct {
	DisplayTagHash string `json:"display_tag_hash"`
	LicenseRef     string `json:"license_ref"`
	MetadataURI    string `json:"metadata_uri"`
}

type ModelConfigSummary struct {
	ActiveParams  uint64       `json:"active_params"`
	Architecture  string       `json:"architecture"`
	ContextLength uint64       `json:"context_length"`
	Modality      []string     `json:"modality"`
	ModelType     string       `json:"model_type"`
	MoE           MoE          `json:"moe"`
	Quantization  Quantization `json:"quantization"`
	TotalParams   uint64       `json:"total_params"`
}

type MoE struct {
	Enabled          bool   `json:"enabled"`
	NumExperts       uint32 `json:"num_experts"`
	NumExpertsPerTok uint32 `json:"num_experts_per_tok"`
}

type Quantization struct {
	Bits   uint32 `json:"bits"`
	Method string `json:"method"`
}

type OutputDecoding struct {
	CleanUpTokenizationSpaces bool     `json:"clean_up_tokenization_spaces"`
	DecodeVectorsPath         string   `json:"decode_vectors_path"`
	Decoder                   string   `json:"decoder"`
	EOSTokenIDs               []uint32 `json:"eos_token_ids"`
	RenderSpecialTokens       bool     `json:"render_special_tokens"`
	StripTrailingEOS          bool     `json:"strip_trailing_eos"`
}

type PricingProfile struct {
	InitialOutputPrice uint64 `json:"initial_output_price"`
	MinOrderValue      uint64 `json:"min_order_value"`
	VerifyRatioBPS     uint32 `json:"verify_ratio_bps"`
}

type Coin struct {
	Amount uint64 `json:"amount"`
	Denom  string `json:"denom"`
}

type ProfileSpec struct {
	ChallengeOpenWindowBlocks uint64   `json:"challenge_open_window_blocks"`
	GenerationType            string   `json:"generation_type"`
	MinStake                  Coin     `json:"min_stake"`
	RequireEncrypted          bool     `json:"require_encrypted"`
	ResourceTier              uint32   `json:"resource_tier"`
	SchemaHash                string   `json:"schema_hash"`
	TaskTypes                 []string `json:"task_types"`
}

// ParserRef is ParserRefV1. The enclosing block is {} when no parser is set.
type ParserRef struct {
	Name    string `json:"name"`
	Version uint32 `json:"version"`
}

type ReasoningParsing struct {
	Parser *ParserRef `json:"parser,omitempty"`
}

type ToolCalling struct {
	CallIDFormat string     `json:"call_id_format,omitempty"`
	Parser       *ParserRef `json:"parser,omitempty"`
}

type RuntimeRequirements struct {
	RecommendedEngine        string   `json:"recommended_engine"`
	RecommendedEngineVersion string   `json:"recommended_engine_version"`
	RequiredCapabilities     []string `json:"required_capabilities"`
	RequiredTopK             uint32   `json:"required_top_k"`
	RuntimeClass             string   `json:"runtime_class"`
}

type Source struct {
	Provider        string `json:"provider"`
	RepoID          string `json:"repo_id"`
	RepoType        string `json:"repo_type"`
	ResolverVersion string `json:"resolver_version"`
	Revision        string `json:"revision"`
	SourceURI       string `json:"source_uri"`
}

type TimeoutBootstrapProfile struct {
	BootstrapValidUntilEpoch     uint64 `json:"bootstrap_valid_until_epoch"`
	CommitTimeoutBootstrapBlocks uint32 `json:"commit_timeout_bootstrap_blocks"`
	InferTimeoutBootstrapBlocks  uint32 `json:"infer_timeout_bootstrap_blocks"`
	VerifyTimeoutBootstrapBlocks uint32 `json:"verify_timeout_bootstrap_blocks"`
}

type EvidenceRequirement struct {
	CommitmentSchemaVersion uint32 `json:"commitment_schema_version"`
	EvidenceKind            string `json:"evidence_kind"`
	MaxEncodedSizeBytes     uint64 `json:"max_encoded_size_bytes"`
}

type EvidenceSchema struct {
	RequiredInferEvidence []EvidenceRequirement `json:"required_infer_evidence"`
	SchemaVersion         uint32                `json:"schema_version"`
}

type MetricSpec struct {
	CompareLogprobDiff bool   `json:"compare_logprob_diff"`
	CompareRankDelta   bool   `json:"compare_rank_delta"`
	CompareTopKJaccard bool   `json:"compare_topk_jaccard"`
	CompareUnionJS     bool   `json:"compare_union_js"`
	ComparedTopK       uint32 `json:"compared_top_k"`
	NumericScale       string `json:"numeric_scale"`
}

type VerificationProfile struct {
	CanonicalEncodingVersion      string         `json:"canonical_encoding_version"`
	EvidenceSchema                EvidenceSchema `json:"evidence_schema"`
	EvidenceSchemaHash            string         `json:"evidence_schema_hash"`
	IncludeGeneratedSpecialTokens bool           `json:"include_generated_special_tokens"`
	IncludePaddingTokens          bool           `json:"include_padding_tokens"`
	IncludePromptTokens           bool           `json:"include_prompt_tokens"`
	JudgmentFunctionVersion       string         `json:"judgment_function_version"`
	MetricAggregateProofVersion   string         `json:"metric_aggregate_proof_version"`
	Metrics                       MetricSpec     `json:"metrics"`
	RequireFinishReason           bool           `json:"require_finish_reason"`
	RequireOutputTokenIDs         bool           `json:"require_output_token_ids"`
	TokenScope                    string         `json:"token_scope"`
	VerificationMode              string         `json:"verification_mode"`
	VerificationProfileID         uint32         `json:"verification_profile_id"`
}

type VerificationThresholds struct {
	PassAbsLogprobDiffP95Max      uint32 `json:"pass_abs_logprob_diff_p95_max"`
	PassAbsLogprobDiffP99Max      uint32 `json:"pass_abs_logprob_diff_p99_max"`
	PassMaxMissingComparedCount   uint32 `json:"pass_max_missing_compared_count"`
	PassMeanAbsLogprobDiffMax     uint32 `json:"pass_mean_abs_logprob_diff_max"`
	PassMinFiniteCount            uint32 `json:"pass_min_finite_count"`
	PassRankDeltaNonzeroRateMax   uint32 `json:"pass_rank_delta_nonzero_rate_max"`
	PassTopKJaccardMeanMin        uint32 `json:"pass_topk_jaccard_mean_min"`
	PassUnionJSP99Max             uint32 `json:"pass_union_js_p99_max"`
	RejectAbsLogprobDiffP95Min    uint32 `json:"reject_abs_logprob_diff_p95_min"`
	RejectAbsLogprobDiffP99Min    uint32 `json:"reject_abs_logprob_diff_p99_min"`
	RejectMeanAbsLogprobDiffMin   uint32 `json:"reject_mean_abs_logprob_diff_min"`
	RejectRankDeltaNonzeroRateMin uint32 `json:"reject_rank_delta_nonzero_rate_min"`
	RejectTopKJaccardMeanMax      uint32 `json:"reject_topk_jaccard_mean_max"`
	RejectUnionJSP99Min           uint32 `json:"reject_union_js_p99_min"`
}

// Hash is manifest_hash over exactly the given bytes. It never re-encodes.
func Hash(body []byte) codec.Hash { return codec.HashV1(HashDomain, body) }

// Parse decodes body strictly: one JSON object, valid UTF-8, no unknown
// fields, no trailing data, and every value of the declared type. It then
// checks the schema rules that the field types alone do not express.
// Parse does not check canonical form; see Canonical.
func Parse(body []byte) (*Manifest, error) {
	if len(body) > MaxManifestBytes {
		return nil, fmt.Errorf("manifest is %d bytes, above max_manifest_bytes %d", len(body), MaxManifestBytes)
	}
	if !utf8.Valid(body) {
		return nil, errors.New("manifest is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("parse manifest: trailing data after the manifest object")
	}
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	return &manifest, nil
}

// Canonical is the canonical JSON encoding of the manifest: keys sorted by
// UTF-8 bytes, no insignificant whitespace, integers in plain decimal, and
// strings escaped in their shortest form.
func Canonical(manifest *Manifest) ([]byte, error) {
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	return canonicalJSON(encoded)
}

// Validate checks the schema rules of a V4 manifest that go beyond field
// types. Projection fields are also compared with the chain later, which is
// authoritative for them; the checks here concern manifest-only content.
func (m *Manifest) Validate() error {
	if m.ManifestVersion != ManifestVersion {
		return fmt.Errorf("manifest_version %d is not %d", m.ManifestVersion, ManifestVersion)
	}
	hashes := map[string]string{
		"artifacts.chat_template_hash":              m.Artifacts.ChatTemplateHash,
		"artifacts.file_manifest_hash":              m.Artifacts.FileManifestHash,
		"artifacts.generation_config_hash":          m.Artifacts.GenerationConfigHash,
		"artifacts.model_config_hash":               m.Artifacts.ModelConfigHash,
		"artifacts.model_weight_digest":             m.Artifacts.ModelWeightDigest,
		"artifacts.quant_config_hash":               m.Artifacts.QuantConfigHash,
		"artifacts.tokenizer_config_hash":           m.Artifacts.TokenizerConfigHash,
		"artifacts.tokenizer_hash":                  m.Artifacts.TokenizerHash,
		"identity.model_id":                         m.Identity.ModelID,
		"metadata.display_tag_hash":                 m.Metadata.DisplayTagHash,
		"profile_spec.schema_hash":                  m.ProfileSpec.SchemaHash,
		"verification_profile.evidence_schema_hash": m.VerificationProfile.EvidenceSchemaHash,
	}
	for name, value := range hashes {
		if _, err := parseBytes32(value); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if m.Identity.ProfileVersion == 0 {
		return errors.New("identity.profile_version must be at least 1")
	}
	if err := validateFiles(m.Artifacts.Files, m.OutputDecoding.DecodeVectorsPath); err != nil {
		return err
	}
	if err := m.OutputDecoding.validate(); err != nil {
		return err
	}
	if err := m.ToolCalling.validate(); err != nil {
		return err
	}
	if parser := m.ReasoningParsing.Parser; parser != nil && (parser.Name == "" || parser.Version == 0) {
		return errors.New("reasoning_parsing.parser needs a name and a version of at least 1, or the block must be {}")
	}
	if m.ProfileSpec.RequireEncrypted {
		return errors.New("profile_spec.require_encrypted must be false")
	}
	for name, value := range map[string]string{
		"source.provider": m.Source.Provider, "source.repo_id": m.Source.RepoID, "source.repo_type": m.Source.RepoType,
		"source.resolver_version": m.Source.ResolverVersion, "source.revision": m.Source.Revision, "source.source_uri": m.Source.SourceURI,
		"runtime_requirements.runtime_class": m.RuntimeRequirements.RuntimeClass,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	return nil
}

// artifactRoles is the closed set of artifacts.files[].role values.
var artifactRoles = map[string]bool{
	"MODEL_CONFIG": true, "WEIGHT_SHARD": true, "TOKENIZER": true, "TOKENIZER_CONFIG": true, "GENERATION_CONFIG": true,
	"CHAT_TEMPLATE": true, "QUANT_CONFIG": true, "DECODE_VECTORS": true, "OTHER_REQUIRED": true,
}

func validateFiles(files []ArtifactFile, decodeVectorsPath string) error {
	if len(files) == 0 {
		return errors.New("artifacts.files must not be empty")
	}
	decodeVectors := 0
	for index, file := range files {
		if file.Path == "" {
			return fmt.Errorf("artifacts.files[%d].path is required", index)
		}
		// Sorted by path in UTF-8 byte order, which Go string comparison is;
		// strict ordering also rules out duplicates.
		if index > 0 && files[index-1].Path >= file.Path {
			return errors.New("artifacts.files must be sorted by path with no duplicates")
		}
		if !artifactRoles[file.Role] {
			return fmt.Errorf("artifacts.files[%d].role %q is not a known role", index, file.Role)
		}
		digest, ok := strings.CutPrefix(file.Digest, "sha256:")
		if !ok || !isLowerHex(digest, 64) {
			return fmt.Errorf("artifacts.files[%d].digest must be sha256: followed by 64 lowercase hex characters", index)
		}
		if file.Role == "DECODE_VECTORS" && file.Path == decodeVectorsPath {
			decodeVectors++
		}
	}
	// An empty decode_vectors_path is accepted: nothing reads the file today, so
	// a manifest that ships no DECODE_VECTORS artifact stays valid. A path that
	// is set still has to name exactly one such file.
	if decodeVectorsPath != "" && decodeVectors != 1 {
		return errors.New("output_decoding.decode_vectors_path must name exactly one DECODE_VECTORS file")
	}
	return nil
}

func (d OutputDecoding) validate() error {
	if d.Decoder != "HF_TOKENIZERS_V1" {
		return fmt.Errorf("output_decoding.decoder %q is not supported", d.Decoder)
	}
	if !d.StripTrailingEOS || !d.RenderSpecialTokens || d.CleanUpTokenizationSpaces {
		return errors.New("output_decoding requires strip_trailing_eos and render_special_tokens true, clean_up_tokenization_spaces false")
	}
	if len(d.EOSTokenIDs) == 0 {
		return errors.New("output_decoding.eos_token_ids must not be empty")
	}
	for index := 1; index < len(d.EOSTokenIDs); index++ {
		if d.EOSTokenIDs[index-1] >= d.EOSTokenIDs[index] {
			return errors.New("output_decoding.eos_token_ids must be strictly ascending")
		}
	}
	return nil
}

func (t ToolCalling) validate() error {
	if t.Parser == nil && t.CallIDFormat == "" {
		return nil
	}
	if t.Parser == nil || t.Parser.Name == "" || t.Parser.Version == 0 {
		return errors.New("tool_calling.parser needs a name and a version of at least 1, or the block must be {}")
	}
	if t.CallIDFormat != "OPENAI_CALL_PREFIX" && t.CallIDFormat != "MISTRAL_ALNUM_9" {
		return fmt.Errorf("tool_calling.call_id_format %q is not supported", t.CallIDFormat)
	}
	return nil
}

// parseBytes32 accepts exactly "0x" followed by 64 lowercase hex characters
// and returns the bare lowercase hex.
func parseBytes32(value string) (string, error) {
	digits, ok := strings.CutPrefix(value, "0x")
	if !ok || !isLowerHex(digits, 64) {
		return "", errors.New("must be 0x followed by 64 lowercase hex characters")
	}
	return digits, nil
}

func isLowerHex(value string, length int) bool {
	if len(value) != length || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
