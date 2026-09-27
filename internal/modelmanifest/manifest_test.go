package modelmanifest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/keepercontract"
	"github.com/TrueOpen/cortex/internal/txclient"
	"github.com/TrueOpen/cortex/internal/wirevectors"
)

// goldenManifest returns the published V4 manifest bytes and their digest.
func goldenManifest(t *testing.T) ([]byte, string) {
	t.Helper()
	raw, err := wirevectors.File("hub/model_manifest_v4.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Domain      string `json:"domain"`
			PayloadUTF8 string `json:"payload_utf8"`
			DigestHex   string `json:"digest_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Vectors) != 1 || fixture.Vectors[0].Domain != HashDomain {
		t.Fatalf("unexpected manifest fixture shape: %+v", fixture.Vectors)
	}
	return []byte(fixture.Vectors[0].PayloadUTF8), fixture.Vectors[0].DigestHex
}

// chainFor builds the chain state a correct registration of manifest leaves.
func chainFor(t *testing.T, manifest *Manifest, manifestHash codec.Hash) chainclient.CurrentModelProfileSnapshot {
	t.Helper()
	decode := func(value string) chainclient.ProtoBytes32 {
		raw, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	taskTypes := make([]string, len(manifest.ProfileSpec.TaskTypes))
	for index, value := range manifest.ProfileSpec.TaskTypes {
		taskTypes[index] = "TASK_TYPE_" + value
	}
	kinds := map[string]int32{"WORKER_VALUE_OPENING": 1, "WORKER_TOKEN_OPENING": 4}
	var requirements []chainclient.CurrentInferEvidenceRequirementSnapshot
	for _, requirement := range manifest.VerificationProfile.EvidenceSchema.RequiredInferEvidence {
		requirements = append(requirements, chainclient.CurrentInferEvidenceRequirementSnapshot{
			EvidenceKind: kinds[requirement.EvidenceKind], CommitmentSchemaVersion: requirement.CommitmentSchemaVersion,
			MaxEncodedSizeBytes: chainclient.NewUint64String(requirement.MaxEncodedSizeBytes),
		})
	}
	v, th := manifest.VerificationProfile, manifest.VerificationThresholds
	modelID := strings.TrimPrefix(manifest.Identity.ModelID, "0x")
	return chainclient.CurrentModelProfileSnapshot{
		Model: chainclient.CurrentModelSnapshot{ModelID: modelID, Provider: manifest.Source.Provider, RepoID: manifest.Source.RepoID},
		Profile: chainclient.CurrentProfileSnapshot{
			ModelID: modelID, ProfileVersion: chainclient.NewProfileVersion(manifest.Identity.ProfileVersion),
			ManifestHash: manifestHash[:], TokenizerHash: decode(manifest.Artifacts.TokenizerHash),
			RuntimeClass: manifest.RuntimeRequirements.RuntimeClass, RequiredTopK: manifest.RuntimeRequirements.RequiredTopK,
			TaskTypes: taskTypes, GenerationType: "GENERATION_TYPE_" + manifest.ProfileSpec.GenerationType,
			ResourceTier: manifest.ProfileSpec.ResourceTier, MinStake: chainclient.NewUint64String(manifest.ProfileSpec.MinStake.Amount),
			ChallengeOpenWindowBlocks: chainclient.NewUint64String(manifest.ProfileSpec.ChallengeOpenWindowBlocks),
			VerificationProfile: chainclient.CurrentVerificationProfileSnapshot{
				VerificationProfileID: v.VerificationProfileID, JudgmentFunctionVersion: v.JudgmentFunctionVersion,
				VerificationMode: "VERIFICATION_MODE_" + v.VerificationMode, TokenScope: "TOKEN_SCOPE_" + v.TokenScope,
				IncludeGeneratedSpecialTokens: v.IncludeGeneratedSpecialTokens, IncludePromptTokens: v.IncludePromptTokens,
				IncludePaddingTokens: v.IncludePaddingTokens, RequireOutputTokenIDs: v.RequireOutputTokenIDs, RequireFinishReason: v.RequireFinishReason,
				Metrics: chainclient.CurrentMetricSpecSnapshot{
					CompareLogprobDiff: v.Metrics.CompareLogprobDiff, CompareRankDelta: v.Metrics.CompareRankDelta,
					CompareTopKJaccard: v.Metrics.CompareTopKJaccard, CompareUnionJS: v.Metrics.CompareUnionJS,
					ComparedTopK: v.Metrics.ComparedTopK, NumericScale: "NUMERIC_SCALE_" + v.Metrics.NumericScale,
				},
				CanonicalEncodingVersion: v.CanonicalEncodingVersion, EvidenceSchemaHash: decode(v.EvidenceSchemaHash),
				MetricAggregateProofVersion: v.MetricAggregateProofVersion,
				EvidenceSchema:              chainclient.CurrentEvidenceSchemaSnapshot{SchemaVersion: v.EvidenceSchema.SchemaVersion, RequiredInferEvidence: requirements},
			},
			VerificationThresholds: chainclient.CurrentVerificationThresholdsSnapshot{
				PassMinFiniteCount: th.PassMinFiniteCount, PassMaxMissingComparedCount: th.PassMaxMissingComparedCount,
				PassMeanAbsLogprobDiffMax: th.PassMeanAbsLogprobDiffMax, PassAbsLogprobDiffP95Max: th.PassAbsLogprobDiffP95Max,
				PassAbsLogprobDiffP99Max: th.PassAbsLogprobDiffP99Max, PassRankDeltaNonzeroRateMax: th.PassRankDeltaNonzeroRateMax,
				PassTopKJaccardMeanMin: th.PassTopKJaccardMeanMin, PassUnionJSP99Max: th.PassUnionJSP99Max,
				RejectMeanAbsLogprobDiffMin: th.RejectMeanAbsLogprobDiffMin, RejectAbsLogprobDiffP95Min: th.RejectAbsLogprobDiffP95Min,
				RejectAbsLogprobDiffP99Min: th.RejectAbsLogprobDiffP99Min, RejectRankDeltaNonzeroRateMin: th.RejectRankDeltaNonzeroRateMin,
				RejectTopKJaccardMeanMax: th.RejectTopKJaccardMeanMax, RejectUnionJSP99Min: th.RejectUnionJSP99Min,
			},
			BatchVerification: chainclient.CurrentBatchVerificationSnapshot{
				Enabled: manifest.BatchVerification.Enabled, MinSampleCount: manifest.BatchVerification.MinSampleCount,
				MinValidSampleCount: manifest.BatchVerification.MinValidSampleCount, PassMinSamplePassRatioBPS: manifest.BatchVerification.PassMinSamplePassRatioBPS,
				RejectMinSampleRejectRatioBPS: manifest.BatchVerification.RejectMinSampleRejectRatioBPS,
			},
			PricingProfile: chainclient.CurrentPricingProfileSnapshot{
				InitialOutputPrice: chainclient.NewUint64String(manifest.PricingProfile.InitialOutputPrice),
				VerifyRatioBPS:     manifest.PricingProfile.VerifyRatioBPS, MinOrderValue: chainclient.NewUint64String(manifest.PricingProfile.MinOrderValue),
			},
			TimeoutBootstrapProfile: chainclient.CurrentTimeoutBootstrapProfileSnapshot{
				InferTimeoutBootstrapBlocks: manifest.TimeoutBootstrapProfile.InferTimeoutBootstrapBlocks, VerifyTimeoutBootstrapBlocks: manifest.TimeoutBootstrapProfile.VerifyTimeoutBootstrapBlocks,
				CommitTimeoutBootstrapBlocks: manifest.TimeoutBootstrapProfile.CommitTimeoutBootstrapBlocks,
				BootstrapValidUntilEpoch:     chainclient.NewUint64String(manifest.TimeoutBootstrapProfile.BootstrapValidUntilEpoch),
			},
			SchemaHash: decode(manifest.ProfileSpec.SchemaHash), PreviousProfileVersion: chainclient.NewProfileVersion(manifest.Identity.PreviousProfileVersion),
			RegistrationFeePaid: chainclient.NewUint64String(1_000_000),
			Source: chainclient.CurrentProfileSourceSnapshot{
				SourceURI: manifest.Source.SourceURI, Revision: manifest.Source.Revision,
				ResolverVersion: manifest.Source.ResolverVersion, RepoType: manifest.Source.RepoType,
			},
			ToolCallParser:  chainParser(manifest.ToolCalling.Parser),
			ReasoningParser: chainParser(manifest.ReasoningParsing.Parser),
		},
	}
}

func chainParser(parser *ParserRef) chainclient.CurrentParserSnapshot {
	if parser == nil {
		return chainclient.CurrentParserSnapshot{}
	}
	return chainclient.CurrentParserSnapshot{Name: parser.Name, Version: parser.Version}
}

// goldenChain parses the golden manifest and returns it with its bytes and a
// chain state that registered exactly it.
func goldenChain(t *testing.T) ([]byte, *Manifest, chainclient.CurrentModelProfileSnapshot) {
	t.Helper()
	body, _ := goldenManifest(t)
	manifest, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	return body, manifest, chainFor(t, manifest, Hash(body))
}

func TestGoldenManifestReproducesTheWireVector(t *testing.T) {
	body, digestHex := goldenManifest(t)
	if got := Hash(body); got.String() != digestHex {
		t.Fatalf("manifest_hash = %s, wire publishes %s", got, digestHex)
	}
	manifest, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := Canonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, body) {
		t.Fatalf("canonical re-encoding differs from the published bytes:\n%s\n%s", canonical, body)
	}
}

// The projection vector shares the golden manifest's values, with an opaque
// manifest_hash and a registration fee that is not inside the manifest.
// Rebuilding it from the manifest must reproduce chain_projection_hash.
func TestManifestProjectionReproducesTheProjectionVector(t *testing.T) {
	body, _ := goldenManifest(t)
	manifest, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := wirevectors.File("hub/model_profile_canonical_v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		ChainProjectionHash string `json:"chain_projection_hash"`
		Projection          struct {
			ManifestHash    string `json:"manifest_hash"`
			RegistrationFee Coin   `json:"registration_fee"`
		} `json:"canonical_projection"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	opaque, err := hex.DecodeString(strings.TrimPrefix(fixture.Projection.ManifestHash, "0x"))
	if err != nil || len(opaque) != 32 {
		t.Fatalf("projection vector manifest_hash %q", fixture.Projection.ManifestHash)
	}
	profile := manifest.Projection(codec.Hash(opaque))
	profile.RegistrationFee = txclient.CoinMessage{Denom: fixture.Projection.RegistrationFee.Denom, Amount: txclient.ProtoUint64(fixture.Projection.RegistrationFee.Amount)}
	projection, err := keepercontract.CanonicalModelProfileProjection(profile)
	if err != nil {
		t.Fatal(err)
	}
	if got := codec.HashV1("TRUEOPEN_MODEL_CHAIN_PROJECTION_V3", projection); got.String() != fixture.ChainProjectionHash {
		t.Fatalf("chain_projection_hash = %s, wire publishes %s", got, fixture.ChainProjectionHash)
	}
}

func TestVerifyAcceptsTheRegisteredManifest(t *testing.T) {
	body, _, chain := goldenChain(t)
	manifest, err := Verify(body, chain)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Identity.DisplayName != "Golden Model" {
		t.Fatalf("parsed manifest: %+v", manifest.Identity)
	}
}

func TestVerifyRejectsBytesTheChainDidNotCommitTo(t *testing.T) {
	body, _, chain := goldenChain(t)
	tampered := bytes.Replace(body, []byte(`"Golden Model"`), []byte(`"Golden Modem"`), 1)
	if _, err := Verify(tampered, chain); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("tampered bytes: %v", err)
	}
	if _, err := Verify(body[:len(body)-1], chain); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("truncated bytes: %v", err)
	}
}

// Each case is committed to by the chain (its hash matches), so only the
// parse, schema or canonical checks can refuse it.
func TestVerifyRejectsCommittedButInvalidBytes(t *testing.T) {
	body, _, chain := goldenChain(t)
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, body, "", "  "); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"pretty printed":        pretty.Bytes(),
		"trailing newline":      append(append([]byte(nil), body...), '\n'),
		"unknown field":         bytes.Replace(body, []byte(`{"artifacts"`), []byte(`{"extra":1,"artifacts"`), 1),
		"missing field":         bytes.Replace(body, []byte(`"display_name":"Golden Model",`), nil, 1),
		"null field":            bytes.Replace(body, []byte(`"license_ref":"apache-2.0"`), []byte(`"license_ref":null`), 1),
		"duplicate key":         bytes.Replace(body, []byte(`"license_ref":"apache-2.0"`), []byte(`"license_ref":"apache-2.0","license_ref":"apache-2.0"`), 1),
		"float integer":         bytes.Replace(body, []byte(`"resource_tier":2`), []byte(`"resource_tier":2.0`), 1),
		"exponent integer":      bytes.Replace(body, []byte(`"resource_tier":2`), []byte(`"resource_tier":2e0`), 1),
		"escaped character":     bytes.Replace(body, []byte(`"Golden Model"`), []byte(`"Golden \u004dodel"`), 1),
		"wrong type":            bytes.Replace(body, []byte(`"resource_tier":2`), []byte(`"resource_tier":"2"`), 1),
		"uppercase hex":         bytes.Replace(body, []byte(`"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"`), []byte(`"0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"`), 1),
		"trailing object":       append(append([]byte(nil), body...), []byte(`{}`)...),
		"invalid UTF-8":         bytes.Replace(body, []byte(`Golden Model`), []byte("Golden \xffodel"), 1),
		"manifest_version 3":    bytes.Replace(body, []byte(`"manifest_version":4`), []byte(`"manifest_version":3`), 1),
		"require_encrypted":     bytes.Replace(body, []byte(`"require_encrypted":false`), []byte(`"require_encrypted":true`), 1),
		"unsorted files":        bytes.Replace(body, []byte(`"path":"config.json"`), []byte(`"path":"zconfig.json"`), 1),
		"unknown role":          bytes.Replace(body, []byte(`"role":"MODEL_CONFIG"`), []byte(`"role":"WEIGHTS"`), 1),
		"tool parser version 0": bytes.Replace(body, []byte(`"tool_calling":{}`), []byte(`"tool_calling":{"call_id_format":"OPENAI_CALL_PREFIX","parser":{"name":"hermes","version":0}}`), 1),
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(candidate, body) {
				t.Fatal("mutation did not apply")
			}
			committed := chain
			committed.Profile.ManifestHash = hashBytes(candidate)
			if _, err := Verify(candidate, committed); !errors.Is(err, ErrInvalid) {
				t.Fatalf("expected ErrInvalid, got %v", err)
			}
		})
	}
}

func TestVerifyRejectsAManifestThatDisagreesWithTheChain(t *testing.T) {
	body, _, chain := goldenChain(t)
	cases := map[string]func(*chainclient.CurrentModelProfileSnapshot){
		"required_top_k":  func(c *chainclient.CurrentModelProfileSnapshot) { c.Profile.RequiredTopK = 8 },
		"source.repo_id":  func(c *chainclient.CurrentModelProfileSnapshot) { c.Model.RepoID = "other/model" },
		"source.revision": func(c *chainclient.CurrentModelProfileSnapshot) { c.Profile.Source.Revision = strings.Repeat("f", 40) },
		"tool_call_parser.name": func(c *chainclient.CurrentModelProfileSnapshot) {
			c.Profile.ToolCallParser = chainclient.CurrentParserSnapshot{Name: "hermes", Version: 1}
		},
		"min_stake.amount": func(c *chainclient.CurrentModelProfileSnapshot) { c.Profile.MinStake = chainclient.NewUint64String(1) },
		"pricing_profile.min_order_value": func(c *chainclient.CurrentModelProfileSnapshot) {
			c.Profile.PricingProfile.MinOrderValue = chainclient.NewUint64String(1)
		},
		"verification_thresholds.pass_min_finite_count": func(c *chainclient.CurrentModelProfileSnapshot) {
			c.Profile.VerificationThresholds.PassMinFiniteCount++
		},
	}
	for field, mutate := range cases {
		t.Run(field, func(t *testing.T) {
			changed := chain
			mutate(&changed)
			// A consistent chain re-derives evidence_schema_hash from the
			// fields it covers.
			hash, err := keepercontract.ComputeEvidenceSchemaHashFromCurrentModelProfile(changed)
			if err != nil {
				t.Fatal(err)
			}
			changed.Profile.VerificationProfile.EvidenceSchemaHash = hash[:]
			_, err = Verify(body, changed)
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), field) {
				t.Fatalf("expected a disagreement on %s, got %v", field, err)
			}
		})
	}
}

func TestCanonicalEscapesOnlyWhatJSONRequires(t *testing.T) {
	got, err := canonicalJSON([]byte(`{"b":"<&>\u2028é\"\\\n\u0001","a":[1,0,-2]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"a\":[1,0,-2],\"b\":\"<&> é\\\"\\\\\\n\\u0001\"}"
	if string(got) != want {
		t.Fatalf("canonical = %s, want %s", got, want)
	}
	for _, number := range []string{`1.0`, `1e3`, `-0`, `01`} {
		if _, err := canonicalJSON([]byte(number)); err == nil {
			t.Errorf("%s was accepted as a canonical integer", number)
		}
	}
}

func hashBytes(body []byte) chainclient.ProtoBytes32 {
	digest := Hash(body)
	return digest[:]
}
