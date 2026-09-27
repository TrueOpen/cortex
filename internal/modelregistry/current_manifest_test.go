package modelregistry

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/keepercontract"
	"github.com/TrueOpen/cortex/internal/txclient"
)

func TestCurrentManifestExampleProjectionIsValid(t *testing.T) {
	data, err := os.ReadFile("../../configs/model-profile.current.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var profile txclient.ModelProfileProjectionMessage
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatalf("decode example projection: %v", err)
	}
	evidenceHash, err := keepercontract.EvidenceSchemaHash(profile)
	if err != nil {
		t.Fatal(err)
	}
	if profile.VerificationProfile.EvidenceSchemaHash.Hex() != hex.EncodeToString(evidenceHash[:]) {
		t.Fatalf("example evidence_schema_hash %s does not match the typed schema %s", profile.VerificationProfile.EvidenceSchemaHash.Hex(), evidenceHash.String())
	}
	if _, err := GenerateCurrentManifest(CurrentManifestInput{
		Version: "1.0.0", Tokenizer: "tokenizer-v1", ModelServiceID: "model-service-main", Profile: profile,
	}); err != nil {
		t.Fatalf("example projection is invalid: %v", err)
	}
}

func TestCurrentManifestLosslesslyEncodesNodeProjection(t *testing.T) {
	input := validCurrentManifestInput()
	manifest, err := GenerateCurrentManifest(input)
	if err != nil {
		t.Fatalf("GenerateCurrentManifest returned error: %v", err)
	}
	if manifest.ManifestSchemaVersion != CurrentManifestSchemaVersion {
		t.Fatalf("schema version = %d", manifest.ManifestSchemaVersion)
	}
	evidenceHash, err := keepercontract.EvidenceSchemaHash(input.Profile)
	if err != nil {
		t.Fatal(err)
	}
	input.Profile.VerificationProfile.EvidenceSchemaHash = txclient.ProtoBytes32(hex.EncodeToString(evidenceHash[:]))
	if !reflect.DeepEqual(manifest.Profile, input.Profile) {
		t.Fatalf("profile changed beyond derived evidence_schema_hash: %#v", manifest.Profile)
	}
	for _, field := range []string{
		`"verification_thresholds"`, `"batch_verification"`, `"pricing_profile"`,
		`"timeout_bootstrap_profile"`, `"registration_fee":{"denom":"utrueopen","amount":"10000000"}`,
	} {
		if !strings.Contains(manifest.Canonical, field) {
			t.Fatalf("canonical manifest missing %s: %s", field, manifest.Canonical)
		}
	}
	if err := ValidateCurrentManifest(manifest); err != nil {
		t.Fatalf("ValidateCurrentManifest returned error: %v", err)
	}
}

func TestCurrentManifestHashIsStableAcrossMetadataOrder(t *testing.T) {
	left := validCurrentManifestInput()
	left.Metadata = map[string]string{"z": "last", "a": "first"}
	right := validCurrentManifestInput()
	right.Metadata = map[string]string{"a": "first", "z": "last"}

	leftManifest, err := GenerateCurrentManifest(left)
	if err != nil {
		t.Fatal(err)
	}
	rightManifest, err := GenerateCurrentManifest(right)
	if err != nil {
		t.Fatal(err)
	}
	if leftManifest.Hash != rightManifest.Hash || leftManifest.Canonical != rightManifest.Canonical {
		t.Fatalf("current manifest is not deterministic: %s / %s", leftManifest.Hash, rightManifest.Hash)
	}
}

func TestCurrentManifestRejectsIncompleteProjectionAndTampering(t *testing.T) {
	input := validCurrentManifestInput()
	input.Profile.VerificationThresholds = txclient.VerificationThresholdsMessage{}
	// Zero thresholds are policy-valid, so use a consensus relationship that
	// cannot be defaulted without changing the signed projection.
	input.Profile.RequiredTopK++
	if _, err := GenerateCurrentManifest(input); err == nil {
		t.Fatal("GenerateCurrentManifest error = nil, want projection rejection")
	}

	manifest, err := GenerateCurrentManifest(validCurrentManifestInput())
	if err != nil {
		t.Fatal(err)
	}
	manifest.Profile.PricingProfile.InitialOutputPrice++
	if err := ValidateCurrentManifest(manifest); err == nil || !strings.Contains(err.Error(), "manifest_hash") {
		t.Fatalf("ValidateCurrentManifest error = %v, want tamper rejection", err)
	}
}

func TestCurrentManifestRejectsLegacySchemaVersion(t *testing.T) {
	manifest, err := GenerateCurrentManifest(validCurrentManifestInput())
	if err != nil {
		t.Fatal(err)
	}
	manifest.ManifestSchemaVersion = 2
	if err := ValidateCurrentManifest(manifest); err == nil || !strings.Contains(err.Error(), "regenerate") {
		t.Fatalf("ValidateCurrentManifest error = %v, want regeneration instruction", err)
	}
}

func TestSelfTestCurrentManifestReportsProjectionValidationOnly(t *testing.T) {
	manifest, err := GenerateCurrentManifest(validCurrentManifestInput())
	if err != nil {
		t.Fatal(err)
	}
	result, err := SelfTestCurrentManifest(manifest)
	if err != nil || !result.Passed || !result.ProjectionValidated || result.ModelID != manifest.Profile.ModelID.Hex() || result.ProfileVersion != 1 {
		t.Fatalf("SelfTestCurrentManifest = %#v, %v", result, err)
	}
	manifest.Profile.RequiredTopK++
	if _, err := SelfTestCurrentManifest(manifest); err == nil {
		t.Fatal("SelfTestCurrentManifest accepted tampered projection")
	}
}

func validCurrentManifestInput() CurrentManifestInput {
	hash := txclient.ProtoBytes32(strings.Repeat("ab", 32))
	return CurrentManifestInput{
		Version: "2026-08-03", Tokenizer: "qwen-tokenizer-v1", ModelServiceID: "modelsvc-local",
		Profile: txclient.ModelProfileProjectionMessage{Source: txclient.SourceRefMessage{Provider: "HUGGINGFACE", RepoID: "org/model", RepoType: "model", ResolverVersion: "HF_RESOLVER_V1", Revision: strings.Repeat("0a", 20), SourceURI: "hf://org/model@" + strings.Repeat("0a", 20)}, ModelID: txclient.ProtoBytes32(strings.Repeat("b0", 32)), ProfileVersion: 1, ManifestHash: hash, TokenizerHash: hash,
			RuntimeClass: "CAUSAL_LM_PREFILL_LOGPROBS_V1", RequiredTopK: 20, TaskTypes: []string{"TASK_TYPE_CHAT"}, GenerationType: "GENERATION_TYPE_SAMPLED",
			ResourceTier: 2, MinStake: txclient.CoinMessage{Denom: "utrueopen", Amount: 1_000_000}, ChallengeOpenWindowBlocks: 1_800,
			VerificationProfile: txclient.VerificationProfileMessage{VerificationProfileID: 1, JudgmentFunctionVersion: "PREFILL_GENERATED_TOKEN_METRICS_V1", VerificationMode: "VERIFICATION_MODE_SINGLE_SAMPLE", TokenScope: "TOKEN_SCOPE_ALL_GENERATED_OUTPUT_TOKENS",
				IncludeGeneratedSpecialTokens: true, RequireOutputTokenIDs: true, RequireFinishReason: true,
				Metrics:                  txclient.MetricSpecMessage{CompareLogprobDiff: true, CompareRankDelta: true, CompareTopKJaccard: true, CompareUnionJS: true, ComparedTopK: 20, NumericScale: "NUMERIC_SCALE_FP_1E6"},
				CanonicalEncodingVersion: "CANONICAL_OUTPUT_TEXT_V1", EvidenceSchemaHash: hash, MetricAggregateProofVersion: "PREFILL_METRIC_AGGREGATE_PROOF_V1", EvidenceSchema: txclient.WorkerEvidenceSchemaV3(1<<30, 64<<20)},
			VerificationThresholds:  txclient.VerificationThresholdsMessage{PassMinFiniteCount: 16, PassMeanAbsLogprobDiffMax: 50_000, RejectMeanAbsLogprobDiffMin: 300_000},
			BatchVerification:       txclient.BatchVerificationMessage{},
			PricingProfile:          txclient.PricingProfileMessage{InitialOutputPrice: 10, VerifyRatioBPS: 1_000, MinOrderValue: 1_000},
			TimeoutBootstrapProfile: txclient.TimeoutBootstrapProfileMessage{InferTimeoutBootstrapBlocks: 100, VerifyTimeoutBootstrapBlocks: 50, CommitTimeoutBootstrapBlocks: 20, BootstrapValidUntilEpoch: 1_000},
			SchemaHash:              hash, RegistrationFee: txclient.CoinMessage{Denom: "utrueopen", Amount: 10_000_000}},
	}
}

func TestCurrentManifestKeepsAValidManifestURIVerbatim(t *testing.T) {
	input := validCurrentManifestInput()
	input.ManifestURI = "https://models.trueopen.example/m/golden.json?rev=3&sig=AbC"
	manifest, err := GenerateCurrentManifest(input)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ManifestURI != input.ManifestURI || !strings.Contains(manifest.Canonical, `"manifest_uri":`) {
		t.Fatalf("manifest_uri not kept: %q in %s", manifest.ManifestURI, manifest.Canonical)
	}
	if err := ValidateCurrentManifest(manifest); err != nil {
		t.Fatal(err)
	}
	// manifest_uri is covered by the document hash.
	manifest.ManifestURI = "https://models.trueopen.example/m/other.json"
	if err := ValidateCurrentManifest(manifest); err == nil || !strings.Contains(err.Error(), "manifest_hash") {
		t.Fatalf("changed manifest_uri was accepted: %v", err)
	}
}

func TestCurrentManifestRejectsAnInvalidManifestURI(t *testing.T) {
	for _, uri := range []string{
		"http://models.trueopen.example/m.json",
		" https://models.trueopen.example/m.json",
		"https://models.trueopen.example/m.json#frag",
		"https://Models.trueopen.example/m.json",
		"ipfs://not-a-cid",
		"https://models.trueopen.example/" + strings.Repeat("a", 2048),
	} {
		input := validCurrentManifestInput()
		input.ManifestURI = uri
		if _, err := GenerateCurrentManifest(input); err == nil || !strings.Contains(err.Error(), "manifest_uri") {
			t.Errorf("%.60q: %v", uri, err)
		}
		manifest, err := GenerateCurrentManifest(validCurrentManifestInput())
		if err != nil {
			t.Fatal(err)
		}
		manifest.ManifestURI = uri
		if err := ValidateCurrentManifest(manifest); err == nil || !strings.Contains(err.Error(), "manifest_uri") {
			t.Errorf("validate %.60q: %v", uri, err)
		}
	}
}
