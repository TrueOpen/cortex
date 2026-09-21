package keepercontract

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/txclient"
)

// The V2 projection formula is checked against the released model fixture.
func TestModelRegistrationDigestBindsCoinDenomination(t *testing.T) {
	profile := nodeGoldenModelProfileProjection()
	digest, projection, err := ModelRegistrationDigest(
		"trueopen-testnet-1",
		"trueopen1registrant000000000000000000000000000",
		profile,
	)
	if err != nil {
		t.Fatalf("ModelRegistrationDigest returned error: %v", err)
	}
	if digest.IsZero() || len(projection) == 0 {
		t.Fatal("registration digest or projection missing")
	}

	profile.MinStake.Denom = "usnga"
	profile.RegistrationFee.Denom = "usnga"
	changedDenomDigest, _, err := ModelRegistrationDigest("trueopen-testnet-1", "trueopen1registrant000000000000000000000000000", profile)
	if err != nil {
		t.Fatalf("changed-denom digest returned error: %v", err)
	}
	if changedDenomDigest == digest {
		t.Fatal("registration digest did not bind the coin denom")
	}
}

func TestModelRegistrationDigestBindsEveryProjectionSection(t *testing.T) {
	base := nodeGoldenModelProfileProjection()
	want, _, err := ModelRegistrationDigest("chain-a", "trueopen1proposer", base)
	if err != nil {
		t.Fatalf("ModelRegistrationDigest returned error: %v", err)
	}
	mutations := map[string]func(*txclient.ModelProfileProjectionMessage){
		"profile": func(profile *txclient.ModelProfileProjectionMessage) { profile.ProfileVersion = 2 },
		"runtime": func(profile *txclient.ModelProfileProjectionMessage) { profile.RuntimeClass += "-changed" },
		"verification": func(profile *txclient.ModelProfileProjectionMessage) {
			profile.VerificationThresholds.PassMinFiniteCount++
		},
		"pricing": func(profile *txclient.ModelProfileProjectionMessage) { profile.PricingProfile.MinOrderValue++ },
		"timeout": func(profile *txclient.ModelProfileProjectionMessage) {
			profile.TimeoutBootstrapProfile.InferTimeoutBootstrapBlocks++
		},
		"evidence schema": func(profile *txclient.ModelProfileProjectionMessage) {
			profile.VerificationProfile.EvidenceSchema.RequiredInferEvidence[0].MaxEncodedSizeBytes++
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := base
			changed.TaskTypes = append([]string(nil), base.TaskTypes...)
			changed.VerificationProfile.EvidenceSchema.RequiredInferEvidence = append(
				[]txclient.InferEvidenceRequirementMessage(nil),
				base.VerificationProfile.EvidenceSchema.RequiredInferEvidence...,
			)
			mutate(&changed)
			evidenceHash, err := EvidenceSchemaHash(changed)
			if err != nil {
				t.Fatalf("EvidenceSchemaHash returned error: %v", err)
			}
			changed.VerificationProfile.EvidenceSchemaHash = txclient.ProtoBytes32(hex.EncodeToString(evidenceHash[:]))
			got, _, err := ModelRegistrationDigest("chain-a", "trueopen1proposer", changed)
			if err != nil {
				t.Fatalf("ModelRegistrationDigest returned error: %v", err)
			}
			if got == want {
				t.Fatal("digest did not change")
			}
		})
	}
}

func nodeGoldenModelProfileProjection() txclient.ModelProfileProjectionMessage {
	return txclient.ModelProfileProjectionMessage{ModelID: "hf-qwen3-8b-test", ProfileVersion: 1,
		ManifestHash:  txclient.ProtoBytes32("9b0148865efde2dbf366305733ee5275dc247e3b9af8def770955d3758b52031"),
		TokenizerHash: txclient.ProtoBytes32(strings.Repeat("44", 32)), RuntimeClass: "CAUSAL_LM_PREFILL_LOGPROBS_V1",
		RequiredTopK: 20, TaskTypes: []string{"TASK_TYPE_TEXT_GENERATION", "TASK_TYPE_CHAT"}, GenerationType: "GENERATION_TYPE_SAMPLED", ResourceTier: 2,
		MinStake: txclient.CoinMessage{Denom: "uusdc", Amount: 1_000_000}, ChallengeOpenWindowBlocks: 100,
		VerificationProfile: txclient.VerificationProfileMessage{VerificationProfileID: 1, JudgmentFunctionVersion: "PREFILL_GENERATED_TOKEN_METRICS_V1", VerificationMode: "VERIFICATION_MODE_SINGLE_SAMPLE", TokenScope: "TOKEN_SCOPE_ALL_GENERATED_OUTPUT_TOKENS",
			IncludeGeneratedSpecialTokens: true, RequireOutputTokenIDs: true, RequireFinishReason: true,
			Metrics:                  txclient.MetricSpecMessage{CompareLogprobDiff: true, CompareRankDelta: true, CompareTopKJaccard: true, CompareUnionJS: true, ComparedTopK: 20, NumericScale: "NUMERIC_SCALE_FP_1E6"},
			CanonicalEncodingVersion: "CANONICAL_OUTPUT_TEXT_V1", EvidenceSchemaHash: txclient.ProtoBytes32(wireGoldenEvidenceSchemaHash), MetricAggregateProofVersion: "PREFILL_METRIC_AGGREGATE_PROOF_V1", EvidenceSchema: txclient.WorkerValueEvidenceSchemaV2(1 << 30)},
		VerificationThresholds: txclient.VerificationThresholdsMessage{
			PassMinFiniteCount: 16, PassMeanAbsLogprobDiffMax: 50_000, PassAbsLogprobDiffP95Max: 100_000, PassAbsLogprobDiffP99Max: 200_000,
			PassRankDeltaNonzeroRateMax: 50_000, PassTopKJaccardMeanMin: 900_000, PassUnionJSP99Max: 50_000,
			RejectMeanAbsLogprobDiffMin: 300_000, RejectAbsLogprobDiffP95Min: 500_000, RejectAbsLogprobDiffP99Min: 800_000,
			RejectRankDeltaNonzeroRateMin: 300_000, RejectTopKJaccardMeanMax: 600_000, RejectUnionJSP99Min: 200_000,
		},
		PricingProfile:          txclient.PricingProfileMessage{InitialOutputPrice: 10, VerifyRatioBPS: 1_000, MinOrderValue: 1_000},
		TimeoutBootstrapProfile: txclient.TimeoutBootstrapProfileMessage{InferTimeoutBootstrapBlocks: 100, VerifyTimeoutBootstrapBlocks: 50, CommitTimeoutBootstrapBlocks: 20, BootstrapValidUntilEpoch: 1_000},
		SchemaHash:              txclient.ProtoBytes32(strings.Repeat("99", 32)), RegistrationFee: txclient.CoinMessage{Denom: "uusdc", Amount: 1_000_000}}
}
