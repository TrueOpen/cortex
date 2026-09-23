package chainclient

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/TrueOpen/cortex/internal/wirevectors"
)

// wireProfileVerificationSnapshot is the snapshot wire's
// profile_verification_snapshot_v1 vector frames, field for field. wire's
// vector names this file's function in its "producer" key, so the two are
// meant to agree exactly.
func wireProfileVerificationSnapshot(t *testing.T) SettlementProfileExecutionSnapshot {
	t.Helper()
	return SettlementProfileExecutionSnapshot{
		ManifestHash:   mustProfileHash(t, "8f14e45fceea167a5a36dedd4bea2543a1b1a9b56b4b8b7f5b6f3f2c1d0e9a87"),
		TokenizerHash:  mustProfileHash(t, "c9f0f895fb98ab9159f51fd0297e236d0f4b3f8b1a2c3d4e5f60718293a4b5c6"),
		RuntimeClass:   "CAUSAL_LM_PREFILL_LOGPROBS_V1",
		RequiredTopK:   20,
		GenerationType: "GENERATION_TYPE_SAMPLED",
		VerificationProfile: CurrentVerificationProfileSnapshot{
			VerificationProfileID:         1,
			JudgmentFunctionVersion:       "PREFILL_GENERATED_TOKEN_METRICS_V1",
			VerificationMode:              "VERIFICATION_MODE_SINGLE_SAMPLE",
			TokenScope:                    "TOKEN_SCOPE_ALL_GENERATED_OUTPUT_TOKENS",
			IncludeGeneratedSpecialTokens: true,
			RequireOutputTokenIDs:         true,
			RequireFinishReason:           true,
			Metrics: CurrentMetricSpecSnapshot{
				CompareLogprobDiff: true, CompareRankDelta: true, CompareTopKJaccard: true,
				CompareUnionJS: true, ComparedTopK: 20, NumericScale: "NUMERIC_SCALE_FP_1E6",
			},
			CanonicalEncodingVersion:    "CANONICAL_OUTPUT_TEXT_V1",
			EvidenceSchemaHash:          mustProfileHash(t, "45c48cce2e2d7fbdea1afc51c7c6ad26a1b2c3d4e5f60718293a4b5c6d7e8f90"),
			MetricAggregateProofVersion: "PREFILL_METRIC_AGGREGATE_PROOF_V1",
			EvidenceSchema: CurrentEvidenceSchemaSnapshot{
				SchemaVersion: 1,
				RequiredInferEvidence: []CurrentInferEvidenceRequirementSnapshot{
					{EvidenceKind: 1, CommitmentSchemaVersion: 1, MaxEncodedSizeBytes: NewUint64String(1073741824)},
					{EvidenceKind: 2, CommitmentSchemaVersion: 1, MaxEncodedSizeBytes: NewUint64String(524288)},
				},
			},
		},
		VerificationThresholds: CurrentVerificationThresholdsSnapshot{
			PassMinFiniteCount: 16, PassMaxMissingComparedCount: 3,
			PassMeanAbsLogprobDiffMax: 50000, PassAbsLogprobDiffP95Max: 100000, PassAbsLogprobDiffP99Max: 200000,
			PassRankDeltaNonzeroRateMax: 40000, PassTopKJaccardMeanMin: 900000, PassUnionJSP99Max: 60000,
			RejectMeanAbsLogprobDiffMin: 300000, RejectAbsLogprobDiffP95Min: 500000, RejectAbsLogprobDiffP99Min: 800000,
			RejectRankDeltaNonzeroRateMin: 310000, RejectTopKJaccardMeanMax: 600000, RejectUnionJSP99Min: 200001,
		},
		BatchVerification: CurrentBatchVerificationSnapshot{
			Enabled: true, MinSampleCount: 8, MinValidSampleCount: 4,
			PassMinSamplePassRatioBPS: 7000, RejectMinSampleRejectRatioBPS: 3000,
		},
		SchemaHash: mustProfileHash(t, "d3d9446802a44259755d38e6d163e820aabbccddeeff00112233445566778899"),
	}
}

func mustProfileHash(t *testing.T, value string) ProtoBytes32 {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 {
		t.Fatalf("hash %q: %v", value, err)
	}
	return ProtoBytes32(raw)
}

// TestProfileVerificationSnapshotHashAgreesWithWireVector drives the production
// derivation with the inputs wire's own vector declares and compares against the
// digest wire publishes.
//
// This is the check that caught the drift it now guards. The digest used to be
// SHA-256 over a canonical-JSON payload wrapped in a TRUEOPEN_FRAME_V1 envelope,
// while the frozen contract is H_FIELDS_V1 over typed fields -- an entirely
// different preimage, which additionally omitted evidence_schema. Since
// settlement material is refused unless this agrees with Keeper's published
// TaskAssignment.profile_verification_snapshot_hash, no real settlement build
// could pass.
func TestProfileVerificationSnapshotHashAgreesWithWireVector(t *testing.T) {
	vector, err := wirevectors.HubDomain(profileVerificationDomain)
	if err != nil {
		t.Fatalf("wire vector: %v", err)
	}
	if vector.Producer == "" {
		t.Fatalf("wire vector for %s names no producer", profileVerificationDomain)
	}
	got, err := wireProfileVerificationSnapshot(t).verificationHash()
	if err != nil {
		t.Fatalf("verificationHash: %v", err)
	}
	if got.Hex() != vector.DigestHex {
		t.Fatalf("%s = %s, wire %s publishes %s (producer %q)",
			profileVerificationDomain, got.Hex(), wirevectors.WireVersion, vector.DigestHex, vector.Producer)
	}
}

// The preimage, not only its digest. A digest comparison says "these differ";
// comparing bytes localises the drift to a field, which is what made the JSON
// framing findable in the first place.
func TestProfileVerificationSnapshotPreimageAgreesWithWireVector(t *testing.T) {
	vector, err := wirevectors.HubDomain(profileVerificationDomain)
	if err != nil {
		t.Fatalf("wire vector: %v", err)
	}
	want, err := hex.DecodeString(vector.PreimageHex)
	if err != nil {
		t.Fatalf("decode wire preimage: %v", err)
	}
	got, err := wireProfileVerificationSnapshot(t).verificationPreimage()
	if err != nil {
		t.Fatalf("verificationPreimage: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("preimage is %d bytes, wire publishes %d\n got: %s\nwant: %s",
			len(got), len(want), hex.EncodeToString(got), vector.PreimageHex)
	}
}

// Each of the three fields the old JSON projection could not express, and the
// one it dropped entirely, must move the digest.
func TestProfileVerificationSnapshotHashBindsTheFieldsTheJSONProjectionMissed(t *testing.T) {
	base, err := wireProfileVerificationSnapshot(t).verificationHash()
	if err != nil {
		t.Fatalf("verificationHash: %v", err)
	}
	for name, mutate := range map[string]func(*SettlementProfileExecutionSnapshot){
		"evidence_schema requirement size": func(s *SettlementProfileExecutionSnapshot) {
			s.VerificationProfile.EvidenceSchema.RequiredInferEvidence[1].MaxEncodedSizeBytes = NewUint64String(524289)
		},
		"evidence_schema requirement count": func(s *SettlementProfileExecutionSnapshot) {
			s.VerificationProfile.EvidenceSchema.RequiredInferEvidence =
				s.VerificationProfile.EvidenceSchema.RequiredInferEvidence[:1]
		},
		"threshold": func(s *SettlementProfileExecutionSnapshot) {
			s.VerificationThresholds.RejectUnionJSP99Min = 200002
		},
		"batch verification": func(s *SettlementProfileExecutionSnapshot) {
			s.BatchVerification.MinSampleCount = 9
		},
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := wireProfileVerificationSnapshot(t)
			mutate(&snapshot)
			changed, err := snapshot.verificationHash()
			if err != nil {
				t.Fatalf("verificationHash: %v", err)
			}
			if bytes.Equal(changed, base) {
				t.Fatalf("%s does not reach the profile verification snapshot digest", name)
			}
		})
	}
}
