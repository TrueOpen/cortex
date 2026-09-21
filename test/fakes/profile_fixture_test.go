package fakes_test

import (
	"context"

	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/keepercontract"
	"github.com/SingaXYZ/cortex/internal/metric"
	"github.com/SingaXYZ/cortex/internal/nodewire"
)

// fakeLockedProfileReader serves the one locked profile this rig runs under.
type fakeLockedProfileReader struct {
	profile chainclient.CurrentModelProfileSnapshot
}

func (r fakeLockedProfileReader) CurrentModelProfile(_ context.Context, _, _ string) (chainclient.CurrentModelProfileSnapshot, error) {
	return r.profile, nil
}

// fakeLockedProfile is a SINGLE_SAMPLE / FP_1E6 profile whose evidence schema
// re-derives to its own evidence_schema_hash, because the verifier checks that
// before it will use the profile at all.
//
// The hashes are non-zero on purpose: keeper §10.0.2 requires it, and
// tokenizer_hash enters every metric leaf preimage, so a 32-zero stand-in would
// be a profile no chain ever registered.
func fakeLockedProfile() chainclient.CurrentModelProfileSnapshot {
	schemaHash := codec.HashWithDomain("FAKE_PROFILE_SCHEMA_HASH_V1", []byte("fake-llm-text"))
	tokenizerHash := codec.HashWithDomain("FAKE_PROFILE_TOKENIZER_HASH_V1", []byte("fake-llm-text"))
	profile := chainclient.CurrentModelProfileSnapshot{
		Profile: chainclient.CurrentProfileSnapshot{
			ModelID:        "fake-llm-text",
			ProfileVersion: chainclient.NewProfileVersion(1),
			SchemaHash:     chainclient.ProtoBytes32(schemaHash[:]),
			TokenizerHash:  chainclient.ProtoBytes32(tokenizerHash[:]),
			GenerationType: "GENERATION_TYPE_DETERMINISTIC",
			RequiredTopK:   4,
			VerificationProfile: chainclient.CurrentVerificationProfileSnapshot{
				VerificationProfileID:       1,
				JudgmentFunctionVersion:     "PREFILL_GENERATED_TOKEN_METRICS_V1",
				VerificationMode:            "VERIFICATION_MODE_SINGLE_SAMPLE",
				TokenScope:                  "TOKEN_SCOPE_ALL_GENERATED_OUTPUT_TOKENS",
				CanonicalEncodingVersion:    "CANONICAL_ENCODING_V1",
				MetricAggregateProofVersion: metric.AggregateProofVersionV1,
				Metrics: chainclient.CurrentMetricSpecSnapshot{
					CompareLogprobDiff: true, CompareRankDelta: true,
					CompareTopKJaccard: true, CompareUnionJS: true,
					ComparedTopK: 4, NumericScale: "NUMERIC_SCALE_FP_1E6",
				},
				EvidenceSchema: chainclient.CurrentEvidenceSchemaSnapshot{
					SchemaVersion: 1,
					RequiredInferEvidence: []chainclient.CurrentInferEvidenceRequirementSnapshot{{
						EvidenceKind:            int32(nodewire.EvidenceKindWorkerValueOpening),
						CommitmentSchemaVersion: 2,
						MaxEncodedSizeBytes:     chainclient.NewUint64String(1 << 20),
					}},
				},
			},
		},
	}
	hash, err := keepercontract.ComputeEvidenceSchemaHashFromCurrentModelProfile(profile)
	if err != nil {
		panic(err)
	}
	profile.Profile.VerificationProfile.EvidenceSchemaHash = chainclient.ProtoBytes32(hash[:])
	return profile
}
