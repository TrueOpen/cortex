package integration_test

import (
	"context"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/keepercontract"
	"github.com/TrueOpen/cortex/internal/metric"
	"github.com/TrueOpen/cortex/internal/nodewire"
	cortexv1 "github.com/TrueOpen/cortex/proto/cortex/v1"
)

// integrationLockedProfileReader serves the locked profile this rig's task was
// assigned under.
type integrationLockedProfileReader struct {
	profile chainclient.CurrentModelProfileSnapshot
}

func (r integrationLockedProfileReader) CurrentModelProfile(_ context.Context, _, _ string) (chainclient.CurrentModelProfileSnapshot, error) {
	return r.profile, nil
}

// integrationLockedProfile is a SINGLE_SAMPLE / FP_1E6 profile whose evidence
// schema re-derives to its own evidence_schema_hash, which the verifier checks
// before it will read anything else off the profile.
func integrationLockedProfile(modelID string) chainclient.CurrentModelProfileSnapshot {
	schemaHash := codec.HashWithDomain("INTEGRATION_PROFILE_SCHEMA_HASH_V1", []byte(modelID))
	tokenizerHash := codec.HashWithDomain("INTEGRATION_PROFILE_TOKENIZER_HASH_V1", []byte(modelID))
	profile := chainclient.CurrentModelProfileSnapshot{
		Profile: chainclient.CurrentProfileSnapshot{
			ModelID:        modelID,
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

// integrationMetricSamples is the per-token comparison the rig's model service
// reports. Two positions with distinct values, so a transport that dropped or
// duplicated one changes metric_root rather than passing quietly.
func integrationMetricSamples() []*cortexv1.MetricSampleV1 {
	present := func(value float64) *cortexv1.MetricOptionalFP {
		return &cortexv1.MetricOptionalFP{Present: true, Value: value}
	}
	return []*cortexv1.MetricSampleV1{
		{
			OutputPosition: 0, EmittedTokenId: 1000,
			WorkerLogprob: -0.125, VerifierLogprob: -0.130,
			WorkerRank: 1, VerifierRank: 1,
			TopkJaccard: present(0.875), UnionJs: present(0.002),
			FiniteFlag: true,
		},
		{
			OutputPosition: 1, EmittedTokenId: 1001,
			WorkerLogprob: -0.250, VerifierLogprob: -0.252,
			WorkerRank: 1, VerifierRank: 2,
			TopkJaccard: present(0.750), UnionJs: present(0.004),
			FiniteFlag: true,
		},
	}
}
