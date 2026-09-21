package verifier

// The metric material: where it is produced, where it is consumed, and why
// those are two different turns of the process.
//
// metric_root, metric_summary and aggregate_proof_hash are derived from the
// prefill/teacher-forcing run, which happens in HandleOpenVerifyAccepted. They
// are CONSUMED in HandleRevealPhaseStarted, which the chain opens later - after
// the commits are counted - and which a restarted process must still be able to
// serve. So the material is persisted beside the compact reveal it belongs to,
// in the same evidence record and under the same task/round identity check: the
// two are one run's output, and a reveal assembled from one run's metrics and
// another run's values would be a credential nothing can reproduce.

import (
	"encoding/hex"
	"fmt"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/metric"
	"github.com/SingaXYZ/cortex/internal/modelservice"
	"github.com/SingaXYZ/cortex/internal/nodewire"
)

// persistedMetricMaterial is the JSON projection of metric.Material written to
// the verifier's reveal-state evidence record.
//
// It is a projection and not the wire: nothing here is hashed, and the hashes
// that matter are re-derived from these values by nodewire when the credential
// is assembled. The optional summary members carry explicit presence flags
// because absent and present-zero are different facts on the wire, and a JSON
// encoding that dropped a zero would silently turn one into the other.
type persistedMetricMaterial struct {
	MetricRoot         string                 `json:"metric_root"`
	MetricLeafCount    int                    `json:"metric_leaf_count"`
	MetricSummary      persistedMetricSummary `json:"metric_summary"`
	AggregateProof     string                 `json:"aggregate_proof"`
	AggregateProofHash string                 `json:"aggregate_proof_hash"`
}

type persistedMetricSummary struct {
	FiniteCount               uint32                  `json:"finite_count"`
	MissingComparedCount      uint32                  `json:"missing_compared_count"`
	MeanAbsLogprobDiffFP1e6   uint32                  `json:"mean_abs_logprob_diff_fp_1e6"`
	AbsLogprobDiffP95FP1e6    uint32                  `json:"abs_logprob_diff_p95_fp_1e6"`
	AbsLogprobDiffP99FP1e6    uint32                  `json:"abs_logprob_diff_p99_fp_1e6"`
	RankDeltaNonzeroRateFP1e6 uint32                  `json:"rank_delta_nonzero_rate_fp_1e6"`
	TopkJaccardMeanFP1e6      persistedOptionalUint32 `json:"topk_jaccard_mean_fp_1e6"`
	UnionJSP99FP1e6           persistedOptionalUint32 `json:"union_js_p99_fp_1e6"`
	ComparedTopkCount         uint32                  `json:"compared_topk_count"`
	ComparedRankCount         uint32                  `json:"compared_rank_count"`
}

type persistedOptionalUint32 struct {
	Present bool   `json:"present"`
	Value   uint32 `json:"value"`
}

// buildMetricMaterial derives the run's metric material from the model
// service's answer.
//
// When the profile is not bound - the fake/dev configuration with no profile
// reader - it returns nothing and no error: there is no locked MetricSpec to
// decide the optional summary members, and inventing one would produce a
// summary the Keeper judges against thresholds it was never measured for. The
// result credential then refuses on its own gate, which is the correct outcome
// for a node that cannot read its own profile.
//
// When the profile IS bound, a model service that returned no samples is an
// error and not a silent skip: it is a real verifier that cannot serve its own
// reveal, and it must say so at the point the material was owed.
func buildMetricMaterial(binding metric.Binding, bound bool, resp modelservice.VerifyResponse) (metric.Material, error) {
	if !bound {
		return metric.Material{}, nil
	}
	if len(resp.MetricSamples) == 0 {
		return metric.Material{}, fmt.Errorf(
			"%w: model service %q returned no per-token metric samples, so metric_root and MetricSummaryV1 "+
				"cannot be derived for this run",
			ErrResultReceiptInputUnavailable, resp.ModelServiceID)
	}
	material, err := metric.Build(binding, resp.MetricSamples)
	if err != nil {
		return metric.Material{}, fmt.Errorf("derive metric material: %w", err)
	}
	return material, nil
}

// hasMetricMaterial reports whether a verify run produced metric material at
// all. A run without it is the fake/dev configuration, which has no locked
// profile to bind to; the result credential then refuses by its own gate rather
// than signing zeros.
func hasMetricMaterial(material metric.Material) bool {
	return !material.Root.IsZero()
}

func projectMetricMaterial(material metric.Material) persistedMetricMaterial {
	return persistedMetricMaterial{
		MetricRoot:      hex.EncodeToString(material.Root[:]),
		MetricLeafCount: material.LeafCount,
		MetricSummary: persistedMetricSummary{
			FiniteCount:               material.Summary.FiniteCount,
			MissingComparedCount:      material.Summary.MissingComparedCount,
			MeanAbsLogprobDiffFP1e6:   material.Summary.MeanAbsLogprobDiffFP1e6,
			AbsLogprobDiffP95FP1e6:    material.Summary.AbsLogprobDiffP95FP1e6,
			AbsLogprobDiffP99FP1e6:    material.Summary.AbsLogprobDiffP99FP1e6,
			RankDeltaNonzeroRateFP1e6: material.Summary.RankDeltaNonzeroRateFP1e6,
			TopkJaccardMeanFP1e6: persistedOptionalUint32{
				Present: material.Summary.TopkJaccardMeanFP1e6.Present,
				Value:   material.Summary.TopkJaccardMeanFP1e6.Value,
			},
			UnionJSP99FP1e6: persistedOptionalUint32{
				Present: material.Summary.UnionJSP99FP1e6.Present,
				Value:   material.Summary.UnionJSP99FP1e6.Value,
			},
			ComparedTopkCount: material.Summary.ComparedTopkCount,
			ComparedRankCount: material.Summary.ComparedRankCount,
		},
		AggregateProof:     hex.EncodeToString(material.AggregateProof.Bytes),
		AggregateProofHash: material.AggregateProof.Hash.String(),
	}
}

// restore rebuilds the material from its persisted projection, re-deriving
// aggregate_proof_hash from the stored proof bytes rather than trusting the
// stored hash.
//
// That re-derivation is the point of the method. The hash is written for an
// operator to read; the credential must be signed over SHA256 of the bytes that
// actually exist, so a record whose two halves disagree is refused here instead
// of producing a receipt whose aggregate_proof_hash no full reveal can match.
func (p persistedMetricMaterial) restore() (metric.Material, error) {
	root, err := hash32FromHex("metric_root", p.MetricRoot)
	if err != nil {
		return metric.Material{}, err
	}
	proof, err := hex.DecodeString(p.AggregateProof)
	if err != nil {
		return metric.Material{}, fmt.Errorf("persisted aggregate_proof is not hex: %w", err)
	}
	if len(proof) == 0 {
		return metric.Material{}, fmt.Errorf("persisted aggregate_proof is empty")
	}
	if p.MetricLeafCount <= 0 {
		return metric.Material{}, fmt.Errorf("persisted metric_leaf_count is %d", p.MetricLeafCount)
	}
	derived := codec.HashBytes(proof)
	if p.AggregateProofHash != "" && p.AggregateProofHash != derived.String() {
		return metric.Material{}, fmt.Errorf(
			"persisted aggregate_proof_hash %s does not match SHA256 of the persisted proof bytes %s",
			p.AggregateProofHash, derived)
	}
	return metric.Material{
		Root:      root,
		LeafCount: p.MetricLeafCount,
		Summary: nodewire.MetricSummaryV1{
			FiniteCount:               p.MetricSummary.FiniteCount,
			MissingComparedCount:      p.MetricSummary.MissingComparedCount,
			MeanAbsLogprobDiffFP1e6:   p.MetricSummary.MeanAbsLogprobDiffFP1e6,
			AbsLogprobDiffP95FP1e6:    p.MetricSummary.AbsLogprobDiffP95FP1e6,
			AbsLogprobDiffP99FP1e6:    p.MetricSummary.AbsLogprobDiffP99FP1e6,
			RankDeltaNonzeroRateFP1e6: p.MetricSummary.RankDeltaNonzeroRateFP1e6,
			TopkJaccardMeanFP1e6: nodewire.OptionalUint32{
				Value: p.MetricSummary.TopkJaccardMeanFP1e6.Value, Present: p.MetricSummary.TopkJaccardMeanFP1e6.Present,
			},
			UnionJSP99FP1e6: nodewire.OptionalUint32{
				Value: p.MetricSummary.UnionJSP99FP1e6.Value, Present: p.MetricSummary.UnionJSP99FP1e6.Present,
			},
			ComparedTopkCount: p.MetricSummary.ComparedTopkCount,
			ComparedRankCount: p.MetricSummary.ComparedRankCount,
		},
		AggregateProof: metric.AggregateProof{Bytes: proof, Hash: derived},
	}, nil
}

func hash32FromHex(name, value string) (codec.Hash, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(codec.Hash{}) || hex.EncodeToString(decoded) != value {
		return codec.Hash{}, fmt.Errorf("persisted %s must be canonical 32-byte hex, got %q", name, value)
	}
	var out codec.Hash
	copy(out[:], decoded)
	return out, nil
}
