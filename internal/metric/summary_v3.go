package metric

import (
	"fmt"
	"math"
	"math/big"
	"slices"

	"github.com/TrueOpen/cortex/internal/nodewire"
)

// SummaryV3 derives MetricSummaryV1 from the metric leaves exactly as
// 05-verification-algorithm defines each field: integer arithmetic on the
// leaves' fixed-point values only, so anyone holding the leaves under
// metric_root recomputes the same summary.
//
// F is the normal leaves (finite, not missing); every other leaf, missing or
// non-finite, counts in missing_compared_count. With no leaves every number is
// 0 and each enabled ratio present(0); with leaves but an empty F (every
// Worker value missing or non-finite) every comparison takes its worst value.
// With F non-empty:
//
//	mean_abs_logprob_diff   = round_half_up(sum_F abs_diff / |F|)
//	abs_logprob_diff_p95/99 = nearest_rank(0.95 / 0.99, F's abs_diff)
//	rank_delta_nonzero_rate = round_half_up(1e6 * #{F: rank_delta != 0} / |F|), compared_rank_count = |F|
//	                          (both 0 when compare_rank_delta is off)
//	topk_jaccard_mean       = present(round_half_up(sum_F jaccard / |F|)) when compare_topk_jaccard is on
//	union_js_p99            = present(nearest_rank(0.99, F's union_js)) when compare_union_js is on
//	compared_topk_count     = |F| when either ratio is compared, else 0
//
// rank_delta is the leaf's effective-rank value, so a token outside the
// required top-k on one side counts. The three abs_diff fields saturate at the
// uint32 maximum: vLLM clamps logprobs at -9999.0, so a legitimate difference
// can exceed the fp_1e6 range, and refusing would block the commit.
func SummaryV3(spec Spec, requiredTopK uint32, samples []SampleV3) (nodewire.MetricSummaryV1, error) {
	var (
		absDiffs []uint64
		jaccard  []uint64
		unionJS  []uint64
		rankDiff uint64
	)
	missing := 0
	for _, s := range samples {
		if s.Missing || !s.Finite {
			missing++
			continue
		}
		diff, err := s.absLogprobDiffFP1e6()
		if err != nil {
			return nodewire.MetricSummaryV1{}, err
		}
		absDiffs = append(absDiffs, diff)
		if s.rankDelta(requiredTopK) != 0 {
			rankDiff++
		}
		if spec.CompareTopKJaccard {
			if !s.TopKJaccardFP1e6.Present {
				return nodewire.MetricSummaryV1{}, fmt.Errorf("output_position %d: compare_topk_jaccard is on but the leaf has no ratio", s.OutputPosition)
			}
			jaccard = append(jaccard, uint64(s.TopKJaccardFP1e6.Value))
		}
		if spec.CompareUnionJS {
			if !s.UnionJSFP1e6.Present {
				return nodewire.MetricSummaryV1{}, fmt.Errorf("output_position %d: compare_union_js is on but the leaf has no ratio", s.OutputPosition)
			}
			unionJS = append(unionJS, uint64(s.UnionJSFP1e6.Value))
		}
	}
	finite := len(absDiffs)
	finiteCount, err := countUint32("finite_count", finite)
	if err != nil {
		return nodewire.MetricSummaryV1{}, err
	}
	missingCount, err := countUint32("missing_compared_count", missing)
	if err != nil {
		return nodewire.MetricSummaryV1{}, err
	}
	summary := nodewire.MetricSummaryV1{FiniteCount: finiteCount, MissingComparedCount: missingCount}
	if len(samples) == 0 {
		// Case 1, no leaves: a legal zero-token output with nothing to compare.
		// Every number is 0 and each enabled ratio is present(0).
		if spec.CompareTopKJaccard {
			summary.TopkJaccardMeanFP1e6 = nodewire.PresentUint32(0)
		}
		if spec.CompareUnionJS {
			summary.UnionJSP99FP1e6 = nodewire.PresentUint32(0)
		}
		return summary, nil
	}
	if finite == 0 {
		// Case 2, no Worker value to compare: nothing comparable must not read
		// as agreement, so every comparison takes its worst value. (Case 3, an
		// empty F caused by the Verifier's own values, is refused before this
		// by CompareLeavesV3.)
		summary.MeanAbsLogprobDiffFP1e6, summary.AbsLogprobDiffP95FP1e6, summary.AbsLogprobDiffP99FP1e6 = math.MaxUint32, math.MaxUint32, math.MaxUint32
		if spec.CompareRankDelta {
			summary.RankDeltaNonzeroRateFP1e6 = FixedPointScale
		}
		if spec.CompareTopKJaccard {
			summary.TopkJaccardMeanFP1e6 = nodewire.PresentUint32(0)
		}
		if spec.CompareUnionJS {
			summary.UnionJSP99FP1e6 = nodewire.PresentUint32(FixedPointScale)
		}
		return summary, nil
	}
	n := uint64(finite)
	summary.MeanAbsLogprobDiffFP1e6 = saturateUint32(roundHalfUpSum(absDiffs, n))
	summary.AbsLogprobDiffP95FP1e6 = saturateUint32(nearestRank(95, absDiffs))
	summary.AbsLogprobDiffP99FP1e6 = saturateUint32(nearestRank(99, absDiffs))
	if spec.CompareRankDelta {
		summary.ComparedRankCount = finiteCount
		summary.RankDeltaNonzeroRateFP1e6 = uint32(roundHalfUp(new(big.Int).SetUint64(rankDiff*FixedPointScale), n))
	}
	if spec.CompareTopKJaccard {
		summary.TopkJaccardMeanFP1e6 = nodewire.PresentUint32(uint32(roundHalfUpSum(jaccard, n)))
	}
	if spec.CompareUnionJS {
		summary.UnionJSP99FP1e6 = nodewire.PresentUint32(uint32(nearestRank(99, unionJS)))
	}
	if spec.CompareTopKJaccard || spec.CompareUnionJS {
		summary.ComparedTopkCount = finiteCount
	}
	return summary, nil
}

// roundHalfUpSum is round_half_up(sum(values) / n), exact for any sum.
func roundHalfUpSum(values []uint64, n uint64) uint64 {
	sum := new(big.Int)
	for _, v := range values {
		sum.Add(sum, new(big.Int).SetUint64(v))
	}
	return roundHalfUp(sum, n)
}

// roundHalfUp is floor((2a + b) / (2b)) for a >= 0 and b > 0, saturating at
// the uint64 maximum.
func roundHalfUp(a *big.Int, b uint64) uint64 {
	bb := new(big.Int).SetUint64(b)
	num := new(big.Int).Lsh(a, 1)
	num.Add(num, bb)
	q := num.Quo(num, new(big.Int).Lsh(bb, 1))
	if !q.IsUint64() {
		return math.MaxUint64
	}
	return q.Uint64()
}

// nearestRank is the ceil(percent/100 * n)-th smallest value (1-based).
func nearestRank(percent uint64, values []uint64) uint64 {
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	n := uint64(len(sorted))
	rank := (percent*n + 99) / 100
	if rank == 0 {
		rank = 1
	}
	return sorted[rank-1]
}

func saturateUint32(v uint64) uint32 {
	if v > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v)
}
