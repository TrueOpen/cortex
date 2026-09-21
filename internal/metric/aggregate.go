package metric

import (
	"math"
	"sort"
)

// AggregateFromSamples derives the single-sample aggregation from the
// per-position samples, and it is the only aggregator in this repository.
//
// # Why this is not a parameter
//
// metric_root is a Merkle tree over the samples; MetricSummaryV1 is what the
// Keeper judges. If the two came from different sources - the samples over one
// channel and the aggregation over another - a producer could hand over honest
// samples and a summary describing different data, and Cortex would sign a
// ResultReceipt whose root and summary disagree. Nothing downstream can catch
// that: the Keeper judges the summary and only ever recomputes the root at an
// opening, so the contradiction would surface as an unexplainable challenge
// months later.
//
// Deriving here makes the two provably the same data by construction, and it
// makes the aggregation openable: anyone holding the leaves can recompute this
// function and get the summary that was signed.
//
// The model service still computes a local verdict, and it classifies from
// exactly these numbers (modelservice.metricAggregates) rather than from a
// second pass of its own.
//
// kGen is the generation top_k (RequiredTopK / the profile's compared_top_k;
// the two are pinned equal in Binding.validate). It is an input here, not a
// per-sample field, because it is a task constant that every metric leaf
// already carries — so an opening can re-derive this same aggregation from the
// leaves alone. See the rank-anomaly rule below.
func AggregateFromSamples(samples []Sample, kGen uint32) Aggregates {
	var aggregates Aggregates
	absDiffs := make([]float64, 0, len(samples))
	jaccards := make([]float64, 0, len(samples))
	unionJSValues := make([]float64, 0, len(samples))
	rankMismatchCount := 0

	for _, sample := range samples {
		if sample.Missing {
			aggregates.MissingComparedCount++
		}
		if sample.Finite {
			aggregates.FiniteCount++
			absDiffs = append(absDiffs, math.Abs(sample.VerifierLogprob-sample.WorkerLogprob))
		}
		// A rank comparison needs both sides to have reported one. Rank 0 is the
		// "no rank reported" spelling, not a rank.
		if !sample.Missing && sample.WorkerRank > 0 && sample.VerifierRank > 0 {
			aggregates.ComparedRankCount++
			// A sample is a rank anomaly when the two sides disagree OR when
			// either side placed the emitted token outside the generation top-k
			// window. A token sampled under top_k=kGen must have rank ≤ kGen, so
			// a rank beyond it could not have been legitimately emitted — and a
			// pure agreement check misses exactly the case where the worker and
			// the verifier computed the same out-of-window rank. Rank == kGen is
			// inside the window; only > kGen is anomalous. kGen == 0 means "not
			// supplied" and disables the window rule rather than flagging every
			// reported rank (production always binds kGen ≥ 1).
			outOfWindow := kGen > 0 && (sample.WorkerRank > kGen || sample.VerifierRank > kGen)
			if sample.WorkerRank != sample.VerifierRank || outOfWindow {
				rankMismatchCount++
			}
		}
		if sample.TopKJaccard.Present {
			aggregates.ComparedTopKCount++
			jaccards = append(jaccards, sample.TopKJaccard.Value)
		}
		if sample.UnionJS.Present {
			unionJSValues = append(unionJSValues, sample.UnionJS.Value)
		}
	}

	aggregates.MeanAbsLogprobDiff = mean(absDiffs)
	aggregates.AbsLogprobDiffP95 = percentile(absDiffs, 0.95)
	aggregates.AbsLogprobDiffP99 = percentile(absDiffs, 0.99)
	if aggregates.ComparedRankCount > 0 {
		aggregates.RankDeltaNonzeroRate = float64(rankMismatchCount) / float64(aggregates.ComparedRankCount)
	}
	// Absent when nothing was measured, rather than present-zero: whether the
	// summary carries these two is the locked profile's decision, and "measured
	// nothing" must not read as "measured a perfect score".
	if len(jaccards) > 0 {
		aggregates.TopKJaccardMean = PresentFP(mean(jaccards))
	}
	if len(unionJSValues) > 0 {
		aggregates.UnionJSP99 = PresentFP(percentile(unionJSValues, 0.99))
	}
	return aggregates
}

func mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	total := 0.0
	for _, value := range values {
		total += value
	}
	return total / float64(len(values))
}

// percentile is nearest-rank on the sorted sample. Like the rounding mode in
// fixedpoint.go this is a choice the protocol does not document, so it is made
// once and stated: two verifiers using different percentile conventions produce
// different summaries for the same model output, and the Keeper judges whichever
// one it is handed.
func percentile(values []float64, q float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	if q <= 0 {
		return sorted[0]
	}
	if q >= 1 {
		return sorted[len(sorted)-1]
	}
	index := int(math.Ceil(q*float64(len(sorted)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}
