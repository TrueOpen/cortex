package metric

import (
	"fmt"

	"github.com/TrueOpen/cortex/internal/nodewire"
)

// Aggregates is the single-sample metric aggregation in real units, as the
// verification run computed it. It is the input to MetricSummaryV1 and nothing
// else; the fixed-point narrowing happens in Summary so that no producer has to
// know the wire widths.
//
// TopKJaccardMean and UnionJSP99 are optional here for the same reason they are
// optional on the wire, but presence on the wire is NOT taken from this struct —
// see Summary.
type Aggregates struct {
	FiniteCount          int
	MissingComparedCount int
	MeanAbsLogprobDiff   float64
	AbsLogprobDiffP95    float64
	AbsLogprobDiffP99    float64
	RankDeltaNonzeroRate float64
	TopKJaccardMean      OptionalFP
	UnionJSP99           OptionalFP
	ComparedTopKCount    int
	ComparedRankCount    int
}

// Summary assembles the frozen typed MetricSummaryV1 (keeper §9.7) from the
// locked profile and the run's aggregates.
//
// Two rules decide this function's shape:
//
// Presence is the profile's decision, not the measurement's. §9.7 says "whether a
// field is present is decided solely by the locked profile's MetricSpec", so fields
// 7 and 8 are present exactly when compare_topk_jaccard / compare_union_js are set.
// A run that measured a jaccard the profile does not ask for must not smuggle it
// into the preimage, and a profile that asks for one the run failed to measure is a
// refusal — not an absent field. Both directions matter: the summary is
// length-framed with explicit presence, so the two cases produce different
// metric_summary_hash values and the Keeper judges the one it is handed.
//
// Field ORDER is the schema's, and it is expressed once, in
// nodewire.MetricSummaryV1's struct layout and its frame encoder. This function
// fills that struct rather than emitting bytes, so there is no second field
// order in the repository that could drift from §9.7's table.
func Summary(spec Spec, aggregates Aggregates) (nodewire.MetricSummaryV1, error) {
	finiteCount, err := countUint32("finite_count", aggregates.FiniteCount)
	if err != nil {
		return nodewire.MetricSummaryV1{}, err
	}
	missingCount, err := countUint32("missing_compared_count", aggregates.MissingComparedCount)
	if err != nil {
		return nodewire.MetricSummaryV1{}, err
	}
	meanAbs, err := summaryFP1e6("mean_abs_logprob_diff", aggregates.MeanAbsLogprobDiff)
	if err != nil {
		return nodewire.MetricSummaryV1{}, err
	}
	p95, err := summaryFP1e6("abs_logprob_diff_p95", aggregates.AbsLogprobDiffP95)
	if err != nil {
		return nodewire.MetricSummaryV1{}, err
	}
	p99, err := summaryFP1e6("abs_logprob_diff_p99", aggregates.AbsLogprobDiffP99)
	if err != nil {
		return nodewire.MetricSummaryV1{}, err
	}
	rankRate, err := summaryFP1e6("rank_delta_nonzero_rate", aggregates.RankDeltaNonzeroRate)
	if err != nil {
		return nodewire.MetricSummaryV1{}, err
	}
	comparedTopK, err := countUint32("compared_topk_count", aggregates.ComparedTopKCount)
	if err != nil {
		return nodewire.MetricSummaryV1{}, err
	}
	comparedRank, err := countUint32("compared_rank_count", aggregates.ComparedRankCount)
	if err != nil {
		return nodewire.MetricSummaryV1{}, err
	}

	jaccard, err := profileDecidedOptional(
		"topk_jaccard_mean", "compare_topk_jaccard", spec.CompareTopKJaccard, aggregates.TopKJaccardMean)
	if err != nil {
		return nodewire.MetricSummaryV1{}, err
	}
	unionJS, err := profileDecidedOptional(
		"union_js_p99", "compare_union_js", spec.CompareUnionJS, aggregates.UnionJSP99)
	if err != nil {
		return nodewire.MetricSummaryV1{}, err
	}

	return nodewire.MetricSummaryV1{
		FiniteCount:               finiteCount,
		MissingComparedCount:      missingCount,
		MeanAbsLogprobDiffFP1e6:   meanAbs,
		AbsLogprobDiffP95FP1e6:    p95,
		AbsLogprobDiffP99FP1e6:    p99,
		RankDeltaNonzeroRateFP1e6: rankRate,
		TopkJaccardMeanFP1e6:      jaccard,
		UnionJSP99FP1e6:           unionJS,
		ComparedTopkCount:         comparedTopK,
		ComparedRankCount:         comparedRank,
	}, nil
}

// profileDecidedOptional resolves one optional summary member.
//
//	profile asks, run measured     -> present
//	profile does not ask           -> absent, whatever the run measured
//	profile asks, run did not      -> refuse
//
// The third case is a refusal rather than an absent field because absent is a
// statement — "this profile does not judge on this metric" — and it would be a
// false one. The Keeper judges the summary it receives, so a silently-absent
// required metric is a sample that skipped one of its own thresholds.
func profileDecidedOptional(
	field, flag string, required bool, measured OptionalFP,
) (nodewire.OptionalUint32, error) {
	if !required {
		return nodewire.OptionalUint32{}, nil
	}
	if !measured.Present {
		return nodewire.OptionalUint32{}, fmt.Errorf(
			"locked profile sets %s, so MetricSummaryV1.%s must be present, but the verification run measured none",
			flag, field)
	}
	value, err := summaryFP1e6(field, measured.Value)
	if err != nil {
		return nodewire.OptionalUint32{}, err
	}
	return nodewire.PresentUint32(value), nil
}
