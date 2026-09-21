package modelservice

import (
	"testing"

	"github.com/SingaXYZ/cortex/internal/metric"
)

// The metric leaf set has to cover EVERY generated token position, contiguously
// and in order, because the Merkle tree records position as index and nothing
// else (05-verification-algorithm §7). A sample set that skipped an incomparable position
// would silently renumber every later leaf.
func TestMetricSamplesCoverEveryGeneratedPositionInOrder(t *testing.T) {
	trace := []tokenLogprob{
		{TokenID: 10, Logprob: -0.1, Rank: 1, TopLogprobs: map[string]float64{"10": -0.1, "11": -2.0}},
		{TokenID: 11, Logprob: -0.2, Rank: 2, TopLogprobs: map[string]float64{"11": -0.2, "12": -3.0}},
		// The verifier has no entry for this one: it is missing, not absent.
		{TokenID: 12, Logprob: -0.3, Rank: 1, TopLogprobs: map[string]float64{"12": -0.3}},
	}
	recomputed := []map[string]logprobEntry{
		{"10": {Logprob: -0.11, Rank: 1}, "11": {Logprob: -2.1, Rank: 2}},
		{"11": {Logprob: -0.22, Rank: 3}, "12": {Logprob: -3.1, Rank: 2}},
		{"99": {Logprob: -5.0, Rank: 1}},
	}

	metrics, samples, err := computeSingleSampleMetrics(trace, 0, recomputed, 2, missingLogprob)
	if err != nil {
		t.Fatalf("computeSingleSampleMetrics returned error: %v", err)
	}

	if len(samples) != len(trace) {
		t.Fatalf("samples = %d, want one per generated token (%d)", len(samples), len(trace))
	}
	for index, sample := range samples {
		if sample.OutputPosition != uint32(index) {
			t.Fatalf("sample %d carries output_position %d", index, sample.OutputPosition)
		}
		if sample.EmittedTokenID != uint32(trace[index].TokenID) {
			t.Fatalf("sample %d emitted_token_id = %d, want %d", index, sample.EmittedTokenID, trace[index].TokenID)
		}
		if sample.WorkerLogprob != trace[index].Logprob {
			t.Fatalf("sample %d worker_logprob = %v, want the trace value %v", index, sample.WorkerLogprob, trace[index].Logprob)
		}
	}

	// The missing position is still a leaf, flagged rather than dropped, and it
	// carries the profile's stand-in logprob rather than a silent zero.
	missing := samples[2]
	if !missing.Missing || missing.Finite {
		t.Fatalf("position 2 = %#v, want missing and not finite", missing)
	}
	if missing.VerifierLogprob != missingLogprob {
		t.Fatalf("missing position verifier_logprob = %v, want the profile stand-in %v", missing.VerifierLogprob, missingLogprob)
	}
	if missing.VerifierRank != 0 {
		t.Fatalf("missing position carries verifier_rank %d, want 0", missing.VerifierRank)
	}

	// A position the verifier compared but whose ranks disagree is finite and
	// keeps both ranks, so the leaf's rank_delta is derivable.
	compared := samples[1]
	if !compared.Finite || compared.Missing {
		t.Fatalf("position 1 = %#v, want a finite comparison", compared)
	}
	if compared.WorkerRank != 2 || compared.VerifierRank != 3 {
		t.Fatalf("position 1 ranks = worker %d verifier %d, want 2 and 3", compared.WorkerRank, compared.VerifierRank)
	}

	// And the aggregates describe the same three positions the samples do -
	// they are computed in one pass precisely so they cannot disagree.
	if metrics.MissingSelectedCount != 1 {
		t.Fatalf("missing_selected_count = %d, want 1", metrics.MissingSelectedCount)
	}
	if metrics.FiniteCount != 2 {
		t.Fatalf("finite_count = %d, want 2", metrics.FiniteCount)
	}
	// And the local verdict's numbers ARE the canonical aggregation: the
	// classifier reads a projection of metric.AggregateFromSamples over these
	// same samples, so the number an operator sees and the number the Keeper
	// judges cannot be about different data.
	// Same kGen the computeSingleSampleMetrics call above used (compared_top_k
	// == the generation top_k), so the canonical rank rate matches the local one.
	canonical := metric.AggregateFromSamples(samples, 2)
	if canonical.FiniteCount != metrics.FiniteCount ||
		canonical.MissingComparedCount != metrics.MissingSelectedCount ||
		canonical.MeanAbsLogprobDiff != metrics.MeanAbsLogprobDiff ||
		canonical.ComparedRankCount != metrics.ComparedRankCount ||
		canonical.ComparedTopKCount != metrics.ComparedTopKCount {
		t.Fatalf("the local metrics %#v are not a projection of the canonical aggregation %#v", metrics, canonical)
	}
}

// An optional per-position metric the run could not measure must stay absent
// rather than becoming a measured zero: the two encode differently in the leaf.
func TestUnmeasuredOptionalSampleMetricsStayAbsent(t *testing.T) {
	trace := []tokenLogprob{{TokenID: 10, Logprob: -0.1, Rank: 1}}
	recomputed := []map[string]logprobEntry{{"10": {Logprob: -0.11, Rank: 1}}}

	_, samples, err := computeSingleSampleMetrics(trace, 0, recomputed, 2, missingLogprob)
	if err != nil {
		t.Fatalf("computeSingleSampleMetrics returned error: %v", err)
	}

	if len(samples) != 1 {
		t.Fatalf("samples = %d, want 1", len(samples))
	}
	if samples[0].TopKJaccard.Present || samples[0].UnionJS.Present {
		t.Fatalf("sample = %#v, want both optional metrics absent when no top-k was reported", samples[0])
	}
}
