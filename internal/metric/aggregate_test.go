package metric

import (
	"reflect"
	"testing"

	"github.com/SingaXYZ/cortex/internal/nodewire"
)

// TestSummaryIsAFunctionOfTheSameSamplesAsTheRoot is the property that makes
// the ResultReceipt internally consistent.
//
// The failure it rules out: a model service returns honest per-token samples and
// a separately-stated aggregation describing different data. metric_root would
// describe the samples, MetricSummaryV1 would describe the other thing, and the
// Keeper - which judges the summary and only recomputes the root at an opening -
// would have no way to notice. Deriving both from one input makes that
// unrepresentable rather than merely unlikely, which is why Build takes no
// aggregates parameter.
func TestSummaryIsAFunctionOfTheSameSamplesAsTheRoot(t *testing.T) {
	binding := fixtureBinding()

	// Build accepts samples ONLY. If an aggregates parameter is ever added back,
	// this stops compiling - which is the intended tripwire.
	base, err := Build(binding, fixtureSamples())
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	// Every change to the samples that moves the aggregation must move the
	// summary too, because there is nowhere else for the summary to come from.
	for name, mutate := range map[string]func([]Sample){
		"a position stops being finite":    func(s []Sample) { s[0].Finite = false },
		"a position becomes missing":       func(s []Sample) { s[0].Missing = true },
		"a logprob moves":                  func(s []Sample) { s[0].VerifierLogprob -= 0.5 },
		"the ranks stop agreeing":          func(s []Sample) { s[0].VerifierRank = 7 },
		"a jaccard moves":                  func(s []Sample) { s[0].TopKJaccard = PresentFP(0.25) },
		"a union js moves":                 func(s []Sample) { s[0].UnionJS = PresentFP(0.5) },
		"an optional stops being measured": func(s []Sample) { s[0].TopKJaccard = OptionalFP{}; s[1].TopKJaccard = OptionalFP{} },
	} {
		t.Run(name, func(t *testing.T) {
			samples := fixtureSamples()
			mutate(samples)
			changed, err := Build(binding, samples)
			if err != nil {
				// "an optional stops being measured" is a refusal under this
				// fixture profile, which requires it - that is the summary
				// reacting, and it is the correct reaction.
				return
			}
			if changed.Summary == base.Summary {
				t.Fatalf("%s left MetricSummaryV1 identical; the summary is not derived from the samples", name)
			}
			if changed.Root == base.Root {
				t.Fatalf("%s left metric_root identical", name)
			}
		})
	}
}

// AggregateFromSamples must read every field of Sample that a summary member
// depends on. A field it silently ignores is a difference the leaves record and
// the summary does not.
func TestAggregateReadsTheSampleFieldsTheSummaryDependsOn(t *testing.T) {
	base := AggregateFromSamples(fixtureSamples(), fixtureBinding().RequiredTopK)
	for name, mutate := range map[string]func([]Sample){
		"finite flag":      func(s []Sample) { s[0].Finite = false },
		"missing flag":     func(s []Sample) { s[0].Missing = true },
		"worker logprob":   func(s []Sample) { s[0].WorkerLogprob -= 1 },
		"verifier logprob": func(s []Sample) { s[0].VerifierLogprob -= 1 },
		"worker rank":      func(s []Sample) { s[0].WorkerRank = 4 },
		"verifier rank":    func(s []Sample) { s[0].VerifierRank = 4 },
		"topk jaccard":     func(s []Sample) { s[0].TopKJaccard = PresentFP(0.1) },
		"union js":         func(s []Sample) { s[0].UnionJS = PresentFP(0.9) },
	} {
		t.Run(name, func(t *testing.T) {
			samples := fixtureSamples()
			mutate(samples)
			if reflect.DeepEqual(AggregateFromSamples(samples, fixtureBinding().RequiredTopK), base) {
				t.Fatalf("changing the %s of a sample did not change the aggregation", name)
			}
		})
	}
}

// TestRankAnomalyCountsOutOfWindowRanksNotJustDisagreements is the gap a pure
// agreement check leaves open: a token sampled under top_k=kGen must have rank
// ≤ kGen, so a worker and a verifier that AGREE on a rank beyond kGen have still
// observed something that could not have been legitimately emitted. That must
// raise rank_delta_nonzero_rate, and rank == kGen must not.
func TestRankAnomalyCountsOutOfWindowRanksNotJustDisagreements(t *testing.T) {
	const kGen uint32 = 4

	sample := func(worker, verifier uint32) Sample {
		return Sample{WorkerRank: worker, VerifierRank: verifier, Finite: true}
	}

	cases := []struct {
		name          string
		worker        uint32
		verifier      uint32
		wantAnomalous bool
	}{
		{"agree inside the window", 2, 2, false},
		{"agree exactly on the boundary", kGen, kGen, false},
		{"agree but both beyond the window", 10, 10, true},
		{"worker alone beyond the window", 10, 2, true},
		{"verifier alone beyond the window", 2, 10, true},
		{"disagree inside the window", 1, 2, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AggregateFromSamples([]Sample{sample(tc.worker, tc.verifier)}, kGen)
			if got.ComparedRankCount != 1 {
				t.Fatalf("compared_rank_count = %d, want 1", got.ComparedRankCount)
			}
			wantRate := 0.0
			if tc.wantAnomalous {
				wantRate = 1.0
			}
			if got.RankDeltaNonzeroRate != wantRate {
				t.Fatalf("rank_delta_nonzero_rate = %v, want %v", got.RankDeltaNonzeroRate, wantRate)
			}
		})
	}
}

// TestUnsetKGenDisablesTheWindowRule guards the footgun: with kGen == 0 every
// reported rank would be "> 0" and flagging them all would be catastrophic, so
// kGen == 0 falls back to the agreement-only rule.
func TestUnsetKGenDisablesTheWindowRule(t *testing.T) {
	agreeing := []Sample{{WorkerRank: 99, VerifierRank: 99, Finite: true}}
	if rate := AggregateFromSamples(agreeing, 0).RankDeltaNonzeroRate; rate != 0 {
		t.Fatalf("kGen==0 flagged an agreeing sample as anomalous: rate = %v", rate)
	}
}

// An all-zero or tampered aggregation can no longer reach the summary, because
// there is no channel for one. The nearest thing a hostile model service can
// still do is send samples that aggregate to zeros - and then the root describes
// those same zero samples, so the receipt stays internally consistent and the
// Keeper judges exactly what was measured.
func TestZeroSamplesProduceAZeroSummaryAndAMatchingRoot(t *testing.T) {
	binding := fixtureBinding()
	// compare_topk_jaccard / compare_union_js are set in the fixture profile, so
	// the samples must still measure them; everything else is zeroed.
	samples := []Sample{{
		OutputPosition: 0,
		TopKJaccard:    PresentFP(0),
		UnionJS:        PresentFP(0),
	}}
	material, err := Build(binding, samples)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if material.Summary.FiniteCount != 0 || material.Summary.ComparedRankCount != 0 {
		t.Fatalf("summary %#v does not describe the zero samples it was built from", material.Summary)
	}
	// And it is still a real commitment: the root is over the leaf that recorded
	// those zeros, not an empty tree.
	if material.Root.IsZero() || material.LeafCount != 1 {
		t.Fatalf("material %#v does not commit to the one sample", material)
	}
	if material.Summary == (nodewire.MetricSummaryV1{}) {
		t.Fatalf("a summary that measured zeros must still carry its present optionals: %#v", material.Summary)
	}
}
