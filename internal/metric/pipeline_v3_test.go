package metric

import (
	"math"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

func leavesFor(t *testing.T, values []PositionValue, requiredTopK uint32) []nodewire.PositionValueV1 {
	t.Helper()
	leaves, err := ValueLeaves(values, requiredTopK)
	if err != nil {
		t.Fatal(err)
	}
	return leaves
}

func TestCompareLeavesV3(t *testing.T) {
	spec := Spec{CompareLogprobDiff: true, CompareRankDelta: true, CompareTopKJaccard: true, CompareUnionJS: true, ComparedTopK: 2}
	top := func(ids ...uint32) []TokenLogprob {
		out := make([]TokenLogprob, len(ids))
		for i, id := range ids {
			out[i] = TokenLogprob{TokenID: id, Logprob: -float64(i+1) / 10}
		}
		return out
	}
	worker := leavesFor(t, []PositionValue{
		{TokenID: 10, Logprob: -0.1, Rank: 1, TopK: top(10, 11, 12)},
		{TokenID: 11, Logprob: -0.2, Rank: 2, TopK: top(12, 11, 13)},
		{TokenID: 12, Logprob: -0.3, Rank: 1, TopK: top(12, 1, 2)},
	}, 3)
	verifier := leavesFor(t, []PositionValue{
		{TokenID: 10, Logprob: -0.11, Rank: 1, TopK: top(10, 13, 11)},
		{TokenID: 11, Missing: true},
		{TokenID: 12, Logprob: math.Inf(-1)},
	}, 3)
	samples, err := CompareLeavesV3(spec, 3, worker, verifier)
	if err != nil {
		t.Fatal(err)
	}
	// Position 0: compared top-k is the first two entries, {10, 11} vs {10, 13}.
	s := samples[0]
	if !s.Finite || s.Missing || s.WorkerLogprobFP1e6 != -100000 || s.VerifierLogprobFP1e6 != -110000 || s.WorkerRank != 1 || s.VerifierRank != 1 {
		t.Fatalf("position 0 = %+v", s)
	}
	if !s.TopKJaccardFP1e6.Present || s.TopKJaccardFP1e6.Value != 333333 || !s.UnionJSFP1e6.Present {
		t.Fatalf("position 0 ratios = %+v %+v", s.TopKJaccardFP1e6, s.UnionJSFP1e6)
	}
	// Position 1: the verifier reported no value. The leaf stays, flagged, with
	// zero values and absent ratios.
	if s := samples[1]; !s.Missing || s.Finite || s.WorkerLogprobFP1e6 != 0 || s.TopKJaccardFP1e6.Present {
		t.Fatalf("position 1 = %+v", s)
	}
	// Position 2: compared but not finite.
	if s := samples[2]; s.Missing || s.Finite || s.TopKJaccardFP1e6.Present {
		t.Fatalf("position 2 = %+v", s)
	}

	// Ranks enter only under compare_rank_delta.
	spec.CompareRankDelta = false
	samples, err = CompareLeavesV3(spec, 3, worker, verifier)
	if err != nil || samples[0].WorkerRank != 0 || samples[0].VerifierRank != 0 {
		t.Fatalf("rank without compare_rank_delta: %+v, %v", samples[0], err)
	}
}

func TestCompareLeavesV3RefusesInconsistentInput(t *testing.T) {
	spec := Spec{CompareTopKJaccard: true, ComparedTopK: 1}
	one := leavesFor(t, []PositionValue{{TokenID: 1, Logprob: -1, Rank: 1, TopK: []TokenLogprob{{TokenID: 1, Logprob: -1}}}}, 1)
	other := leavesFor(t, []PositionValue{{TokenID: 2, Logprob: -1, Rank: 1, TopK: []TokenLogprob{{TokenID: 2, Logprob: -1}}}}, 1)
	if _, err := CompareLeavesV3(spec, 1, one, nil); err == nil {
		t.Fatal("length mismatch accepted")
	}
	if _, err := CompareLeavesV3(spec, 1, one, other); err == nil {
		t.Fatal("verifier scored another token")
	}
}

// BuildV3's root binds the verifier value root, so two runs over the same
// samples under different committed values have different metric roots.
func TestBuildV3BindsTheVerifierValueRoot(t *testing.T) {
	binding := fixtureBinding()
	samples, err := samplesToV3([]Sample{sampleAt(0), sampleAt(1)})
	if err != nil {
		t.Fatal(err)
	}
	a, err := BuildV3(binding, testVerifierValueRoot, samples)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildV3(binding, codec.HashBytes([]byte("other values")), samples)
	if err != nil {
		t.Fatal(err)
	}
	if a.Root == b.Root || a.VerifierValueRoot != testVerifierValueRoot {
		t.Fatal("metric root does not bind verifier_value_root")
	}
	if a.LeafCount != 2 || a.Summary.FiniteCount+a.Summary.MissingComparedCount != uint32(a.LeafCount) {
		t.Fatalf("leaf count %d does not match summary %+v", a.LeafCount, a.Summary)
	}
}
