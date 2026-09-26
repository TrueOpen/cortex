package metric

import (
	"math"
	"testing"
)

func TestTopKJaccard(t *testing.T) {
	a := []TokenLogprob{{1, -0.1}, {2, -1}, {3, -2}}
	for name, tc := range map[string]struct {
		b    []TokenLogprob
		want float64
	}{
		"identical sets":          {[]TokenLogprob{{3, -9}, {1, -9}, {2, -9}}, 1},
		"disjoint":                {[]TokenLogprob{{4, -1}}, 0},
		"two of four":             {[]TokenLogprob{{1, -1}, {2, -1}, {4, -1}}, 0.5},
		"order is not a factor":   {[]TokenLogprob{{2, -1}, {1, -1}, {4, -1}}, 0.5},
		"logprob is not a factor": {[]TokenLogprob{{1, 0}, {2, 0}, {4, 0}}, 0.5},
	} {
		if got := TopKJaccard(a, tc.b); got != tc.want {
			t.Errorf("%s: TopKJaccard = %v, want %v", name, got, tc.want)
		}
	}
	if got := TopKJaccard(nil, nil); got != 1 {
		t.Fatalf("two empty lists = %v, want 1", got)
	}
}

func TestUnionJSDivergence(t *testing.T) {
	// p = (0.5, 0.5) over tokens 1 and 2; q puts all mass on token 1.
	p := []TokenLogprob{{1, math.Log(0.5)}, {2, math.Log(0.5)}}
	q := []TokenLogprob{{1, 0}}
	want := 0.25*math.Log(0.5/0.75) + 0.25*math.Log(0.5/0.25) + 0.5*math.Log(1/0.75)
	got, ok := UnionJSDivergence(p, q)
	if !ok || math.Abs(got-want) > 1e-15 {
		t.Fatalf("UnionJSDivergence = %v, %v; want %v", got, ok, want)
	}
	if same, ok := UnionJSDivergence(p, p); !ok || same != 0 {
		t.Fatalf("identical lists = %v, %v; want 0", same, ok)
	}
	if _, ok := UnionJSDivergence(nil, nil); ok {
		t.Fatal("two empty lists reported a divergence")
	}
	if _, ok := UnionJSDivergence(p, []TokenLogprob{{1, math.Inf(-1)}}); ok {
		t.Fatal("a side with no finite mass reported a divergence")
	}

	// The sums run in a fixed order, so the result is the same bits every time.
	// A map-ordered sum over these six-plus tokens varies in its last bits.
	a := []TokenLogprob{{1, -0.3}, {2, -1.7}, {3, -2.2}, {4, -2.9}, {5, -3.1}, {6, -4.0}}
	b := []TokenLogprob{{1, -0.35}, {2, -1.5}, {7, -2.4}, {4, -3.3}, {8, -3.0}, {9, -4.4}}
	first, _ := UnionJSDivergence(a, b)
	for range 500 {
		if again, _ := UnionJSDivergence(a, b); math.Float64bits(again) != math.Float64bits(first) {
			t.Fatalf("UnionJSDivergence is not deterministic: %v then %v", first, again)
		}
	}
}

func TestCompareSamples(t *testing.T) {
	const missing = -100.0
	worker := []PositionValue{
		{TokenID: 10, Logprob: -0.1, Rank: 1, TopK: []TokenLogprob{{10, -0.1}, {11, -2}, {12, -3}}},
		{TokenID: 11, Logprob: -0.2, Rank: 2, TopK: []TokenLogprob{{11, -0.2}}},
		{TokenID: 12, Logprob: -0.3, Rank: 1},
	}
	verifier := []PositionValue{
		{TokenID: 10, Logprob: -0.11, Rank: 1, TopK: []TokenLogprob{{10, -0.11}, {13, -2}}},
		{TokenID: 11, Missing: true, TopK: []TokenLogprob{{11, -0.3}}},
		{TokenID: 12, Logprob: math.Inf(-1), Rank: 3, TopK: []TokenLogprob{{12, -1}}},
	}
	samples, err := CompareSamples(worker, verifier, 2, missing)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 3 {
		t.Fatalf("%d samples, want 3", len(samples))
	}

	// Position 0: top-k truncated to its first two entries, {10, 11} vs {10, 13}.
	s := samples[0]
	if !s.Finite || s.Missing || s.WorkerRank != 1 || s.VerifierRank != 1 || s.VerifierLogprob != -0.11 {
		t.Fatalf("position 0 = %#v", s)
	}
	if !s.TopKJaccard.Present || s.TopKJaccard.Value != 1.0/3 || !s.UnionJS.Present {
		t.Fatalf("position 0 top-k metrics = %#v %#v", s.TopKJaccard, s.UnionJS)
	}

	// Position 1: the verifier has no value for the emitted token. The leaf stays,
	// flagged, with the stand-in logprob and no verifier rank, and its top-k is
	// still compared.
	s = samples[1]
	if !s.Missing || s.Finite || s.VerifierLogprob != missing || s.VerifierRank != 0 || s.WorkerRank != 2 {
		t.Fatalf("position 1 = %#v", s)
	}
	if !s.TopKJaccard.Present || s.TopKJaccard.Value != 1 {
		t.Fatalf("position 1 top-k = %#v", s.TopKJaccard)
	}

	// Position 2: compared but not finite, and the Worker listed no top-k, so the
	// optional metrics stay absent rather than becoming a measured zero.
	s = samples[2]
	if s.Missing || s.Finite || s.VerifierRank != 3 || s.TopKJaccard.Present || s.UnionJS.Present {
		t.Fatalf("position 2 = %#v", s)
	}
}

func TestCompareSamplesKeepsTheGivenTopKOrder(t *testing.T) {
	// Equal logprobs: truncation keeps the first entries as given and does not
	// re-sort, so listing 30 before 20 keeps 30.
	worker := []PositionValue{{TokenID: 1, Rank: 1, TopK: []TokenLogprob{{1, -1}, {30, -2}, {20, -2}}}}
	verifier := []PositionValue{{TokenID: 1, Rank: 1, TopK: []TokenLogprob{{1, -1}, {30, -2}}}}
	samples, err := CompareSamples(worker, verifier, 2, -100)
	if err != nil {
		t.Fatal(err)
	}
	if samples[0].TopKJaccard.Value != 1 {
		t.Fatalf("top-k Jaccard = %v, want 1: the order was not kept", samples[0].TopKJaccard.Value)
	}

	// Non-finite entries are dropped before truncation, not counted towards K.
	worker[0].TopK = []TokenLogprob{{1, -1}, {9, math.NaN()}, {30, -2}}
	if samples, err = CompareSamples(worker, verifier, 2, -100); err != nil || samples[0].TopKJaccard.Value != 1 {
		t.Fatalf("non-finite entry took a top-k slot: %#v, %v", samples, err)
	}
}

func TestCompareSamplesRefusesInconsistentInput(t *testing.T) {
	one := []PositionValue{{TokenID: 1}}
	for name, tc := range map[string]struct{ worker, verifier []PositionValue }{
		"length mismatch":             {one, nil},
		"verifier scored other token": {one, []PositionValue{{TokenID: 2}}},
		"repeated top-k token": {
			[]PositionValue{{TokenID: 1, TopK: []TokenLogprob{{1, -1}, {1, -2}}}}, one,
		},
	} {
		if _, err := CompareSamples(tc.worker, tc.verifier, 2, -100); err == nil {
			t.Errorf("%s: CompareSamples() error = nil", name)
		}
	}
	// A missing verifier value carries no token of its own to disagree with.
	if _, err := CompareSamples(one, []PositionValue{{TokenID: 2, Missing: true}}, 2, -100); err != nil {
		t.Fatalf("missing verifier value refused: %v", err)
	}
}
