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
