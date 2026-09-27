package modelservice

import (
	"math"
	"math/rand"
	"strconv"
	"testing"

	"github.com/TrueOpen/cortex/internal/metric"
)

// unionJSTolerance bounds the only allowed difference from the legacy path.
// The legacy union JS summed over Go map iteration order, which changes from
// run to run, so its last bits were never stable; metric.UnionJSDivergence sums
// in a fixed order. Everything else must match exactly.
const unionJSTolerance = 1e-12

// computeSingleSampleMetrics now delegates the comparison to
// metric.CompareSamples. On every input below it must produce the samples and
// aggregates the pre-refactor implementation produced.
func TestComparisonMatchesLegacyImplementation(t *testing.T) {
	type input struct {
		name       string
		trace      []tokenLogprob
		inputLen   int
		recomputed []map[string]logprobEntry
		topK       int
	}
	inputs := []input{
		{
			name: "covers every position fixture",
			trace: []tokenLogprob{
				{TokenID: 10, Logprob: -0.1, Rank: 1, TopLogprobs: map[string]float64{"10": -0.1, "11": -2.0}},
				{TokenID: 11, Logprob: -0.2, Rank: 2, TopLogprobs: map[string]float64{"11": -0.2, "12": -3.0}},
				{TokenID: 12, Logprob: -0.3, Rank: 1, TopLogprobs: map[string]float64{"12": -0.3}},
			},
			recomputed: []map[string]logprobEntry{
				{"10": {Logprob: -0.11, Rank: 1}, "11": {Logprob: -2.1, Rank: 2}},
				{"11": {Logprob: -0.22, Rank: 3}, "12": {Logprob: -3.1, Rank: 2}},
				{"99": {Logprob: -5.0, Rank: 1}},
			},
			topK: 2,
		},
		{
			name:       "no top-k reported",
			trace:      []tokenLogprob{{TokenID: 10, Logprob: -0.1, Rank: 1}},
			recomputed: []map[string]logprobEntry{{"10": {Logprob: -0.11, Rank: 1}}},
			topK:       2,
		},
		{
			name: "ties at the truncation boundary sort by key text",
			trace: []tokenLogprob{{TokenID: 9, Logprob: -1, Rank: 1, TopLogprobs: map[string]float64{
				"9": -1, "10": -1, "100": -1, "8": -2,
			}}},
			recomputed: []map[string]logprobEntry{{"9": {Logprob: -1, Rank: 1}, "10": {Logprob: -1, Rank: 2}, "11": {Logprob: -1, Rank: 3}}},
			topK:       2,
		},
		{
			name: "text keys and prefixed keys",
			trace: []tokenLogprob{{TokenID: 5, Logprob: -0.5, Rank: 1, TopLogprobs: map[string]float64{
				"hello": -0.5, "token_id:7": -1.5, " world ": -2,
			}}},
			recomputed: []map[string]logprobEntry{{"token_id:5": {Logprob: -0.4, Rank: 1}, "hello": {Logprob: -0.6, Rank: 2}, "7": {Logprob: -1.2, Rank: 3}}},
			topK:       3,
		},
		{
			name: "non-finite entries are dropped before truncation",
			trace: []tokenLogprob{{TokenID: 1, Logprob: -0.1, Rank: 1, TopLogprobs: map[string]float64{
				"1": -0.1, "2": math.Inf(-1), "3": math.NaN(), "4": -3,
			}}},
			recomputed: []map[string]logprobEntry{{"1": {Logprob: math.Inf(-1), Rank: 1}, "4": {Logprob: -2, Rank: 2}}},
			topK:       2,
		},
		{
			name:       "prompt offset",
			trace:      []tokenLogprob{{TokenID: 3, Logprob: -0.3, Rank: 1, TopLogprobs: map[string]float64{"3": -0.3}}},
			inputLen:   2,
			recomputed: []map[string]logprobEntry{nil, {"0": {Logprob: -1}}, {"3": {Logprob: -0.31, Rank: 1}}},
			topK:       0,
		},
	}
	rng := rand.New(rand.NewSource(20260927))
	for c := 0; c < 200; c++ {
		inputs = append(inputs, randomComparisonInput(rng, c))
	}
	for _, in := range inputs {
		wantMetrics, wantSamples, wantErr := legacyComputeSingleSampleMetrics(in.trace, in.inputLen, in.recomputed, in.topK, missingLogprob)
		gotMetrics, gotSamples, gotErr := computeSingleSampleMetrics(in.trace, in.inputLen, in.recomputed, in.topK, missingLogprob)
		if (wantErr == nil) != (gotErr == nil) {
			t.Fatalf("%s: error = %v, legacy %v", in.name, gotErr, wantErr)
		}
		if len(gotSamples) != len(wantSamples) {
			t.Fatalf("%s: %d samples, legacy %d", in.name, len(gotSamples), len(wantSamples))
		}
		for i := range wantSamples {
			if !sameSample(gotSamples[i], wantSamples[i]) {
				t.Fatalf("%s: sample %d = %#v, legacy %#v", in.name, i, gotSamples[i], wantSamples[i])
			}
		}
		if !sameMetrics(gotMetrics, wantMetrics) {
			t.Fatalf("%s: metrics = %#v, legacy %#v", in.name, gotMetrics, wantMetrics)
		}
	}
}

func randomComparisonInput(rng *rand.Rand, c int) struct {
	name       string
	trace      []tokenLogprob
	inputLen   int
	recomputed []map[string]logprobEntry
	topK       int
} {
	// A small vocabulary makes overlaps, ties and misses common. Logprobs are
	// drawn from a coarse grid so equal values - the tie-break path - occur.
	logprob := func() float64 {
		switch rng.Intn(20) {
		case 0:
			return math.Inf(-1)
		case 1:
			return math.NaN()
		}
		return -float64(rng.Intn(12)) / 4
	}
	// One key spelling per input: an engine reports either bare or prefixed ids,
	// never both, and a map holding "7" and "token_id:7" normalizes to one key
	// with a winner chosen by map iteration order in both implementations.
	prefix := ""
	if rng.Intn(4) == 0 {
		prefix = "token_id:"
	}
	key := func(id int) string { return prefix + strconv.Itoa(id) }
	positions := 1 + rng.Intn(6)
	inputLen := rng.Intn(3)
	trace := make([]tokenLogprob, positions)
	recomputed := make([]map[string]logprobEntry, inputLen+positions)
	for i := range trace {
		top := map[string]float64{}
		for n := rng.Intn(6); n > 0; n-- {
			top[key(rng.Intn(15))] = logprob()
		}
		trace[i] = tokenLogprob{TokenID: rng.Intn(15), Logprob: logprob(), Rank: rng.Intn(4), TopLogprobs: top}
		row := map[string]logprobEntry{}
		for n := rng.Intn(6); n > 0; n-- {
			row[key(rng.Intn(15))] = logprobEntry{Logprob: logprob(), Rank: 1 + rng.Intn(5)}
		}
		recomputed[inputLen+i] = row
	}
	return struct {
		name       string
		trace      []tokenLogprob
		inputLen   int
		recomputed []map[string]logprobEntry
		topK       int
	}{"random " + strconv.Itoa(c), trace, inputLen, recomputed, rng.Intn(5)}
}

func sameSample(a, b metric.Sample) bool {
	unionJSA, unionJSB := a.UnionJS, b.UnionJS
	a.UnionJS, b.UnionJS = metric.OptionalFP{}, metric.OptionalFP{}
	return sameFloatBits(a.WorkerLogprob, b.WorkerLogprob) && sameFloatBits(a.VerifierLogprob, b.VerifierLogprob) &&
		a.OutputPosition == b.OutputPosition && a.EmittedTokenID == b.EmittedTokenID &&
		a.WorkerRank == b.WorkerRank && a.VerifierRank == b.VerifierRank &&
		a.TopKJaccard == b.TopKJaccard && a.Missing == b.Missing && a.Finite == b.Finite &&
		unionJSA.Present == unionJSB.Present && math.Abs(unionJSA.Value-unionJSB.Value) <= unionJSTolerance
}

func sameMetrics(a, b singleSampleMetrics) bool {
	jsA, jsB := a.UnionJSP99, b.UnionJSP99
	a.UnionJSP99, b.UnionJSP99 = nil, nil
	if (jsA == nil) != (jsB == nil) || (jsA != nil && math.Abs(*jsA-*jsB) > unionJSTolerance) {
		return false
	}
	jaccardA, jaccardB := a.TopKJaccardMean, b.TopKJaccardMean
	a.TopKJaccardMean, b.TopKJaccardMean = nil, nil
	if (jaccardA == nil) != (jaccardB == nil) || (jaccardA != nil && *jaccardA != *jaccardB) {
		return false
	}
	return a == b
}

// sameFloatBits treats two NaNs as equal, which == does not.
func sameFloatBits(a, b float64) bool {
	return math.Float64bits(a) == math.Float64bits(b) || (math.IsNaN(a) && math.IsNaN(b))
}
