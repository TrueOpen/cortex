package metric

import (
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/wirevectors"
)

func normalSample(position uint32, worker, verifier int64, workerRank, verifierRank uint32) SampleV3 {
	return SampleV3{OutputPosition: position, EmittedTokenID: 100 + position, WorkerLogprobFP1e6: worker, VerifierLogprobFP1e6: verifier,
		WorkerRank: workerRank, VerifierRank: verifierRank, Finite: true}
}

// The worked example of 05-verification-algorithm: required_top_k 20, two
// normal leaves (one with the Worker's rank outside the top-k), one missing and
// one non-finite leaf.
func TestSummaryV3ReproducesTheSpecWorkedExample(t *testing.T) {
	samples := []SampleV3{
		normalSample(0, -1250000, -1200000, 3, 2),
		normalSample(1, -3000000, -2500000, 0, 5),
		{OutputPosition: 2, EmittedTokenID: 102, Missing: true},
		{OutputPosition: 3, EmittedTokenID: 103},
	}
	if samples[0].rankDelta(20) != -1 || samples[1].rankDelta(20) != -16 {
		t.Fatalf("rank_delta = %d, %d, want -1, -16", samples[0].rankDelta(20), samples[1].rankDelta(20))
	}
	got, err := SummaryV3(Spec{CompareLogprobDiff: true, CompareRankDelta: true, ComparedTopK: 20}, 20, samples)
	if err != nil {
		t.Fatal(err)
	}
	want := nodewire.MetricSummaryV1{
		FiniteCount: 2, MissingComparedCount: 2,
		MeanAbsLogprobDiffFP1e6: 275000, AbsLogprobDiffP95FP1e6: 500000, AbsLogprobDiffP99FP1e6: 500000,
		RankDeltaNonzeroRateFP1e6: 1000000, ComparedRankCount: 2,
	}
	if got != want {
		t.Fatalf("summary = %+v, want %+v", got, want)
	}
}

// The chain vector: result_metric_v3.json's leaves summarise to the
// metric_summary result_receipt_v3.json signs.
func TestSummaryV3ReproducesThePublishedReceiptSummary(t *testing.T) {
	var samples []SampleV3
	requiredTopK := uint32(0)
	for _, vector := range loadV3Vectors(t, "task/result_metric_v3.json") {
		if vector.Domain != DomainLeafV3 {
			continue
		}
		binding, sample, _, _ := parseLeafV3(t, vector)
		requiredTopK = binding.RequiredTopK
		samples = append(samples, sample)
	}
	got, err := SummaryV3(Spec{CompareLogprobDiff: true, CompareRankDelta: true, ComparedTopK: requiredTopK}, requiredTopK, samples)
	if err != nil {
		t.Fatal(err)
	}
	data, err := wirevectors.File("task/result_receipt_v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			Name   string `json:"name"`
			Fields []struct {
				Fields []struct {
					Name    string `json:"name"`
					Value   uint32 `json:"value"`
					Present *bool  `json:"present"`
				} `json:"fields"`
			} `json:"fields"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	published := map[string]uint32{}
	for _, v := range file.Vectors {
		if v.Name != "metric_summary_v1" {
			continue
		}
		for _, f := range v.Fields[0].Fields {
			if f.Present == nil || *f.Present {
				published[f.Name] = f.Value
			}
		}
	}
	if len(published) == 0 {
		t.Fatal("result_receipt_v3.json publishes no metric_summary_v1")
	}
	for name, value := range map[string]uint32{
		"finite_count": got.FiniteCount, "missing_compared_count": got.MissingComparedCount,
		"mean_abs_logprob_diff_fp_1e6": got.MeanAbsLogprobDiffFP1e6, "abs_logprob_diff_p95_fp_1e6": got.AbsLogprobDiffP95FP1e6,
		"abs_logprob_diff_p99_fp_1e6": got.AbsLogprobDiffP99FP1e6, "rank_delta_nonzero_rate_fp_1e6": got.RankDeltaNonzeroRateFP1e6,
		"compared_topk_count": got.ComparedTopkCount, "compared_rank_count": got.ComparedRankCount,
	} {
		if published[name] != value {
			t.Fatalf("%s = %d, the chain vector publishes %d", name, value, published[name])
		}
	}
}

// A token outside the required top-k on one side is a rank change; both sides
// outside is not. No window rule beyond the leaf applies.
func TestSummaryV3CountsOneSideRankZero(t *testing.T) {
	samples := []SampleV3{
		normalSample(0, -100, -100, 0, 3), // one side outside: counts
		normalSample(1, -100, -100, 2, 0), // other side outside: counts
		normalSample(2, -100, -100, 0, 0), // both outside: rank_delta 0
		normalSample(3, -100, -100, 4, 4), // agree
	}
	got, err := SummaryV3(Spec{CompareRankDelta: true, ComparedTopK: 4}, 4, samples)
	if err != nil {
		t.Fatal(err)
	}
	if got.RankDeltaNonzeroRateFP1e6 != 500000 || got.ComparedRankCount != 4 {
		t.Fatalf("rank rate = %d over %d, want 500000 over 4", got.RankDeltaNonzeroRateFP1e6, got.ComparedRankCount)
	}
	off, err := SummaryV3(Spec{ComparedTopK: 4}, 4, samples)
	if err != nil || off.RankDeltaNonzeroRateFP1e6 != 0 || off.ComparedRankCount != 0 {
		t.Fatalf("rank compare off = %+v, %v, want both rank fields 0", off, err)
	}
}

// Non-finite leaves count in missing_compared_count, so the two counts always
// cover the tree.
func TestSummaryV3CountsNonFiniteLeavesAsMissing(t *testing.T) {
	samples := []SampleV3{normalSample(0, -1, -1, 1, 1), {OutputPosition: 1}, {OutputPosition: 2, Missing: true}}
	got, err := SummaryV3(Spec{ComparedTopK: 4}, 4, samples)
	if err != nil || got.FiniteCount != 1 || got.MissingComparedCount != 2 {
		t.Fatalf("summary = %+v, %v, want finite 1 missing 2", got, err)
	}
}

// compared_topk_count is |F| when either ratio is compared, and each ratio's
// presence follows its own flag.
func TestSummaryV3ComparedTopKCountFollowsEitherRatio(t *testing.T) {
	sample := func(p uint32, jaccard, js uint32) SampleV3 {
		s := normalSample(p, -1, -1, 1, 1)
		s.TopKJaccardFP1e6 = OptionalFP1e6{Value: jaccard, Present: true}
		s.UnionJSFP1e6 = OptionalFP1e6{Value: js, Present: true}
		return s
	}
	samples := []SampleV3{sample(0, 800000, 10), sample(1, 900001, 30)}
	onlyJS, err := SummaryV3(Spec{CompareUnionJS: true, ComparedTopK: 4}, 4, samples)
	if err != nil {
		t.Fatal(err)
	}
	if onlyJS.ComparedTopkCount != 2 || onlyJS.TopkJaccardMeanFP1e6.Present || onlyJS.UnionJSP99FP1e6 != nodewire.PresentUint32(30) {
		t.Fatalf("union JS only = %+v", onlyJS)
	}
	both, err := SummaryV3(Spec{CompareTopKJaccard: true, CompareUnionJS: true, ComparedTopK: 4}, 4, samples)
	if err != nil {
		t.Fatal(err)
	}
	// (800000 + 900001) / 2 = 850000.5, rounded half up.
	if both.TopkJaccardMeanFP1e6 != nodewire.PresentUint32(850001) || both.ComparedTopkCount != 2 {
		t.Fatalf("both ratios = %+v", both)
	}
	neither, err := SummaryV3(Spec{ComparedTopK: 4}, 4, samples)
	if err != nil || neither.ComparedTopkCount != 0 || neither.TopkJaccardMeanFP1e6.Present || neither.UnionJSP99FP1e6.Present {
		t.Fatalf("neither ratio = %+v, %v", neither, err)
	}
	unmeasured := []SampleV3{normalSample(0, -1, -1, 1, 1)}
	if _, err := SummaryV3(Spec{CompareTopKJaccard: true, ComparedTopK: 4}, 4, unmeasured); err == nil {
		t.Fatal("a required ratio the leaf does not carry was accepted")
	}
}

// vLLM clamps logprobs at -9999.0, so a legitimate difference can exceed the
// uint32 fp_1e6 range; the three abs-diff fields saturate instead of refusing.
func TestSummaryV3SaturatesAbsDiff(t *testing.T) {
	samples := []SampleV3{normalSample(0, -9999000000, -100000, 1, 1)}
	got, err := SummaryV3(Spec{ComparedTopK: 4}, 4, samples)
	if err != nil {
		t.Fatal(err)
	}
	if got.MeanAbsLogprobDiffFP1e6 != math.MaxUint32 || got.AbsLogprobDiffP95FP1e6 != math.MaxUint32 || got.AbsLogprobDiffP99FP1e6 != math.MaxUint32 {
		t.Fatalf("summary = %+v, want the abs-diff fields saturated", got)
	}
}

// nearest_rank takes the ceil(q*n)-th smallest value.
func TestSummaryV3NearestRankPercentiles(t *testing.T) {
	samples := make([]SampleV3, 20)
	for i := range samples {
		samples[i] = normalSample(uint32(i), 0, -int64(i+1)*10, 1, 1) // diffs 10..200
	}
	got, err := SummaryV3(Spec{ComparedTopK: 4}, 4, samples)
	if err != nil {
		t.Fatal(err)
	}
	// p95: ceil(19) = 19th = 190; p99: ceil(19.8) = 20th = 200; mean 105.
	if got.AbsLogprobDiffP95FP1e6 != 190 || got.AbsLogprobDiffP99FP1e6 != 200 || got.MeanAbsLogprobDiffFP1e6 != 105 {
		t.Fatalf("summary = %+v", got)
	}
}

var allCompared = Spec{CompareLogprobDiff: true, CompareRankDelta: true, CompareTopKJaccard: true, CompareUnionJS: true, ComparedTopK: 4}

// Case 1: no leaves is a legal zero-token output. Every number is 0, each
// enabled ratio present(0), and the material still builds.
func TestSummaryV3ZeroLeaves(t *testing.T) {
	got, err := SummaryV3(allCompared, 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := nodewire.MetricSummaryV1{TopkJaccardMeanFP1e6: nodewire.PresentUint32(0), UnionJSP99FP1e6: nodewire.PresentUint32(0)}
	if got != want {
		t.Fatalf("summary = %+v, want %+v", got, want)
	}
	material, err := BuildV3(fixtureBinding(), testVerifierValueRoot, nil)
	if err != nil || material.LeafCount != 0 || material.Root.IsZero() {
		t.Fatalf("zero-leaf material = %+v, %v", material, err)
	}
}

// Case 2: every Worker value is missing or non-finite, so nothing is
// comparable and every comparison takes its worst value.
func TestSummaryV3WorkerSideEmptyTakesWorstValues(t *testing.T) {
	worker := []nodewire.PositionValueV1{{Position: 0, TokenID: 7, Missing: true}, {Position: 1, TokenID: 8}}
	verifier := []nodewire.PositionValueV1{
		{Position: 0, TokenID: 7, Finite: true, Rank: 1, TopK: []nodewire.TopKEntryV1{{TokenID: 7}}},
		{Position: 1, TokenID: 8, Finite: true, Rank: 1, TopK: []nodewire.TopKEntryV1{{TokenID: 8}}},
	}
	samples, err := CompareLeavesV3(allCompared, 4, worker, verifier)
	if err != nil {
		t.Fatal(err)
	}
	got, err := SummaryV3(allCompared, 4, samples)
	if err != nil {
		t.Fatal(err)
	}
	want := nodewire.MetricSummaryV1{
		MissingComparedCount:    2,
		MeanAbsLogprobDiffFP1e6: math.MaxUint32, AbsLogprobDiffP95FP1e6: math.MaxUint32, AbsLogprobDiffP99FP1e6: math.MaxUint32,
		RankDeltaNonzeroRateFP1e6: 1000000,
		TopkJaccardMeanFP1e6:      nodewire.PresentUint32(0), UnionJSP99FP1e6: nodewire.PresentUint32(1000000),
	}
	if got != want {
		t.Fatalf("summary = %+v, want %+v", got, want)
	}
	rankOff, err := SummaryV3(Spec{ComparedTopK: 4}, 4, samples)
	if err != nil || rankOff.RankDeltaNonzeroRateFP1e6 != 0 || rankOff.TopkJaccardMeanFP1e6.Present {
		t.Fatalf("worst values with rank and ratios off = %+v, %v", rankOff, err)
	}
}

// Case 3: F is empty because of the Verifier's own values while the Worker
// had a finite one. That is a Verifier execution failure, refused before any
// summary exists.
func TestCompareLeavesV3RefusesAVerifierSideEmptySet(t *testing.T) {
	worker := []nodewire.PositionValueV1{
		{Position: 0, TokenID: 7, Missing: true},
		{Position: 1, TokenID: 8, Finite: true, Rank: 1, TopK: []nodewire.TopKEntryV1{{TokenID: 8}}},
	}
	for name, verifierSecond := range map[string]nodewire.PositionValueV1{
		"verifier missing":    {Position: 1, TokenID: 8, Missing: true},
		"verifier non-finite": {Position: 1, TokenID: 8},
	} {
		verifier := []nodewire.PositionValueV1{{Position: 0, TokenID: 7, Missing: true}, verifierSecond}
		if _, err := CompareLeavesV3(allCompared, 4, worker, verifier); !errors.Is(err, ErrVerifierValuesUnavailable) {
			t.Fatalf("%s: err = %v, want ErrVerifierValuesUnavailable", name, err)
		}
	}
	// A Verifier-side gap next to a comparable position is an ordinary
	// missing leaf.
	both := append(worker, nodewire.PositionValueV1{Position: 2, TokenID: 9, Finite: true, Rank: 1, TopK: []nodewire.TopKEntryV1{{TokenID: 9}}})
	verifier := []nodewire.PositionValueV1{
		{Position: 0, TokenID: 7, Missing: true}, {Position: 1, TokenID: 8, Missing: true},
		{Position: 2, TokenID: 9, Finite: true, Rank: 1, TopK: []nodewire.TopKEntryV1{{TokenID: 9}}},
	}
	if _, err := CompareLeavesV3(Spec{ComparedTopK: 4}, 4, both, verifier); err != nil {
		t.Fatalf("a comparable position alongside a Verifier gap was refused: %v", err)
	}
}
