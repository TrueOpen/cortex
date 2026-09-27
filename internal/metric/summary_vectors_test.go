package metric

import (
	"encoding/json"
	"testing"

	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/wirevectors"
)

// summaryVector is one standalone MetricSummaryV1 vector of
// result_receipt_v3.json: its inputs, its ten fields and its digest.
type summaryVector struct {
	Name      string `json:"name"`
	DigestHex string `json:"digest_hex"`
	Inputs    struct {
		CompareLogprobDiff bool `json:"compare_logprob_diff"`
		CompareRankDelta   bool `json:"compare_rank_delta"`
		CompareTopKJaccard bool `json:"compare_topk_jaccard"`
		CompareUnionJS     bool `json:"compare_union_js"`
		Leaves             []struct {
			OutputPosition uint32 `json:"output_position"`
			WorkerValue    string `json:"worker_value"`
			VerifierValue  string `json:"verifier_value"`
		} `json:"leaves"`
	} `json:"inputs"`
	Fields []struct {
		Fields []struct {
			Name    string `json:"name"`
			Value   uint32 `json:"value"`
			Present *bool  `json:"present"`
			Fields  []struct {
				Value uint32 `json:"value"`
			} `json:"fields"`
		} `json:"fields"`
	} `json:"fields"`
}

func (v summaryVector) summary(t *testing.T) nodewire.MetricSummaryV1 {
	t.Helper()
	var s nodewire.MetricSummaryV1
	optional := func(f struct {
		Name    string `json:"name"`
		Value   uint32 `json:"value"`
		Present *bool  `json:"present"`
		Fields  []struct {
			Value uint32 `json:"value"`
		} `json:"fields"`
	}) nodewire.OptionalUint32 {
		if f.Present == nil || !*f.Present {
			return nodewire.OptionalUint32{}
		}
		return nodewire.PresentUint32(f.Fields[0].Value)
	}
	for _, f := range v.Fields[0].Fields {
		switch f.Name {
		case "finite_count":
			s.FiniteCount = f.Value
		case "missing_compared_count":
			s.MissingComparedCount = f.Value
		case "mean_abs_logprob_diff_fp_1e6":
			s.MeanAbsLogprobDiffFP1e6 = f.Value
		case "abs_logprob_diff_p95_fp_1e6":
			s.AbsLogprobDiffP95FP1e6 = f.Value
		case "abs_logprob_diff_p99_fp_1e6":
			s.AbsLogprobDiffP99FP1e6 = f.Value
		case "rank_delta_nonzero_rate_fp_1e6":
			s.RankDeltaNonzeroRateFP1e6 = f.Value
		case "topk_jaccard_mean_fp_1e6":
			s.TopkJaccardMeanFP1e6 = optional(f)
		case "union_js_p99_fp_1e6":
			s.UnionJSP99FP1e6 = optional(f)
		case "compared_topk_count":
			s.ComparedTopkCount = f.Value
		case "compared_rank_count":
			s.ComparedRankCount = f.Value
		default:
			t.Fatalf("%s: unexpected summary field %s", v.Name, f.Name)
		}
	}
	return s
}

// The two published summaries with no comparable leaf are reproduced from
// their inputs: no leaves at all, and three leaves whose Worker values are all
// missing. Both the fields and the TRUEOPEN_METRIC_SUMMARY_V1 digest match.
func TestSummaryV3ReproducesThePublishedEmptySummaries(t *testing.T) {
	data, err := wirevectors.File("task/result_receipt_v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []summaryVector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	const requiredTopK = 4
	seen := 0
	for _, v := range file.Vectors {
		if v.Name != "metric_summary_v1_zero_leaves" && v.Name != "metric_summary_v1_worker_values_missing" {
			continue
		}
		seen++
		spec := Spec{CompareLogprobDiff: v.Inputs.CompareLogprobDiff, CompareRankDelta: v.Inputs.CompareRankDelta,
			CompareTopKJaccard: v.Inputs.CompareTopKJaccard, CompareUnionJS: v.Inputs.CompareUnionJS, ComparedTopK: requiredTopK}
		worker := make([]nodewire.PositionValueV1, len(v.Inputs.Leaves))
		verifier := make([]nodewire.PositionValueV1, len(v.Inputs.Leaves))
		for i, leaf := range v.Inputs.Leaves {
			value := func(state string) nodewire.PositionValueV1 {
				out := nodewire.PositionValueV1{Position: leaf.OutputPosition, TokenID: 100 + leaf.OutputPosition}
				switch state {
				case "missing":
					out.Missing = true
				case "finite":
					out.Finite, out.LogprobFP1e6, out.Rank = true, -500000, 1
					out.TopK = []nodewire.TopKEntryV1{{TokenID: out.TokenID, LogprobFP1e6: -500000}}
				default:
					t.Fatalf("%s: unknown leaf state %q", v.Name, state)
				}
				return out
			}
			worker[i], verifier[i] = value(leaf.WorkerValue), value(leaf.VerifierValue)
		}
		samples, err := CompareLeavesV3(spec, requiredTopK, worker, verifier)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		got, err := SummaryV3(spec, requiredTopK, samples)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if want := v.summary(t); got != want {
			t.Fatalf("%s: summary = %+v, published %+v", v.Name, got, want)
		}
		digest, err := nodewire.MetricSummaryHash(got)
		if err != nil || digest.String() != v.DigestHex {
			t.Fatalf("%s: metric_summary_hash = %s, published %s (%v)", v.Name, digest, v.DigestHex, err)
		}
	}
	if seen != 2 {
		t.Fatalf("found %d empty-summary vectors, want 2", seen)
	}
}
