package verifier

import (
	"encoding/json"
	"testing"

	"github.com/TrueOpen/cortex/internal/metric"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/wirevectors"
)

// sourcedReceipt is a result body whose every other frozen value is sourced, so
// only the metric summary decides whether it may be signed.
func sourcedReceipt(summary nodewire.MetricSummaryV1, leafCount uint32) nodewire.ResultReceiptV3 {
	one := make([]byte, 32)
	one[31] = 1
	return nodewire.ResultReceiptV3{
		MetricRoot: one, MetricSummary: summary, MetricLeafCount: leafCount, AggregateProofHash: one,
		VerifierEvidenceBundleHash: one, VerifierEvidenceManifestSizeBytes: 1, Salt: one, VerifierValueRoot: one,
	}
}

// A zero-leaf result is a legal zero-token output. Whatever optional ratios the
// profile enables, the summary SummaryV3 derives for it must pass the signing
// gate.
func TestZeroLeafSummaryIsSignable(t *testing.T) {
	for _, tc := range []struct {
		name            string
		jaccard, unionJ bool
	}{
		{"both optional ratios off", false, false},
		{"top-k jaccard on", true, false},
		{"union JS on", false, true},
		{"both optional ratios on", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := metric.Spec{CompareLogprobDiff: true, CompareRankDelta: true,
				CompareTopKJaccard: tc.jaccard, CompareUnionJS: tc.unionJ, ComparedTopK: 4}
			summary, err := metric.SummaryV3(spec, 4, nil)
			if err != nil {
				t.Fatal(err)
			}
			if unsourced := resultReceiptUnsourced(sourcedReceipt(summary, 0)); len(unsourced) != 0 {
				t.Fatalf("legal zero-leaf summary %+v refused as unsourced: %v", summary, unsourced)
			}
		})
	}
}

// wire's metric_summary_v1_zero_leaves vector (all four comparisons enabled)
// is the published shape of a zero-leaf summary; it must pass the gate.
func TestWireZeroLeafSummaryVectorIsSignable(t *testing.T) {
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
					Fields  []struct {
						Value uint32 `json:"value"`
					} `json:"fields"`
				} `json:"fields"`
			} `json:"fields"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	for _, v := range file.Vectors {
		if v.Name != "metric_summary_v1_zero_leaves" {
			continue
		}
		var s nodewire.MetricSummaryV1
		for _, f := range v.Fields[0].Fields {
			optional := nodewire.OptionalUint32{}
			if f.Present != nil && *f.Present {
				optional = nodewire.PresentUint32(f.Fields[0].Value)
			}
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
				s.TopkJaccardMeanFP1e6 = optional
			case "union_js_p99_fp_1e6":
				s.UnionJSP99FP1e6 = optional
			case "compared_topk_count":
				s.ComparedTopkCount = f.Value
			case "compared_rank_count":
				s.ComparedRankCount = f.Value
			default:
				t.Fatalf("unexpected summary field %s", f.Name)
			}
		}
		derived, err := metric.SummaryV3(metric.Spec{CompareLogprobDiff: true, CompareRankDelta: true,
			CompareTopKJaccard: true, CompareUnionJS: true, ComparedTopK: 4}, 4, nil)
		if err != nil || derived != s {
			t.Fatalf("SummaryV3 zero-leaf = %+v (%v), wire publishes %+v", derived, err, s)
		}
		if unsourced := resultReceiptUnsourced(sourcedReceipt(s, 0)); len(unsourced) != 0 {
			t.Fatalf("wire zero-leaf summary refused as unsourced: %v", unsourced)
		}
		return
	}
	t.Fatal("wire publishes no metric_summary_v1_zero_leaves vector")
}

// A summary that never came from a verify run must still be refused: with
// metric leaves present an all-zero summary is not a legal outcome, and a
// zero-leaf body cannot carry non-zero members.
func TestMissingMetricSummaryIsStillRefused(t *testing.T) {
	for name, receipt := range map[string]nodewire.ResultReceiptV3{
		"absent summary with leaves":    sourcedReceipt(nodewire.MetricSummaryV1{}, 3),
		"zero-leaf with a count":        sourcedReceipt(nodewire.MetricSummaryV1{FiniteCount: 1}, 0),
		"zero-leaf with non-zero ratio": sourcedReceipt(nodewire.MetricSummaryV1{UnionJSP99FP1e6: nodewire.PresentUint32(1)}, 0),
	} {
		t.Run(name, func(t *testing.T) {
			unsourced := resultReceiptUnsourced(receipt)
			if len(unsourced) != 1 || unsourced[0] != "metric_summary" {
				t.Fatalf("unsourced = %v, want [metric_summary]", unsourced)
			}
		})
	}
	// With no metric material at all the root is zero too, and the zero-leaf
	// summary is reported as unsourced beside it.
	absent := sourcedReceipt(nodewire.MetricSummaryV1{}, 0)
	absent.MetricRoot = make([]byte, 32)
	unsourced := resultReceiptUnsourced(absent)
	if len(unsourced) != 2 || unsourced[0] != "metric_root" || unsourced[1] != "metric_summary" {
		t.Fatalf("unsourced = %v, want [metric_root metric_summary]", unsourced)
	}
}
