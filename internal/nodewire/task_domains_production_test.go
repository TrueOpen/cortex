package nodewire_test

import (
	"encoding/hex"
	"testing"

	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// TestTaskDomainVectorsBindToProductionFunctions checks the task_domains_v1
// vectors that a Cortex production function derives, beyond the signing
// contracts TestProductionDigestsMatchGoldens covers.
func TestTaskDomainVectorsBindToProductionFunctions(t *testing.T) {
	vectors := goldenVectorsByName(t)

	t.Run("task_id_v1", func(t *testing.T) {
		vector := requireVector(t, vectors, "task_id_v1")
		session := hex.EncodeToString(fieldBytes(t, vector, 0, "session_id"))
		got := identity.TaskID(session, fieldUint(t, vector, 1, "order_sequence"))
		if got.String() != vector.DigestHex {
			t.Fatalf("TaskID = %s, published %s", got, vector.DigestHex)
		}
	})

	t.Run("metric_summary_v1_optional_presence", func(t *testing.T) {
		vector := requireVector(t, vectors, "metric_summary_v1_optional_presence")
		summary := goldenVector{Name: vector.Name + ".summary", Fields: vector.Fields[0].Fields}
		got, err := nodewire.MetricSummaryHash(nodewire.MetricSummaryV1{
			FiniteCount:               uint32(fieldUint(t, summary, 0, "finite_count")),
			MissingComparedCount:      uint32(fieldUint(t, summary, 1, "missing_compared_count")),
			MeanAbsLogprobDiffFP1e6:   uint32(fieldUint(t, summary, 2, "mean_abs_logprob_diff_fp_1e6")),
			AbsLogprobDiffP95FP1e6:    uint32(fieldUint(t, summary, 3, "abs_logprob_diff_p95_fp_1e6")),
			AbsLogprobDiffP99FP1e6:    uint32(fieldUint(t, summary, 4, "abs_logprob_diff_p99_fp_1e6")),
			RankDeltaNonzeroRateFP1e6: uint32(fieldUint(t, summary, 5, "rank_delta_nonzero_rate_fp_1e6")),
			TopkJaccardMeanFP1e6:      fieldOptionalUint32(t, summary, 6, "topk_jaccard_mean_fp_1e6"),
			UnionJSP99FP1e6:           fieldOptionalUint32(t, summary, 7, "union_js_p99_fp_1e6"),
			ComparedTopkCount:         uint32(fieldUint(t, summary, 8, "compared_topk_count")),
			ComparedRankCount:         uint32(fieldUint(t, summary, 9, "compared_rank_count")),
		})
		if err != nil || got.String() != vector.DigestHex {
			t.Fatalf("MetricSummaryHash = %s (%v), published %s", got, err, vector.DigestHex)
		}
	})
}
