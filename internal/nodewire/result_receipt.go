package nodewire

import (
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
)

// DomainMetricSummaryV1 hashes the canonical nested summary frame.
const DomainMetricSummaryV1 = "TRUEOPEN_METRIC_SUMMARY_V1"

// OptionalUint32 carries the explicit presence of a proto3 optional uint32. The
// zero value is absent, which matches the wire: whether MetricSummaryV1 fields 7
// and 8 are present is decided solely by the locked profile MetricSpec, and an
// absent metric is a different fact from a metric that measured zero.
type OptionalUint32 struct {
	Value   uint32
	Present bool
}

// PresentUint32 marks an optional uint32 as present. Absent is OptionalUint32{}.
func PresentUint32(value uint32) OptionalUint32 {
	return OptionalUint32{Value: value, Present: true}
}

// MetricSummaryV1 is the frozen typed verification summary carried as
// ResultReceiptV2 field 9. Fields are in schema field-number order, which is
// also the order the nested frame writes them. There are no floats, no maps and
// no free JSON: the whole message is fixed-width big-endian integers plus the
// two presence-tagged optionals.
type MetricSummaryV1 struct {
	FiniteCount               uint32
	MissingComparedCount      uint32
	MeanAbsLogprobDiffFP1e6   uint32
	AbsLogprobDiffP95FP1e6    uint32
	AbsLogprobDiffP99FP1e6    uint32
	RankDeltaNonzeroRateFP1e6 uint32
	TopkJaccardMeanFP1e6      OptionalUint32 // proto3 optional, wire field 7
	UnionJSP99FP1e6           OptionalUint32 // proto3 optional, wire field 8
	ComparedTopkCount         uint32
	ComparedRankCount         uint32
}

// MetricSummaryHash derives metric_summary_hash:
//
//	H_FIELDS_V1("TRUEOPEN_METRIC_SUMMARY_V1", canonical MetricSummaryV1)
//
// One field: the same nested frame the result credential carries as its field 9.
// The summary is a message, so it is framed as a nested value and not flattened
// into ten top-level fields - the frame the Keeper hashes is the frame the
// signature already covers.
func MetricSummaryHash(summary MetricSummaryV1) (codec.Hash, error) {
	return hfields.Digest(DomainMetricSummaryV1, metricSummaryFrame(summary))
}

// metricSummaryFrame encodes MetricSummaryV1 as a nested FieldFrameV1 with no
// domain prefix and its ten members in ascending schema field-number order:
//
//	u64_be(4)  || uint32_be(finite_count)
//	u64_be(4)  || uint32_be(missing_compared_count)
//	u64_be(4)  || uint32_be(mean_abs_logprob_diff_fp_1e6)
//	u64_be(4)  || uint32_be(abs_logprob_diff_p95_fp_1e6)
//	u64_be(4)  || uint32_be(abs_logprob_diff_p99_fp_1e6)
//	u64_be(4)  || uint32_be(rank_delta_nonzero_rate_fp_1e6)
//	u64_be(n)  || optional topk_jaccard_mean_fp_1e6
//	u64_be(n)  || optional union_js_p99_fp_1e6
//	u64_be(4)  || uint32_be(compared_topk_count)
//	u64_be(4)  || uint32_be(compared_rank_count)
//
// The whole frame is one top-level field of the result preimage. Flattening it
// into ten fields would produce a different digest for the same message.
func metricSummaryFrame(summary MetricSummaryV1) hfields.Field {
	return hfields.Frame(
		hfields.Uint32(summary.FiniteCount),
		hfields.Uint32(summary.MissingComparedCount),
		hfields.Uint32(summary.MeanAbsLogprobDiffFP1e6),
		hfields.Uint32(summary.AbsLogprobDiffP95FP1e6),
		hfields.Uint32(summary.AbsLogprobDiffP99FP1e6),
		hfields.Uint32(summary.RankDeltaNonzeroRateFP1e6),
		optionalUint32Field(summary.TopkJaccardMeanFP1e6),
		optionalUint32Field(summary.UnionJSP99FP1e6),
		hfields.Uint32(summary.ComparedTopkCount),
		hfields.Uint32(summary.ComparedRankCount),
	)
}

// optionalUint32Field encodes one proto3-optional uint32 with explicit presence:
//
//	absent  -> 0x00
//	present -> 0x01 || u64_be(4) || uint32_be(value)
//
// The presence byte is what stops an absent metric from colliding with a metric
// that measured exactly zero, and it is not itself length-prefixed - the framed
// value is appended to it raw, and the concatenation is the field. Encoding
// absent as a present zero, or dropping the inner frame, both silently merge two
// distinct summaries into one digest.
func optionalUint32Field(value OptionalUint32) hfields.Field {
	return hfields.Optional(value.Present, hfields.Uint32(value.Value))
}
