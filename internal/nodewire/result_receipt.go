package nodewire

import (
	"fmt"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/hfields"
)

// DomainResultV2 is the released verifier credential signing domain.
const DomainResultV2 = "TRUEOPEN_RESULT_V2"

// DomainMetricSummaryV1 hashes the canonical nested summary frame.
const DomainMetricSummaryV1 = "TRUEOPEN_METRIC_SUMMARY_V1"

// ResultReceiptSchemaVersionV2 rejects the retired V1 credential.
const ResultReceiptSchemaVersionV2 uint32 = 2

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

// ResultReceiptV2 binds a verifier result to its bundle manifest and salt.
// ServiceSignature is field 15 and is excluded from the signing preimage.
// Keeper derives commit_key, metric_summary_hash and result_payload_hash.
type ResultReceiptV2 struct {
	SchemaVersion                     uint32
	ChainID                           string
	TaskID                            []byte // Hash32
	VerifyRound                       uint32
	VerifierOperatorAddress           string // canonical Bech32; framed as codec bytes
	ServiceAuthorizationNonce         uint64
	GenerationParamsDigest            []byte // Hash32
	MetricRoot                        []byte // Hash32
	MetricSummary                     MetricSummaryV1
	AggregateProofHash                []byte // Hash32: PLAIN SHA-256 of the proof bytes
	VerifierEvidenceBundleHash        []byte // Hash32: H_V1 of the canonical manifest
	VerifierEvidenceManifestSizeBytes uint64
	Salt                              []byte // Hash32
	ExpiryHeight                      uint64
	ServiceSignature                  []byte // excluded from the preimage
}

// ResultReceiptSigningPreimage frames the fourteen V2 fields in schema order.
// MetricSummary is one nested field and operator addresses use codec bytes.
func ResultReceiptSigningPreimage(receipt ResultReceiptV2) ([]byte, error) {
	if receipt.SchemaVersion != ResultReceiptSchemaVersionV2 {
		return nil, fmt.Errorf("result receipt schema_version must be 2")
	}
	chainID, err := canonicalUTF8Field("chain_id", receipt.ChainID)
	if err != nil {
		return nil, err
	}
	taskID, err := canonicalHash32("task_id", receipt.TaskID)
	if err != nil {
		return nil, err
	}
	verifier, err := CanonicalOperatorAddressBytes("verifier_operator_address", receipt.VerifierOperatorAddress)
	if err != nil {
		return nil, err
	}
	generationParamsDigest, err := canonicalHash32("generation_params_digest", receipt.GenerationParamsDigest)
	if err != nil {
		return nil, err
	}
	metricRoot, err := canonicalHash32("metric_root", receipt.MetricRoot)
	if err != nil {
		return nil, err
	}
	aggregateProofHash, err := canonicalHash32("aggregate_proof_hash", receipt.AggregateProofHash)
	if err != nil {
		return nil, err
	}
	verifierEvidenceBundleHash, err := canonicalHash32("verifier_evidence_bundle_hash", receipt.VerifierEvidenceBundleHash)
	if err != nil {
		return nil, err
	}
	salt, err := canonicalHash32("salt", receipt.Salt)
	if err != nil {
		return nil, err
	}
	return hfields.Preimage(
		DomainResultV2,
		hfields.Uint32(receipt.SchemaVersion),
		hfields.String(chainID),
		hfields.Bytes(taskID),
		hfields.Uint32(receipt.VerifyRound),
		hfields.Bytes(verifier),
		hfields.Uint64(receipt.ServiceAuthorizationNonce),
		hfields.Bytes(generationParamsDigest),
		hfields.Bytes(metricRoot),
		metricSummaryFrame(receipt.MetricSummary),
		hfields.Bytes(aggregateProofHash),
		hfields.Bytes(verifierEvidenceBundleHash),
		hfields.Uint64(receipt.VerifierEvidenceManifestSizeBytes),
		hfields.Bytes(salt),
		hfields.Uint64(receipt.ExpiryHeight),
	)
}

// ResultReceiptSigningDigest is the frozen result credential digest: the value a
// verifier's service key signs, and the value the Keeper recomputes from the
// submitted body before it will accept anything.
func ResultReceiptSigningDigest(receipt ResultReceiptV2) (codec.Hash, error) {
	return digestOf(ResultReceiptSigningPreimage(receipt))
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
