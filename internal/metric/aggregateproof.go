package metric

import (
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// AggregateProof is the metric aggregate proof and the plain SHA-256 the frozen
// wire carries as aggregate_proof_hash.
//
// # Why the hash is a bare SHA-256
//
// It is one of exactly three values canonical-encoding-and-domain-hashing §9.3 permits as a bare
// SHA-256 producer — the proof is an opaque blob, so it has no field frame to
// hash. It is NOT H_V1 and NOT H_FIELDS_V1, and result_reveal_hash sitting next
// to it in the same preimage IS H_V1: unifying the two produces a credential no
// Keeper accepts.
type AggregateProof struct {
	// Bytes is the raw proof exactly as it goes on the wire as
	// FullResultRevealV1 field 9. aggregate_proof_hash is SHA-256 of these
	// bytes and nothing else, so they are stored rather than re-encoded.
	Bytes []byte
	Hash  codec.Hash
}

// BuildAggregateProof encodes the aggregate proof for
// metric_aggregate_proof_version = PREFILL_METRIC_AGGREGATE_PROOF_V1.
//
// # This blob introduces no domain, and that is deliberate
//
// The bytes are a bare FRAME_V1 (§3.2) — a length-framed field list with no
// domain and no magic. An earlier draft built them with H_FIELDS_V1 framing,
// which was wrong twice over: it put the version token in the domain slot §4.2
// governs (a domain must match ^TRUEOPEN_[A-Z0-9_]+_V[1-9][0-9]* and be registered,
// and "PREFILL_METRIC_AGGREGATE_PROOF_V1" is neither), and it hashed the
// locked-profile projection under an invented TRUEOPEN_..._BINDING_V1 domain that
// exists in no registry. §7 requires every domain be registered before use, so
// the fix is not to register two new ones — it is to need none. A blob committed
// to by a bare SHA-256 has no domain separation to provide.
//
// # What is in it, and what is still missing
//
// No monorepo document defines the CONTENT of aggregate_proof. keeper §5.14
// defines only its hash, §10.11 rule 7 bounds its size together with result_reveal,
// rule 8 says it uses "the canonical compact encoding bound to the profile" without
// saying which, and §9.7 opening rule 5 says the proof plus the counts
// and the finite/missing facts must satisfy the locked MetricSpec. On the normal
// reveal path the chain hashes the blob and compares; it does not parse it.
//
// So the encoding below is Cortex's, and it is stated rather than implied:
//
//	FRAME_V1(
//	  utf8("PREFILL_METRIC_AGGREGATE_PROOF_V1"),   # self-describing version
//	  utf8(chain_id),
//	  task_id,
//	  utf8(model_id),
//	  u32_be(profile_version),
//	  utf8(judgment_function_version),
//	  utf8(canonical_encoding_version),
//	  evidence_schema_hash,
//	  tokenizer_hash,
//	  generation_params_digest,
//	  u32_be(required_top_k),
//	  compare_logprob_diff, compare_rank_delta,
//	  compare_topk_jaccard, compare_union_js,       # 1 byte each
//	  u32_be(compared_top_k),
//	  metric_root,
//	  u32_be(metric_leaf_count),
//	  metric_summary_hash,
//	)
//
// The locked-profile fields are inlined rather than pre-hashed, so the blob is
// readable by anyone holding it without a second digest definition to agree on.
// The summary enters as its metric_summary_hash because nodewire owns the §9.7
// field order and a second encoder of it here would be a place for the two to
// drift; the hash is injective over the summary, so the commitment is the same.
//
// # The honest limits
//
// This binds the summary to the root, the count and the locked profile. It does
// NOT by itself prove the summary is the aggregation of those leaves — that
// property comes from SummaryV3 being the only aggregator, so an
// opening that reveals the leaves lets anyone recompute the summary and check
// it. A proof that carried the aggregation inline would be O(tokens) inside a
// consensus state whose bound nobody has published.
//
// It remains UNREGISTERED upstream. A second implementer cannot produce
// byte-identical bytes from the specification, because the specification does
// not describe them. That is an open protocol question raised on WORK-55, not a
// property this package can fix; until it is answered the only thing the chain
// relies on is that the hash is stable and the producer can reproduce it.
func BuildAggregateProof(
	binding Binding,
	metricRoot codec.Hash,
	leafCount int,
	summary nodewire.MetricSummaryV1,
) (AggregateProof, error) {
	if err := binding.validate(); err != nil {
		return AggregateProof{}, err
	}
	if metricRoot.IsZero() {
		return AggregateProof{}, fmt.Errorf("aggregate proof requires a derived metric_root")
	}
	count, err := countUint32("metric_leaf_count", leafCount)
	if err != nil {
		return AggregateProof{}, err
	}
	summaryHash, err := nodewire.MetricSummaryHash(summary)
	if err != nil {
		return AggregateProof{}, fmt.Errorf("derive metric_summary_hash for the aggregate proof: %w", err)
	}
	fields := append(
		[]hfields.Field{hfields.String(AggregateProofVersionV1)},
		binding.proofFields()...,
	)
	fields = append(fields,
		hfields.Hash(metricRoot),
		hfields.Uint32(count),
		hfields.Hash(summaryHash),
	)
	proof, err := hfields.FrameBytes(fields...)
	if err != nil {
		return AggregateProof{}, err
	}
	return AggregateProof{Bytes: proof, Hash: codec.HashBytes(proof)}, nil
}

// proofFields is the locked binding as ordered frame fields, in Binding's own
// declaration order — the same order the leaf preimage carries them in.
func (b Binding) proofFields() []hfields.Field {
	return []hfields.Field{
		hfields.String(b.ChainID),
		hfields.Hash(b.TaskID),
		hfields.String(b.ModelID),
		hfields.Uint32(b.ProfileVersion),
		hfields.String(b.JudgmentFunctionVersion),
		hfields.String(b.CanonicalEncodingVersion),
		hfields.Hash(b.EvidenceSchemaHash),
		hfields.Hash(b.TokenizerHash),
		hfields.Hash(b.GenerationParamsDigest),
		hfields.Uint32(b.RequiredTopK),
		hfields.Bool(b.Spec.CompareLogprobDiff),
		hfields.Bool(b.Spec.CompareRankDelta),
		hfields.Bool(b.Spec.CompareTopKJaccard),
		hfields.Bool(b.Spec.CompareUnionJS),
		hfields.Uint32(b.Spec.ComparedTopK),
	}
}
