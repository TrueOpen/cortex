package metric

import (
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// Material is everything the metric pipeline produces for one verification run:
// the three frozen result-credential values, plus the two facts an operator and
// a later opening need beside them.
type Material struct {
	// Root is metric_root, ResultReceiptV3 field 8.
	Root codec.Hash
	// Summary is metric_summary, ResultReceiptV3 field 9.
	Summary nodewire.MetricSummaryV1
	// AggregateProof carries the raw proof bytes and aggregate_proof_hash,
	// ResultReceiptV3 field 10.
	AggregateProof AggregateProof
	// VerifierValueRoot is the root of this Verifier's own value tree. The
	// commit binds it, every V3 metric leaf carries it, and ResultReceiptV3
	// field 16 and the reveal payload repeat it.
	VerifierValueRoot codec.Hash
	// LeafCount is the number of generated token positions the tree covers. The
	// VERIFIER_VALUE_OPENING carries metric_leaf_count beside metric_root, and
	// the tree itself records no length.
	LeafCount int
	// LeafHashes are the ordered leaves. They are kept so an opening can be
	// answered without re-running the model, and are never part of any preimage
	// beyond the root.
	LeafHashes []codec.Hash
}
