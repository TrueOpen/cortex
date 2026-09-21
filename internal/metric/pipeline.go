package metric

import (
	"fmt"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/nodewire"
)

// Material is everything the metric pipeline produces for one verification run:
// the three frozen result-credential values, plus the two facts an operator and
// a later opening need beside them.
type Material struct {
	// Root is metric_root, frozen ResultReceiptV2 field 8.
	Root codec.Hash
	// Summary is metric_summary, frozen ResultReceiptV2 field 9.
	Summary nodewire.MetricSummaryV1
	// AggregateProof carries the raw proof bytes and aggregate_proof_hash,
	// frozen ResultReceiptV2 field 10 / FullResultRevealV1 field 9.
	AggregateProof AggregateProof
	// LeafCount is the number of generated token positions the tree covers. The
	// VERIFIER_VALUE_OPENING carries metric_leaf_count beside metric_root, and
	// the tree itself records no length.
	LeafCount int
	// LeafHashes are the ordered leaves. They are kept so an opening can be
	// answered without re-running the model, and are never part of any preimage
	// beyond the root.
	LeafHashes []codec.Hash
}

// Build produces the metric material for one single-sample verification run.
//
// Ordering is not incidental. The profile is bound first, so an unsupported
// verification_mode or aggregate-proof version stops the run before any hashing;
// leaves are derived and their positions checked before the root exists, so a
// gap cannot be rooted; and the aggregate proof is built last because it
// commits to both the root and the summary.
//
// samples must be one entry per generated token position, in output_position
// order starting at zero. An empty set is refused: the empty MERKLE_ROOT_V1 is a
// perfectly valid 32 bytes, and submitting it would be a signed claim that the
// worker generated nothing.
//
// The aggregation is DERIVED here, not accepted from the caller. Root and
// summary must describe the same data, and the only way to guarantee that is to
// compute both from one input; see AggregateFromSamples.
func Build(binding Binding, samples []Sample) (Material, error) {
	if err := binding.validate(); err != nil {
		return Material{}, err
	}
	if len(samples) == 0 {
		return Material{}, fmt.Errorf(
			"metric pipeline has no token samples; an empty tree has a valid root, so it is refused rather " +
				"than signed as a claim that no token was generated")
	}
	leafHashes, err := LeafHashes(binding, samples)
	if err != nil {
		return Material{}, err
	}
	root, err := Root(leafHashes)
	if err != nil {
		return Material{}, err
	}
	summary, err := Summary(binding.Spec, AggregateFromSamples(samples, binding.RequiredTopK))
	if err != nil {
		return Material{}, err
	}
	proof, err := BuildAggregateProof(binding, root, len(leafHashes), summary)
	if err != nil {
		return Material{}, err
	}
	return Material{
		Root:           root,
		Summary:        summary,
		AggregateProof: proof,
		LeafCount:      len(leafHashes),
		LeafHashes:     leafHashes,
	}, nil
}
