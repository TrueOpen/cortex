// Package metric produces canonical wire v0.3.0 verifier metric leaves,
// roots, typed summaries and aggregate proofs.
package metric

const (
	// LeafVersionV1 is the leaf_version 05-verification-algorithm §7 frames as the first field
	// of the leaf hash, beside the canonical leaf bytes. It is a schema counter
	// inside the domain, not the domain's own version.
	LeafVersionV1 uint32 = 1
)
