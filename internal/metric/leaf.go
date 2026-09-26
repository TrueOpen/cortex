// Package metric produces canonical wire v0.3.0 verifier metric leaves,
// roots, typed summaries and aggregate proofs.
package metric

const (
	// LeafVersionV1 is the leaf_version 05-verification-algorithm §7 frames as the first field
	// of the leaf hash, beside the canonical leaf bytes. It is a schema counter
	// inside the domain, not the domain's own version.
	LeafVersionV1 uint32 = 1
)

// OptionalFP is one optional fixed-point metric with explicit presence. Absent
// and "present, measured zero" are different facts and encode differently, so
// the zero value is absent rather than zero.
type OptionalFP struct {
	Value   float64
	Present bool
}

// PresentFP marks an optional metric as measured.
func PresentFP(value float64) OptionalFP { return OptionalFP{Value: value, Present: true} }

// Sample is the verifier's prefill/teacher-forcing comparison at one generated
// token position, in real units. It is deliberately pre-fixed-point: the
// conversion, its rounding mode and its overflow rule live in one place
// (fixedpoint.go) rather than at every producer.
//
// WorkerRank / VerifierRank are 1-based, and zero means "this side reported no
// rank at all" — the same convention the model service already uses.
type Sample struct {
	OutputPosition  uint32
	EmittedTokenID  uint32
	WorkerLogprob   float64
	VerifierLogprob float64
	WorkerRank      uint32
	VerifierRank    uint32
	TopKJaccard     OptionalFP
	UnionJS         OptionalFP
	// Missing says the verifier's recomputation had no entry for the token the
	// worker emitted at this position.
	Missing bool
	// Finite says both logprobs were finite and therefore comparable. A
	// non-finite pair is still a leaf: the position happened, and dropping it
	// would renumber every later output_position.
	Finite bool
}
