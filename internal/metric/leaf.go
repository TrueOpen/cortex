// Package metric produces canonical wire v0.4.0 verifier metric leaves,
// roots, typed summaries and aggregate proofs.
package metric

import (
	"fmt"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/hfields"
)

const (
	// The V2 domains bind each metric to its accepted task and verify round.
	DomainLeafV2 = "TRUEOPEN_PREFILL_TOKEN_METRIC_LEAF_V2"
	DomainRootV2 = "TRUEOPEN_PREFILL_TOKEN_METRIC_ROOT_V2"

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

// LeafHash hashes leaf_version and the canonical V2 leaf frame. TaskHash and
// VerifyRound bind the accepted task scope; rank_delta is int64 and optional
// ratios are presence-tagged uint32 values, as published in metric_leaf_v2.json.
func LeafHash(binding Binding, sample Sample) (codec.Hash, error) {
	if err := binding.validate(); err != nil {
		return codec.Hash{}, err
	}
	position := fmt.Sprintf("output_position %d", sample.OutputPosition)

	workerLogprob, err := signedFP1e6(position+" worker_logprob", sample.WorkerLogprob)
	if err != nil {
		return codec.Hash{}, err
	}
	verifierLogprob, err := signedFP1e6(position+" verifier_logprob", sample.VerifierLogprob)
	if err != nil {
		return codec.Hash{}, err
	}
	absDiff := workerLogprob - verifierLogprob
	if absDiff < 0 {
		absDiff = -absDiff
	}
	// rank_delta is signed: the verifier ranking a token lower than the worker
	// did and ranking it higher are different observations, and an unsigned
	// delta would report them identically.
	rankDelta := int64(sample.VerifierRank) - int64(sample.WorkerRank)

	leaf := []hfields.Field{
		hfields.String(binding.ChainID),
		hfields.Hash(binding.TaskID),
		hfields.Hash(binding.TaskHash),
		hfields.Uint32(binding.VerifyRound),
		hfields.String(binding.ModelID),
		hfields.Uint32(binding.ProfileVersion),
		hfields.String(binding.JudgmentFunctionVersion),
		hfields.String(binding.CanonicalEncodingVersion),
		hfields.Hash(binding.EvidenceSchemaHash),
		hfields.String(binding.MetricAggregateProofVersion),
		hfields.Hash(binding.TokenizerHash),
		hfields.Hash(binding.GenerationParamsDigest),
		hfields.Uint32(sample.OutputPosition),
		hfields.Uint32(sample.EmittedTokenID),
		hfields.Uint32(binding.RequiredTopK),
		hfields.Int64(workerLogprob),
		hfields.Int64(verifierLogprob),
		hfields.Uint64(uint64(absDiff)),
		hfields.Uint32(sample.WorkerRank),
		hfields.Uint32(sample.VerifierRank),
		hfields.Int64(rankDelta),
	}

	jaccard, err := optionalFPField(position+" topk_jaccard", sample.TopKJaccard)
	if err != nil {
		return codec.Hash{}, err
	}
	unionJS, err := optionalFPField(position+" union_js", sample.UnionJS)
	if err != nil {
		return codec.Hash{}, err
	}
	leaf = append(leaf, jaccard, unionJS, hfields.Bool(sample.Missing), hfields.Bool(sample.Finite))

	return hfields.Digest(DomainLeafV2, hfields.Uint32(LeafVersionV1), hfields.Frame(leaf...))
}

// Root derives metric_root over leaf hashes already in output_position order.
//
// The ordering rule has exactly one definition (05-verification-algorithm §7: output_position
// ascending, contiguous and unique) and it is enforced by LeafHashes rather than
// by re-sorting here — MERKLE_ROOT_V1 does not sort, so a caller that hands over
// shuffled leaves must be refused, not silently corrected.
func Root(leafHashes []codec.Hash) (codec.Hash, error) {
	return codec.MerkleRootV1(DomainRootV2, leafHashes)
}

// LeafHashes derives every leaf hash for a sample set and enforces the position
// rule while doing it: positions must start at zero, be contiguous, be unique
// and ascend. A gap or a duplicate is refused rather than hashed, because the
// tree carries no positions of its own — position is expressed purely as index,
// so a missing position silently shifts every later leaf into the wrong slot.
func LeafHashes(binding Binding, samples []Sample) ([]codec.Hash, error) {
	hashes := make([]codec.Hash, 0, len(samples))
	for index, sample := range samples {
		want, err := countUint32("output_position", index)
		if err != nil {
			return nil, err
		}
		if sample.OutputPosition != want {
			return nil, fmt.Errorf(
				"metric leaves are not contiguous ascending from zero: element %d carries output_position %d, want %d",
				index, sample.OutputPosition, want)
		}
		hash, err := LeafHash(binding, sample)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, hash)
	}
	return hashes, nil
}

func optionalFPField(name string, value OptionalFP) (hfields.Field, error) {
	if !value.Present {
		return hfields.Optional(false, hfields.Field{}), nil
	}
	scaled, err := summaryFP1e6(name, value.Value)
	if err != nil {
		return hfields.Field{}, err
	}
	return hfields.Optional(true, hfields.Uint32(scaled)), nil
}
