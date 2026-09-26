package metric

import (
	"encoding/hex"
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// CompareLeavesV3 compares the Worker's committed value leaves with the
// Verifier's own value leaves, position by position, and returns one V3 metric
// sample per generated token.
//
// Both sides are read from their fixed-point leaves, never from the model
// service's doubles: the Worker's values are only known as committed leaves,
// and comparing the Verifier's from its leaves too means anyone holding the two
// value trees can recompute every sample.
//
// A position is missing when either side is missing, finite only when both
// sides are finite, and otherwise carries zero values and absent ratios. For a
// finite position the locked MetricSpec decides which comparisons are filled:
// ranks only under compare_rank_delta, and each ratio is present exactly when
// its compare flag is set.
func CompareLeavesV3(spec Spec, requiredTopK uint32, worker, verifier []nodewire.PositionValueV1) ([]SampleV3, error) {
	if len(worker) != len(verifier) {
		return nil, fmt.Errorf("metric compare: %d worker values but %d verifier values", len(worker), len(verifier))
	}
	limit := int(spec.ComparedTopK)
	samples := make([]SampleV3, len(worker))
	for i := range worker {
		w, v := worker[i], verifier[i]
		if uint64(w.Position) != uint64(i) || uint64(v.Position) != uint64(i) {
			return nil, fmt.Errorf("metric compare: position %d is out of order", i)
		}
		if v.TokenID != w.TokenID {
			return nil, fmt.Errorf("metric compare: position %d verifier scored token %d, worker emitted %d", i, v.TokenID, w.TokenID)
		}
		sample := SampleV3{OutputPosition: w.Position, EmittedTokenID: w.TokenID, Missing: w.Missing || v.Missing}
		sample.Finite = !sample.Missing && w.Finite && v.Finite
		if sample.Finite {
			sample.WorkerLogprobFP1e6, sample.VerifierLogprobFP1e6 = w.LogprobFP1e6, v.LogprobFP1e6
			if spec.CompareRankDelta {
				sample.WorkerRank, sample.VerifierRank = w.Rank, v.Rank
			}
			workerTopK, verifierTopK := leafTopK(w.TopK, limit), leafTopK(v.TopK, limit)
			if spec.CompareTopKJaccard {
				ratio, err := ratioFP1e6(fmt.Sprintf("position %d topk_jaccard", i), TopKJaccard(workerTopK, verifierTopK))
				if err != nil {
					return nil, err
				}
				sample.TopKJaccardFP1e6 = ratio
			}
			if spec.CompareUnionJS {
				js, ok := UnionJSDivergence(workerTopK, verifierTopK)
				if !ok {
					// The flag makes the ratio's presence mandatory, and there is no
					// value to put in it; refusing is the only honest answer.
					return nil, fmt.Errorf("metric compare: position %d union JS divergence is undefined for these top-k lists", i)
				}
				ratio, err := ratioFP1e6(fmt.Sprintf("position %d union_js", i), js)
				if err != nil {
					return nil, err
				}
				sample.UnionJSFP1e6 = ratio
			}
		}
		samples[i] = sample
	}
	return samples, nil
}

// BuildV3 produces the metric material for one single-sample verification run
// from V3 samples. The root is over V3 leaves bound to the Verifier's committed
// value root; the summary is derived from the same samples, read in real units,
// by the one aggregator (AggregateFromSamples), so root and summary describe
// the same data.
func BuildV3(binding Binding, verifierValueRoot codec.Hash, samples []SampleV3) (Material, error) {
	if err := binding.validate(); err != nil {
		return Material{}, err
	}
	// The leaf binds the raw Hash32; the binding carries its canonical hex.
	rawModelID, err := hex.DecodeString(binding.ModelID)
	if err != nil || len(rawModelID) != len(codec.Hash{}) || hex.EncodeToString(rawModelID) != binding.ModelID {
		return Material{}, fmt.Errorf("metric binding model_id must be 64 lowercase hex characters")
	}
	modelID := codec.Hash(rawModelID)
	if len(samples) == 0 {
		return Material{}, fmt.Errorf(
			"metric pipeline has no token samples; an empty tree has a valid root, so it is refused rather " +
				"than signed as a claim that no token was generated")
	}
	bindingV3 := BindingV3{
		ChainID: binding.ChainID, TaskID: binding.TaskID, TaskHash: binding.TaskHash, VerifyRound: binding.VerifyRound,
		ModelID: modelID, ProfileVersion: binding.ProfileVersion, JudgmentFunctionVersion: binding.JudgmentFunctionVersion,
		CanonicalEncodingVersion: binding.CanonicalEncodingVersion, EvidenceSchemaHash: binding.EvidenceSchemaHash,
		MetricAggregateProofVersion: binding.MetricAggregateProofVersion, TokenizerHash: binding.TokenizerHash,
		GenerationParamsDigest: binding.GenerationParamsDigest, RequiredTopK: binding.RequiredTopK,
		VerifierValueRoot: verifierValueRoot,
	}
	leafHashes, err := LeafHashesV3(bindingV3, samples)
	if err != nil {
		return Material{}, err
	}
	root, err := RootV3(leafHashes)
	if err != nil {
		return Material{}, err
	}
	summary, err := Summary(binding.Spec, AggregateFromSamples(samplesFromV3(samples), binding.RequiredTopK))
	if err != nil {
		return Material{}, err
	}
	proof, err := BuildAggregateProof(binding, root, len(leafHashes), summary)
	if err != nil {
		return Material{}, err
	}
	return Material{Root: root, Summary: summary, AggregateProof: proof, VerifierValueRoot: verifierValueRoot, LeafCount: len(leafHashes), LeafHashes: leafHashes}, nil
}

// samplesFromV3 reads fixed-point samples in real units for the aggregator.
// A V3 rank of 0 means "not in the required top-k"; the aggregator treats 0 as
// "no rank", so such a position does not enter the rank comparison.
func samplesFromV3(samples []SampleV3) []Sample {
	out := make([]Sample, len(samples))
	for i, s := range samples {
		out[i] = Sample{
			OutputPosition: s.OutputPosition, EmittedTokenID: s.EmittedTokenID,
			WorkerLogprob: float64(s.WorkerLogprobFP1e6) / FixedPointScale, VerifierLogprob: float64(s.VerifierLogprobFP1e6) / FixedPointScale,
			WorkerRank: s.WorkerRank, VerifierRank: s.VerifierRank, Missing: s.Missing, Finite: s.Finite,
		}
		if s.TopKJaccardFP1e6.Present {
			out[i].TopKJaccard = PresentFP(float64(s.TopKJaccardFP1e6.Value) / FixedPointScale)
		}
		if s.UnionJSFP1e6.Present {
			out[i].UnionJS = PresentFP(float64(s.UnionJSFP1e6.Value) / FixedPointScale)
		}
	}
	return out
}

func leafTopK(entries []nodewire.TopKEntryV1, limit int) []TokenLogprob {
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}
	out := make([]TokenLogprob, len(entries))
	for i, entry := range entries {
		out[i] = TokenLogprob{TokenID: entry.TokenID, Logprob: float64(entry.LogprobFP1e6) / FixedPointScale}
	}
	return out
}

func ratioFP1e6(name string, value float64) (OptionalFP1e6, error) {
	scaled, err := unsignedFP1e6(name, value)
	if err != nil {
		return OptionalFP1e6{}, err
	}
	if scaled > FixedPointScale {
		return OptionalFP1e6{}, fmt.Errorf("%s = %v exceeds 1", name, value)
	}
	return OptionalFP1e6{Value: uint32(scaled), Present: true}, nil
}
