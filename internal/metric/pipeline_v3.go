package metric

import (
	"encoding/hex"
	"errors"
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
	// An empty F is only the Worker's to answer for when no position had a
	// finite Worker value. If one did and the Verifier's own value is what is
	// missing, the Verifier cannot produce an attributable sample: that is its
	// own execution failure, and no worst-value summary may be committed.
	anyFinite, verifierGap := false, false
	for i, s := range samples {
		anyFinite = anyFinite || s.Finite
		// A missing leaf is never finite, so this covers both missing and
		// non-finite Verifier values.
		verifierGap = verifierGap || worker[i].Finite && !verifier[i].Finite
	}
	if !anyFinite && verifierGap {
		return nil, ErrVerifierValuesUnavailable
	}
	return samples, nil
}

// ErrVerifierValuesUnavailable is an empty comparison set caused by the
// Verifier's own missing or non-finite values. The verification stops without
// a commit; it counts as a verifier miss, never against the Worker.
var ErrVerifierValuesUnavailable = errors.New(
	"metric compare: no comparable position, and at least one has a finite Worker value but no finite Verifier value; " +
		"this is a Verifier execution failure, not a sample")

// BuildV3 produces the metric material for one single-sample verification run
// from V3 samples. The root is over V3 leaves bound to the Verifier's committed
// value root; the summary is derived from the same samples by SummaryV3, so
// root and summary describe the same data.
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
	summary, err := SummaryV3(binding.Spec, binding.RequiredTopK, samples)
	if err != nil {
		return Material{}, err
	}
	// Every leaf is either normal or counted as missing; a summary that does
	// not cover the tree must never reach a commit.
	if uint64(summary.FiniteCount)+uint64(summary.MissingComparedCount) != uint64(len(leafHashes)) {
		return Material{}, fmt.Errorf("metric summary covers %d+%d leaves, the tree has %d",
			summary.FiniteCount, summary.MissingComparedCount, len(leafHashes))
	}
	proof, err := BuildAggregateProof(binding, root, len(leafHashes), summary)
	if err != nil {
		return Material{}, err
	}
	return Material{Root: root, Summary: summary, AggregateProof: proof, VerifierValueRoot: verifierValueRoot, LeafCount: len(leafHashes), LeafHashes: leafHashes}, nil
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
