package metric

// The V3 metric leaf and root of wire v0.3.0 (TrueOpen/wire#14,
// task/metric_leaf_v3.json and task/result_metric_v3.json). They sit beside the
// V2 leaf; nothing produces them yet.
//
// Unlike Sample, SampleV3 is already fixed point. In V3 the Worker side of every
// comparison comes from the committed worker_values leaves, which are fp_1e6 on
// the wire, so converting back to float here would only add a lossy round trip.

import (
	"errors"
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
)

const (
	DomainLeafV3 = "TRUEOPEN_PREFILL_TOKEN_METRIC_LEAF_V3"
	DomainRootV3 = "TRUEOPEN_PREFILL_TOKEN_METRIC_ROOT_V3"
)

// BindingV3 is the locked-profile projection every V3 leaf carries. ModelID is
// the raw Hash32 model identity, not text, and VerifierValueRoot is the root
// this Verifier committed before reading the Worker's values.
type BindingV3 struct {
	ChainID                     string
	TaskID                      codec.Hash
	TaskHash                    codec.Hash
	VerifyRound                 uint32
	ModelID                     codec.Hash
	ProfileVersion              uint32
	JudgmentFunctionVersion     string
	CanonicalEncodingVersion    string
	EvidenceSchemaHash          codec.Hash
	MetricAggregateProofVersion string
	TokenizerHash               codec.Hash
	GenerationParamsDigest      codec.Hash
	RequiredTopK                uint32
	VerifierValueRoot           codec.Hash
}

// OptionalFP1e6 is an optional uint32 fp_1e6 ratio with explicit presence.
type OptionalFP1e6 struct {
	Value   uint32
	Present bool
}

// SampleV3 is one generated position's comparison in fixed point. Ranks are
// 0 for "not in the required top-k", otherwise 1..RequiredTopK.
type SampleV3 struct {
	OutputPosition       uint32
	EmittedTokenID       uint32
	WorkerLogprobFP1e6   int64
	VerifierLogprobFP1e6 int64
	WorkerRank           uint32
	VerifierRank         uint32
	TopKJaccardFP1e6     OptionalFP1e6
	UnionJSFP1e6         OptionalFP1e6
	Missing              bool
	Finite               bool
}

// LeafHashV3 hashes leaf_version and the 26-field canonical V3 leaf frame.
// abs_logprob_diff and rank_delta are derived here, so they cannot disagree
// with the values they describe.
func LeafHashV3(binding BindingV3, sample SampleV3) (codec.Hash, error) {
	if err := binding.validate(); err != nil {
		return codec.Hash{}, err
	}
	if err := sample.validate(binding.RequiredTopK); err != nil {
		return codec.Hash{}, fmt.Errorf("output_position %d: %w", sample.OutputPosition, err)
	}
	absDiff, err := sample.absLogprobDiffFP1e6()
	if err != nil {
		return codec.Hash{}, err
	}
	rankDelta := sample.rankDelta(binding.RequiredTopK)

	return hfields.Digest(DomainLeafV3, hfields.Uint32(LeafVersionV1), hfields.Frame(
		hfields.String(binding.ChainID),
		hfields.Hash(binding.TaskID),
		hfields.Hash(binding.TaskHash),
		hfields.Uint32(binding.VerifyRound),
		hfields.Hash(binding.ModelID),
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
		hfields.Int64(sample.WorkerLogprobFP1e6),
		hfields.Int64(sample.VerifierLogprobFP1e6),
		hfields.Uint64(absDiff),
		hfields.Uint32(sample.WorkerRank),
		hfields.Uint32(sample.VerifierRank),
		hfields.Int64(rankDelta),
		hfields.Optional(sample.TopKJaccardFP1e6.Present, hfields.Uint32(sample.TopKJaccardFP1e6.Value)),
		hfields.Optional(sample.UnionJSFP1e6.Present, hfields.Uint32(sample.UnionJSFP1e6.Value)),
		hfields.Bool(sample.Missing),
		hfields.Bool(sample.Finite),
		hfields.Hash(binding.VerifierValueRoot),
	))
}

// absLogprobDiffFP1e6 is the leaf's abs_logprob_diff_fp_1e6.
func (s SampleV3) absLogprobDiffFP1e6() (uint64, error) {
	diff := s.WorkerLogprobFP1e6 - s.VerifierLogprobFP1e6
	if (s.WorkerLogprobFP1e6 < 0) != (s.VerifierLogprobFP1e6 < 0) && (diff < 0) != (s.WorkerLogprobFP1e6 < 0) {
		return 0, fmt.Errorf("output_position %d: logprob difference overflows int64", s.OutputPosition)
	}
	if diff < 0 {
		return uint64(-diff), nil
	}
	return uint64(diff), nil
}

// rankDelta is the leaf's rank_delta. effective_rank maps "not in the required
// top-k" (rank 0) past the last rank, so dropping out of the top-k on either
// side counts as a rank change; both sides at 0 give 0.
func (s SampleV3) rankDelta(requiredTopK uint32) int64 {
	effectiveRank := func(rank uint32) int64 {
		if rank == 0 {
			return int64(requiredTopK) + 1
		}
		return int64(rank)
	}
	return effectiveRank(s.VerifierRank) - effectiveRank(s.WorkerRank)
}

// RootV3 derives the V3 metric_root over leaf hashes in output_position order.
func RootV3(leafHashes []codec.Hash) (codec.Hash, error) {
	return codec.MerkleRootV1(DomainRootV3, leafHashes)
}

// LeafHashesV3 derives every V3 leaf hash and enforces the position rule:
// contiguous and ascending from zero.
func LeafHashesV3(binding BindingV3, samples []SampleV3) ([]codec.Hash, error) {
	hashes := make([]codec.Hash, 0, len(samples))
	for index, sample := range samples {
		if uint64(sample.OutputPosition) != uint64(index) {
			return nil, fmt.Errorf(
				"metric leaves are not contiguous ascending from zero: element %d carries output_position %d",
				index, sample.OutputPosition)
		}
		hash, err := LeafHashV3(binding, sample)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, hash)
	}
	return hashes, nil
}

func (b BindingV3) validate() error {
	switch {
	case strings.TrimSpace(b.ChainID) == "":
		return errors.New("metric binding chain_id is required")
	case b.TaskID.IsZero():
		return errors.New("metric binding task_id is required")
	case b.TaskHash.IsZero():
		return errors.New("metric binding task_hash is required")
	case b.VerifyRound == 0:
		return errors.New("metric binding verify_round is required")
	case b.ModelID.IsZero():
		return errors.New("metric binding model_id is required")
	case b.ProfileVersion == 0:
		return errors.New("metric binding profile_version is required")
	case strings.TrimSpace(b.JudgmentFunctionVersion) == "":
		return errors.New("metric binding judgment_function_version is required")
	case strings.TrimSpace(b.CanonicalEncodingVersion) == "":
		return errors.New("metric binding canonical_encoding_version is required")
	case b.EvidenceSchemaHash.IsZero():
		return errors.New("metric binding evidence_schema_hash is required")
	case strings.TrimSpace(b.MetricAggregateProofVersion) == "":
		return errors.New("metric binding metric_aggregate_proof_version is required")
	case b.TokenizerHash.IsZero():
		return errors.New("metric binding tokenizer_hash is required")
	case b.GenerationParamsDigest.IsZero():
		return errors.New("metric binding generation_params_digest is required")
	case b.RequiredTopK == 0:
		return errors.New("metric binding required_top_k is required")
	case b.VerifierValueRoot.IsZero():
		return errors.New("metric binding verifier_value_root is required")
	}
	return nil
}

// validate enforces the leaf state rules: missing and finite together is
// illegal; a missing or non-finite leaf carries zero logprobs and ranks and no
// optional ratios; ranks stay inside the required top-k; ratios stay in
// 0..1_000_000.
func (s SampleV3) validate(requiredTopK uint32) error {
	if s.Missing && s.Finite {
		return errors.New("missing_flag and finite_flag cannot both be set")
	}
	if !s.Finite {
		if s.WorkerLogprobFP1e6 != 0 || s.VerifierLogprobFP1e6 != 0 || s.WorkerRank != 0 || s.VerifierRank != 0 ||
			s.TopKJaccardFP1e6.Present || s.UnionJSFP1e6.Present {
			return errors.New("a missing or non-finite leaf must carry zero values and absent ratios")
		}
		return nil
	}
	if s.WorkerRank > requiredTopK || s.VerifierRank > requiredTopK {
		return fmt.Errorf("rank exceeds required_top_k %d", requiredTopK)
	}
	for _, ratio := range []OptionalFP1e6{s.TopKJaccardFP1e6, s.UnionJSFP1e6} {
		if ratio.Present && ratio.Value > FixedPointScale {
			return fmt.Errorf("ratio %d exceeds %d", ratio.Value, FixedPointScale)
		}
	}
	return nil
}
