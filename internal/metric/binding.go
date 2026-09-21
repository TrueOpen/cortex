package metric

import (
	"errors"
	"fmt"
	"strings"

	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/codec"
)

// ErrProfileUnsupported marks a profile this pipeline refuses to compute under:
// a verification mode it does not implement, a numeric scale it does not
// produce, or an aggregate-proof version it has no encoder for.
//
// It is a distinct error because the caller's response differs. A missing input
// is retried when it arrives; an unsupported profile never becomes supported by
// waiting, and the task must stop rather than spin until the reveal deadline.
var ErrProfileUnsupported = errors.New("locked verification profile is not supported by this verifier")

// Supported profile tokens. All three are compared against the LOCKED task
// snapshot, never against the newest registered profile.
const (
	// VerificationModeSingleSample is the only mode the protocol accepts today
	// (keeper §9.7: BATCH_SAMPLES is rejected with ERR_BATCH_VERIFICATION_UNSUPPORTED
	// and "a verifier must not choose batch aggregation semantics on its own").
	VerificationModeSingleSample = "SINGLE_SAMPLE"
	// AggregateProofVersionV1 is the metric_aggregate_proof_version this
	// pipeline encodes under.
	AggregateProofVersionV1 = "PREFILL_METRIC_AGGREGATE_PROOF_V1"
)

// Binding is the locked-profile projection every leaf carries. Its whole reason
// for existing is 05-verification-algorithm §5: the same opening must re-judge to the same
// verdict, which holds only if the material was computed under the profile and
// version tokens the task snapshot locked — not under whatever profile is
// current when the verifier happens to run.
//
// Every field here is copied from that snapshot. None is derived locally, and
// none has a default: a zero would be a claim about a consensus value.
type Binding struct {
	ChainID                     string
	TaskID                      codec.Hash
	TaskHash                    codec.Hash
	VerifyRound                 uint32
	ModelID                     string
	ProfileVersion              uint32
	JudgmentFunctionVersion     string
	CanonicalEncodingVersion    string
	EvidenceSchemaHash          codec.Hash
	MetricAggregateProofVersion string
	TokenizerHash               codec.Hash
	GenerationParamsDigest      codec.Hash
	RequiredTopK                uint32
	// Spec is the locked MetricSpec. It is the sole decider of whether
	// MetricSummaryV1 fields 7 and 8 are present.
	Spec Spec
}

// Spec is the locked MetricSpec projection this pipeline reads. The four
// compare_* flags are the profile's statement of which metrics the sample is
// judged on; compare_topk_jaccard and compare_union_js additionally decide the
// presence of the two optional summary members.
type Spec struct {
	CompareLogprobDiff bool
	CompareRankDelta   bool
	CompareTopKJaccard bool
	CompareUnionJS     bool
	ComparedTopK       uint32
}

// BindTask projects a locked task snapshot and the Keeper-served
// generation_params_digest into a Binding, refusing every profile this pipeline
// cannot honestly compute under.
//
// The three refusals are all fail-closed on purpose:
//
//   - verification_mode must be SINGLE_SAMPLE. BATCH_SAMPLES is not "not built
//     yet" — keeper §9.7 rejects it at registration and assign, and inventing a
//     batch aggregation here is the specific thing the contract forbids.
//   - numeric_scale must be FP_1E6, because that is the only scale the
//     fixed-point conversion in this package implements.
//   - metric_aggregate_proof_version must be the one version aggregateproof.go
//     encodes. keeper §9.7 requires an unknown version be refused before state
//     is written or funds move; refusing before the proof is built is the
//     verifier-side half of that.
func BindTask(
	chainID string,
	taskID codec.Hash,
	taskHash codec.Hash,
	verifyRound uint32,
	profile chainclient.CurrentProfileSnapshot,
	generationParamsDigest codec.Hash,
) (Binding, error) {
	verification := profile.VerificationProfile

	if mode := trimProfileEnum(verification.VerificationMode, "VERIFICATION_MODE_"); mode != VerificationModeSingleSample {
		return Binding{}, fmt.Errorf(
			"%w: verification_mode %q; only %s is implemented, and keeper §9.7 forbids choosing a batch "+
				"aggregation semantics locally",
			ErrProfileUnsupported, verification.VerificationMode, VerificationModeSingleSample)
	}
	if scale := trimProfileEnum(verification.Metrics.NumericScale, "NUMERIC_SCALE_"); scale != numericScaleFP1e6 {
		return Binding{}, fmt.Errorf(
			"%w: metric numeric_scale %q; this verifier only produces %s fixed point",
			ErrProfileUnsupported, verification.Metrics.NumericScale, numericScaleFP1e6Prefixed)
	}
	if version := strings.TrimSpace(verification.MetricAggregateProofVersion); version != AggregateProofVersionV1 {
		return Binding{}, fmt.Errorf(
			"%w: metric_aggregate_proof_version %q; this verifier encodes only %s",
			ErrProfileUnsupported, verification.MetricAggregateProofVersion, AggregateProofVersionV1)
	}

	binding := Binding{
		ChainID:                     chainID,
		TaskID:                      taskID,
		TaskHash:                    taskHash,
		VerifyRound:                 verifyRound,
		ModelID:                     profile.ModelID,
		ProfileVersion:              profile.ProfileVersion.Uint32(),
		JudgmentFunctionVersion:     strings.TrimSpace(verification.JudgmentFunctionVersion),
		CanonicalEncodingVersion:    strings.TrimSpace(verification.CanonicalEncodingVersion),
		MetricAggregateProofVersion: strings.TrimSpace(verification.MetricAggregateProofVersion),
		RequiredTopK:                profile.RequiredTopK,
		Spec: Spec{
			CompareLogprobDiff: verification.Metrics.CompareLogprobDiff,
			CompareRankDelta:   verification.Metrics.CompareRankDelta,
			CompareTopKJaccard: verification.Metrics.CompareTopKJaccard,
			CompareUnionJS:     verification.Metrics.CompareUnionJS,
			ComparedTopK:       verification.Metrics.ComparedTopK,
		},
	}
	copy(binding.EvidenceSchemaHash[:], verification.EvidenceSchemaHash)
	copy(binding.TokenizerHash[:], profile.TokenizerHash)
	binding.GenerationParamsDigest = generationParamsDigest

	if err := binding.validate(); err != nil {
		return Binding{}, err
	}
	return binding, nil
}

// validate refuses a binding with an unset consensus field. Each of these enters
// every leaf preimage, so a zero is not a gap marker the Keeper can see — it is
// a leaf that hashes cleanly and re-derives to a different value on the chain.
func (b Binding) validate() error {
	switch {
	case strings.TrimSpace(b.ChainID) == "":
		return errors.New("metric binding chain_id is required")
	case b.TaskID.IsZero():
		return errors.New("metric binding task_id is required")
	case b.TaskHash.IsZero():
		return errors.New("metric binding task_hash is required")
	case b.VerifyRound == 0:
		return errors.New("metric binding verify_round is required")
	case strings.TrimSpace(b.ModelID) == "":
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
	case b.Spec.ComparedTopK != b.RequiredTopK:
		return fmt.Errorf(
			"metric binding compared_top_k %d does not equal required_top_k %d; the locked profile is inconsistent",
			b.Spec.ComparedTopK, b.RequiredTopK)
	}
	return nil
}

// trimProfileEnum accepts both the bare and the fully-prefixed spelling of a
// Keeper enum token. The chain serves the prefixed form; the local profile
// resolver already normalises to the bare one, and a reader that only knew one
// of them would refuse a perfectly valid profile.
func trimProfileEnum(value, prefix string) string {
	return strings.TrimPrefix(strings.TrimSpace(value), prefix)
}
