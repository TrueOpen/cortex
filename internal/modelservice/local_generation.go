package modelservice

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
)

// generationDecoding is the backend-ready projection of a validated
// GenerationContext: the frozen decoding parameters mapped into the units and
// types vLLM expects. It is transport-neutral, so both the raw-text
// (completionRequest) and chat (chatCompletionRequest) request builders share
// one validated source of the chain-bound sampling parameters.
type generationDecoding struct {
	maxTokens         int
	temperature       float64
	topP              float64
	topK              int
	seed              int
	presencePenalty   float64
	frequencyPenalty  float64
	repetitionPenalty float64
	stop              []string
	stopTokenIDs      []int
}

// decodeGenerationParams validates req.Generation against its digest and maps the
// frozen decoding parameters into backend units. It is the single place the
// chain-bound sampling contract is turned into engine parameters, so the
// raw-text and chat paths cannot drift in how they honour the order. It returns
// the local output-duration budget alongside the decoded parameters.
func decodeGenerationParams(req InferRequest) (generationDecoding, time.Duration, error) {
	if err := ValidateGenerationContext(req.Generation, req.GenerationParamsDigest, req.ModelID, req.ProfileVersion); err != nil {
		return generationDecoding{}, 0, err
	}
	g := req.Generation.Params
	d := g.DecodingParams
	maxInt := uint64(^uint(0) >> 1)
	if g.MaxOutputTokens > maxInt || d.Seed > maxInt || uint64(d.TopK) > maxInt {
		return generationDecoding{}, 0, fmt.Errorf("generation parameters exceed backend integer range")
	}
	if g.MaxOutputDuration > uint64(math.MaxInt64/int64(time.Millisecond)) {
		return generationDecoding{}, 0, fmt.Errorf("max_output_duration exceeds local timer range")
	}
	stopIDs := make([]int, len(d.StopTokenIDs))
	for i, id := range d.StopTokenIDs {
		if uint64(id) > maxInt {
			return generationDecoding{}, 0, fmt.Errorf("stop token id exceeds backend integer range")
		}
		stopIDs[i] = int(id)
	}
	for _, stop := range d.StopSequences {
		if stop == "" {
			return generationDecoding{}, 0, fmt.Errorf("empty stop sequence is unsupported by vLLM")
		}
	}
	// vLLM clamps positive temperatures below 0.01, which would change the
	// frozen parameters despite a successful HTTP response.
	if d.SamplingEnabled && d.TemperatureMilli > 0 && d.TemperatureMilli < 10 {
		return generationDecoding{}, 0, fmt.Errorf("vLLM cannot preserve temperature_milli below 10 except zero")
	}
	temperature := float64(d.TemperatureMilli) / 1000
	if !d.SamplingEnabled {
		temperature = 0
	}
	return generationDecoding{
		maxTokens:         int(g.MaxOutputTokens),
		temperature:       temperature,
		topP:              float64(d.TopPPPM) / 1000000,
		topK:              int(d.TopK),
		seed:              int(d.Seed),
		presencePenalty:   float64(d.PresencePenaltyMilli) / 1000,
		frequencyPenalty:  float64(d.FrequencyPenaltyMilli) / 1000,
		repetitionPenalty: float64(d.RepetitionPenaltyPPM) / 1000000,
		stop:              slices.Clone(d.StopSequences),
		stopTokenIDs:      stopIDs,
	}, time.Duration(g.MaxOutputDuration) * time.Millisecond, nil
}

func localGenerationRequest(req InferRequest, profile localModelProfile, streaming bool) (completionRequest, time.Duration, error) {
	p, duration, err := decodeGenerationParams(req)
	if err != nil {
		return completionRequest{}, 0, err
	}
	// top_k is not a user parameter: it is not an OpenAI knob, and the verifier
	// never samples, so it is platform-controlled. Cortex pins it to required_top_k
	// (below) so the sampled token always lands inside the reported top_logprobs --
	// the top-k evidence the verifier compares, capped at the API's 20. An order
	// that freezes its own top_k is refused rather than silently overridden.
	if p.topK != 0 {
		return completionRequest{}, 0, fmt.Errorf("modelservice local: generation context sets top_k (%d); top_k is platform-controlled and fixed to required_top_k, not a user parameter", p.topK)
	}
	seed, topK, skipSpecial, spacesBetweenSpecial := p.seed, profile.Sampling.Logprobs, profile.Sampling.SkipSpecialTokens, false
	return completionRequest{
		Model: profile.ServedModel, Prompt: string(req.Input), MaxTokens: p.maxTokens,
		Temperature: p.temperature, TopP: p.topP, TopK: profile.RequiredTopK, Seed: &seed,
		PresencePenalty: p.presencePenalty, FrequencyPenalty: p.frequencyPenalty,
		RepetitionPenalty: p.repetitionPenalty,
		Stop:              p.stop, StopTokenIDs: p.stopTokenIDs,
		// Token ids, never text: the top-logprobs keys become value-leaf entries,
		// and a text key cannot.
		Logprobs: &topK, Stream: streaming, ReturnTokenIDs: true,
		ReturnTokensAsTokenIDs: true, SkipSpecialTokens: &skipSpecial,
		SpacesBetweenSpecialTokens: &spacesBetweenSpecial,
	}, duration, nil
}

// Keys of the vllm_xargs entries the anchor engine reads.
const (
	anchorXArgChainID   = "slp_chain_id"
	anchorXArgTaskID    = "slp_task_id"
	anchorXArgOrderSeed = "slp_order_seed"
)

// AnchorSeedRuleV2 names the only seed rule this node can bind a generation
// to (model_management.anchor_seed_rule).
const AnchorSeedRuleV2 = "seed-v2"

// anchorSeedXArgs returns the vllm_xargs that bind the engine's canonical
// sampler to the task under seed rule "seed-v2" (ADR-0040 content track).
// The engine does not sample with the order's seed; it derives
//
//	seed = BLAKE3-256( "TRUEOPEN_ANCHOR_SAMPLING_SEED_V1"   32 ASCII bytes, no terminator
//	                 ‖ u32_be(len(chain_id))                4 bytes, length in bytes of the UTF-8 chain id
//	                 ‖ chain_id                             UTF-8 bytes
//	                 ‖ task_id                              32 raw bytes (not its hex text)
//	                 ‖ u64_be(order seed) )                 8 bytes, DecodingParamsV1.seed
//
// and uses the 32-byte digest, as 64 lowercase hex characters, as the seed of
// its sampler. All three inputs are fixed by the chain and the signed order
// before this node computes anything, and the validators recompute the same
// seed from the chain, so the Worker has no seed to choose. The derivation
// has one definition, in the engine, shared with the validators; this node
// computes no seed and only passes the three facts:
//
//	slp_chain_id    the chain id as it is
//	slp_task_id     the task id as 64 lowercase hex characters, decoded
//	                through the canonical Hash32 decoder first, so what the
//	                engine turns back into 32 bytes is the chain's task id
//	slp_order_seed  the order seed in decimal
//
// The order seed travels as a decimal string because a JSON number above
// 2^53 does not survive every decoder on the way. That is about the encoding
// only: an order seed above 2^63-1 never gets here, decodeGenerationParams
// refuses it ("generation parameters exceed backend integer range"), so the
// effective range of a seed is the backend's int64.
//
// A request that does not require an anchor commitment gets no xargs. One
// that does must carry all three facts: a seed derived from a wrong or
// missing fact is a seed the validators will not reproduce, so the call
// fails instead of generating under it.
func anchorSeedXArgs(req InferRequest) (map[string]string, error) {
	if !req.RequireAnchorCommit {
		return nil, nil
	}
	if req.ChainID == "" {
		return nil, errors.New("modelservice local: the anchor seed rule needs the chain id of the task")
	}
	if req.Generation == nil {
		return nil, errors.New("modelservice local: the anchor seed rule needs the order's generation parameters")
	}
	taskID, err := builderclient.CanonicalWireHash(req.TaskID, "task_id")
	if err != nil {
		return nil, fmt.Errorf("modelservice local: the anchor seed rule needs the task id: %w", err)
	}
	return map[string]string{
		anchorXArgChainID:   req.ChainID,
		anchorXArgTaskID:    taskID.String(),
		anchorXArgOrderSeed: strconv.FormatUint(req.Generation.Params.DecodingParams.Seed, 10),
	}, nil
}

// SetAnchorSeedRule turns the seed binding on ("seed-v2") or off (""). Off,
// which is the default, a generation that requires an anchor commitment is
// sampled exactly as any other: no vllm_xargs, the order's seed. It must be
// turned on together with the chain's content verdict track, and only with
// an engine that implements the rule: on, such an engine derives the seed of
// every such generation from the task (anchorSeedXArgs).
func (s *LocalService) SetAnchorSeedRule(rule string) {
	s.anchorSeedRule = rule
}

// seedXArgs is anchorSeedXArgs when the seed binding is on, and nothing when
// it is off.
func (s *LocalService) seedXArgs(req InferRequest) (map[string]string, error) {
	if s.anchorSeedRule == "" {
		return nil, nil
	}
	xargs, err := anchorSeedXArgs(req)
	if err != nil {
		// Deterministic: the task id, the chain id and the order do not
		// change between two attempts.
		return nil, Deterministic(FaultCodeAnchorSeedInputs, err)
	}
	return xargs, nil
}
