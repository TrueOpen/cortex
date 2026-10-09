package modelservice

import (
	"fmt"
	"math"
	"slices"
	"time"
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
