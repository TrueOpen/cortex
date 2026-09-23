package modelservice

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"time"

	"github.com/TrueOpen/cortex/internal/nodewire"
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
	seed, topK, skipSpecial := p.seed, profile.Sampling.Logprobs, profile.Sampling.SkipSpecialTokens
	return completionRequest{
		Model: profile.ServedModel, Prompt: string(req.Input), MaxTokens: p.maxTokens,
		Temperature: p.temperature, TopP: p.topP, TopK: p.topK, Seed: &seed,
		PresencePenalty: p.presencePenalty, FrequencyPenalty: p.frequencyPenalty,
		RepetitionPenalty: p.repetitionPenalty,
		Stop:              p.stop, StopTokenIDs: p.stopTokenIDs,
		Logprobs: &topK, Stream: streaming, ReturnTokenIDs: profile.Sampling.ReturnTokenIDs,
		ReturnTokensAsTokenIDs: profile.Sampling.ReturnTokensAsTokenIDs, SkipSpecialTokens: &skipSpecial,
	}, duration, nil
}

// GenerationContextFromTrace extracts a context from authenticated evidence.
// The caller must authenticate the trace commitment and match the resulting
// digest against authoritative task facts before trusting these parameters.
func GenerationContextFromTrace(trace []byte) (*nodewire.GenerationContext, error) {
	var env struct {
		Generation *nodewire.GenerationContext `json:"generation_context"`
	}
	if err := json.Unmarshal(trace, &env); err != nil {
		return nil, fmt.Errorf("decode trace generation context: %w", err)
	}
	if env.Generation == nil {
		return nil, fmt.Errorf("trace generation context is required")
	}
	if _, err := env.Generation.Digest(); err != nil {
		return nil, fmt.Errorf("invalid trace generation context: %w", err)
	}
	g := env.Generation.Clone()
	return &g, nil
}

// ValidateGenerationEvidence checks the shared local artifact contract. The
// caller remains responsible for authenticating the evidence commitment.
func ValidateGenerationEvidence(g *nodewire.GenerationContext, digest []byte, output, trace, checkpoint []byte) (uint64, nodewire.FinishReasonV1, error) {
	if g == nil {
		return 0, 0, fmt.Errorf("generation context is required")
	}
	if err := ValidateGenerationContext(g, digest, g.ModelID, strconv.FormatUint(uint64(g.ProfileVersion), 10)); err != nil {
		return 0, 0, err
	}
	var env traceEnvelope
	if err := json.Unmarshal(trace, &env); err != nil {
		return 0, 0, Deterministic(FaultCodeTraceUndecodable,
			fmt.Errorf("decode generation trace: %w", err),
			FaultInt("trace_bytes", len(trace)))
	}
	if err := ValidateGenerationContext(env.Generation, digest, g.ModelID, strconv.FormatUint(uint64(g.ProfileVersion), 10)); err != nil {
		return 0, 0, Deterministic(FaultCodeTraceGenerationContext,
			fmt.Errorf("trace: %w", err),
			FaultStr("model_id", g.ModelID),
			FaultUint("profile_version", uint64(g.ProfileVersion)))
	}
	if env.ModelID != g.ModelID || env.ProfileVersion != strconv.FormatUint(uint64(g.ProfileVersion), 10) {
		return 0, 0, Deterministic(FaultCodeTraceIdentityMismatch,
			fmt.Errorf("trace model/profile mismatch"),
			FaultStr("model_id", g.ModelID), FaultStr("trace_model_id", env.ModelID),
			FaultUint("profile_version", uint64(g.ProfileVersion)),
			FaultStr("trace_profile_version", env.ProfileVersion))
	}
	if !bytes.Equal(output, []byte(env.Output)) {
		// Lengths only. The two disagreeing values are the model output itself.
		return 0, 0, Deterministic(FaultCodeTraceOutputMismatch,
			fmt.Errorf("trace output does not match output bytes"),
			FaultInt("output_bytes", len(output)), FaultInt("trace_output_bytes", len(env.Output)))
	}
	// Three separate refusals, not one disjunction. They are three different
	// facts about the run -- a malformed count, a count the evidence does not
	// support, and a run that outgrew the order's budget -- and only the last is
	// a statement about the model's behaviour. Folded into one message an
	// operator reading "exceeds limit or does not match token evidence" cannot
	// tell which of the three fired, let alone by how much; every one of the
	// numbers that answers that is right here and now travels with the error.
	//
	// All three are Deterministic: the trace and checkpoint are bytes this node
	// already holds, so re-running the model cannot change the verdict on them.
	if env.GeneratedTokenCount < 0 {
		return 0, 0, Deterministic(FaultCodeTokenCountNegative,
			fmt.Errorf("trace generated_token_count is negative"),
			FaultInt("generated_token_count", env.GeneratedTokenCount),
			FaultStr("model_id", g.ModelID),
			FaultUint("profile_version", uint64(g.ProfileVersion)))
	}
	if env.GeneratedTokenCount != len(env.OutTokens) {
		return 0, 0, Deterministic(FaultCodeTokenEvidenceCountMismatch,
			fmt.Errorf("trace generated_token_count does not match the per-token evidence length"),
			FaultInt("generated_token_count", env.GeneratedTokenCount),
			FaultInt("out_tokens", len(env.OutTokens)),
			FaultInt("input_token_ids", len(env.InputTokenIDs)),
			FaultUint("max_output_tokens", g.Params.MaxOutputTokens),
			FaultStr("model_id", g.ModelID),
			FaultUint("profile_version", uint64(g.ProfileVersion)))
	}
	if uint64(env.GeneratedTokenCount) > g.Params.MaxOutputTokens {
		return 0, 0, Deterministic(FaultCodeTokenBudgetExceeded,
			fmt.Errorf("trace generated_token_count exceeds the order's max_output_tokens"),
			FaultInt("generated_token_count", env.GeneratedTokenCount),
			FaultUint("max_output_tokens", g.Params.MaxOutputTokens),
			FaultInt("out_tokens", len(env.OutTokens)),
			FaultInt("input_token_ids", len(env.InputTokenIDs)),
			FaultStr("finish_reason", env.FinishReason),
			FaultStr("model_id", g.ModelID),
			FaultUint("profile_version", uint64(g.ProfileVersion)))
	}
	if env.InputTokenIDsHash != hashTokenIDs(env.InputTokenIDs) || env.GeneratedTokenIDsHash != hashGeneratedTokenIDs(env.OutTokens) {
		// Which of the two hashes disagreed, named: they cover different token
		// vectors and a prompt-side mismatch is a different fault from an
		// output-side one.
		return 0, 0, Deterministic(FaultCodeTraceTokenIDsHashMismatch,
			fmt.Errorf("trace token ids hash mismatch"),
			FaultStr("input_token_ids_hash_matches", strconv.FormatBool(env.InputTokenIDsHash == hashTokenIDs(env.InputTokenIDs))),
			FaultStr("generated_token_ids_hash_matches", strconv.FormatBool(env.GeneratedTokenIDsHash == hashGeneratedTokenIDs(env.OutTokens))),
			FaultInt("input_token_ids", len(env.InputTokenIDs)), FaultInt("out_tokens", len(env.OutTokens)))
	}
	for i, id := range env.InputTokenIDs {
		if id < 0 {
			return 0, 0, Deterministic(FaultCodeTraceNegativeTokenID,
				fmt.Errorf("negative prompt token id"),
				FaultStr("vector", "input_token_ids"), FaultInt("index", i))
		}
	}
	for i, token := range env.OutTokens {
		if token.TokenID < 0 {
			return 0, 0, Deterministic(FaultCodeTraceNegativeTokenID,
				fmt.Errorf("negative generated token id"),
				FaultStr("vector", "out_tokens"), FaultInt("index", i))
		}
	}
	if err := validateCheckpoint(checkpoint, env); err != nil {
		return 0, 0, Deterministic(FaultCodeCheckpointMismatch, err,
			FaultInt("checkpoint_bytes", len(checkpoint)),
			FaultInt("generated_token_count", env.GeneratedTokenCount))
	}
	finish, err := localGenerationFinishReason(g, env.FinishReason, env.StopReason, uint64(env.GeneratedTokenCount))
	if err != nil {
		return 0, 0, Deterministic(FaultCodeFinishReasonUnsupported, err,
			FaultStr("finish_reason", env.FinishReason),
			FaultInt("generated_token_count", env.GeneratedTokenCount),
			FaultUint("max_output_tokens", g.Params.MaxOutputTokens))
	}
	return uint64(env.GeneratedTokenCount), finish, nil
}
