package modelservice

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/TrueOpen/cortex/internal/modelmanifest"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// This file implements the chat generation path: it interprets req.Input as an
// OpenAI Chat Completions request body (see proto/cortex/v1/chat_input.proto),
// calls vLLM's /v1/chat/completions, and projects the response back onto the
// same completionResponse shape the raw-text path (inferV0) produces, so the
// token-id and position-value material and the Verifier are unchanged.
//
// The transport mirrors inferV0: the streamInference switch (SetStreamInference,
// default on) selects SSE vs. a single JSON body, and reassembleChatStream folds
// the server-sent chunks back into the SAME chatCompletionResponse a non-streaming
// call would decode -- so the committed output and material are
// byte-identical regardless of which transport ran, and streaming is a node-local
// detail never carried on the protocol. Verify is always non-streaming.
//
// Output is NOT the engine's detokenized message.content, nor a ChatCompletion
// JSON envelope: the delivered output and the streamed chunk text are both the
// committed output, built from the generated token_ids T -- each token's bytes
// (logprobs.content[i].bytes) concatenated in order, with exactly one trailing
// token left out if and only if it is one of the profile's
// output_decoding.eos_token_ids (decodeTokensFromLogprobs). Special tokens are
// rendered like any other token and nothing is cleaned up, so every text
// artifact corresponds byte-for-byte to the token_ids the Verifier scores,
// rather than to the engine's own detokenization. T itself keeps the EOS: it is
// what the Verifier prefills and what the token count covers. tool_calls are
// therefore not parsed out separately; any tool-call syntax the model emitted
// is just tokens in that raw text.
//
// Scope: the sampling parameters come from the chain-bound generation context
// (NOT from the request), exactly as the raw-text path (see decodeGenerationParams).
// But the chat endpoint honours only the OpenAI Chat Completions sampling subset:
// a context that sets a vLLM-only knob (top_k, repetition_penalty) or ANY stop
// condition (stop_sequences, stop_token_ids) is refused up front
// (rejectNonOpenAIChatGenerationParams) rather than silently dropped. So chat
// generations terminate only by natural EOS or max_output_tokens; there is no stop
// condition to disambiguate. A "tool_calls" finish is normalised to EOS in
// projectChatToCompletion, so the finish handling (completionFinishResolver) and
// evidence re-derivation are identical to the raw-text path.

// chatInferInput is the accepted subset of the OpenAI chat request. Only the
// content/intent fields are accepted here: messages/tools/tool_choice/
// response_format/parallel_tool_calls. They are kept as raw JSON and forwarded
// verbatim to vLLM -- the input is already OpenAI-shaped, so re-modelling them
// would only risk lossy round-trips.
//
// The sampling parameters (temperature, top_p, max_completion_tokens, seed,
// presence/frequency penalty, stop) are NOT taken from the request: they are the
// generation_params_digest subset, owned by the order's chain-bound generation
// context. Supplying any of them in the input is refused (chatRejectedInputFields)
// rather than silently overridden, so the request cannot claim parameters the
// order did not freeze.
type chatInferInput struct {
	Messages          json.RawMessage `json:"messages"`
	Tools             json.RawMessage `json:"tools,omitempty"`
	ToolChoice        json.RawMessage `json:"tool_choice,omitempty"`
	ResponseFormat    json.RawMessage `json:"response_format,omitempty"`
	ParallelToolCalls *bool           `json:"parallel_tool_calls,omitempty"`
}

// chatRejectedInputFields are OpenAI request fields Cortex refuses on the chat
// path, because silently dropping (or overriding) them would answer a different
// request than the caller sent. Two groups, one behaviour:
//   - logprobs/top_logprobs/logit_bias/n: their COUNT/bias is owned by the
//     verification profile or fixed by Cortex.
//   - temperature/top_p/max_completion_tokens/max_tokens/seed/presence_penalty/
//     frequency_penalty/stop: the generation_params_digest subset. These are
//     frozen by the order's chain-bound generation context and applied from there
//     (decodeGenerationParams), so accepting them from the request would let it
//     diverge from the committed parameters.
//
// See proto/cortex/v1/chat_input.proto.
var chatRejectedInputFields = []string{
	"logprobs", "top_logprobs", "logit_bias", "n",
	"temperature", "top_p", "max_completion_tokens", "max_tokens", "seed",
	"presence_penalty", "frequency_penalty", "stop",
}

// chatCompletionRequest is the /v1/chat/completions request Cortex sends. The
// content-shape fields pass through raw; the verification-relevant fields
// (logprobs/top_logprobs/return_token_ids/return_tokens_as_token_ids/
// skip_special_tokens) and stream are set by Cortex and never taken from input.
type chatCompletionRequest struct {
	Model             string          `json:"model"`
	Messages          json.RawMessage `json:"messages"`
	Tools             json.RawMessage `json:"tools,omitempty"`
	ToolChoice        json.RawMessage `json:"tool_choice,omitempty"`
	ResponseFormat    json.RawMessage `json:"response_format,omitempty"`
	ParallelToolCalls *bool           `json:"parallel_tool_calls,omitempty"`

	// Sampling parameters, set from the chain-bound generation context
	// (localChatGenerationRequest), never from the request. Only the OpenAI Chat
	// Completions sampling subset is sent: the vLLM-only knobs the raw-text path can
	// carry (top_k, repetition_penalty) and the stop conditions (stop_sequences,
	// stop_token_ids) are NOT forwarded -- a generation context that sets any of
	// them is refused upstream (rejectNonOpenAIChatGenerationParams), so this request
	// stays a pure OpenAI body.
	Temperature         float64 `json:"temperature"`
	TopP                float64 `json:"top_p"`
	MaxCompletionTokens int     `json:"max_completion_tokens,omitempty"`
	Seed                *int64  `json:"seed,omitempty"`
	PresencePenalty     float64 `json:"presence_penalty,omitempty"`
	FrequencyPenalty    float64 `json:"frequency_penalty,omitempty"`

	Stream                 bool               `json:"stream"`
	StreamOptions          *chatStreamOptions `json:"stream_options,omitempty"`
	Logprobs               bool               `json:"logprobs"`
	TopLogprobs            int                `json:"top_logprobs"`
	ReturnTokenIDs         bool               `json:"return_token_ids"`
	ReturnTokensAsTokenIDs bool               `json:"return_tokens_as_token_ids"`
	SkipSpecialTokens      *bool              `json:"skip_special_tokens,omitempty"`
}

// chatStreamOptions is set only when Cortex streams the generation. include_usage
// makes vLLM emit a terminal usage-only chunk, so the committed output carries the
// same usage a non-streaming response would -- without it usage would be absent on
// the streaming path and break byte parity.
type chatStreamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

// chatCompletionResponse is the subset of the /v1/chat/completions response
// Cortex reads. prompt_token_ids is TOP-LEVEL here (unlike /v1/completions where
// it is per-choice); the generated token_ids are per-choice. id/created/usage are
// echoed into the delivered OpenAI ChatCompletion output.
type chatCompletionResponse struct {
	ID             string               `json:"id"`
	Created        int64                `json:"created"`
	Model          string               `json:"model"`
	Choices        []chatResponseChoice `json:"choices"`
	Usage          *chatRespUsage       `json:"usage"`
	PromptTokenIDs []int                `json:"prompt_token_ids"`
}

type chatRespUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type chatResponseChoice struct {
	Index        int               `json:"index"`
	Message      chatRespMessage   `json:"message"`
	FinishReason string            `json:"finish_reason"`
	TokenIDs     []int             `json:"token_ids"`
	Logprobs     *chatRespLogprobs `json:"logprobs"`
}

type chatRespMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRespLogprobs struct {
	Content []chatRespLogprobContent `json:"content"`
}

type chatRespLogprobContent struct {
	Token   string  `json:"token"`
	Logprob float64 `json:"logprob"`
	// Bytes is the UTF-8 byte values of this generated token, used to decode the
	// committed token_ids back into the delivered text (decodeTokensFromLogprobs).
	// It is populated regardless of return_tokens_as_token_ids (which only changes
	// the Token string to the "token_id:X" form).
	Bytes       []int                `json:"bytes"`
	TopLogprobs []chatRespTopLogprob `json:"top_logprobs"`
}

type chatRespTopLogprob struct {
	Token   string  `json:"token"`
	Logprob float64 `json:"logprob"`
}

// Infer generates output for one task. It routes by input shape: a JSON object
// carrying a "messages" field is a chat request served over /v1/chat/completions;
// anything else is the legacy raw-text prompt served by inferV0. (Capability-based
// routing via a dedicated llm_chat_v1 is the eventual mechanism.)
func (s *LocalService) Infer(ctx context.Context, req InferRequest) (InferResponse, error) {
	if err := validateCapability(req.Capability); err != nil {
		return InferResponse{}, err
	}
	input, isChat, err := parseChatInferInput(req.Input)
	if err != nil {
		return InferResponse{}, err
	}
	if !isChat {
		return s.inferV0(ctx, req)
	}
	// The chat path is now chain-bound just like inferV0: validate req.Generation
	// against its digest, then clone it (and the digest) so post-processing sees a
	// stable copy while it is re-derived against the evidence.
	if err := ValidateGenerationContext(req.Generation, req.GenerationParamsDigest, req.ModelID, req.ProfileVersion); err != nil {
		return InferResponse{}, err
	}
	// Fail fast on a context that carries a parameter chat does not support, before
	// resolving the profile (a possibly remote call): the digest is already
	// validated above, so the frozen params can be trusted here.
	if err := rejectNonOpenAIChatGenerationParams(req.Generation); err != nil {
		return InferResponse{}, err
	}
	generation := req.Generation.Clone()
	req.Generation = &generation
	req.GenerationParamsDigest = slices.Clone(req.GenerationParamsDigest)
	profile, err := s.resolveLocalProfile(ctx, req.ModelID, req.ProfileVersion)
	if err != nil {
		return InferResponse{}, err
	}
	// Before the engine call: without the EOS set neither the committed output
	// nor the streamed frames can be built, so there is no point generating.
	profile, err = s.outputDecodingFor(ctx, profile)
	if err != nil {
		return InferResponse{}, err
	}
	streaming := s.streamInferenceEnabled()
	chatReq, duration, err := localChatGenerationRequest(req, profile, input, streaming)
	if err != nil {
		return InferResponse{}, err
	}
	// max_output_duration ends the generation successfully rather than failing
	// the call; see the same split in inferV0. Only the streaming transport can
	// honour it, and the context deadline sits budgetGrace behind so a silent
	// engine still fails.
	budgetAt := time.Now().Add(duration)
	ctx, cancel := context.WithDeadline(ctx, budgetAt.Add(budgetGrace))
	defer cancel()
	if req.DeadlineMS > 0 {
		var deadlineCancel context.CancelFunc
		ctx, deadlineCancel = context.WithDeadline(ctx, time.UnixMilli(req.DeadlineMS))
		defer deadlineCancel()
	}
	ctx, inferCancel := s.withInferTimeout(ctx)
	defer inferCancel()
	var chatResp chatCompletionResponse
	if streaming {
		ident := inferStreamIdentity{
			requestID: req.RequestID,
			jobID:     req.JobID,
			taskID:    req.TaskID,
			modelID:   profile.ModelID,
		}
		if err := s.postStreamingChat(ctx, "/v1/chat/completions", chatReq, &chatResp, ident, budgetAt, profile.OutputDecoding); err != nil {
			return InferResponse{}, err
		}
	} else if err := s.post(ctx, "/v1/chat/completions", chatReq, &chatResp); err != nil {
		return InferResponse{}, err
	}
	if err := ctx.Err(); err != nil && !chatBudgetStopped(&chatResp) {
		return InferResponse{}, err
	}
	projected, err := projectChatToCompletion(chatResp, profile.OutputDecoding)
	if err != nil {
		return InferResponse{}, err
	}
	if err := validateChatUsage(chatResp); err != nil {
		return InferResponse{}, err
	}
	// outputBytes is nil so the delivered output defaults to choice.Text -- the raw
	// text decoded from the committed token_ids (set by projectChatToCompletion).
	// req.Generation is now set, so buildInferResultFromCompletion re-derives the
	// chain-bound evidence contract (ValidateGenerationEvidence) for the chat path
	// exactly as for inferV0. projectChatToCompletion already normalised the chat-only
	// "tool_calls" finish to EOS, so the raw-text resolver applies unchanged.
	return s.buildInferResultFromCompletion(ctx, req, profile, projected, nil, completionFinishResolver(req))
}

// validateChatUsage fails closed when the engine's reported completion token count
// disagrees with the number of generated token ids the decoded output is built
// from. It only checks when usage is present (it may be absent). On the streaming
// path usage arrives on the terminal include_usage chunk (reassembleChatStream
// sets out.Usage), so the same check covers both transports.
func validateChatUsage(chatResp chatCompletionResponse) error {
	if chatResp.Usage == nil || len(chatResp.Choices) == 0 {
		return nil
	}
	if got, want := chatResp.Usage.CompletionTokens, len(chatResp.Choices[0].TokenIDs); got != want {
		return fmt.Errorf("modelservice local chat: usage completion_tokens=%d != generated token ids=%d", got, want)
	}
	return nil
}

// parseChatInferInput decides whether the bytes are a chat request and, if so,
// decodes them. It returns isChat=false (with no error) for non-JSON or
// message-less input so the caller can fall back to the raw-text path, and a
// hard error only when the input IS a chat request but carries a rejected field
// or fails to decode.
func parseChatInferInput(input []byte) (chatInferInput, bool, error) {
	trimmed := bytes.TrimSpace(input)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return chatInferInput{}, false, nil
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &probe); err != nil {
		return chatInferInput{}, false, nil
	}
	if _, ok := probe["messages"]; !ok {
		return chatInferInput{}, false, nil
	}
	// From here the payload is a chat request. Refuse the fields Cortex owns.
	for _, field := range chatRejectedInputFields {
		if _, bad := probe[field]; bad {
			return chatInferInput{}, true, fmt.Errorf(
				"modelservice local chat: request field %q is not accepted (owned by the generation context or verification profile, or fixed by Cortex)", field)
		}
	}
	var parsed chatInferInput
	if err := json.Unmarshal(trimmed, &parsed); err != nil {
		return chatInferInput{}, true, fmt.Errorf("modelservice local chat: decode input: %w", err)
	}
	if messagesEmpty(parsed.Messages) {
		return chatInferInput{}, true, fmt.Errorf("modelservice local chat: request has no messages")
	}
	return parsed, true, nil
}

// messagesEmpty reports whether the raw messages value is absent or an empty
// array.
func messagesEmpty(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return true
	}
	var msgs []json.RawMessage
	if err := json.Unmarshal(trimmed, &msgs); err != nil {
		// Not an array; leave the decode error to the outer unmarshal / vLLM.
		return false
	}
	return len(msgs) == 0
}

// repetitionPenaltyNeutralPPM is repetition_penalty == 1.0 (no penalty) in the
// generation context's parts-per-million units. A context that sets anything else
// is applying the vLLM-only repetition_penalty, which the chat path refuses.
const repetitionPenaltyNeutralPPM = 1_000_000

// rejectNonOpenAIChatGenerationParams fails closed when the (already
// digest-validated) generation context carries a parameter with no OpenAI Chat
// Completions analog. The chat endpoint's supported feature set is the OpenAI
// sampling subset (temperature/top_p/max_completion_tokens/seed/presence_penalty/
// frequency_penalty). The raw-text path may set the vLLM-only knobs below, but chat
// REFUSES them rather than silently dropping ordered parameters (which would commit
// a computation different from the one the order froze). stop_sequences is an OpenAI
// field but is refused too: it cannot be honoured under the chat path's
// decode-from-token_ids invariant (see the file header).
func rejectNonOpenAIChatGenerationParams(g *nodewire.GenerationContext) error {
	d := g.Params.DecodingParams
	switch {
	case d.TopK != 0:
		return fmt.Errorf("modelservice local chat: generation context sets top_k (%d); the chat path supports only the OpenAI sampling subset", d.TopK)
	case d.RepetitionPenaltyPPM != repetitionPenaltyNeutralPPM:
		return fmt.Errorf("modelservice local chat: generation context sets repetition_penalty (%d ppm); the chat path supports only the OpenAI sampling subset", d.RepetitionPenaltyPPM)
	case len(d.StopSequences) != 0:
		return fmt.Errorf("modelservice local chat: generation context sets stop_sequences; the chat path does not support them (unverifiable under decode-from-token_ids)")
	case len(d.StopTokenIDs) != 0:
		return fmt.Errorf("modelservice local chat: generation context sets stop_token_ids; the chat path supports only the OpenAI sampling subset")
	}
	return nil
}

// localChatGenerationRequest assembles the outgoing chat request from the
// content/intent input and the chain-bound generation context. The sampling
// parameters come entirely from decodeGenerationParams (the same validated source
// the raw-text path uses), never from the request -- and only the OpenAI sampling
// subset is forwarded. The caller (Infer) has already rejected any context that
// sets a non-OpenAI knob (top_k / repetition_penalty) or a stop condition
// (rejectNonOpenAIChatGenerationParams), so decodeGenerationParams' stop/top_k
// fields are guaranteed empty/zero here. The verification-relevant fields (logprobs
// count, return_token_ids, skip_special_tokens) are pinned by Cortex from the
// profile. It returns the local output-duration budget alongside the request.
func localChatGenerationRequest(req InferRequest, profile localModelProfile, in chatInferInput, streaming bool) (chatCompletionRequest, time.Duration, error) {
	p, duration, err := decodeGenerationParams(req)
	if err != nil {
		return chatCompletionRequest{}, 0, err
	}
	skipSpecial := profile.Sampling.SkipSpecialTokens
	seed := int64(p.seed)
	chatReq := chatCompletionRequest{
		Model:             profile.ServedModel,
		Messages:          in.Messages,
		Tools:             in.Tools,
		ToolChoice:        in.ToolChoice,
		ResponseFormat:    in.ResponseFormat,
		ParallelToolCalls: in.ParallelToolCalls,

		Temperature:         p.temperature,
		TopP:                p.topP,
		MaxCompletionTokens: p.maxTokens,
		Seed:                &seed,
		PresencePenalty:     p.presencePenalty,
		FrequencyPenalty:    p.frequencyPenalty,

		Stream:                 streaming,
		Logprobs:               true,
		TopLogprobs:            profile.Sampling.Logprobs,
		ReturnTokenIDs:         true,
		ReturnTokensAsTokenIDs: true,
		SkipSpecialTokens:      &skipSpecial,
	}
	if streaming {
		// Ask vLLM for the terminal usage-only chunk so the committed output's
		// usage matches the non-streaming body (see chatStreamOptions).
		chatReq.StreamOptions = &chatStreamOptions{IncludeUsage: true}
	}
	return chatReq, duration, nil
}

// projectChatToCompletion maps a chat response onto the completionResponse shape
// the shared post-processing consumes. choice.Text is the RAW TEXT decoded from
// the committed token_ids (decodeTokensFromLogprobs) -- because Infer passes
// outputBytes=nil, it is the delivered output. The token-level
// fields (token ids and logprobs) are what the Verifier reconstructs from, and they
// are carried unchanged. This is also the authoritative point where each token id
// is checked against its logprobs entry (decodeTokensFromLogprobs fails closed on a
// mismatch), for both the non-streaming body and the reassembled stream.
func projectChatToCompletion(chatResp chatCompletionResponse, decoding modelmanifest.OutputDecoding) (completionResponse, error) {
	if len(chatResp.Choices) == 0 {
		return completionResponse{}, fmt.Errorf("modelservice local chat: empty choices")
	}
	c := chatResp.Choices[0]

	text, err := decodeTokensFromLogprobs(c.TokenIDs, c.Logprobs, decoding)
	if err != nil {
		return completionResponse{}, err
	}

	// vLLM's chat endpoint reports "tool_calls" when the model finished its turn by
	// emitting a tool call. That is not a member of the frozen finish set, and it is
	// the model completing its turn at the EOS boundary, so it is normalised to
	// "eos_token" HERE -- before the material is built from this value and
	// before ValidateGenerationEvidence re-derives the finish reason from it -- so
	// the whole pipeline (resolver, evidence, Verifier) sees one in-set value. The
	// raw-text path never sees "tool_calls"; with this normalisation the chat path's
	// finish handling is identical to it (completionFinishResolver).
	finishReason := c.FinishReason
	if strings.EqualFold(strings.TrimSpace(finishReason), "tool_calls") {
		finishReason = "eos_token"
	}

	var logprobs *completionLogprobs
	if c.Logprobs != nil {
		logprobs = &completionLogprobs{
			Tokens:        make([]string, 0, len(c.Logprobs.Content)),
			TokenLogprobs: make([]float64, 0, len(c.Logprobs.Content)),
			TopLogprobs:   make([]TopLogprobRow, 0, len(c.Logprobs.Content)),
		}
		for _, entry := range c.Logprobs.Content {
			logprobs.Tokens = append(logprobs.Tokens, entry.Token)
			logprobs.TokenLogprobs = append(logprobs.TokenLogprobs, entry.Logprob)
			logprobs.TopLogprobs = append(logprobs.TopLogprobs, chatTopLogprobRow(entry.TopLogprobs))
		}
	}

	// StopReason is deliberately left unset: chat refuses any configured stop
	// condition (rejectNonOpenAIChatGenerationParams), so a natural EOS is the only
	// termination and localGenerationFinishReason resolves it from finishReason alone.
	return completionResponse{
		Choices: []completionChoice{{
			Text:           text,
			FinishReason:   finishReason,
			PromptTokenIDs: chatResp.PromptTokenIDs,
			TokenIDs:       c.TokenIDs,
			Logprobs:       logprobs,
		}},
	}, nil
}

// decodeTokensFromLogprobs builds the committed output from the generated
// token_ids: it concatenates, in order, the bytes of each generated token
// (logprobs.content[i].bytes), leaving out one trailing token if and only if it
// is in decoding.EOSTokenIDs. It also verifies that content[i]'s token id equals
// tokenIDs[i] (under return_tokens_as_token_ids=true content[i].Token is the
// "token_id:X" form), so the bytes being decoded provably belong to the token_ids
// the Verifier scores. A length or per-position mismatch fails closed. Special
// tokens are decoded like any other; an EOS token anywhere but the last position
// is kept.
func decodeTokensFromLogprobs(tokenIDs []int, lp *chatRespLogprobs, decoding modelmanifest.OutputDecoding) (string, error) {
	if lp == nil || len(lp.Content) != len(tokenIDs) {
		n := 0
		if lp != nil {
			n = len(lp.Content)
		}
		return "", fmt.Errorf("modelservice local chat: token_ids (%d) / logprobs (%d) length mismatch", len(tokenIDs), n)
	}
	// The alignment check runs over every position, the bytes only over the
	// committed prefix. Those are different questions: alignment is about
	// whether these logprob entries describe these token ids at all, and a
	// mismatch in the EOS position is just as much a broken response as one in
	// the middle -- it must not go unnoticed merely because its bytes are about
	// to be dropped.
	committed := decoding.CommittedTokenCount(tokenIDs)
	var buf []byte
	for i, e := range lp.Content {
		if id, err := tokenIDFromKey(e.Token); err != nil || int64(id) != int64(tokenIDs[i]) {
			return "", fmt.Errorf("modelservice local chat: token id mismatch at position %d: token_ids=%d logprobs token=%q", i, tokenIDs[i], e.Token)
		}
		if i >= committed {
			continue
		}
		for _, v := range e.Bytes {
			buf = append(buf, byte(v))
		}
	}
	return string(buf), nil
}

// lastCompleteUTF8Boundary returns the length of the largest prefix of b that
// ends on a complete UTF-8 rune boundary. It strips at most utf8.UTFMax-1
// trailing bytes that form a truncated-but-valid multi-byte sequence (a
// multi-byte character split across streaming frame boundaries), so the caller
// can hold those bytes back until the next frame completes the character.
// Genuinely invalid bytes (a bad lead byte, or a run of continuation bytes with
// no lead) are left in place so a downstream UTF-8 check can fail closed rather
// than being silently buffered forever.
func lastCompleteUTF8Boundary(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	// Walk back over continuation bytes (10xxxxxx) to the last lead byte, bounded
	// by the max UTF-8 sequence length.
	start := len(b) - 1
	for i := 0; start >= 0 && i < utf8.UTFMax && b[start]&0xC0 == 0x80; i++ {
		start--
	}
	if start < 0 || b[start]&0xC0 == 0x80 {
		return len(b) // no lead byte within range: malformed tail, leave for fail-closed
	}
	var n int // expected byte length of the rune the lead byte opens
	switch c := b[start]; {
	case c < 0x80:
		n = 1
	case c >= 0xC0 && c <= 0xDF:
		n = 2
	case c >= 0xE0 && c <= 0xEF:
		n = 3
	case c >= 0xF0 && c <= 0xF4:
		n = 4
	default:
		// Continuation byte (0x80-0xBF) or an invalid lead (0xF5-0xFF): not a
		// completable prefix, leave it in place so the UTF-8 check can fail closed.
		return len(b)
	}
	if start+n <= len(b) {
		return len(b) // last rune is fully present
	}
	return start // last rune is truncated: hold it back from its lead byte
}

// --- streaming transport ---------------------------------------------------
//
// A streaming /v1/chat/completions response is a text/event-stream of
// "chat.completion.chunk" objects whose choices carry a `delta` (role/content/
// tool_calls fragments) rather than a full `message`. reassembleChatStream folds
// those deltas back into the non-streaming chatCompletionResponse shape so the
// projection/output builders and the Verifier see one shape either way.

// chatCompletionChunk is one SSE frame of a streaming chat completion. Usage is
// carried on the terminal include_usage chunk (whose Choices is empty).
type chatCompletionChunk struct {
	ID             string            `json:"id"`
	Created        int64             `json:"created"`
	Model          string            `json:"model"`
	Choices        []chatChunkChoice `json:"choices"`
	Usage          *chatRespUsage    `json:"usage"`
	PromptTokenIDs []int             `json:"prompt_token_ids"`
}

type chatChunkChoice struct {
	Index        int               `json:"index"`
	Delta        chatChunkDelta    `json:"delta"`
	FinishReason string            `json:"finish_reason"`
	TokenIDs     []int             `json:"token_ids"`
	Logprobs     *chatRespLogprobs `json:"logprobs"`
}

type chatChunkDelta struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// postStreamingChat issues a streaming chat request and reassembles the SSE frames
// into out. If the server did not actually stream (Content-Type is not
// text/event-stream -- a stub, or a vLLM that ignored stream:true), it falls back
// to the plain JSON decode, mirroring postStreamingCompletion. decoding is the
// profile's output_decoding, which the streamed text must follow exactly as the
// committed output does.
func (s *LocalService) postStreamingChat(ctx context.Context, path string, body any, out *chatCompletionResponse, ident inferStreamIdentity, budget time.Time, decoding modelmanifest.OutputDecoding) error {
	resp, err := s.doPost(ctx, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if !isEventStream(resp.Header.Get("Content-Type")) {
		// A unary body arrives whole or not at all, so there is nothing to
		// truncate; the caller's context deadline is the only bound that applies.
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("modelservice local chat: decode response %s: %w", path, err)
		}
		return nil
	}
	return s.reassembleChatStream(ctx, resp.Body, out, ident, budget, decoding)
}

// chatBudgetStopped reports whether this node, rather than the engine, ended the
// generation. See budgetStopped for the completions shape.
func chatBudgetStopped(out *chatCompletionResponse) bool {
	return len(out.Choices) > 0 && out.Choices[0].FinishReason == finishReasonMaxOutputDuration
}

// reassembleChatStream folds the SSE `data:` frames of a streaming chat completion
// into out, and emits each frame's delta to the per-frame observer (best-effort).
// The result matches a non-streaming response: generated token ids / logprob
// entries appended in order, prompt_token_ids and usage taken once, finish_reason
// taken from the frame that carries it. The delivered text (committed output and
// each frame's TextDelta) is decoded from the token ids via their logprobs bytes,
// not the engine's delta.content -- see decodeTokensFromLogprobs -- and
// concat(TextDelta) is exactly the committed output; see committedTextStream for
// how a trailing EOS and a multi-byte character split across frames are held
// back.
// budget, when non-zero, is the max_output_duration deadline. It is checked
// between whole frames so a truncation never lands inside a token, and it ends
// the generation successfully rather than failing it; see the completions
// counterpart for the full reasoning.
func (s *LocalService) reassembleChatStream(ctx context.Context, r io.Reader, out *chatCompletionResponse, ident inferStreamIdentity, budget time.Time, decoding modelmanifest.OutputDecoding) error {
	overBudget := func() bool { return !budget.IsZero() && !time.Now().Before(budget) }
	// observerForRequest, not inferObserver: the Worker installs its output-stream
	// recorder per request with WithInferStreamObserver, and the process-wide sink
	// this used to read has no production caller at all, so it is always nil. The
	// completions path already reads the request-scoped one. Reading the wrong one
	// here meant no frame ever reached the recorder on the chat path, and
	// outputStreamRecorder.finish then took its "no frames observed" branch and
	// committed the whole generation as a single output chunk.
	observer := s.observerForRequest(ctx)
	observerActive := observer != nil

	scanner := bufio.NewScanner(r)
	// One JSON object per SSE frame; with top-k logprobs a frame can be large, so
	// raise the line limit well above bufio's 64 KiB default.
	scanner.Buffer(make([]byte, 0, 1<<20), 8<<20)

	sawChoice := false
	finishReason := ""
	text := committedTextStream{decoding: decoding}

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" || strings.HasPrefix(line, ":") {
			// Blank separator or SSE comment/keepalive.
			continue
		}
		payload, ok := strings.CutPrefix(line, "data:")
		if !ok {
			// Ignore other SSE fields (event:, id:, retry:).
			continue
		}
		payload = strings.TrimSpace(payload)
		if payload == "[DONE]" {
			break
		}
		var chunk chatCompletionChunk
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			return fmt.Errorf("modelservice local chat: decode stream frame: %w", err)
		}
		// Envelope fields and usage may arrive on any frame (usage on the terminal
		// include_usage frame, whose Choices is empty).
		if out.ID == "" && chunk.ID != "" {
			out.ID = chunk.ID
		}
		if out.Created == 0 && chunk.Created != 0 {
			out.Created = chunk.Created
		}
		if out.Model == "" && chunk.Model != "" {
			out.Model = chunk.Model
		}
		if out.Usage == nil && chunk.Usage != nil {
			out.Usage = chunk.Usage
		}
		if len(out.PromptTokenIDs) == 0 && len(chunk.PromptTokenIDs) > 0 {
			out.PromptTokenIDs = chunk.PromptTokenIDs
		}
		if len(chunk.Choices) == 0 {
			continue
		}
		cc := chunk.Choices[0]
		if !sawChoice {
			out.Choices = append(out.Choices, chatResponseChoice{
				Index:   cc.Index,
				Message: chatRespMessage{Role: defaultChatRole(cc.Delta.Role)},
			})
			sawChoice = true
		}
		dst := &out.Choices[0]
		dst.TokenIDs = append(dst.TokenIDs, cc.TokenIDs...)
		if cc.FinishReason != "" {
			dst.FinishReason = cc.FinishReason
			finishReason = cc.FinishReason
		}
		if src := cc.Logprobs; src != nil {
			if dst.Logprobs == nil {
				dst.Logprobs = &chatRespLogprobs{}
			}
			dst.Logprobs.Content = append(dst.Logprobs.Content, src.Content...)
		}

		if observerActive {
			// The text is read off the accumulated sequence, not this chunk
			// alone: committedTextStream holds back the most recent token until
			// it is known not to be a trailing EOS, and any bytes that do not
			// yet end a UTF-8 character. TokenIDs / logprobs stay per-frame.
			// This is transient delivery, so an alignment error only stops the
			// text -- the authoritative check runs over the full reassembled
			// sequence in projectChatToCompletion, and fails the inference.
			textDelta := text.push(dst.TokenIDs, dst.Logprobs)
			frame := InferStreamFrame{
				RequestID:    ident.requestID,
				JobID:        ident.jobID,
				TaskID:       ident.taskID,
				ModelID:      ident.modelID,
				TextDelta:    textDelta,
				TokenIDs:     cc.TokenIDs,
				FinishReason: cc.FinishReason,
			}
			if cc.Logprobs != nil {
				frame.TokenLogprobs, frame.TopLogprobs = chatLogprobDeltas(cc.Logprobs)
			}
			if err := observer.ObserveInferFrame(ctx, frame); err != nil {
				// Best-effort: a failed downstream must not fail the committed
				// inference. Stop delivering, keep reassembling.
				observerActive = false
			}
		}
		// After the frame is folded in, never mid-frame: what the budget
		// truncates is the generation, not a token.
		if overBudget() && out.Choices[0].FinishReason == "" {
			out.Choices[0].FinishReason = finishReasonMaxOutputDuration
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("modelservice local chat: read completion stream: %w", err)
	}

	if rest := text.finish(); observerActive && rest != "" {
		// The generation has ended, so the held-back last token is released
		// unless it is an EOS, together with any bytes still waiting for the
		// end of a UTF-8 character. Ill-formed UTF-8 is delivered as-is so the
		// downstream UTF-8 check fails closed and byte parity with the
		// committed output is preserved.
		if err := observer.ObserveInferFrame(ctx, InferStreamFrame{
			RequestID: ident.requestID,
			JobID:     ident.jobID,
			TaskID:    ident.taskID,
			ModelID:   ident.modelID,
			TextDelta: rest,
		}); err != nil {
			observerActive = false
		}
	}

	if observerActive {
		_ = observer.ObserveInferFrame(ctx, InferStreamFrame{
			RequestID:    ident.requestID,
			JobID:        ident.jobID,
			TaskID:       ident.taskID,
			ModelID:      ident.modelID,
			FinishReason: finishReason,
			Done:         true,
		})
	}
	return nil
}

// committedTextStream turns a generation that arrives a few tokens at a time
// into text deltas whose concatenation is exactly the committed output (see
// decodeTokensFromLogprobs), so that no byte is ever streamed that the
// committed output does not contain.
//
// Two things are held back:
//   - the bytes of the most recent token, until the next token arrives or the
//     stream ends. Only then is it known whether that token is the last one,
//     and a last token in eos_token_ids is dropped rather than released;
//   - released bytes that do not yet end on a UTF-8 character boundary (a
//     multi-byte character split across tokens), so every delta stays valid
//     UTF-8. See lastCompleteUTF8Boundary.
type committedTextStream struct {
	decoding modelmanifest.OutputDecoding
	next     int    // next position of the accumulated sequence to read
	held     []byte // bytes of the most recent token
	heldID   int
	holding  bool
	pending  []byte // released bytes not yet delivered
	broken   bool   // a token id disagreed with its logprobs entry
}

// push reads the positions of the accumulated sequence it has not seen yet and
// returns the text that can now be delivered.
func (c *committedTextStream) push(tokenIDs []int, lp *chatRespLogprobs) string {
	if c.broken || lp == nil {
		return ""
	}
	n := min(len(tokenIDs), len(lp.Content))
	for ; c.next < n; c.next++ {
		entry := lp.Content[c.next]
		if id, err := tokenIDFromKey(entry.Token); err != nil || int64(id) != int64(tokenIDs[c.next]) {
			c.broken = true
			return ""
		}
		c.release()
		c.held = c.held[:0]
		for _, v := range entry.Bytes {
			c.held = append(c.held, byte(v))
		}
		c.heldID, c.holding = tokenIDs[c.next], true
	}
	cut := lastCompleteUTF8Boundary(c.pending)
	delta := string(c.pending[:cut])
	c.pending = c.pending[:copy(c.pending, c.pending[cut:])]
	return delta
}

// finish ends the stream: the held token is the last one, so it is dropped if
// it is an EOS and released otherwise, and everything still pending is
// returned.
func (c *committedTextStream) finish() string {
	if c.broken {
		return ""
	}
	if c.holding && !c.decoding.IsEOS(c.heldID) {
		c.release()
	}
	c.holding = false
	rest := string(c.pending)
	c.pending = nil
	return rest
}

func (c *committedTextStream) release() {
	if c.holding {
		c.pending = append(c.pending, c.held...)
		c.holding = false
	}
}

// defaultChatRole returns the assistant role for a delta that omitted it (only the
// first delta carries the role).
func defaultChatRole(role string) string {
	if strings.TrimSpace(role) == "" {
		return "assistant"
	}
	return role
}

// chatLogprobDeltas projects a chunk's logprobs.content into the positional
// (token_logprobs, top_logprobs) shape InferStreamFrame carries, matching what the
// raw-text path emits.
func chatLogprobDeltas(lp *chatRespLogprobs) ([]float64, []TopLogprobRow) {
	tokenLogprobs := make([]float64, 0, len(lp.Content))
	topLogprobs := make([]TopLogprobRow, 0, len(lp.Content))
	for _, entry := range lp.Content {
		tokenLogprobs = append(tokenLogprobs, entry.Logprob)
		topLogprobs = append(topLogprobs, chatTopLogprobRow(entry.TopLogprobs))
	}
	return tokenLogprobs, topLogprobs
}

// chatTopLogprobRow carries chat's top_logprobs list in the engine's order (the
// sampled token first, not rank order); completionTopK sorts it by logprob.
func chatTopLogprobRow(entries []chatRespTopLogprob) TopLogprobRow {
	row := make(TopLogprobRow, len(entries))
	for i, t := range entries {
		row[i] = TopLogprob{Token: t.Token, Logprob: t.Logprob}
	}
	return row
}
