package modelservice

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// This file implements the chat generation path: it interprets req.Input as an
// OpenAI Chat Completions request body (see proto/cortex/v1/chat_input.proto),
// calls vLLM's /v1/chat/completions, and projects the response back onto the
// same completionResponse shape the raw-text path (inferV0) produces, so all
// downstream trace/checkpoint building and the Verifier are unchanged.
//
// The transport mirrors inferV0: the streamInference switch (SetStreamInference,
// default on) selects SSE vs. a single JSON body, and reassembleChatStream folds
// the server-sent chunks back into the SAME chatCompletionResponse a non-streaming
// call would decode -- so the committed output, trace and checkpoint are
// byte-identical regardless of which transport ran, and streaming is a node-local
// detail never carried on the protocol. Verify is always non-streaming.
//
// Output is NOT the engine's detokenized message.content, nor a ChatCompletion
// JSON envelope: the delivered output, the streamed chunk text, trace.Output and
// checkpoint.Output are all the RAW TEXT decoded from the committed token_ids --
// each generated token's bytes (logprobs.content[i].bytes) concatenated in order
// (decodeTokensFromLogprobs). This makes every text artifact correspond
// byte-for-byte to the token_ids the Verifier scores (including the trailing EOS
// special token, which the engine drops from message.content), rather than to the
// engine's own detokenization. tool_calls are therefore not parsed out separately;
// any tool-call syntax the model emitted is just tokens in that raw text.
//
// Scope: sampling params are the OpenAI subset; stop sequences are intentionally
// refused (not forwarded) so a "stop" finish_reason stays unambiguous EOS; a
// "tool_calls" finish maps to EOS in finish_reason.go.

// chatInferInput is the accepted subset of the OpenAI chat request. Content-shape
// fields (messages/tools/tool_choice/response_format) are kept as raw JSON and
// forwarded verbatim to vLLM -- the input is already OpenAI-shaped, so re-modelling
// them would only risk lossy round-trips. Only the sampling scalars are typed,
// because they are read (for the generation subset) and defaulted from the profile.
type chatInferInput struct {
	Messages          json.RawMessage `json:"messages"`
	Tools             json.RawMessage `json:"tools,omitempty"`
	ToolChoice        json.RawMessage `json:"tool_choice,omitempty"`
	ResponseFormat    json.RawMessage `json:"response_format,omitempty"`
	ParallelToolCalls *bool           `json:"parallel_tool_calls,omitempty"`

	// Generation params (the generation_params_digest subset). Pointers so an
	// absent field falls back to the profile default rather than a zero value.
	Temperature         *float64 `json:"temperature,omitempty"`
	TopP                *float64 `json:"top_p,omitempty"`
	MaxCompletionTokens *int     `json:"max_completion_tokens,omitempty"`
	MaxTokens           *int     `json:"max_tokens,omitempty"` // legacy OpenAI alias
	Seed                *int64   `json:"seed,omitempty"`
	PresencePenalty     *float64 `json:"presence_penalty,omitempty"`
	FrequencyPenalty    *float64 `json:"frequency_penalty,omitempty"`
}

// chatRejectedInputFields are OpenAI request fields Cortex refuses on the chat
// path, because silently dropping them would answer a different request than the
// caller sent. Two reasons, one behaviour:
//   - logprobs/top_logprobs/logit_bias/n: their COUNT/bias is owned by the
//     verification profile or fixed by Cortex.
//   - stop: the first cut does NOT forward stop sequences so a "stop"
//     finish_reason stays unambiguous EOS (see finish_reason.go's ambiguousStop).
//     Until that ambiguity is handled it is refused rather than dropped, matching
//     the proto's "leave empty until handled" note (chat_input.proto:100).
//
// See proto/cortex/v1/chat_input.proto.
var chatRejectedInputFields = []string{"logprobs", "top_logprobs", "logit_bias", "n", "stop"}

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
	if err := validateCapability(req.Capability, true, true); err != nil {
		return InferResponse{}, err
	}
	input, isChat, err := parseChatInferInput(req.Input)
	if err != nil {
		return InferResponse{}, err
	}
	if !isChat {
		return s.inferV0(ctx, req)
	}
	profile, err := s.resolveLocalProfile(ctx, req.ModelID, req.ProfileVersion)
	if err != nil {
		return InferResponse{}, err
	}
	streaming := s.streamInferenceEnabled()
	chatReq := s.buildChatCompletionRequest(profile, input, streaming)
	var chatResp chatCompletionResponse
	{
		ctx, cancel := s.withInferTimeout(ctx)
		defer cancel()
		if streaming {
			ident := inferStreamIdentity{
				requestID: req.RequestID,
				jobID:     req.JobID,
				taskID:    req.TaskID,
				modelID:   profile.ModelID,
			}
			if err := s.postStreamingChat(ctx, "/v1/chat/completions", chatReq, &chatResp, ident); err != nil {
				return InferResponse{}, err
			}
		} else if err := s.post(ctx, "/v1/chat/completions", chatReq, &chatResp); err != nil {
			return InferResponse{}, err
		}
	}
	projected, err := projectChatToCompletion(chatResp)
	if err != nil {
		return InferResponse{}, err
	}
	if err := validateChatUsage(chatResp); err != nil {
		return InferResponse{}, err
	}
	// outputBytes is nil so the delivered output defaults to choice.Text -- the raw
	// text decoded from the committed token_ids (set by projectChatToCompletion).
	// The delivered output, trace.Output and checkpoint.Output are thus identical.
	return s.buildInferResultFromCompletion(ctx, req, profile, projected, nil, chatFinishResolver)
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
				"modelservice local chat: request field %q is not accepted (owned by the verification profile or fixed by Cortex)", field)
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

// buildChatCompletionRequest assembles the outgoing request: content-shape fields
// pass through, sampling params come from the input where present else the profile
// default, and the verification-relevant fields are pinned by Cortex.
func (s *LocalService) buildChatCompletionRequest(profile localModelProfile, in chatInferInput, streaming bool) chatCompletionRequest {
	skipSpecial := profile.Sampling.SkipSpecialTokens
	seed := int64(profile.Sampling.Seed)
	req := chatCompletionRequest{
		Model:             profile.ServedModel,
		Messages:          in.Messages,
		Tools:             in.Tools,
		ToolChoice:        in.ToolChoice,
		ResponseFormat:    in.ResponseFormat,
		ParallelToolCalls: in.ParallelToolCalls,

		Temperature: profile.Sampling.Temperature,
		TopP:        profile.Sampling.TopP,
		// No profile-level max: #370 removed the fixed 128-token default so output
		// is not artificially truncated. The chat path carries no chain-bound
		// generation params yet, so the bound comes only from the request's
		// max_completion_tokens / max_tokens below (omitted when unset, letting the
		// engine use its context-limited default).
		Seed: &seed,

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
		req.StreamOptions = &chatStreamOptions{IncludeUsage: true}
	}
	if in.Temperature != nil {
		req.Temperature = *in.Temperature
	}
	if in.TopP != nil {
		req.TopP = *in.TopP
	}
	switch {
	case in.MaxCompletionTokens != nil:
		req.MaxCompletionTokens = *in.MaxCompletionTokens
	case in.MaxTokens != nil:
		req.MaxCompletionTokens = *in.MaxTokens
	}
	if in.Seed != nil {
		req.Seed = in.Seed
	}
	if in.PresencePenalty != nil {
		req.PresencePenalty = *in.PresencePenalty
	}
	if in.FrequencyPenalty != nil {
		req.FrequencyPenalty = *in.FrequencyPenalty
	}
	return req
}

// projectChatToCompletion maps a chat response onto the completionResponse shape
// the shared post-processing consumes. choice.Text is the RAW TEXT decoded from
// the committed token_ids (decodeTokensFromLogprobs) -- it is both trace.Output and,
// because Infer passes outputBytes=nil, the delivered output. The token-level
// fields (token ids and logprobs) are what the Verifier reconstructs from, and they
// are carried unchanged. This is also the authoritative point where each token id
// is checked against its logprobs entry (decodeTokensFromLogprobs fails closed on a
// mismatch), for both the non-streaming body and the reassembled stream.
func projectChatToCompletion(chatResp chatCompletionResponse) (completionResponse, error) {
	if len(chatResp.Choices) == 0 {
		return completionResponse{}, fmt.Errorf("modelservice local chat: empty choices")
	}
	c := chatResp.Choices[0]

	text, err := decodeTokensFromLogprobs(c.TokenIDs, c.Logprobs)
	if err != nil {
		return completionResponse{}, err
	}

	var logprobs *completionLogprobs
	if c.Logprobs != nil {
		logprobs = &completionLogprobs{
			Tokens:        make([]string, 0, len(c.Logprobs.Content)),
			TokenLogprobs: make([]float64, 0, len(c.Logprobs.Content)),
			TopLogprobs:   make([]map[string]float64, 0, len(c.Logprobs.Content)),
		}
		for _, entry := range c.Logprobs.Content {
			logprobs.Tokens = append(logprobs.Tokens, entry.Token)
			logprobs.TokenLogprobs = append(logprobs.TokenLogprobs, entry.Logprob)
			top := make(map[string]float64, len(entry.TopLogprobs))
			for _, t := range entry.TopLogprobs {
				top[normalizeTokenKey(t.Token)] = t.Logprob
			}
			logprobs.TopLogprobs = append(logprobs.TopLogprobs, top)
		}
	}

	return completionResponse{
		Choices: []completionChoice{{
			Text:           text,
			FinishReason:   c.FinishReason,
			PromptTokenIDs: chatResp.PromptTokenIDs,
			TokenIDs:       c.TokenIDs,
			Logprobs:       logprobs,
		}},
	}, nil
}

// decodeTokensFromLogprobs reconstructs the delivered text from the committed
// token_ids: it concatenates, in order, the bytes of each generated token
// (logprobs.content[i].bytes). It also verifies that content[i]'s token id equals
// tokenIDs[i] (under return_tokens_as_token_ids=true content[i].Token is the
// "token_id:X" form), so the bytes being decoded provably belong to the token_ids
// the Verifier scores. A length or per-position mismatch fails closed. Special/EOS
// tokens are decoded like any other, so the result corresponds byte-for-byte to the
// full token_ids sequence (unlike the engine's message.content, which drops EOS).
func decodeTokensFromLogprobs(tokenIDs []int, lp *chatRespLogprobs) (string, error) {
	if lp == nil || len(lp.Content) != len(tokenIDs) {
		n := 0
		if lp != nil {
			n = len(lp.Content)
		}
		return "", fmt.Errorf("modelservice local chat: token_ids (%d) / logprobs (%d) length mismatch", len(tokenIDs), n)
	}
	var buf []byte
	for i, e := range lp.Content {
		if normalizeTokenKey(e.Token) != strconv.Itoa(tokenIDs[i]) {
			return "", fmt.Errorf("modelservice local chat: token id mismatch at position %d: token_ids=%d logprobs token=%q", i, tokenIDs[i], e.Token)
		}
		for _, v := range e.Bytes {
			buf = append(buf, byte(v))
		}
	}
	return string(buf), nil
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
// to the plain JSON decode, mirroring postStreamingCompletion.
func (s *LocalService) postStreamingChat(ctx context.Context, path string, body any, out *chatCompletionResponse, ident inferStreamIdentity) error {
	resp, err := s.doPost(ctx, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if !isEventStream(resp.Header.Get("Content-Type")) {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("modelservice local chat: decode response %s: %w", path, err)
		}
		return nil
	}
	return s.reassembleChatStream(ctx, resp.Body, out, ident)
}

// reassembleChatStream folds the SSE `data:` frames of a streaming chat completion
// into out, and emits each frame's delta to the per-frame observer (best-effort).
// The result matches a non-streaming response: generated token ids / logprob
// entries appended in order, prompt_token_ids and usage taken once, finish_reason
// taken from the frame that carries it. The delivered text (committed output and
// each frame's TextDelta) is decoded from the token ids via their logprobs bytes,
// not the engine's delta.content -- see decodeTokensFromLogprobs.
func (s *LocalService) reassembleChatStream(ctx context.Context, r io.Reader, out *chatCompletionResponse, ident inferStreamIdentity) error {
	observer := s.inferObserver()
	observerActive := observer != nil

	scanner := bufio.NewScanner(r)
	// One JSON object per SSE frame; with top-k logprobs a frame can be large, so
	// raise the line limit well above bufio's 64 KiB default.
	scanner.Buffer(make([]byte, 0, 1<<20), 8<<20)

	sawChoice := false
	finishReason := ""

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
			// The frame's text is decoded from this chunk's token ids via their
			// logprobs bytes (not delta.content). This is transient delivery, so a
			// decode/alignment error just drops this frame's text -- the authoritative
			// check runs over the full reassembled sequence in projectChatToCompletion.
			textDelta, _ := decodeTokensFromLogprobs(cc.TokenIDs, cc.Logprobs)
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
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("modelservice local chat: read completion stream: %w", err)
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
func chatLogprobDeltas(lp *chatRespLogprobs) ([]float64, []map[string]float64) {
	tokenLogprobs := make([]float64, 0, len(lp.Content))
	topLogprobs := make([]map[string]float64, 0, len(lp.Content))
	for _, entry := range lp.Content {
		tokenLogprobs = append(tokenLogprobs, entry.Logprob)
		top := make(map[string]float64, len(entry.TopLogprobs))
		for _, t := range entry.TopLogprobs {
			top[normalizeTokenKey(t.Token)] = t.Logprob
		}
		topLogprobs = append(topLogprobs, top)
	}
	return tokenLogprobs, topLogprobs
}
