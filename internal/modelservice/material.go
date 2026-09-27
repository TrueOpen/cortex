package modelservice

import (
	"fmt"
	"math"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/metric"
	"github.com/TrueOpen/cortex/internal/nodewire"
	cortexv1 "github.com/TrueOpen/cortex/proto/cortex/v1"
)

// TokenIDs is the token id material of one generation: the prompt as the model
// service tokenized it and the tokens it emitted. It is the raw material of the
// A-level Worker evidence (WORKER_TOKEN_OPENING).
type TokenIDs struct {
	Input     []uint32
	Generated []uint32
}

// The two Infer artifacts are the cortex.v1 TokenIDsV1 and PositionValuesV1
// messages in protobuf binary form, so a local and a remote model service hand
// Cortex identical bytes. They are transport, not preimage: nothing hashes them
// into a protocol commitment, and Cortex re-derives every committed encoding
// from the decoded values.
var artifactMarshal = proto.MarshalOptions{Deterministic: true}

// EncodeTokenIDsArtifact is the token_ids_ref artifact for ids.
func EncodeTokenIDsArtifact(ids TokenIDs) ([]byte, error) {
	return artifactMarshal.Marshal(&cortexv1.TokenIDsV1{InputTokenIds: ids.Input, GeneratedTokenIds: ids.Generated})
}

// DecodeTokenIDsArtifact parses a token_ids_ref artifact. Unknown fields are
// refused: a newer model service speaking a field this Cortex does not know
// would otherwise have it silently dropped from the evidence.
func DecodeTokenIDsArtifact(raw []byte) (TokenIDs, error) {
	var message cortexv1.TokenIDsV1
	if err := proto.Unmarshal(raw, &message); err != nil {
		return TokenIDs{}, fmt.Errorf("decode token ids artifact: %w", err)
	}
	if len(message.ProtoReflect().GetUnknown()) != 0 {
		return TokenIDs{}, fmt.Errorf("token ids artifact carries unknown fields")
	}
	ids := TokenIDs{Input: message.GetInputTokenIds(), Generated: message.GetGeneratedTokenIds()}
	if len(ids.Input) > nodewire.MaxTokenIDCountV1 || len(ids.Generated) > nodewire.MaxTokenIDCountV1 {
		return TokenIDs{}, fmt.Errorf("token ids artifact exceeds %d tokens", nodewire.MaxTokenIDCountV1)
	}
	return ids, nil
}

// EncodePositionValuesArtifact is the position_values_ref artifact: one
// PositionValueV1 per generated position, in position order.
func EncodePositionValuesArtifact(values []metric.PositionValue) ([]byte, error) {
	message := &cortexv1.PositionValuesV1{Values: make([]*cortexv1.PositionValueV1, len(values))}
	for i, value := range values {
		position, err := positionUint32(i)
		if err != nil {
			return nil, err
		}
		entry := &cortexv1.PositionValueV1{
			Position: position, TokenId: value.TokenID, Missing: value.Missing,
			Logprob: value.Logprob, Rank: value.Rank,
			TopLogprobs: make([]*cortexv1.TokenLogprobV1, len(value.TopK)),
		}
		for j, top := range value.TopK {
			entry.TopLogprobs[j] = &cortexv1.TokenLogprobV1{TokenId: top.TokenID, Logprob: top.Logprob}
		}
		message.Values[i] = entry
	}
	return artifactMarshal.Marshal(message)
}

// DecodePositionValuesArtifact parses a position_values_ref artifact and checks
// its shape: positions run 0..n-1 in order and each top-k lists a token once.
func DecodePositionValuesArtifact(raw []byte) ([]metric.PositionValue, error) {
	var message cortexv1.PositionValuesV1
	if err := proto.Unmarshal(raw, &message); err != nil {
		return nil, fmt.Errorf("decode position values artifact: %w", err)
	}
	if len(message.ProtoReflect().GetUnknown()) != 0 {
		return nil, fmt.Errorf("position values artifact carries unknown fields")
	}
	if len(message.GetValues()) > nodewire.MaxTokenIDCountV1 {
		return nil, fmt.Errorf("position values artifact exceeds %d positions", nodewire.MaxTokenIDCountV1)
	}
	values := make([]metric.PositionValue, len(message.GetValues()))
	for i, entry := range message.GetValues() {
		if len(entry.ProtoReflect().GetUnknown()) != 0 {
			return nil, fmt.Errorf("position value %d carries unknown fields", i)
		}
		if uint64(entry.GetPosition()) != uint64(i) {
			return nil, fmt.Errorf("position value %d names position %d; positions must run 0..n-1 in order", i, entry.GetPosition())
		}
		value := metric.PositionValue{
			TokenID: entry.GetTokenId(), Logprob: entry.GetLogprob(), Rank: entry.GetRank(), Missing: entry.GetMissing(),
			TopK: make([]metric.TokenLogprob, len(entry.GetTopLogprobs())),
		}
		seen := make(map[uint32]struct{}, len(entry.GetTopLogprobs()))
		for j, top := range entry.GetTopLogprobs() {
			if _, dup := seen[top.GetTokenId()]; dup {
				return nil, fmt.Errorf("position value %d top-k repeats token %d", i, top.GetTokenId())
			}
			seen[top.GetTokenId()] = struct{}{}
			value.TopK[j] = metric.TokenLogprob{TokenID: top.GetTokenId(), Logprob: top.GetLogprob()}
		}
		values[i] = value
	}
	return values, nil
}

// ValidateGenerationMaterial checks the material of one Infer against the
// chain-bound generation context: one value per generated token, measured for
// that token, and no more tokens than the order allowed. It returns the
// generated token count. Every refusal is Deterministic: the material is bytes
// this node already holds, so re-running the model cannot change the verdict
// on them.
func ValidateGenerationMaterial(g *nodewire.GenerationContext, digest []byte, ids TokenIDs, values []metric.PositionValue) (uint64, error) {
	if g == nil {
		return 0, fmt.Errorf("generation context is required")
	}
	if err := ValidateGenerationContext(g, digest, g.ModelID, fmt.Sprint(g.ProfileVersion)); err != nil {
		return 0, err
	}
	if len(values) != len(ids.Generated) {
		return 0, Deterministic(FaultCodeTokenEvidenceCountMismatch,
			fmt.Errorf("position values do not cover the generated tokens one to one"),
			FaultInt("generated_token_ids", len(ids.Generated)), FaultInt("position_values", len(values)),
			FaultStr("model_id", g.ModelID), FaultUint("profile_version", uint64(g.ProfileVersion)))
	}
	if uint64(len(ids.Generated)) > g.Params.MaxOutputTokens {
		return 0, Deterministic(FaultCodeTokenBudgetExceeded,
			fmt.Errorf("generated token count exceeds the order's max_output_tokens"),
			FaultInt("generated_token_count", len(ids.Generated)), FaultUint("max_output_tokens", g.Params.MaxOutputTokens),
			FaultStr("model_id", g.ModelID), FaultUint("profile_version", uint64(g.ProfileVersion)))
	}
	for i, value := range values {
		if value.TokenID != ids.Generated[i] {
			return 0, Deterministic(FaultCodeTokenEvidenceCountMismatch,
				fmt.Errorf("position value %d was measured for token %d, but token %d was generated", i, value.TokenID, ids.Generated[i]),
				FaultInt("position", i))
		}
	}
	return uint64(len(ids.Generated)), nil
}

func positionUint32(i int) (uint32, error) {
	if i < 0 || int64(i) > math.MaxUint32 {
		return 0, fmt.Errorf("position %d does not fit uint32", i)
	}
	return uint32(i), nil
}

// ProtocolTokenIDs encodes ids as the two A-level artifacts, input_token_ids
// and generated_token_ids, in the protocol's raw count/vector encoding.
func ProtocolTokenIDs(ids TokenIDs) (input, generated []byte, err error) {
	input, err = nodewire.EncodeTokenIDs(ids.Input)
	if err != nil {
		return nil, nil, err
	}
	generated, err = nodewire.EncodeTokenIDs(ids.Generated)
	return input, generated, err
}

// ValidateFinishReason applies the local finish-reason checks of 05 section
// 8.3 to a completed generation, whatever transport produced it:
//
//	MAX_OUTPUT_TOKENS   the generated count equals max_output_tokens
//	MAX_OUTPUT_DURATION the generated count is below max_output_tokens
//	STOP_TOKEN          the last generated token is one of stop_token_ids
//	every reason but MAX_OUTPUT_DURATION and USER_STOP needs at least one token
//
// A contradiction is deterministic: the same material fails the same way.
func ValidateFinishReason(g *nodewire.GenerationContext, generated []uint32, reason nodewire.FinishReasonV1) error {
	if g == nil {
		return fmt.Errorf("generation context is required")
	}
	count, limit := uint64(len(generated)), g.Params.MaxOutputTokens
	fail := func(format string, args ...any) error {
		return Deterministic(FaultCodeFinishReasonInconsistent, fmt.Errorf(format, args...),
			FaultUint("finish_reason", uint64(reason)), FaultInt("generated_token_count", len(generated)), FaultUint("max_output_tokens", limit))
	}
	if count == 0 && reason != nodewire.FinishReasonV1MaxOutputDuration && reason != nodewire.FinishReasonV1UserStop {
		return fail("finish reason %d requires at least one generated token", reason)
	}
	switch reason {
	case nodewire.FinishReasonV1MaxOutputTokens:
		if count != limit {
			return fail("MAX_OUTPUT_TOKENS with %d generated tokens, max_output_tokens is %d", count, limit)
		}
	case nodewire.FinishReasonV1MaxOutputDuration:
		if count >= limit {
			return fail("MAX_OUTPUT_DURATION with %d generated tokens reaches max_output_tokens %d", count, limit)
		}
	case nodewire.FinishReasonV1StopToken:
		if !slices.Contains(g.Params.DecodingParams.StopTokenIDs, generated[count-1]) {
			return fail("STOP_TOKEN, but the last generated token %d is not a stop token id", generated[count-1])
		}
	case nodewire.FinishReasonV1Unspecified:
		return fail("finish reason is unspecified")
	}
	return nil
}
