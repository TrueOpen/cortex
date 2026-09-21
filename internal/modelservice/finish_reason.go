package modelservice

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/SingaXYZ/cortex/internal/nodewire"
)

// finishReasonV1FromString maps a model service finish_reason string to the
// nodewire.FinishReasonV1 enum used for receipt commitments.
//
// It refuses:
//   - empty or unknown values,
//   - the ambiguous "stop" value when ambiguousStop is true (a remote service
//     may apply its own stop sequences, so the gRPC path passes true).
func finishReasonV1FromString(reason string, ambiguousStop bool) (nodewire.FinishReasonV1, error) {
	trimmed := strings.TrimSpace(reason)
	if trimmed == "" {
		return nodewire.FinishReasonV1Unspecified, fmt.Errorf("missing finish reason")
	}
	switch strings.ToLower(trimmed) {
	case "length":
		return nodewire.FinishReasonV1MaxOutputTokens, nil
	case "stop":
		if ambiguousStop {
			return nodewire.FinishReasonV1Unspecified, fmt.Errorf("ambiguous finish reason %q: cannot distinguish EOS from stop sequence", reason)
		}
		return nodewire.FinishReasonV1EosToken, nil
	case "eos_token":
		return nodewire.FinishReasonV1EosToken, nil
	case "stop_sequence":
		return nodewire.FinishReasonV1StopSequence, nil
	case "max_output_duration":
		return nodewire.FinishReasonV1MaxOutputDuration, nil
	case "tool_calls":
		// vLLM's chat endpoint reports "tool_calls" when the model finished a turn
		// by emitting a tool call. The frozen successful-termination set
		// (nodewire.SuccessfulFinishReasonsV1) has no tool_calls member, and a
		// Verifier does not read finish_reason -- it recovers it by searching that
		// closed set for the value that reproduces the worker-value commitment. So
		// the Worker must commit an in-set value; EOS is the right one, because a
		// tool call is the model successfully completing its turn at the
		// turn/EOS boundary. See internal/nodewire/worker_value_commitment.go and
		// the finish_reason boundary in CLAUDE.md.
		return nodewire.FinishReasonV1EosToken, nil
	default:
		return nodewire.FinishReasonV1Unspecified, fmt.Errorf("unsupported finish reason %q", reason)
	}
}

func localGenerationFinishReason(g *nodewire.GenerationContext, reason string, stop json.RawMessage, count uint64) (nodewire.FinishReasonV1, error) {
	// This is the FIRST place an over-budget generation is caught -- it runs
	// inside buildInferResultFromCompletion, before the trace and checkpoint are
	// even marshalled, so it is what a live Worker hits and what a live log
	// reports. It carries the same code as the evidence-side check of the same
	// inequality on purpose: one fact, one code, wherever it is noticed.
	if count > g.Params.MaxOutputTokens {
		return 0, Deterministic(FaultCodeTokenBudgetExceeded,
			fmt.Errorf("generated token count exceeds max_output_tokens"),
			FaultUint("generated_token_count", count),
			FaultUint("max_output_tokens", g.Params.MaxOutputTokens),
			FaultStr("finish_reason", strings.TrimSpace(reason)),
			FaultStr("source", "model_response"),
			FaultStr("model_id", g.ModelID),
			FaultUint("profile_version", uint64(g.ProfileVersion)))
	}
	stop = bytes.TrimSpace(stop)
	hasStop := len(stop) != 0 && !bytes.Equal(stop, []byte("null"))
	switch strings.ToLower(strings.TrimSpace(reason)) {
	case "length":
		if hasStop || count != g.Params.MaxOutputTokens {
			return 0, fmt.Errorf("length finish does not match max_output_tokens")
		}
		return nodewire.FinishReasonV1MaxOutputTokens, nil
	case "stop", "stop_sequence", "eos_token":
		if hasStop {
			var sequence string
			if err := json.Unmarshal(stop, &sequence); err != nil {
				// The frozen receipt has no explicit stop-token outcome. Do not
				// turn numeric stop_reason into EOS or a string-stop assertion.
				return 0, fmt.Errorf("unsupported stop_reason: explicit token stop has no frozen finish reason")
			}
			if strings.EqualFold(strings.TrimSpace(reason), "eos_token") || !slices.Contains(g.Params.DecodingParams.StopSequences, sequence) {
				return 0, fmt.Errorf("stop_reason does not match a configured stop sequence")
			}
			return nodewire.FinishReasonV1StopSequence, nil
		}
		if strings.EqualFold(strings.TrimSpace(reason), "stop_sequence") {
			return 0, fmt.Errorf("stop sequence completion is missing stop_reason")
		}
		// vLLM reports null for EOS; omitted metadata is a separate legacy
		// response shape that cannot disambiguate configured stop conditions.
		if strings.EqualFold(strings.TrimSpace(reason), "eos_token") || bytes.Equal(stop, []byte("null")) {
			return nodewire.FinishReasonV1EosToken, nil
		}
		if len(g.Params.DecodingParams.StopSequences) != 0 || len(g.Params.DecodingParams.StopTokenIDs) != 0 {
			return 0, fmt.Errorf("ambiguous stop: backend did not identify the stop condition")
		}
		return nodewire.FinishReasonV1EosToken, nil
	default:
		return 0, fmt.Errorf("unsupported local finish reason %q", reason)
	}
}
