package modelservice

import (
	"context"
	"strings"
	"testing"
)

// The offline half of the token-count investigation.
//
// A live Worker refused a task with "trace generated token count exceeds limit
// or does not match token evidence" -- one sentence covering three different
// inequalities, so the log could not say which one fired, and the engine's own
// numbers never reached it. That sentence is gone (each inequality has its own
// code and carries its measurements), but the remaining question is which
// engine behaviour produced the numbers.
//
// This table is the lookup that answers it. Each case is a hypothesis about what
// the SSE frames could contain, driven through the REAL streaming path --
// postStreamingCompletion, reassembleCompletionStream,
// buildInferResultFromCompletion, ValidateGenerationEvidence -- and pinned to
// the fault code it produces. An operator holding a code from a live node reads
// the column backwards to the engine behaviour that explains it.
//
// It deliberately does NOT change how the stream is folded. Two of the
// hypotheses below would be fixed in reassembleCompletionStream and one in the
// request mapping, and they need different fixes, so guessing between them from
// a symptom would be a change nothing measured. What this pins is the mapping
// from cause to code, which is what makes the live reading decisive.
//
// One thing the table already establishes, and it narrows the live search: on
// the GENERATING node every over-budget shape is caught by
// localGenerationFinishReason, before the trace is even marshalled, and it
// reports source=model_response. The live refusal was the evidence-side message
// instead, so on that node the budget was NOT the failing inequality -- a
// GENERATION_TRACE_* or GENERATION_TOKEN_EVIDENCE_COUNT_MISMATCH code is what
// the same task produces now, and those are reachable from four call sites
// (Worker post-generation, Worker restart re-validation, LocalService.Verify,
// and the Verifier's evidence path) reading artifacts a PEER produced. The
// source= and model_id= fields are what separate them.
func TestStreamingTokenCountFaultsAreDistinguishableByCode(t *testing.T) {
	const budget = 4
	for _, tc := range []struct {
		name string
		// hypothesis names the engine behaviour this frame sequence models.
		hypothesis string
		frames     []completionResponse
		wantCode   string
		// wantFields are measurements the refusal must carry, because the code
		// alone does not say by how much.
		wantFields map[string]string
	}{
		{
			name:       "cumulative token_ids per chunk",
			hypothesis: "the engine repeats every token id emitted so far in each SSE frame instead of only the delta; appending them squares the count",
			frames: []completionResponse{
				streamFrame("a", []int{10}, []float64{-0.1}, nil, []int{1, 2, 3}, ""),
				streamFrame("b", []int{10, 11}, []float64{-0.1, -0.2}, nil, nil, ""),
				streamFrame("c", []int{10, 11, 12}, []float64{-0.1, -0.2, -0.3}, nil, nil, "stop"),
			},
			wantCode: FaultCodeTokenBudgetExceeded,
			wantFields: map[string]string{
				"generated_token_count": "6",
				"max_output_tokens":     "4",
				"source":                "model_response",
			},
		},
		{
			name:       "a usage-only trailer frame repeats the last token",
			hypothesis: "the terminal frame carries usage plus a duplicate of the final token id, so the fold counts one token twice",
			frames: []completionResponse{
				streamFrame("a", []int{10}, []float64{-0.1}, nil, []int{1, 2, 3}, ""),
				streamFrame("b", []int{11}, []float64{-0.2}, nil, nil, ""),
				streamFrame("c", []int{12}, []float64{-0.3}, nil, nil, ""),
				streamFrame("d", []int{13}, []float64{-0.4}, nil, nil, ""),
				streamFrame("", []int{13}, []float64{-0.4}, nil, nil, "stop"),
			},
			wantCode: FaultCodeTokenBudgetExceeded,
			wantFields: map[string]string{
				"generated_token_count": "5",
				"max_output_tokens":     "4",
				"source":                "model_response",
			},
		},
		{
			name:       "the engine ignored max_tokens",
			hypothesis: "the request mapping did not carry the order's max_output_tokens, or the engine overrode it; the frames are well-formed and simply too many",
			frames: []completionResponse{
				streamFrame("a", []int{10}, []float64{-0.1}, nil, []int{1, 2, 3}, ""),
				streamFrame("b", []int{11}, []float64{-0.2}, nil, nil, ""),
				streamFrame("c", []int{12}, []float64{-0.3}, nil, nil, ""),
				streamFrame("d", []int{13}, []float64{-0.4}, nil, nil, ""),
				streamFrame("e", []int{14}, []float64{-0.5}, nil, nil, "length"),
			},
			wantCode: FaultCodeTokenBudgetExceeded,
			wantFields: map[string]string{
				"generated_token_count": "5",
				"max_output_tokens":     "4",
				"finish_reason":         "length",
				"source":                "model_response",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Log("hypothesis: " + tc.hypothesis)
			err := inferWithStreamedFrames(t, tc.frames, budget)
			if err == nil {
				t.Fatalf("Infer accepted %d tokens against a budget of %d", countStreamedTokens(tc.frames), budget)
			}
			if got := FaultCode(err); got != tc.wantCode {
				t.Fatalf("FaultCode = %q, want %q (error: %v)", got, tc.wantCode, err)
			}
			fields := map[string]string{}
			for _, field := range FaultFields(err) {
				fields[field.Key] = field.Value
			}
			for key, want := range tc.wantFields {
				if fields[key] != want {
					t.Fatalf("field %s = %q, want %q; all: %#v", key, fields[key], want, fields)
				}
			}
		})
	}
}

// The logprob vector and the token-id vector are folded separately, so they can
// come apart on their own. That is a different fault from the budget one and it
// must be reported as one: an operator seeing "incomplete logprobs" knows the
// frames disagreed with themselves, not that the model ran long.
func TestAStreamWhoseLogprobsAndTokenIDsDisagreeIsNotABudgetFault(t *testing.T) {
	frames := []completionResponse{
		streamFrame("a", []int{10}, []float64{-0.1}, nil, []int{1, 2, 3}, ""),
		// Two ids, one logprob.
		streamFrame("bc", []int{11, 12}, []float64{-0.2}, nil, nil, "stop"),
	}
	err := inferWithStreamedFrames(t, frames, 128)
	if err == nil {
		t.Fatal("Infer accepted a stream whose logprob vector is shorter than its token ids")
	}
	if code := FaultCode(err); code == FaultCodeTokenBudgetExceeded {
		t.Fatalf("a logprob/token-id disagreement was reported as a budget fault: %v", err)
	}
	if !strings.Contains(err.Error(), "logprobs are incomplete") {
		t.Fatalf("unexpected refusal for an incomplete logprob vector: %v", err)
	}
}

// A well-formed stream inside the budget still passes. Without this the table
// above could be green because everything fails.
func TestAWellFormedStreamInsideTheBudgetIsAccepted(t *testing.T) {
	frames := []completionResponse{
		streamFrame("a", []int{10}, []float64{-0.1}, nil, []int{1, 2, 3}, ""),
		streamFrame("b", []int{11}, []float64{-0.2}, nil, nil, "stop"),
	}
	if err := inferWithStreamedFrames(t, frames, 4); err != nil {
		t.Fatalf("a two-token generation against a budget of 4 was refused: %v", err)
	}
}

func countStreamedTokens(frames []completionResponse) int {
	total := 0
	for _, frame := range frames {
		if len(frame.Choices) > 0 {
			total += len(frame.Choices[0].TokenIDs)
		}
	}
	return total
}

// inferWithStreamedFrames runs one Infer against an SSE stub serving frames,
// under a generation context whose max_output_tokens is budget.
func inferWithStreamedFrames(t *testing.T, frames []completionResponse, budget uint64) error {
	t.Helper()
	models := []string{"Qwen/Qwen3-8B"}
	srv, _ := newVLLMStreamStub(t, frames, verifyResponse(), models)
	svc := NewLocalService(srv.URL, "local-svc", 4, 0, 0)

	generation := localTestGeneration(testQwenModelID(), 1)
	generation.Params.MaxOutputTokens = budget
	req := localGenerationInfer(t, generation)
	req.RequestID = "token-count-diagnosis"
	req.Capability = CapabilityLLMTextV1
	req.Input = []byte("say hi")

	_, err := svc.Infer(context.Background(), req)
	return err
}
