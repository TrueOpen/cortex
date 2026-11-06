package modelservice

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/modelmanifest"
)

// The OpenRouter shim refuses structured tool_calls after it has already sent
// the 200 and the role frame, and drops the connection (TrueOpen/cortex#100).
// What reaches cortex is a stream with no tokens and no finish_reason.
const shimAbortedChatStream = `data: {"id":"chatcmpl-1","choices":[{"index":0,"delta":{"role":"assistant","content":""},"logprobs":null,"finish_reason":null}],"prompt_token_ids":[1,2,3]}

`

func reassembleChat(t *testing.T, body string) error {
	t.Helper()
	var out chatCompletionResponse
	return (&LocalService{}).reassembleChatStream(context.Background(), strings.NewReader(body), &out, inferStreamIdentity{}, time.Time{}, modelmanifest.OutputDecoding{})
}

func reassembleCompletion(t *testing.T, body string) error {
	t.Helper()
	var out completionResponse
	return (&LocalService{}).reassembleCompletionStream(context.Background(), strings.NewReader(body), &out, inferStreamIdentity{}, time.Time{})
}

func TestChatStreamWithoutAFinishReasonIsATruncation(t *testing.T) {
	for name, body := range map[string]string{
		"shim abort after the role frame": shimAbortedChatStream,
		"empty stream":                    "",
		"tokens then a dropped connection": `data: {"choices":[{"index":0,"delta":{"content":"hi"},"token_ids":[7],"logprobs":{"content":[{"token":"token_id:7","logprob":-0.1,"bytes":[104,105]}]}}]}

`,
	} {
		t.Run(name, func(t *testing.T) {
			err := reassembleChat(t, body)
			if FaultCode(err) != "MODEL_STREAM_TRUNCATED" || ClassOf(err) != FaultTransient {
				t.Fatalf("err = %v (code %q, class %v), want a transient MODEL_STREAM_TRUNCATED", err, FaultCode(err), ClassOf(err))
			}
		})
	}
}

func TestCompletionStreamWithoutAFinishReasonIsATruncation(t *testing.T) {
	err := reassembleCompletion(t, `data: {"choices":[{"index":0,"text":"hi","token_ids":[7]}]}

`)
	if FaultCode(err) != "MODEL_STREAM_TRUNCATED" || ClassOf(err) != FaultTransient {
		t.Fatalf("err = %v (code %q)", err, FaultCode(err))
	}
}

// An in-band error frame carries the model service's own reason; a refusal of
// the request itself is deterministic, so the task runner halts rather than
// re-running the same input until the chain deadline.
func TestStreamErrorFrameIsClassifiedByItsCode(t *testing.T) {
	for _, tc := range []struct {
		name, frame string
		class       FaultClass
		code, msg   string
	}{
		{"vLLM error wrapper, bad request", `{"error":{"message":"\"auto\" tool choice requires --enable-auto-tool-choice","type":"BadRequestError","code":400}}`, FaultDeterministic, "MODEL_SERVICE_REFUSED", "--enable-auto-tool-choice"},
		{"flat vLLM error object", `{"object":"error","message":"tool calls are not supported","type":"NotImplementedError","code":501}`, FaultDeterministic, "MODEL_SERVICE_REFUSED", "tool calls are not supported"},
		{"upstream failure", `{"error":{"message":"upstream provider failed","type":"UpstreamError","code":503}}`, FaultTransient, "MODEL_SERVICE_STREAM_ERROR", "upstream provider failed"},
		{"rate limited", `{"error":{"message":"slow down","code":429}}`, FaultTransient, "MODEL_SERVICE_STREAM_ERROR", "slow down"},
		{"code as a string", `{"error":{"message":"bad input","code":"400"}}`, FaultDeterministic, "MODEL_SERVICE_REFUSED", "bad input"},
		{"no code", `{"error":{"message":"something broke"}}`, FaultTransient, "MODEL_SERVICE_STREAM_ERROR", "something broke"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := shimAbortedChatStream + "data: " + tc.frame + "\n\n"
			for path, err := range map[string]error{
				"chat":        reassembleChat(t, body),
				"completions": reassembleCompletion(t, "data: "+tc.frame+"\n\n"),
			} {
				if ClassOf(err) != tc.class || FaultCode(err) != tc.code {
					t.Fatalf("%s: err = %v (class %v, code %q), want %v %s", path, err, ClassOf(err), FaultCode(err), tc.class, tc.code)
				}
				if !strings.Contains(err.Error(), tc.msg) {
					t.Fatalf("%s: err = %v does not carry the service's message %q", path, err, tc.msg)
				}
			}
		})
	}
}

func TestStreamFrameErrorIgnoresOrdinaryFrames(t *testing.T) {
	for _, frame := range []string{
		`{"id":"x","choices":[]}`,
		`{"choices":[{"index":0,"text":"a"}]}`,
		`{"object":"chat.completion.chunk","choices":[]}`,
		`{"error":null,"choices":[]}`,
	} {
		if err := streamFrameError([]byte(frame)); err != nil {
			t.Fatalf("streamFrameError(%s) = %v", frame, err)
		}
	}
}
