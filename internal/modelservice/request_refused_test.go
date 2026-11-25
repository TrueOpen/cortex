package modelservice

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A request the engine refuses as invalid is refused again with the same
// inputs: vLLM answers 400 to an output budget above its context length, and
// the scheduler must stop instead of spending the retry budget on it.
func TestRefusedRequestIsADeterministicFault(t *testing.T) {
	const vllm400 = `{"error":{"message":"max_completion_tokens=30744 cannot be greater than max_model_len=4096.","type":"BadRequestError","code":400}}`
	for _, c := range []struct {
		status int
		want   FaultClass
	}{
		{http.StatusBadRequest, FaultDeterministic},
		{http.StatusRequestEntityTooLarge, FaultDeterministic},
		{http.StatusUnprocessableEntity, FaultDeterministic},
		{http.StatusUnauthorized, FaultUnclassified},
		{http.StatusNotFound, FaultUnclassified},
		{http.StatusTooManyRequests, FaultTransient},
		{http.StatusInternalServerError, FaultTransient},
		{http.StatusServiceUnavailable, FaultTransient},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, vllm400, c.status)
		}))
		svc := NewLocalService(srv.URL, "local-svc", 8, 0, 0)
		var out map[string]any
		err := svc.post(context.Background(), "/v1/chat/completions", map[string]any{"max_completion_tokens": 30744}, &out)
		srv.Close()
		if err == nil {
			t.Fatalf("status %d: no error", c.status)
		}
		if got := ClassOf(err); got != c.want {
			t.Fatalf("status %d: class %s, want %s (%v)", c.status, got, c.want, err)
		}
		if c.want == FaultDeterministic && FaultCode(err) != FaultCodeRequestRefused {
			t.Fatalf("status %d: code %q", c.status, FaultCode(err))
		}
	}
}

func TestRefusedGRPCRequestIsADeterministicFault(t *testing.T) {
	for code, want := range map[codes.Code]FaultClass{
		codes.InvalidArgument:   FaultDeterministic,
		codes.OutOfRange:        FaultDeterministic,
		codes.Unavailable:       FaultTransient,
		codes.ResourceExhausted: FaultTransient,
		codes.Internal:          FaultUnclassified,
		codes.NotFound:          FaultUnclassified,
	} {
		if got := ClassOf(mapGRPCError(status.Error(code, "x"))); got != want {
			t.Fatalf("%s: class %s, want %s", code, got, want)
		}
	}
	if err := mapGRPCError(context.Canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancellation is passed through: %v", err)
	}
}
