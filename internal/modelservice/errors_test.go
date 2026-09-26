package modelservice

import (
	"errors"
	"fmt"
	"testing"
)

// The classification is only worth anything if it survives the wrapping every
// caller does. worker.go wraps with "model generation evidence: %w", the task
// runner reads the class several frames later, and a class that only answered
// at the raising site would be read as unclassified there -- which is the
// default, which is "retry the model", which is the loop this exists to stop.
func TestFaultClassSurvivesWrapping(t *testing.T) {
	base := Deterministic(FaultCodeTokenBudgetExceeded, errors.New("boom"), FaultUint("max_output_tokens", 512))
	wrapped := fmt.Errorf("model generation evidence: %w", fmt.Errorf("infer: %w", base))

	if got := ClassOf(wrapped); got != FaultDeterministic {
		t.Fatalf("ClassOf through two wrappings = %v, want %v", got, FaultDeterministic)
	}
	if got := FaultCode(wrapped); got != FaultCodeTokenBudgetExceeded {
		t.Fatalf("FaultCode through two wrappings = %q, want %q", got, FaultCodeTokenBudgetExceeded)
	}
	if !IsDeterministic(wrapped) || IsRetryable(wrapped) || IsRegenerationForbidden(wrapped) {
		t.Fatalf("predicates disagree with the class for %v", wrapped)
	}
	fields := FaultFields(wrapped)
	if len(fields) != 1 || fields[0].Key != "max_output_tokens" || fields[0].Value != "512" {
		t.Fatalf("FaultFields = %#v, want the single measurement it was raised with", fields)
	}
}

// retryableError predates the classification and is produced on the HTTP and
// gRPC paths. It must read as transient rather than as unclassified, or a
// 503 from vLLM would stop a task the way a contract violation does.
func TestRetryableErrorReadsAsTransient(t *testing.T) {
	err := fmt.Errorf("post: %w", retryableError{err: errors.New("connection refused")})
	if got := ClassOf(err); got != FaultTransient {
		t.Fatalf("ClassOf = %v, want %v", got, FaultTransient)
	}
	if !IsRetryable(err) {
		t.Fatalf("IsRetryable(%v) = false", err)
	}
}

// An unmarked error keeps the previous behaviour. Nothing may infer "stop
// calling the model" from silence.
func TestUnmarkedErrorStaysUnclassified(t *testing.T) {
	err := errors.New("something went wrong")
	if got := ClassOf(err); got != FaultUnclassified {
		t.Fatalf("ClassOf = %v, want %v", got, FaultUnclassified)
	}
	if IsRetryable(err) || IsDeterministic(err) || IsRegenerationForbidden(err) {
		t.Fatalf("an unmarked error answered a class predicate")
	}
	if FaultSummary(err) != "" {
		t.Fatalf("FaultSummary of an unmarked error = %q, want empty", FaultSummary(err))
	}
}
