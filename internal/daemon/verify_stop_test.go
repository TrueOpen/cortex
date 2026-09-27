package daemon

import (
	"fmt"
	"testing"

	"github.com/TrueOpen/cortex/internal/metric"
	"github.com/TrueOpen/cortex/internal/store"
)

// A Verifier-side empty comparison set is retried a bounded number of times,
// then stops the round with its reason kept on the record.
func TestVerifierValuesUnavailableRetriesThenStops(t *testing.T) {
	err := fmt.Errorf("verify: %w", metric.ErrVerifierValuesUnavailable)
	for attempt := uint32(0); attempt+1 < maxVerifierValueAttempts; attempt++ {
		task, retryErr := verifierValuesUnavailable(store.VerifyTask{RetryCount: attempt}, err)
		if retryErr == nil || task.Stage == "failed" {
			t.Fatalf("attempt %d stopped early: %+v", attempt, task)
		}
	}
	task, retryErr := verifierValuesUnavailable(store.VerifyTask{TaskID: "t", RetryCount: maxVerifierValueAttempts - 1}, err)
	if retryErr != nil || task.Stage != "failed" || task.LastError != err.Error() {
		t.Fatalf("last attempt = %+v, %v, want a failed stage with the reason", task, retryErr)
	}
	merged := mergeVerifyExecution(store.VerifyTask{TaskID: "t", Stage: "queued"}, task)
	if merged.Stage != "failed" || merged.LastError != err.Error() {
		t.Fatalf("merged = %+v, want the stop reason kept", merged)
	}
}
