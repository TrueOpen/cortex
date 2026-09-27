package modelservice

import (
	"testing"
	"time"
)

// newBoundLocalService is NewLocalService with testQwenModelID bound to its
// served repository, as the daemon binds a configured model at startup.
func newBoundLocalService(baseURL, serviceID string, maxConcurrency uint32, inferTimeout, probeTimeout time.Duration) *LocalService {
	svc := NewLocalService(baseURL, serviceID, maxConcurrency, inferTimeout, probeTimeout)
	if err := svc.BindModel(testQwenModelID(), LocalModelProvider, "Qwen/Qwen3-8B"); err != nil {
		panic(err)
	}
	return svc
}

func TestBindModelRefusesANonLocalProvider(t *testing.T) {
	svc := NewLocalService("http://127.0.0.1:1", "", 1, time.Second, time.Second)
	if err := svc.BindModel(testQwenModelID(), "OCI", "Qwen/Qwen3-8B"); err == nil {
		t.Fatal("BindModel accepted an OCI-sourced model on the vLLM adapter")
	}
	if err := svc.BindModel(testQwenModelID(), LocalModelProvider, "Qwen/Qwen3-8B"); err != nil {
		t.Fatalf("BindModel with the local provider: %v", err)
	}
}
