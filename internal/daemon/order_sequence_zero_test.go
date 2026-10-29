package daemon

import (
	"context"
	"testing"

	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/policy"
)

// TestKeeperHandraiseEligibilityAcceptsSessionFirstOrderSequenceZero covers the
// second gate on the same path. Admission and eligibility both derive the same
// canonical task id, so a zero-sequence rejection in either one stops the
// handraise; fixing only the first would move the refusal one frame later.
func TestKeeperHandraiseEligibilityAcceptsSessionFirstOrderSequenceZero(t *testing.T) {
	const session = "84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b"
	resolver := NewKeeperHandraiseEligibility(KeeperHandraiseEligibilityConfig{
		ChainStatus: handraiseChainStatus{height: 120, chainID: "chain-A"}, Keeper: activeHandraiseKeeper(), Model: modelservice.NewFakeService(),
		ChainID: "chain-A", OperatorAddress: "cortex-node-1", ModelServiceID: "fake-model-service", SelfRescueGasBudget: 10,
	})

	input, expires, err := resolver.Worker(context.Background(), WorkerHandraiseCandidate{
		TaskID: identity.TaskIDString(session, 0), SessionID: session, OrderSequence: 0, ModelID: modelservice.FakeModelID,
		ProfileVersion: 1, Capability: modelservice.CapabilityLLMTextV1, DeadlineHeight: 140,
	})
	if err != nil {
		t.Fatalf("Worker eligibility error = %v, want the session's first order accepted", err)
	}
	if !policy.EvaluateWorkerPrecheck(input).Accepted || expires != 140 {
		t.Fatalf("Worker eligibility = %#v expires=%d", input, expires)
	}

	// The identity equation still has to bite at sequence 0: a task_id derived
	// from a different sequence must be refused, or dropping the zero check
	// would have replaced one bug with a hole.
	if _, _, err := resolver.Worker(context.Background(), WorkerHandraiseCandidate{
		TaskID: identity.TaskIDString(session, 1), SessionID: session, OrderSequence: 0, ModelID: modelservice.FakeModelID,
		ProfileVersion: 1, Capability: modelservice.CapabilityLLMTextV1, DeadlineHeight: 140,
	}); err == nil {
		t.Fatal("Worker eligibility accepted a task_id that does not derive from order_sequence 0")
	}
}
