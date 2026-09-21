package daemon

import (
	"context"
	"testing"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/identity"
	"github.com/SingaXYZ/cortex/internal/modelservice"
)

const capacityTestSession = "84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b"

func capacityTestResolver(t *testing.T, snapshot modelservice.ResourceSnapshot) HandraiseEligibility {
	t.Helper()
	return NewKeeperHandraiseEligibility(KeeperHandraiseEligibilityConfig{
		ChainStatus:         handraiseChainStatus{height: 120, chainID: "chain-A"},
		Keeper:              activeHandraiseKeeper(),
		Model:               handraiseCapacityModel{Client: modelservice.NewFakeService(), snapshot: snapshot},
		ChainID:             "chain-A",
		OperatorAddress:     "cortex-node-1",
		ModelServiceID:      "fake-model-service",
		SelfRescueGasBudget: 10,
	})
}

func capacityTestWorkerCandidate() WorkerHandraiseCandidate {
	return WorkerHandraiseCandidate{
		TaskID: identity.TaskIDString(capacityTestSession, 1), SessionID: capacityTestSession, OrderSequence: 1,
		ModelID: "fake-llm-text", ProfileVersion: 1, Capability: modelservice.CapabilityLLMTextV1, DeadlineHeight: 140,
	}
}

func capacityTestVerifierCandidate() VerifierHandraiseCandidate {
	return VerifierHandraiseCandidate{
		TaskID: "task-2", SessionID: "session-2", ModelID: "fake-llm-text", ProfileVersion: 1,
		Capability: modelservice.CapabilityLLMTextV1, WorkerAddress: "remote-node", OpenHeight: 115,
	}
}

// "Every slot is busy" and "the engine is still loading" describe a moment. Left
// as unmarked errors they were permanent verdicts, and a permanent verdict is
// the harshest disposition in the pipeline: the inbox records admissionRefused,
// the envelope's replay claim stays consumed, and the Verifier re-drive drops
// the round. A node that was briefly full therefore refused the order for good.
func TestATemporarilyFullNodeRefusesRetryably(t *testing.T) {
	for _, tc := range []struct {
		name     string
		snapshot modelservice.ResourceSnapshot
	}{
		{"no free slot", modelservice.ResourceSnapshot{LoadedModels: 1, QueueDepth: 2, MaxConcurrency: 2}},
		{"queue beyond the configured maximum", modelservice.ResourceSnapshot{LoadedModels: 1, QueueDepth: 3, MaxConcurrency: 2}},
		{"engine has not loaded a model yet", modelservice.ResourceSnapshot{LoadedModels: 0, MaxConcurrency: 4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := capacityTestResolver(t, tc.snapshot)

			_, _, err := resolver.Worker(context.Background(), capacityTestWorkerCandidate())
			if err == nil {
				t.Fatal("Worker eligibility accepted a node with no capacity")
			}
			if !builderclient.IsRetryable(err) {
				t.Fatalf("Worker capacity refusal is not retryable, so the frame is refused for good: %v", err)
			}

			_, err = resolver.Verifier(context.Background(), capacityTestVerifierCandidate())
			if err == nil {
				t.Fatal("Verifier eligibility accepted a node with no capacity")
			}
			if !builderclient.IsRetryable(err) {
				t.Fatalf("Verifier capacity refusal is not retryable: %v", err)
			}
		})
	}
}

// The other half of the rule, and the one that keeps this from being a blanket
// "retry everything": a refusal that answers "may this node EVER serve this
// order" must stay permanent. Retrying it would NAK the same frame until the
// stream gives up.
func TestPermanentHandraiseRefusalsStayPermanent(t *testing.T) {
	// Capacity is healthy throughout; only the question being asked changes.
	healthy := modelservice.ResourceSnapshot{LoadedModels: 1, QueueDepth: 0, MaxConcurrency: 4}

	t.Run("the model service does not expose this capability", func(t *testing.T) {
		resolver := capacityTestResolver(t, healthy)
		candidate := capacityTestWorkerCandidate()
		candidate.Capability = "llm-capability-this-node-does-not-serve"
		_, _, err := resolver.Worker(context.Background(), candidate)
		if err == nil {
			t.Fatal("Worker eligibility accepted a capability the model service does not expose")
		}
		if builderclient.IsRetryable(err) {
			t.Fatalf("a capability mismatch was marked retryable; it is a deployment fact, not a moment: %v", err)
		}
	})

	t.Run("the candidate identity is not canonical", func(t *testing.T) {
		resolver := capacityTestResolver(t, healthy)
		candidate := capacityTestWorkerCandidate()
		candidate.TaskID = "not-the-task-id-this-session-and-sequence-derive"
		_, _, err := resolver.Worker(context.Background(), candidate)
		if err == nil {
			t.Fatal("Worker eligibility accepted a non-canonical task identity")
		}
		if builderclient.IsRetryable(err) {
			t.Fatalf("a broken identity equation was marked retryable: %v", err)
		}
	})

	t.Run("max concurrency is not configured", func(t *testing.T) {
		resolver := capacityTestResolver(t, modelservice.ResourceSnapshot{LoadedModels: 1})
		_, _, err := resolver.Worker(context.Background(), capacityTestWorkerCandidate())
		if err == nil {
			t.Fatal("Worker eligibility accepted a node with no admission budget configured")
		}
		if builderclient.IsRetryable(err) {
			t.Fatalf("an unset max_concurrency was marked retryable; waiting does not supply a config value: %v", err)
		}
	})

	t.Run("the chain is not the configured one", func(t *testing.T) {
		resolver := NewKeeperHandraiseEligibility(KeeperHandraiseEligibilityConfig{
			ChainStatus:     handraiseChainStatus{height: 120, chainID: "chain-B"},
			Keeper:          activeHandraiseKeeper(),
			Model:           handraiseCapacityModel{Client: modelservice.NewFakeService(), snapshot: healthy},
			ChainID:         "chain-A",
			OperatorAddress: "cortex-node-1",
			ModelServiceID:  "fake-model-service",
		})
		_, _, err := resolver.Worker(context.Background(), capacityTestWorkerCandidate())
		if err == nil {
			t.Fatal("Worker eligibility accepted a foreign chain")
		}
		if builderclient.IsRetryable(err) {
			t.Fatalf("a chain mismatch was marked retryable: %v", err)
		}
	})
}
