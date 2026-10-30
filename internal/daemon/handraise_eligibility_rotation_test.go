package daemon

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/modelservice"
)

func rotationTestResolver(keeper handraiseKeeper) HandraiseEligibility {
	return NewKeeperHandraiseEligibility(KeeperHandraiseEligibilityConfig{
		ChainStatus: handraiseChainStatus{height: 120, chainID: "chain-A"}, Keeper: keeper,
		Model: handraiseCapacityModel{
			Client:   modelservice.NewFakeService(),
			snapshot: modelservice.ResourceSnapshot{LoadedModels: 1, QueueDepth: 0, MaxConcurrency: 4},
		},
		ChainID: "chain-A", OperatorAddress: "cortex-node-1", ModelServiceID: "fake-model-service",
	})
}

// A pending service-key rotation stops new duty (CD §8.4), the same chain
// fact the standing handraise gates read. It is a fact for this round, so the
// refusal is permanent.
func TestVerifierEligibilityRefusesWhileServiceKeyRotationIsPending(t *testing.T) {
	var reads []uint64
	keeper := activeHandraiseKeeper()
	keeper.keyReads = &reads
	keeper.serviceKey = chainclient.ServiceKeySnapshot{
		ParticipantType: chainclient.ParticipantTypeCortexNode, OperatorAddress: "cortex-node-1", Status: "ACTIVE",
		HasPendingRotation: true,
		PendingRotation:    chainclient.PendingServiceKeyRotationSnapshot{EffectiveHeight: 200, NextAuthorizationNonce: 2},
	}
	_, err := rotationTestResolver(keeper).Verifier(context.Background(), capacityTestVerifierCandidate())
	if err == nil || !strings.Contains(err.Error(), "rotation") {
		t.Fatalf("err = %v, want a pending-rotation refusal", err)
	}
	if builderclient.IsRetryable(err) {
		t.Fatalf("a pending rotation is a fact for this round, not retryable: %v", err)
	}
	if !slices.Equal(reads, []uint64{120}) {
		t.Fatalf("service key read at heights %v, want the eligibility height 120", reads)
	}

	keeper.serviceKey.HasPendingRotation = false
	keeper.serviceKey.PendingRotation = chainclient.PendingServiceKeyRotationSnapshot{}
	if _, err := rotationTestResolver(keeper).Verifier(context.Background(), capacityTestVerifierCandidate()); err != nil {
		t.Fatalf("without a pending rotation the node is eligible: %v", err)
	}
}

func TestVerifierEligibilityServiceKeyReadFailureIsRetryable(t *testing.T) {
	keeper := activeHandraiseKeeper()
	keeper.keyErr = errors.New("rpc down")
	_, err := rotationTestResolver(keeper).Verifier(context.Background(), capacityTestVerifierCandidate())
	if err == nil || !builderclient.IsRetryable(err) {
		t.Fatalf("err = %v, want a retryable read failure", err)
	}
}
