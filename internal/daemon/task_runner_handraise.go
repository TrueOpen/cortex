package daemon

import (
	"context"
	"fmt"
	"strings"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/policy"
)

type WorkerHandraiseCandidate struct {
	TaskID, SessionID string
	OrderSequence     uint64
	ModelID           string
	ProfileVersion    uint32
	Capability        string
	DeadlineHeight    uint64
}
type VerifierHandraiseCandidate struct {
	TaskID, SessionID, ModelID string
	ProfileVersion             uint32
	Capability, WorkerAddress  string
	OpenHeight                 uint64
}
type HandraiseEligibility interface {
	Worker(context.Context, WorkerHandraiseCandidate) (policy.WorkerPrecheckInput, uint64, error)
	Verifier(context.Context, VerifierHandraiseCandidate) (policy.VerifierPrecheckInput, error)
}

func (r *TaskRunner) publishCandidate(ctx context.Context, taskID string, payload []byte, dedupID string) error {
	if r.cfg.Builder == nil {
		return builderclient.Retryable(fmt.Errorf("builder client is required"))
	}
	if err := r.cfg.Builder.Publish(ctx, builderclient.PublishRequest{Subject: builderclient.NATSWorkerHandraiseSubject(taskID), TaskID: taskID, Payload: append([]byte(nil), payload...), DedupID: dedupID}); err != nil {
		return builderclient.Retryable(err)
	}
	return nil
}

func (r *TaskRunner) capabilityFor(modelID string, profile uint32) (string, error) {
	c := strings.TrimSpace(r.cfg.ProfileCapabilities[modelID+"\x00"+fmt.Sprintf("%d", profile)])
	if c == "" {
		return "", fmt.Errorf("model profile capability is unavailable")
	}
	return c, nil
}

func (r *TaskRunner) workerEligibility(ctx context.Context, c WorkerHandraiseCandidate) (policy.WorkerPrecheckInput, uint64, error) {
	if r.cfg.HandraiseEligibility != nil {
		return r.cfg.HandraiseEligibility.Worker(ctx, c)
	}
	if !r.cfg.FakeOutput {
		return policy.WorkerPrecheckInput{}, 0, fmt.Errorf("production Worker handraise eligibility resolver is required")
	}
	return policy.WorkerPrecheckInput{ChainSynced: true, CurrentHeight: 1, SupportState: policy.SupportActive, SupportLastConfirmedHeight: 1, SupportFreshnessWindow: 1, Profile: c.Capability, SupportedProfiles: []string{c.Capability}, AvailableSlots: 1, CapacitySnapshotRef: "fixture", RewardEligible: true, SelfRescueGasAvailable: true, SelfRescueGasBudgetNanoTRUEOPEN: 1}, c.DeadlineHeight, nil
}
