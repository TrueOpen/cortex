package daemon

import (
	"context"
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/policy"
)

type VerifierHandraiseCandidate struct {
	TaskID, SessionID, ModelID string
	ProfileVersion             uint32
	Capability, WorkerAddress  string
	OpenHeight                 uint64
}
type HandraiseEligibility interface {
	Verifier(context.Context, VerifierHandraiseCandidate) (policy.VerifierPrecheckInput, error)
}

func (r *TaskRunner) capabilityFor(modelID string, profile uint32) (string, error) {
	c := strings.TrimSpace(r.cfg.ProfileCapabilities[modelID+"\x00"+fmt.Sprintf("%d", profile)])
	if c == "" {
		return "", fmt.Errorf("model profile capability is unavailable")
	}
	return c, nil
}
