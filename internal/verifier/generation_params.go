package verifier

import (
	"context"
	"fmt"

	"github.com/SingaXYZ/cortex/internal/modelservice"
	"github.com/SingaXYZ/cortex/internal/nodewire"
)

func (v *Verifier) generationForEvidence(ctx context.Context, state TaskState, output, trace, checkpoint []byte) (*nodewire.GenerationContext, []byte, error) {
	if v.cfg.FakeOutput {
		return nil, nil, nil
	}
	facts, err := v.taskFacts(ctx, state.TaskID)
	if err != nil {
		return nil, nil, err
	}
	generation, err := modelservice.GenerationContextFromTrace(trace)
	if err != nil {
		return nil, nil, fmt.Errorf("Worker evidence generation parameters: %w", err)
	}
	if err := modelservice.ValidateGenerationContext(generation, facts.GenerationParamsDigest, state.ModelID, fmt.Sprint(state.ProfileVersion)); err != nil {
		return nil, nil, err
	}
	_, reason, err := modelservice.ValidateGenerationEvidence(generation, facts.GenerationParamsDigest, output, trace, checkpoint)
	if err != nil {
		return nil, nil, fmt.Errorf("Worker generation evidence: %w", err)
	}
	if reason != state.ConfirmedFinishReason {
		return nil, nil, fmt.Errorf("Worker generation evidence finish reason differs from receipt commitment")
	}
	return generation, append([]byte(nil), facts.GenerationParamsDigest...), nil
}
