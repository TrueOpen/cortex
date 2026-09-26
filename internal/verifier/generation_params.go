package verifier

import (
	"context"
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// GenerationReader reads the frozen generation parameters of an accepted task
// from the order it was accepted under.
type GenerationReader interface {
	TaskGeneration(context.Context, string, codec.Hash) (nodewire.GenerationContext, error)
}

// taskGeneration is the generation context the prefill runs under. It comes
// from the accepted order, never from Worker evidence: the Worker's values are
// no longer a verify input, and the order is what generation_params_digest
// commits.
func (v *Verifier) taskGeneration(ctx context.Context, state TaskState) (*nodewire.GenerationContext, []byte, error) {
	if v.cfg.FakeOutput && v.cfg.GenerationReader == nil {
		return nil, nil, nil
	}
	facts, err := v.taskFacts(ctx, state.TaskID)
	if err != nil {
		return nil, nil, err
	}
	if v.cfg.GenerationReader == nil {
		return nil, nil, fmt.Errorf("frozen task generation parameter reader is required")
	}
	generation, err := v.cfg.GenerationReader.TaskGeneration(ctx, state.TaskID, codec.Hash(facts.AcceptedTaskHash))
	if err != nil {
		return nil, nil, fmt.Errorf("read frozen task generation parameters: %w", err)
	}
	if err := modelservice.ValidateGenerationContext(&generation, facts.GenerationParamsDigest, state.ModelID, fmt.Sprint(state.ProfileVersion)); err != nil {
		return nil, nil, err
	}
	generation = generation.Clone()
	return &generation, append([]byte(nil), facts.GenerationParamsDigest...), nil
}
