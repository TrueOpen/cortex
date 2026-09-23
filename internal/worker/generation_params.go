package worker

import (
	"context"
	"fmt"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

type GenerationReader interface {
	TaskGeneration(context.Context, string, codec.Hash) (nodewire.GenerationContext, error)
}

func (w *Worker) taskGeneration(ctx context.Context, event chainclient.AssignmentFinalized) (*nodewire.GenerationContext, []byte, error) {
	if w.cfg.FakeOutput && w.cfg.GenerationReader == nil {
		return nil, nil, nil
	}
	facts, err := w.taskFacts(ctx, event.TaskID)
	if err != nil {
		return nil, nil, err
	}
	if w.cfg.GenerationReader == nil {
		return nil, nil, fmt.Errorf("frozen task generation parameter reader is required")
	}
	generation, err := w.cfg.GenerationReader.TaskGeneration(ctx, event.TaskID, codec.Hash(facts.AcceptedTaskHash))
	if err != nil {
		return nil, nil, fmt.Errorf("read frozen task generation parameters: %w", err)
	}
	if err := modelservice.ValidateGenerationContext(&generation, facts.GenerationParamsDigest, event.ModelID, fmt.Sprint(event.ProfileVersion)); err != nil {
		return nil, nil, err
	}
	generation = generation.Clone()
	return &generation, append([]byte(nil), facts.GenerationParamsDigest...), nil
}

func (w *Worker) validateGenerationOutput(ctx context.Context, event chainclient.AssignmentFinalized, output, trace, checkpoint []byte, descriptor outputDescriptor) error {
	generation, digest, err := w.taskGeneration(ctx, event)
	if err != nil || generation == nil {
		return err
	}
	count, reason, err := modelservice.ValidateGenerationEvidence(generation, digest, output, trace, checkpoint)
	if err != nil {
		return fmt.Errorf("validate retained generation evidence: %w", err)
	}
	if reason != descriptor.FinishReason {
		return fmt.Errorf("retained generation evidence finish reason differs from descriptor")
	}
	if count != descriptor.GeneratedTokenCount {
		return fmt.Errorf("retained generated token count differs from evidence")
	}
	return nil
}
