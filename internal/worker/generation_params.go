package worker

import (
	"bytes"
	"context"
	"fmt"

	"github.com/TrueOpen/cortex/internal/builderclient"
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

// validateGenerationOutput re-checks the retained model material of a prepared
// output against the frozen generation parameters and its descriptor, so a
// restart signs nothing the order would not have allowed.
func (w *Worker) validateGenerationOutput(ctx context.Context, event chainclient.AssignmentFinalized, output, tokenIDs, positionValues []byte, descriptor outputDescriptor) error {
	generation, digest, err := w.taskGeneration(ctx, event)
	if err != nil || generation == nil {
		return err
	}
	ids, values, err := decodeMaterial(tokenIDs, positionValues)
	if err != nil {
		return fmt.Errorf("validate retained generation material: %w", err)
	}
	count, err := modelservice.ValidateGenerationMaterial(generation, digest, ids, values)
	if err != nil {
		return fmt.Errorf("validate retained generation material: %w", err)
	}
	if count != descriptor.GeneratedTokenCount {
		return fmt.Errorf("retained generated token count differs from material")
	}
	return nil
}

// generationParamsArtifact is the A-level generation_params artifact: the
// Worker's own order's canonical generation parameters, which must hash to the
// task's generation_params_digest.
func (w *Worker) generationParamsArtifact(ctx context.Context, event chainclient.AssignmentFinalized, digest []byte) ([]byte, *nodewire.GenerationContext, error) {
	generation, _, err := w.taskGeneration(ctx, event)
	if err != nil {
		return nil, nil, err
	}
	if generation == nil {
		return nil, nil, fmt.Errorf("%w: the generation_params artifact requires the task's generation parameters", builderclient.ErrInferReceiptInputUnavailable)
	}
	raw, err := generation.CanonicalJSON()
	if err != nil {
		return nil, nil, err
	}
	if len(raw) > nodewire.MaxGenerationParamsBytes {
		return nil, nil, fmt.Errorf("canonical generation parameters are %d bytes, above the %d-byte artifact bound", len(raw), nodewire.MaxGenerationParamsBytes)
	}
	if got := nodewire.GenerationParamsDigest(raw); !bytes.Equal(got[:], digest) {
		return nil, nil, fmt.Errorf("generation parameters do not hash to the task's generation_params_digest")
	}
	return raw, generation, nil
}
