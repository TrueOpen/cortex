package verifier

import (
	"bytes"
	"context"
	"fmt"

	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// taskGeneration is the generation context the prefill runs under. Its only
// source is the Worker's confirmed A-level generation_params artifact: the raw
// bytes are hashed as received, never re-serialized, and must equal the
// chain's generation_params_digest and the one the signed receipt binds.
// No locally persisted order is consulted, so a Verifier that never held the
// order (or released it after losing the bid) still prefills under exactly
// the committed parameters.
//
// Without the artifact there is nothing to prefill under, except in the
// fake/dev configuration, whose model service ignores generation parameters.
func (v *Verifier) taskGeneration(ctx context.Context, state TaskState, raw []byte) (*nodewire.GenerationContext, []byte, error) {
	if len(raw) == 0 {
		if v.cfg.FakeOutput {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("task %s: the prefill requires the Worker's confirmed generation_params artifact", state.TaskID)
	}
	facts, err := v.taskFacts(ctx, state.TaskID)
	if err != nil {
		return nil, nil, err
	}
	digest := nodewire.GenerationParamsDigest(raw)
	if !bytes.Equal(digest[:], facts.GenerationParamsDigest[:]) {
		return nil, nil, fmt.Errorf("generation_params artifact does not hash to the chain's generation_params_digest")
	}
	if receipt := state.ConfirmedInferReceipt; receipt != nil && receipt.GenerationParamsDigest != digest.String() {
		return nil, nil, fmt.Errorf("generation_params artifact does not hash to the receipt's generation_params_digest")
	}
	generation, err := nodewire.ParseCanonicalGenerationParams(raw)
	if err != nil {
		return nil, nil, err
	}
	if err := modelservice.ValidateGenerationContext(&generation, digest[:], state.ModelID, fmt.Sprint(state.ProfileVersion)); err != nil {
		return nil, nil, err
	}
	return &generation, digest[:], nil
}
