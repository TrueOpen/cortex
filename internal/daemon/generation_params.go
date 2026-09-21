package daemon

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/identity"
	"github.com/SingaXYZ/cortex/internal/nodewire"
	"github.com/SingaXYZ/cortex/internal/store"
	"github.com/SingaXYZ/cortex/internal/store/layout"
)

// The selected Worker's admission already retains the complete order until
// terminal cleanup. Re-derive its identity on every recovery rather than storing
// a second, independently mutable parameter copy.
type persistedGenerationReader struct {
	store   *store.Store
	chainID string
}

func (r persistedGenerationReader) TaskGeneration(ctx context.Context, taskID string, acceptedHash codec.Hash) (nodewire.GenerationContext, error) {
	if r.store == nil || acceptedHash == (codec.Hash{}) {
		return nodewire.GenerationContext{}, fmt.Errorf("persisted generation parameters require a store and accepted task hash")
	}
	admission, err := layout.GetCandidateAdmission(ctx, r.store, layout.StoredHash(acceptedHash))
	if err != nil {
		return nodewire.GenerationContext{}, fmt.Errorf("read signed order for task generation parameters: %w", err)
	}
	if len(admission.SignedOrder) == 0 {
		return nodewire.GenerationContext{}, fmt.Errorf("persisted signed order has no generation parameters")
	}
	carrier := string(admission.SignedOrder)
	if admission.SignedOrder[0] == 0x0a {
		carrier = hex.EncodeToString(admission.SignedOrder)
	}
	hash, facts, err := nodewire.TaskOrderHashAndFactsEnvelope(carrier)
	if err != nil {
		return nodewire.GenerationContext{}, fmt.Errorf("decode persisted task generation parameters: %w", err)
	}
	if hash != acceptedHash || facts.ChainID != r.chainID || identity.TaskIDString(facts.SessionID, facts.OrderSequence) != taskID {
		return nodewire.GenerationContext{}, fmt.Errorf("persisted generation parameters do not match the accepted task identity")
	}
	if facts.Generation == nil {
		return nodewire.GenerationContext{}, fmt.Errorf("persisted order lacks generation context")
	}
	return facts.Generation.Clone(), nil
}
