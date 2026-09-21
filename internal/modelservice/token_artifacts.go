package modelservice

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"slices"

	"github.com/SingaXYZ/cortex/internal/nodewire"
)

// TokenIDArtifacts exports the local model evidence into the protocol's raw
// count/vector encoding. Local JSON fingerprints are not protocol commitments.
func TokenIDArtifacts(trace, checkpoint []byte) (input, generated []byte, err error) {
	var t, c traceEnvelope
	if err = json.Unmarshal(trace, &t); err != nil {
		return nil, nil, fmt.Errorf("decode token trace: %w", err)
	}
	if err = json.Unmarshal(checkpoint, &c); err != nil {
		return nil, nil, fmt.Errorf("decode token checkpoint: %w", err)
	}
	if !slices.Equal(t.InputTokenIDs, c.InputTokenIDs) || t.GeneratedTokenCount != len(t.OutTokens) || c.GeneratedTokenCount != t.GeneratedTokenCount || t.InputTokenIDsHash != hashTokenIDs(t.InputTokenIDs) || c.InputTokenIDsHash != t.InputTokenIDsHash || t.GeneratedTokenIDsHash != hashGeneratedTokenIDs(t.OutTokens) || c.GeneratedTokenIDsHash != t.GeneratedTokenIDsHash {
		return nil, nil, fmt.Errorf("trace/checkpoint token vectors disagree")
	}
	inputs := make([]uint32, len(t.InputTokenIDs))
	for i, id := range t.InputTokenIDs {
		if id < 0 || uint64(id) > math.MaxUint32 {
			return nil, nil, fmt.Errorf("input token id exceeds uint32")
		}
		inputs[i] = uint32(id)
	}
	outputs := make([]uint32, len(t.OutTokens))
	for i, token := range t.OutTokens {
		if token.TokenID < 0 || uint64(token.TokenID) > math.MaxUint32 {
			return nil, nil, fmt.Errorf("generated token id differs from checkpoint or exceeds uint32")
		}
		outputs[i] = uint32(token.TokenID)
	}
	if len(c.OutTokens) != 0 {
		if len(c.OutTokens) != len(t.OutTokens) {
			return nil, nil, fmt.Errorf("checkpoint token sequence differs from trace")
		}
		for i, token := range c.OutTokens {
			if token.TokenID != t.OutTokens[i].TokenID {
				return nil, nil, fmt.Errorf("checkpoint token sequence differs from trace")
			}
		}
	}
	input, err = nodewire.EncodeTokenIDs(inputs)
	if err != nil {
		return nil, nil, err
	}
	generated, err = nodewire.EncodeTokenIDs(outputs)
	return input, generated, err
}

func ValidateTokenIDArtifacts(trace, checkpoint, input, generated []byte) error {
	wantInput, wantGenerated, err := TokenIDArtifacts(trace, checkpoint)
	if err != nil {
		return err
	}
	if !bytes.Equal(input, wantInput) || !bytes.Equal(generated, wantGenerated) {
		return fmt.Errorf("token artifacts differ from authenticated model trace/checkpoint")
	}
	return nil
}
