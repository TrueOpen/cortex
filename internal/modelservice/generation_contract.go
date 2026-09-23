package modelservice

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/TrueOpen/cortex/internal/nodewire"
)

// ValidateGenerationContext binds the typed execution parameters to the request
// scope and the chain's frozen generation_params_digest.
func ValidateGenerationContext(g *nodewire.GenerationContext, digest []byte, modelID, profileVersion string) error {
	if g == nil {
		return fmt.Errorf("generation context is required")
	}
	if g.ModelID != modelID || strconv.FormatUint(uint64(g.ProfileVersion), 10) != profileVersion {
		return fmt.Errorf("generation context model/profile mismatch")
	}
	want, err := g.Digest()
	if err != nil {
		return fmt.Errorf("invalid generation context: %w", err)
	}
	if !bytes.Equal(digest, want[:]) {
		return fmt.Errorf("generation_params_digest does not match generation context")
	}
	return nil
}

func validateGenerationResponseDigest(expected, applied []byte) error {
	if len(applied) != 32 || !bytes.Equal(expected, applied) {
		return fmt.Errorf("model service generation_params_digest missing or mismatched")
	}
	return nil
}
