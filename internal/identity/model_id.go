package identity

// The wire v0.3.0 model identity (TrueOpen/wire#14, hub/model_id_v1.json):
// an opaque Hash32 derived from the immutable repository coordinates and the
// proposer. It replaces the "hf-"-prefixed text id.

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/codec"
)

const (
	ModelIDDomainV1 = "TRUEOPEN_MODEL_ID_V1"
	// ModelProviderHuggingFace is the only provider this version accepts.
	ModelProviderHuggingFace = "HUGGINGFACE"
	// modelAddressPrefix is the proposer's required Bech32 prefix.
	modelAddressPrefix = "trueopen1"
	maxRepoIDBytes     = 255
)

// canonicalModelProviders are the closed provider tokens. OCI is canonical but
// not yet supported, which is a different refusal from an unknown token.
var canonicalModelProviders = map[string]bool{ModelProviderHuggingFace: true, "OCI": true}

// ModelIDHex renders a Hash32 model id in the one text form Cortex uses
// internally, in configuration and in logs: 64 lowercase hex characters. That
// is also the REST projection wire declares for every model_id field.
func ModelIDHex(raw []byte) (string, error) {
	if len(raw) != len(codec.Hash{}) {
		return "", fmt.Errorf("model_id must be exactly 32 bytes, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// ModelIDBytes parses the canonical text form back to the Hash32 a protocol
// message carries. Uppercase, prefixes and surrounding space are refused rather
// than normalized, so one model has exactly one spelling.
func ModelIDBytes(text string) ([]byte, error) {
	if len(text) != 2*len(codec.Hash{}) || strings.ToLower(text) != text {
		return nil, fmt.Errorf("model_id %q must be 64 lowercase hex characters", text)
	}
	raw, err := hex.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("model_id %q must be 64 lowercase hex characters", text)
	}
	return raw, nil
}

// ValidModelIDHex reports whether text is a canonical model id.
func ValidModelIDHex(text string) bool {
	_, err := ModelIDBytes(text)
	return err == nil
}
