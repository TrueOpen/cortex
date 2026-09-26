package identity

// The wire v0.3.0 model identity (TrueOpen/wire#14, hub/model_id_v1.json):
// an opaque Hash32 derived from the immutable repository coordinates and the
// proposer. It replaces the "hf-"-prefixed text id. Nothing calls it yet.

import (
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
	"github.com/TrueOpen/cortex/internal/nodewire"
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

// ModelIDV1 derives
//
//	H_FIELDS_V1("TRUEOPEN_MODEL_ID_V1", chain_id, provider, repo_id, proposer_address_bytes)
//
// Every input is checked, never normalized: the provider token is
// case-sensitive, repo_id keeps its case, and the proposer is framed as its
// decoded bytes, not its Bech32 text.
func ModelIDV1(chainID, provider, repoID, proposerAddress string) (codec.Hash, error) {
	if chainID == "" {
		return codec.Hash{}, fmt.Errorf("model id chain_id is required")
	}
	if !canonicalModelProviders[provider] {
		return codec.Hash{}, fmt.Errorf("model provider %q is not a canonical token", provider)
	}
	if provider != ModelProviderHuggingFace {
		return codec.Hash{}, fmt.Errorf("model provider %s is not supported", provider)
	}
	if err := validateHuggingFaceRepoID(repoID); err != nil {
		return codec.Hash{}, err
	}
	if !strings.HasPrefix(proposerAddress, modelAddressPrefix) {
		return codec.Hash{}, fmt.Errorf("model proposer must be a %s address", strings.TrimSuffix(modelAddressPrefix, "1"))
	}
	proposer, err := nodewire.CanonicalOperatorAddressBytes("proposer_address", proposerAddress)
	if err != nil {
		return codec.Hash{}, err
	}
	return hfields.Digest(ModelIDDomainV1, hfields.String(chainID), hfields.String(provider), hfields.String(repoID), hfields.Bytes(proposer))
}

// validateHuggingFaceRepoID accepts exactly "owner/name" with both segments
// non-empty and drawn from [A-Za-z0-9._-], at most 255 bytes. The ASCII
// charset also makes NFC hold by construction.
func validateHuggingFaceRepoID(repoID string) error {
	if len(repoID) > maxRepoIDBytes {
		return fmt.Errorf("repo_id exceeds %d bytes", maxRepoIDBytes)
	}
	owner, name, found := strings.Cut(repoID, "/")
	if !found || owner == "" || name == "" || strings.Contains(name, "/") {
		return fmt.Errorf("repo_id must be owner/name with exactly one slash")
	}
	for _, r := range repoID {
		if r != '/' && r != '.' && r != '_' && r != '-' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return fmt.Errorf("repo_id contains %q outside [A-Za-z0-9._-]", r)
		}
	}
	return nil
}
