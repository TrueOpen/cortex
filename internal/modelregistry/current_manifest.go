package modelregistry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/SingaXYZ/cortex/internal/keepercontract"
	"github.com/SingaXYZ/cortex/internal/txclient"
)

const CurrentManifestSchemaVersion = uint64(3)

// CurrentManifestInput contains operator-facing metadata plus the exact
// immutable projection signed and registered by the current Node contract.
type CurrentManifestInput struct {
	Version        string                                 `json:"version"`
	Tokenizer      string                                 `json:"tokenizer"`
	ModelServiceID string                                 `json:"model_service_id"`
	Metadata       map[string]string                      `json:"metadata,omitempty"`
	Profile        txclient.ModelProfileProjectionMessage `json:"profile"`
}

// CurrentManifest is lossless with respect to ModelProfileProjection. Hash is
// the Cortex document hash; Profile.ManifestHash remains Node's model artifact
// manifest hash and is intentionally not derived from this document.
type CurrentManifest struct {
	ManifestSchemaVersion uint64                                 `json:"manifest_schema_version"`
	Version               string                                 `json:"version"`
	Tokenizer             string                                 `json:"tokenizer"`
	ModelServiceID        string                                 `json:"model_service_id"`
	Metadata              map[string]string                      `json:"metadata,omitempty"`
	Profile               txclient.ModelProfileProjectionMessage `json:"profile"`
	Canonical             string                                 `json:"-"`
	Hash                  string                                 `json:"manifest_hash"`
}

type CurrentSelfTestResult struct {
	Passed              bool   `json:"passed"`
	ManifestHash        string `json:"manifest_hash"`
	ModelID             string `json:"model_id"`
	ProfileVersion      uint32 `json:"profile_version"`
	ProjectionValidated bool   `json:"projection_validated"`
}

func SelfTestCurrentManifest(manifest CurrentManifest) (CurrentSelfTestResult, error) {
	if err := ValidateCurrentManifest(manifest); err != nil {
		return CurrentSelfTestResult{}, err
	}
	return CurrentSelfTestResult{
		Passed: true, ManifestHash: manifest.Hash, ModelID: manifest.Profile.ModelID,
		ProfileVersion: uint32(manifest.Profile.ProfileVersion), ProjectionValidated: true,
	}, nil
}

func GenerateCurrentManifest(input CurrentManifestInput) (CurrentManifest, error) {
	manifest := CurrentManifest{
		ManifestSchemaVersion: CurrentManifestSchemaVersion,
		Version:               strings.TrimSpace(input.Version),
		Tokenizer:             strings.TrimSpace(input.Tokenizer),
		ModelServiceID:        strings.TrimSpace(input.ModelServiceID),
		Metadata:              sortedMetadata(input.Metadata),
		Profile:               input.Profile,
	}
	evidenceHash, err := keepercontract.EvidenceSchemaHash(manifest.Profile)
	if err != nil {
		return CurrentManifest{}, fmt.Errorf("derive evidence_schema_hash: %w", err)
	}
	manifest.Profile.VerificationProfile.EvidenceSchemaHash = txclient.ProtoBytes32(hex.EncodeToString(evidenceHash[:]))
	if err := validateCurrentManifestFields(manifest); err != nil {
		return CurrentManifest{}, err
	}
	canonical, err := canonicalCurrentManifest(manifest)
	if err != nil {
		return CurrentManifest{}, err
	}
	digest := sha256.Sum256(canonical)
	manifest.Canonical = string(canonical)
	manifest.Hash = "sha256:" + hex.EncodeToString(digest[:])
	return manifest, nil
}

func ValidateCurrentManifest(manifest CurrentManifest) error {
	if manifest.ManifestSchemaVersion != CurrentManifestSchemaVersion {
		return fmt.Errorf("manifest_schema_version %d is required; regenerate the manifest", CurrentManifestSchemaVersion)
	}
	if err := validateCurrentManifestFields(manifest); err != nil {
		return err
	}
	evidenceHash, err := keepercontract.EvidenceSchemaHash(manifest.Profile)
	if err != nil {
		return err
	}
	if manifest.Profile.VerificationProfile.EvidenceSchemaHash.Hex() != hex.EncodeToString(evidenceHash[:]) {
		return fmt.Errorf("evidence_schema_hash does not match typed evidence_schema")
	}
	canonical, err := canonicalCurrentManifest(manifest)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
	expected := "sha256:" + hex.EncodeToString(digest[:])
	if manifest.Hash != "" && manifest.Hash != expected {
		return fmt.Errorf("manifest_hash does not match canonical current manifest")
	}
	return nil
}

func validateCurrentManifestFields(manifest CurrentManifest) error {
	if manifest.Version == "" || strings.TrimSpace(manifest.Version) != manifest.Version {
		return fmt.Errorf("version is required without surrounding whitespace")
	}
	if manifest.Tokenizer == "" || strings.TrimSpace(manifest.Tokenizer) != manifest.Tokenizer {
		return fmt.Errorf("tokenizer is required without surrounding whitespace")
	}
	if manifest.ModelServiceID == "" || strings.TrimSpace(manifest.ModelServiceID) != manifest.ModelServiceID {
		return fmt.Errorf("model_service_id is required without surrounding whitespace")
	}
	return txclient.ValidateModelProfileProjection(manifest.Profile)
}

func canonicalCurrentManifest(manifest CurrentManifest) ([]byte, error) {
	wire := struct {
		ManifestSchemaVersion uint64                                 `json:"manifest_schema_version"`
		Version               string                                 `json:"version"`
		Tokenizer             string                                 `json:"tokenizer"`
		ModelServiceID        string                                 `json:"model_service_id"`
		Metadata              map[string]string                      `json:"metadata,omitempty"`
		Profile               txclient.ModelProfileProjectionMessage `json:"profile"`
	}{
		ManifestSchemaVersion: manifest.ManifestSchemaVersion,
		Version:               manifest.Version,
		Tokenizer:             manifest.Tokenizer,
		ModelServiceID:        manifest.ModelServiceID,
		Metadata:              sortedMetadata(manifest.Metadata),
		Profile:               manifest.Profile,
	}
	return json.Marshal(wire)
}
