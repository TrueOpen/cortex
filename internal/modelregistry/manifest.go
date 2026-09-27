package modelregistry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/TrueOpen/cortex/internal/codec"
)

type ManifestInput struct {
	ModelID                   string
	Version                   string
	Digest                    string
	Tokenizer                 string
	ModelServiceID            string
	Verification              VerificationSpec
	Pricing                   PricingSpec
	Metadata                  map[string]string
	HardwareTierFloor         uint64
	TokenizerHash             string
	RuntimeVersion            string
	RuntimeHash               string
	QuantHash                 string
	ResourceTier              string
	MinStake                  uint64
	ChallengeOpenWindowBlocks uint64
	EpsilonParams             string
	TimeoutBootstrapProfile   string
	SchemaHash                string
	PreviousProfileVersion    string
	MetadataHash              string
	DisplayTagHash            string
}

type VerificationSpec struct {
	Method         string `json:"method"`
	ProfileVersion string `json:"profile_version"`
}

type PricingSpec struct {
	Denom               string `json:"denom"`
	PromptUnitPrice     uint64 `json:"prompt_unit_price"`
	CompletionUnitPrice uint64 `json:"completion_unit_price"`
}

type Manifest struct {
	ManifestSchemaVersion     uint64            `json:"manifest_schema_version"`
	ModelID                   string            `json:"model_id"`
	Version                   string            `json:"version"`
	Digest                    string            `json:"digest"`
	Tokenizer                 string            `json:"tokenizer"`
	ModelServiceID            string            `json:"model_service_id"`
	Verification              VerificationSpec  `json:"verification"`
	Pricing                   PricingSpec       `json:"pricing"`
	Metadata                  map[string]string `json:"metadata,omitempty"`
	Canonical                 string            `json:"-"`
	Hash                      string            `json:"manifest_hash"`
	HardwareTierFloor         uint64            `json:"hardware_tier_floor"`
	TokenizerHash             string            `json:"tokenizer_hash"`
	RuntimeVersion            string            `json:"runtime_version"`
	RuntimeHash               string            `json:"runtime_hash"`
	QuantHash                 string            `json:"quant_hash"`
	ResourceTier              uint64            `json:"resource_tier"`
	MinStake                  uint64            `json:"min_stake"`
	ChallengeOpenWindowBlocks uint64            `json:"challenge_open_window_blocks"`
	EpsilonParams             string            `json:"epsilon_params"`
	TimeoutBootstrapProfile   string            `json:"timeout_bootstrap_profile"`
	SchemaHash                string            `json:"schema_hash"`
	PreviousProfileVersion    string            `json:"previous_profile_version,omitempty"`
	MetadataHash              string            `json:"metadata_hash"`
	DisplayTagHash            string            `json:"display_tag_hash,omitempty"`
}

func GenerateManifest(input ManifestInput) (Manifest, error) {
	resourceTierText := strings.TrimSpace(input.ResourceTier)
	resourceTier, err := strconv.ParseUint(resourceTierText, 10, 64)
	if err != nil || resourceTierText == "" || strconv.FormatUint(resourceTier, 10) != resourceTierText {
		return Manifest{}, fmt.Errorf("resource_tier must be an unsigned integer")
	}
	for name, value := range map[string]string{
		"tokenizer_hash": input.TokenizerHash,
		"runtime_hash":   input.RuntimeHash,
		"quant_hash":     input.QuantHash,
	} {
		if err := validateManifestHash(name, value); err != nil {
			return Manifest{}, err
		}
	}
	manifest := Manifest{
		ManifestSchemaVersion: 2,
		ModelID:               strings.TrimSpace(input.ModelID),
		Version:               strings.TrimSpace(input.Version),
		Digest:                strings.TrimSpace(input.Digest),
		Tokenizer:             strings.TrimSpace(input.Tokenizer),
		ModelServiceID:        strings.TrimSpace(input.ModelServiceID),
		Verification: VerificationSpec{
			Method:         strings.TrimSpace(input.Verification.Method),
			ProfileVersion: strings.TrimSpace(input.Verification.ProfileVersion),
		},
		Pricing: PricingSpec{
			Denom:               strings.TrimSpace(input.Pricing.Denom),
			PromptUnitPrice:     input.Pricing.PromptUnitPrice,
			CompletionUnitPrice: input.Pricing.CompletionUnitPrice,
		},
		Metadata:          sortedMetadata(input.Metadata),
		HardwareTierFloor: input.HardwareTierFloor,
		TokenizerHash:     strings.TrimSpace(input.TokenizerHash), RuntimeVersion: strings.TrimSpace(input.RuntimeVersion),
		RuntimeHash: strings.TrimSpace(input.RuntimeHash), QuantHash: strings.TrimSpace(input.QuantHash),
		ResourceTier: resourceTier, MinStake: input.MinStake, ChallengeOpenWindowBlocks: input.ChallengeOpenWindowBlocks,
		EpsilonParams: strings.TrimSpace(input.EpsilonParams), TimeoutBootstrapProfile: strings.TrimSpace(input.TimeoutBootstrapProfile),
		SchemaHash: strings.TrimSpace(input.SchemaHash), PreviousProfileVersion: strings.TrimSpace(input.PreviousProfileVersion),
		MetadataHash: strings.TrimSpace(input.MetadataHash), DisplayTagHash: strings.TrimSpace(input.DisplayTagHash),
	}
	canonical, err := canonicalManifest(manifest)
	if err != nil {
		return Manifest{}, err
	}
	sum := sha256.Sum256([]byte(canonical))
	manifest.Canonical = canonical
	manifest.Hash = "sha256:" + hex.EncodeToString(sum[:])
	return manifest, nil
}

func ValidateManifest(manifest Manifest) error {
	if manifest.ManifestSchemaVersion != 2 {
		return fmt.Errorf("manifest_schema_version 2 is required; regenerate the manifest")
	}
	if strings.TrimSpace(manifest.ModelID) == "" {
		return fmt.Errorf("model_id is required")
	}
	if strings.TrimSpace(manifest.Version) == "" {
		return fmt.Errorf("version is required")
	}
	if strings.TrimSpace(manifest.Digest) == "" {
		return fmt.Errorf("digest is required")
	}
	if strings.TrimSpace(manifest.Tokenizer) == "" {
		return fmt.Errorf("tokenizer is required")
	}
	if strings.TrimSpace(manifest.ModelServiceID) == "" {
		return fmt.Errorf("model_service_id is required")
	}
	if strings.TrimSpace(manifest.Verification.Method) == "" {
		return fmt.Errorf("verification.method is required")
	}
	if strings.TrimSpace(manifest.Verification.ProfileVersion) == "" {
		return fmt.Errorf("verification.profile_version is required")
	}
	if strings.TrimSpace(manifest.Pricing.Denom) == "" {
		return fmt.Errorf("pricing.denom is required")
	}
	if strings.TrimSpace(manifest.TokenizerHash) == "" || strings.TrimSpace(manifest.RuntimeHash) == "" || strings.TrimSpace(manifest.QuantHash) == "" || strings.TrimSpace(manifest.RuntimeVersion) == "" || manifest.MinStake == 0 || manifest.ChallengeOpenWindowBlocks == 0 || strings.TrimSpace(manifest.EpsilonParams) == "" || strings.TrimSpace(manifest.TimeoutBootstrapProfile) == "" || strings.TrimSpace(manifest.SchemaHash) == "" || strings.TrimSpace(manifest.MetadataHash) == "" {
		return fmt.Errorf("latest Keeper model profile fields are required")
	}
	for name, value := range map[string]string{"tokenizer_hash": manifest.TokenizerHash, "runtime_hash": manifest.RuntimeHash, "quant_hash": manifest.QuantHash, "schema_hash": manifest.SchemaHash, "metadata_hash": manifest.MetadataHash} {
		if err := validateManifestHash(name, value); err != nil {
			return err
		}
	}
	if manifest.Pricing.PromptUnitPrice == 0 {
		return fmt.Errorf("pricing.prompt_unit_price is required")
	}
	if manifest.Pricing.CompletionUnitPrice == 0 {
		return fmt.Errorf("pricing.completion_unit_price is required")
	}
	expected, err := GenerateManifest(ManifestInput{
		ModelID:           manifest.ModelID,
		Version:           manifest.Version,
		Digest:            manifest.Digest,
		Tokenizer:         manifest.Tokenizer,
		ModelServiceID:    manifest.ModelServiceID,
		Verification:      manifest.Verification,
		Pricing:           manifest.Pricing,
		Metadata:          manifest.Metadata,
		HardwareTierFloor: manifest.HardwareTierFloor,
		TokenizerHash:     manifest.TokenizerHash, RuntimeVersion: manifest.RuntimeVersion, RuntimeHash: manifest.RuntimeHash, QuantHash: manifest.QuantHash,
		ResourceTier: strconv.FormatUint(manifest.ResourceTier, 10),
		MinStake:     manifest.MinStake, ChallengeOpenWindowBlocks: manifest.ChallengeOpenWindowBlocks,
		EpsilonParams: manifest.EpsilonParams, TimeoutBootstrapProfile: manifest.TimeoutBootstrapProfile,
		SchemaHash: manifest.SchemaHash, PreviousProfileVersion: manifest.PreviousProfileVersion,
		MetadataHash: manifest.MetadataHash, DisplayTagHash: manifest.DisplayTagHash,
	})
	if err != nil {
		return err
	}
	if manifest.Hash != "" && manifest.Hash != expected.Hash {
		return fmt.Errorf("manifest_hash does not match canonical manifest")
	}
	return nil
}

func canonicalManifest(manifest Manifest) (string, error) {
	var buf bytes.Buffer
	buf.WriteString("{")
	writeJSONField(&buf, "digest", manifest.Digest, true)
	writeJSONNumberField(&buf, "challenge_open_window_blocks", manifest.ChallengeOpenWindowBlocks, false)
	if manifest.DisplayTagHash != "" {
		writeJSONField(&buf, "display_tag_hash", manifest.DisplayTagHash, false)
	}
	writeJSONField(&buf, "epsilon_params", manifest.EpsilonParams, false)
	writeJSONNumberField(&buf, "hardware_tier_floor", manifest.HardwareTierFloor, false)
	writeJSONNumberField(&buf, "manifest_schema_version", manifest.ManifestSchemaVersion, false)
	writeJSONField(&buf, "metadata_hash", manifest.MetadataHash, false)
	writeJSONNumberField(&buf, "min_stake", manifest.MinStake, false)
	writeJSONField(&buf, "model_id", manifest.ModelID, false)
	writeJSONField(&buf, "model_service_id", manifest.ModelServiceID, false)
	if len(manifest.Metadata) > 0 {
		buf.WriteString(`,"metadata":{`)
		keys := make([]string, 0, len(manifest.Metadata))
		for key := range manifest.Metadata {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for i, key := range keys {
			writeJSONField(&buf, key, manifest.Metadata[key], i == 0)
		}
		buf.WriteString("}")
	}
	buf.WriteString(`,"pricing":{`)
	writeJSONField(&buf, "denom", manifest.Pricing.Denom, true)
	writeJSONNumberField(&buf, "completion_unit_price", manifest.Pricing.CompletionUnitPrice, false)
	writeJSONNumberField(&buf, "prompt_unit_price", manifest.Pricing.PromptUnitPrice, false)
	buf.WriteString("}")
	if manifest.PreviousProfileVersion != "" {
		writeJSONField(&buf, "previous_profile_version", manifest.PreviousProfileVersion, false)
	}
	writeJSONField(&buf, "quant_hash", manifest.QuantHash, false)
	writeJSONNumberField(&buf, "resource_tier", manifest.ResourceTier, false)
	writeJSONField(&buf, "runtime_hash", manifest.RuntimeHash, false)
	writeJSONField(&buf, "runtime_version", manifest.RuntimeVersion, false)
	writeJSONField(&buf, "schema_hash", manifest.SchemaHash, false)
	writeJSONField(&buf, "tokenizer", manifest.Tokenizer, false)
	writeJSONField(&buf, "tokenizer_hash", manifest.TokenizerHash, false)
	writeJSONField(&buf, "timeout_bootstrap_profile", manifest.TimeoutBootstrapProfile, false)
	buf.WriteString(`,"verification":{`)
	writeJSONField(&buf, "method", manifest.Verification.Method, true)
	writeJSONField(&buf, "profile_version", manifest.Verification.ProfileVersion, false)
	buf.WriteString("}")
	writeJSONField(&buf, "version", manifest.Version, false)
	buf.WriteString("}")
	return buf.String(), nil
}

func validateManifestHash(name, value string) error {
	trimmed := strings.TrimPrefix(strings.TrimSpace(value), "sha256:")
	decoded, err := hex.DecodeString(trimmed)
	if err != nil || len(decoded) != sha256.Size || trimmed != strings.ToLower(trimmed) {
		return fmt.Errorf("%s must be a 32-byte lowercase SHA-256 hex", name)
	}
	return nil
}

func writeJSONField(buf *bytes.Buffer, key string, value string, first bool) {
	if !first {
		buf.WriteString(",")
	}
	keyBytes, _ := codec.CanonicalJSON(key)
	valueBytes, _ := codec.CanonicalJSON(value)
	buf.Write(keyBytes)
	buf.WriteString(":")
	buf.Write(valueBytes)
}

func writeJSONNumberField(buf *bytes.Buffer, key string, value uint64, first bool) {
	if !first {
		buf.WriteString(",")
	}
	keyBytes, _ := codec.CanonicalJSON(key)
	buf.Write(keyBytes)
	buf.WriteString(":")
	buf.WriteString(fmt.Sprintf("%d", value))
}

func sortedMetadata(metadata map[string]string) map[string]string {
	if len(metadata) == 0 {
		return nil
	}
	out := make(map[string]string, len(metadata))
	for key, value := range metadata {
		out[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return out
}
