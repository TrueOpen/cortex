package integration_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/keepercontract"
	"github.com/TrueOpen/cortex/internal/modelregistry"
	"github.com/TrueOpen/cortex/internal/txclient"
)

func TestDevnetCurrentModelRegistrationDryRunUsesExactNodeDigestWithoutSigning(t *testing.T) {
	data, err := os.ReadFile("../../configs/model-profile.current.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var profile txclient.ModelProfileProjectionMessage
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatalf("decode current profile example: %v", err)
	}
	manifest, err := modelregistry.GenerateCurrentManifest(modelregistry.CurrentManifestInput{
		Version: "devnet-dry-run", Tokenizer: "qwen-tokenizer", ModelServiceID: "modelsvc-dev", Profile: profile,
	})
	if err != nil {
		t.Fatalf("GenerateCurrentManifest: %v", err)
	}
	reader := &devnetRegistrationReader{}
	registry := modelregistry.NewRegistry(modelregistry.RegistryConfig{
		CurrentRegistrationReader: reader,
		ChainID:                   "trueopen-devnet-1",
		ProposerAddress:           "trueopen1operator",
	})

	result, err := registry.RegisterCurrent(context.Background(), modelregistry.CurrentRegisterRequest{Manifest: manifest, DryRun: true})
	if err != nil {
		t.Fatalf("RegisterCurrent dry-run: %v", err)
	}
	want, _, err := keepercontract.ModelRegistrationDigest("trueopen-devnet-1", "trueopen1operator", profile)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != modelregistry.RegistrationStagePlanned || result.RegistrationDigest != hex.EncodeToString(want[:]) {
		t.Fatalf("dry-run result = %#v, want exact Node digest %x", result, want)
	}
	if reader.modelID != profile.ModelID.Hex() || reader.profileVersion != "1" {
		t.Fatalf("Keeper query = %q/%q", reader.modelID, reader.profileVersion)
	}
}

type devnetRegistrationReader struct {
	modelID        string
	profileVersion string
}

func (r *devnetRegistrationReader) CurrentModelProfile(_ context.Context, modelID, profileVersion string) (chainclient.CurrentModelProfileSnapshot, error) {
	r.modelID, r.profileVersion = modelID, profileVersion
	return chainclient.CurrentModelProfileSnapshot{}, chainclient.ErrNotFound
}
