package modelservice

import (
	"context"
	"reflect"
	"testing"
)

func TestFakeGetModelDetailsReturnsArtifactAndProvenanceDetails(t *testing.T) {
	fake := NewFakeService()
	resp, err := fake.GetModelDetails(context.Background(), GetModelDetailsRequest{
		RequestID:      "details-1",
		ModelServiceID: fakeServiceID,
		ModelID:        "fake-llm-text",
	})
	if err != nil {
		t.Fatalf("GetModelDetails returned error: %v", err)
	}
	want := testModelDetailsFixture("fake-llm-text")
	if resp.RequestID != "details-1" || resp.ModelServiceID != fakeServiceID || !reflect.DeepEqual(resp.Details, want) || resp.Error != nil {
		t.Fatalf("GetModelDetails = %#v, want details %#v", resp, want)
	}
	if resp.Details.Metadata.LicenseFiles == nil {
		t.Fatal("GetModelDetails license_files = nil, want empty slice")
	}
}

func TestFakeGetModelDetailsReturnsStructuredNotFound(t *testing.T) {
	fake := NewFakeService()
	resp, err := fake.GetModelDetails(context.Background(), GetModelDetailsRequest{
		RequestID: "details-2",
		ModelID:   "missing",
	})
	if err != nil {
		t.Fatalf("GetModelDetails returned transport error: %v", err)
	}
	if resp.RequestID != "details-2" || resp.ModelServiceID != fakeServiceID {
		t.Fatalf("GetModelDetails envelope = %#v", resp)
	}
	if resp.Error == nil || resp.Error.Code != "MODEL_NOT_FOUND" || resp.Error.Retryable {
		t.Fatalf("GetModelDetails error = %#v", resp.Error)
	}
}

func TestStaticClientDelegatesGetModelDetails(t *testing.T) {
	client := StaticClient{Backend: NewFakeService()}
	resp, err := client.GetModelDetails(context.Background(), GetModelDetailsRequest{ModelID: "fake-llm-text"})
	if err != nil {
		t.Fatalf("GetModelDetails returned error: %v", err)
	}
	if resp.Details.Identity.ModelID != "fake-llm-text" {
		t.Fatalf("GetModelDetails details = %#v", resp.Details)
	}
}

func testModelDetailsFixture(modelID string) ModelDetails {
	return ModelDetails{
		Artifacts: ModelArtifacts{
			ChatTemplateHash:     "0x61b8845f882c3cb6f4cab52994f110bea67358332558b13fd5bc9e6f0df6e5c5",
			FileManifestHash:     "0xed8c589f047c91227b3a320dcac809a87d081b8506abfa0ebd8f9dcaf78330b7",
			GenerationConfigHash: "0x33d7ac3c32fbc2686dad18c89f3246655b333c215e4635eb9310876c4e2f3054",
			ModelConfigHash:      "0x0080f1daa1fbe44121c27ed9496d325a3250f56b2fa73c05b159a2587641a76e",
			ModelWeightDigest:    "0x088ae5f99b985db53d9ddef1ef1cd8020e1819792e2b093818ea3f96c5859ed0",
			QuantConfigHash:      "0x0000000000000000000000000000000000000000000000000000000000000000",
			TokenizerConfigHash:  "0x5eb4e4c74dc16f1b10000b830ebf465ca61ba4caf74029d1fb979359a6f16d8e",
			TokenizerHash:        "0xcbdf28d8de232c9451d0b25d75dc1ce15d74add14c3f46796838f66168d69c3b",
			Files: []ModelArtifactFile{
				{Digest: "sha256:f7c4eadfbbf522470667b797a3c89be2524832d2d599797248dc304fff447c30", Path: "config.json", Role: "MODEL_CONFIG", SizeBytes: 728},
				{Digest: "sha256:31d6a825ae35f11fb85b195b4c42c146c051e446433125a215336abdf95cbf5f", Path: "model-00001-of-00005.safetensors", Role: "WEIGHT_SHARD", SizeBytes: 3_996_250_744},
			},
		},
		Derivation: ModelDerivation{
			ArtifactSources: ModelArtifactSources{
				ChatTemplateSource:   "tokenizer_config.json:chat_template",
				ConfigPath:           "config.json",
				GenerationConfigPath: "generation_config.json",
				QuantConfigSource:    "empty",
				TokenizerConfigPath:  "tokenizer_config.json",
				TokenizerPaths:       []string{"merges.txt", "tokenizer.json", "tokenizer_config.json", "vocab.json"},
				WeightPaths:          []string{"model-00001-of-00005.safetensors", "model-00002-of-00005.safetensors"},
			},
			Warnings: []string{"using deterministic fake model details", "license metadata was not found in local model files"},
		},
		Identity: ModelIdentity{DisplayName: "Fake LLM Text", ModelID: modelID},
		Metadata: ModelMetadata{LicenseFiles: []string{}, LicenseRef: ""},
		ModelConfigSummary: ModelConfigSummary{
			ActiveParams:  8_190_735_360,
			Architecture:  "causal_lm",
			ContextLength: 40_960,
			Modality:      []string{"TEXT"},
			MOE:           ModelMOESummary{Enabled: false, NumExperts: 0, NumExpertsPerTok: 0},
			Quantization:  ModelQuantizationSummary{Bits: 16, Method: "BF16"},
			TotalParams:   8_190_735_360,
		},
		ModelDir: "/models/fake-llm-text",
		ModelRef: "fake/fake-llm-text",
		Source: ModelSource{
			Provider:        "FAKE",
			RepoID:          "fake/fake-llm-text",
			RepoType:        "model",
			ResolverVersion: "FAKE_RESOLVER_V1",
			Revision:        "v1",
			SourceURI:       "fake://fake/fake-llm-text@v1",
		},
	}
}
