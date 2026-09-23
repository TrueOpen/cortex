package modelservice

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/metric"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

const fakeServiceID = "fake-model-service"

type FakeService struct {
	mu        sync.RWMutex
	serviceID string
	artifacts map[string][]byte
	root      string
	// modelIDs are the chain model identifiers this fake advertises. Handraise
	// eligibility matches the configured model id against what the model
	// service exposes, so a deployment testing against real Keeper records has
	// to advertise those identifiers rather than a fixed placeholder.
	modelIDs []string
}

// fakeModelID keeps the historical advertisement when no chain model is
// configured, so existing fixtures and tests are unaffected.
const fakeModelID = "fake-llm-text"

// The fake emits one deterministic synthetic result token per inference.
const fakeGeneratedTokenCount uint64 = 1

// advertisesModelID keeps GetModelDetails consistent with ListCapabilities.
// A service that claims to support a model must also describe it.
func (f *FakeService) advertisesModelID(modelID string) bool {
	ids := f.modelIDs
	if len(ids) == 0 {
		ids = []string{fakeModelID}
	}
	for _, advertised := range ids {
		if advertised == modelID {
			return true
		}
	}
	return false
}

func (f *FakeService) advertisedCapabilities() []ManagedModelCapability {
	ids := f.modelIDs
	if len(ids) == 0 {
		ids = []string{fakeModelID}
	}
	out := make([]ManagedModelCapability, 0, len(ids))
	for _, modelID := range ids {
		out = append(out, ManagedModelCapability{
			ModelID:            modelID,
			Capability:         CapabilityLLMTextV1,
			SupportsTrace:      true,
			SupportsCheckpoint: true,
			SupportsBatchLog:   true,
		})
	}
	return out
}

func NewSharedFakeService(serviceID string, fixtureRoot string, modelIDs ...string) (*FakeService, error) {
	serviceID = strings.TrimSpace(serviceID)
	fixtureRoot = strings.TrimSpace(fixtureRoot)
	if serviceID == "" || strings.ContainsAny(serviceID, "/\\?#") {
		return nil, fmt.Errorf("fake model service id is invalid")
	}
	if fixtureRoot == "" {
		return nil, fmt.Errorf("fake model fixture root is required")
	}
	root, err := filepath.Abs(fixtureRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve fake model fixture root: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "model-artifacts"), 0o700); err != nil {
		return nil, fmt.Errorf("create fake model artifact directory: %w", err)
	}
	advertised := make([]string, 0, len(modelIDs))
	for _, modelID := range modelIDs {
		modelID = strings.TrimSpace(modelID)
		if modelID == "" {
			continue
		}
		advertised = append(advertised, modelID)
	}
	if len(advertised) == 0 {
		advertised = []string{fakeModelID}
	}
	return &FakeService{serviceID: serviceID, root: root, modelIDs: advertised}, nil
}

func NewFakeService() *FakeService {
	return &FakeService{
		serviceID: fakeServiceID,
		artifacts: make(map[string][]byte),
	}
}

func (f *FakeService) Health(_ context.Context, req HealthRequest) (HealthResponse, error) {
	return HealthResponse{
		RequestID:      req.RequestID,
		ModelServiceID: f.serviceID,
		Healthy:        true,
	}, nil
}

func (f *FakeService) ListCapabilities(_ context.Context, req ListCapabilitiesRequest) (ListCapabilitiesResponse, error) {
	return ListCapabilitiesResponse{
		RequestID:                  req.RequestID,
		ModelServiceID:             f.serviceID,
		ModelManagementAPIVersions: []string{"cortex.model_management.v1"},
		Capabilities:               f.advertisedCapabilities(),
		ResourceSnapshot:           ResourceSnapshot{LoadedModels: 1, MaxConcurrency: 1},
	}, nil
}

func (f *FakeService) GetModelDetails(_ context.Context, req GetModelDetailsRequest) (GetModelDetailsResponse, error) {
	resp := GetModelDetailsResponse{
		RequestID:      req.RequestID,
		ModelServiceID: f.serviceID,
	}
	if !f.advertisesModelID(req.ModelID) {
		resp.Error = &ServiceError{
			Code:    "MODEL_NOT_FOUND",
			Message: fmt.Sprintf("model %q not found", req.ModelID),
		}
		return resp, nil
	}
	resp.Details = fakeModelDetails(req.ModelID)
	return resp, nil
}

func fakeModelDetails(modelID string) ModelDetails {
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

func (f *FakeService) LoadModel(_ context.Context, req LoadModelRequest) (LoadModelResponse, error) {
	if err := validateCapability(req.Capability, true, true); err != nil {
		return LoadModelResponse{}, err
	}
	return LoadModelResponse{
		RequestID:      req.RequestID,
		ModelServiceID: f.serviceID,
		ModelID:        req.ModelID,
		Loaded:         true,
	}, nil
}

func (f *FakeService) Estimate(_ context.Context, req EstimateRequest) (EstimateResponse, error) {
	if err := validateCapability(req.Capability, true, true); err != nil {
		return EstimateResponse{}, err
	}
	return EstimateResponse{
		RequestID:      req.RequestID,
		ModelServiceID: f.serviceID,
		EstimatedMS:    10,
		EstimatedBytes: req.InputBytes + 64,
	}, nil
}

func (f *FakeService) Infer(ctx context.Context, req InferRequest) (InferResponse, error) {
	if req.Generation != nil || len(req.GenerationParamsDigest) != 0 {
		if err := ValidateGenerationContext(req.Generation, req.GenerationParamsDigest, req.ModelID, req.ProfileVersion); err != nil {
			return InferResponse{}, err
		}
	}
	if err := validateCapability(req.Capability, true, true); err != nil {
		return InferResponse{}, err
	}
	material := bytes.Join([][]byte{
		[]byte(req.ModelID),
		[]byte(req.Capability),
		req.Input,
	}, []byte{0})
	outputDigest := codec.HashWithDomain("CORTEX_FAKE_LLM_TEXT_OUTPUT_V1", material)
	output := []byte(fmt.Sprintf("fake llm_text_v1 output %x", outputDigest[:]))
	outputRef, err := f.putArtifact(output)
	if err != nil {
		return InferResponse{}, err
	}
	var trace, checkpoint []byte
	{
		var generation *nodewire.GenerationContext
		if req.Generation != nil {
			copy := req.Generation.Clone()
			generation = &copy
		}
		env := traceEnvelope{
			Generation: generation, ModelID: req.ModelID, ProfileVersion: req.ProfileVersion, Output: string(output),
			InputTokenIDs: []int{1}, InputTokenIDsHash: hashTokenIDs([]int{1}),
			GeneratedTokenIDsHash: hashTokenIDs([]int{1000}), GeneratedTokenCount: int(fakeGeneratedTokenCount),
			FinishReason: "stop", OutTokens: []tokenLogprob{{TokenID: 1000, Logprob: -0.5, Rank: 1, TopLogprobs: map[string]float64{"token_id:1000": -0.5}}},
		}
		trace, err = json.Marshal(env)
		if err != nil {
			return InferResponse{}, err
		}
		env.OutTokens = nil
		checkpoint, err = json.Marshal(env)
		if err != nil {
			return InferResponse{}, err
		}
	}
	traceRef, err := f.putArtifact(trace)
	if err != nil {
		return InferResponse{}, err
	}
	checkpointRef, err := f.putArtifact(checkpoint)
	if err != nil {
		return InferResponse{}, err
	}
	if observer, ok := ctx.Value(inferStreamObserverKey{}).(InferStreamObserver); ok {
		frame := InferStreamFrame{RequestID: req.RequestID, JobID: req.JobID, TaskID: req.TaskID, ModelID: req.ModelID, TextDelta: string(output), TokenIDs: []int{1000}, TokenLogprobs: []float64{-0.5}}
		if observer.ObserveInferFrame(ctx, frame) == nil {
			_ = observer.ObserveInferFrame(ctx, InferStreamFrame{RequestID: req.RequestID, JobID: req.JobID, TaskID: req.TaskID, ModelID: req.ModelID, Done: true, FinishReason: "stop"})
		}
	}
	return InferResponse{
		RequestID:              req.RequestID,
		ModelServiceID:         f.serviceID,
		JobID:                  req.JobID,
		TaskID:                 req.TaskID,
		ModelID:                req.ModelID,
		ProfileVersion:         req.ProfileVersion,
		RequestDigest:          req.RequestDigest,
		OutputRef:              outputRef,
		TraceRef:               traceRef,
		CheckpointRef:          checkpointRef,
		GeneratedTokenCount:    fakeGeneratedTokenCount,
		GenerationParamsDigest: append([]byte(nil), req.GenerationParamsDigest...),
		WorkUnit:               fakeGeneratedTokenCount,
		FinishReason:           nodewire.FinishReasonV1EosToken,
	}, nil
}

func (f *FakeService) Verify(_ context.Context, req VerifyRequest) (VerifyResponse, error) {
	if req.Generation != nil || len(req.GenerationParamsDigest) != 0 {
		if err := ValidateGenerationContext(req.Generation, req.GenerationParamsDigest, req.ModelID, req.ProfileVersion); err != nil {
			return VerifyResponse{}, err
		}
	}
	item, err := validateVerifyRequest(req)
	if err != nil {
		return VerifyResponse{}, err
	}
	sampleDigest := codec.HashBytes(req.Sample)
	materialDigest := codec.HashWithDomain("CORTEX_FAKE_VERIFY_MATERIAL_V1", req.Sample, item.Trace, item.Checkpoint)
	sequenceRef, err := f.putArtifact([]byte(strconv.FormatUint(binary.BigEndian.Uint64(materialDigest[:8]), 10)))
	if err != nil {
		return VerifyResponse{}, err
	}
	samples := fakeMetricSamples(materialDigest)
	return VerifyResponse{
		RequestID:                      req.RequestID,
		ModelServiceID:                 f.serviceID,
		JobID:                          req.JobID,
		TaskID:                         req.TaskID,
		ModelID:                        req.ModelID,
		ProfileVersion:                 req.ProfileVersion,
		RequestDigest:                  req.RequestDigest,
		VerifierID:                     "fake-verifier-v1",
		MainMismatchCount:              0,
		SelectedPositionsOrCheckpoints: []int{0},
		SampleValueSequenceRef:         sequenceRef,
		SampleDigest:                   sampleDigest[:],
		MaterialDigest:                 materialDigest[:],
		MetricSamples:                  samples,
		GenerationParamsDigest:         append([]byte(nil), req.GenerationParamsDigest...),
	}, nil
}

// fakeMetricSamples synthesises the per-position comparison a real
// prefill/teacher-forcing run would produce.
//
// It is a function of the material digest rather than a constant, so two
// different verify inputs do not produce the same metric_root - a fixture that
// collapsed every run onto one root would let a wiring bug that ignores its
// inputs pass the whole metric path. Both optional metrics are measured,
// because whether they reach the summary is the locked profile's decision and
// the fake must not pre-empt it.
//
// No aggregates: the pipeline derives those from these samples, so there is
// nothing for a fixture to state independently.
func fakeMetricSamples(materialDigest codec.Hash) []metric.Sample {
	const positions = int(fakeGeneratedTokenCount)
	samples := make([]metric.Sample, 0, positions)
	for position := 0; position < positions; position++ {
		// A small, deterministic per-position spread in the 1e-4 range: close
		// enough to read as agreement, distinct enough that no two positions
		// share a leaf.
		drift := float64(materialDigest[position%len(materialDigest)]%17) / 100000
		worker := -0.5 - float64(position)/64
		samples = append(samples, metric.Sample{
			OutputPosition:  uint32(position),
			EmittedTokenID:  uint32(1000 + position),
			WorkerLogprob:   worker,
			VerifierLogprob: worker - drift,
			WorkerRank:      1,
			VerifierRank:    1,
			TopKJaccard:     metric.PresentFP(1),
			UnionJS:         metric.PresentFP(0),
			Finite:          true,
		})
	}
	return samples
}

func (f *FakeService) FetchArtifact(_ context.Context, req FetchArtifactRequest) (Artifact, error) {
	ref, err := ParseArtifactRef(req.Ref)
	if err != nil {
		return Artifact{}, err
	}
	if ref.ServiceID != f.serviceID {
		return Artifact{}, fmt.Errorf("%w: service id %q", ErrInvalidArtifactRef, ref.ServiceID)
	}
	if req.ModelServiceID != "" && req.ModelServiceID != f.serviceID {
		return Artifact{}, fmt.Errorf("%w: request model_service_id %q", ErrInvalidArtifactRef, req.ModelServiceID)
	}
	var data []byte
	if f.root != "" {
		path := f.artifactPath(ref.ArtifactID)
		// Check the size before reading. os.ReadFile allocates the whole file
		// first, so checking afterwards proves the bound was exceeded using the
		// very allocation the bound exists to prevent.
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return Artifact{}, fmt.Errorf("%w: %v", ErrArtifactNotFound, err)
			}
			return Artifact{}, fmt.Errorf("stat fake model artifact: %w", err)
		}
		if req.SizeLimitBytes > 0 && info.Size() >= 0 && uint64(info.Size()) > req.SizeLimitBytes {
			return Artifact{}, fmt.Errorf("%w: kind=%s, bound=%d, observed=%d", ErrArtifactSizeExceeded, req.Kind, req.SizeLimitBytes, info.Size())
		}
		data, err = os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				return Artifact{}, fmt.Errorf("%w: %v", ErrArtifactNotFound, err)
			}
			return Artifact{}, fmt.Errorf("read fake model artifact: %w", err)
		}
	} else {
		f.mu.RLock()
		var ok bool
		data, ok = f.artifacts[ref.ArtifactID]
		f.mu.RUnlock()
		if !ok {
			return Artifact{}, ErrArtifactNotFound
		}
	}
	if req.SizeLimitBytes > 0 && uint64(len(data)) > req.SizeLimitBytes {
		return Artifact{}, fmt.Errorf("%w: kind=%s, bound=%d, observed=%d", ErrArtifactSizeExceeded, req.Kind, req.SizeLimitBytes, len(data))
	}
	if err := verifyArtifactBytes(ref, data, req.AllowEmpty); err != nil {
		return Artifact{}, err
	}
	return Artifact{Ref: ref.String(), MediaType: "application/octet-stream", Data: append([]byte(nil), data...)}, nil
}

// PutArtifactForTest stores data as an artifact and returns its ref. This is a
// test-only seam kept out of the Service interface; the ForTest suffix marks it
// so production code never reaches for it. A rooted fake writes to disk, and a
// failure there means the test environment is broken rather than the code under
// test, so it panics instead of returning an error the callers cannot act on.
func (f *FakeService) PutArtifactForTest(data []byte) string {
	ref, err := f.putArtifact(data)
	if err != nil {
		panic(fmt.Sprintf("put fake artifact: %v", err))
	}
	return ref
}

func (f *FakeService) putArtifact(data []byte) (string, error) {
	ref := NewArtifactRef(f.serviceID, data)
	if f.root != "" {
		if err := writeArtifactAtomically(f.artifactPath(ref.ArtifactID), data); err != nil {
			return "", err
		}
		return ref.String(), nil
	}
	f.mu.Lock()
	f.artifacts[ref.ArtifactID] = append([]byte(nil), data...)
	f.mu.Unlock()
	return ref.String(), nil
}

func (f *FakeService) artifactPath(artifactID string) string {
	return filepath.Join(f.root, "model-artifacts", artifactID+".bin")
}

func writeArtifactAtomically(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".artifact-*")
	if err != nil {
		return fmt.Errorf("create fake model artifact temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set fake model artifact permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write fake model artifact: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync fake model artifact: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close fake model artifact: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("commit fake model artifact: %w", err)
	}
	return nil
}

func validateCapability(capability string, supportsTrace bool, supportsCheckpoint bool) error {
	switch capability {
	case CapabilityLLMTextV1:
		return nil
	default:
		if !supportsTrace || !supportsCheckpoint {
			return ErrUnsupportedCapability
		}
		return ErrUnsupportedCapability
	}
}

// validateVerifyRequest checks that the request carries exactly the evidence
// required by the capability, no more and no less, and that each item matches
// the expected commitment when the caller supplies one. When RequiredEvidence is
// empty, the requirement set is derived from the capability so existing callers
// still work; production callers should populate RequiredEvidence from the locked
// Profile.
func validateVerifyRequest(req VerifyRequest) (VerifyEvidence, error) {
	var empty VerifyEvidence
	switch req.Capability {
	case CapabilityLLMTextV1:
	default:
		return empty, ErrUnsupportedCapability
	}

	// Build the required set: explicit requirements take precedence; otherwise
	// fall back to the hardcoded capability requirements.
	var requirements []EvidenceRequirement
	if len(req.RequiredEvidence) > 0 {
		requirements = req.RequiredEvidence
	} else {
		switch req.Capability {
		case CapabilityLLMTextV1:
			requirements = []EvidenceRequirement{{Kind: EvidenceKindWorkerValueOpening}}
		}
	}

	required := make(map[string]EvidenceRequirement, len(requirements))
	for _, r := range requirements {
		required[r.Kind] = r
	}

	// Check every required kind is present.
	for kind, r := range required {
		item, ok := req.Evidence[kind]
		if !ok {
			return empty, fmt.Errorf("verify request missing %s evidence", kind)
		}
		if len(item.Trace) == 0 || len(item.Checkpoint) == 0 {
			return empty, fmt.Errorf("verify request %s requires trace and checkpoint", kind)
		}
		if len(r.ExpectedRoot) > 0 && !bytes.Equal(item.ExpectedRoot, r.ExpectedRoot) {
			return empty, fmt.Errorf("verify request %s expected root mismatch", kind)
		}
		if r.EncodedSizeBytes != 0 && item.EncodedSizeBytes != r.EncodedSizeBytes {
			return empty, fmt.Errorf("verify request %s encoded size mismatch: got %d, want %d", kind, item.EncodedSizeBytes, r.EncodedSizeBytes)
		}
	}

	// Reject any unexpected extra kind.
	for kind := range req.Evidence {
		if _, ok := required[kind]; !ok {
			return empty, fmt.Errorf("verify request contains unexpected evidence kind %s", kind)
		}
	}

	return req.Evidence[requirements[0].Kind], nil
}
