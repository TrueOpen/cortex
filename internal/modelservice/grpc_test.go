package modelservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	cortexv1 "github.com/TrueOpen/cortex/proto/cortex/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestInferResponseGRPCConversionPreservesTokenCountAndWorkUnit(t *testing.T) {
	got, err := fromProtoInferResponse(&cortexv1.InferResponse{
		GeneratedTokenCount: 17,
		WorkUnit:            23,
		FinishReason:        "eos_token",
	})
	if err != nil {
		t.Fatalf("fromProtoInferResponse() returned error: %v", err)
	}
	if got.GeneratedTokenCount != 17 || got.WorkUnit != 23 {
		t.Fatalf("fromProtoInferResponse() metering = %d/%d, want 17/23", got.GeneratedTokenCount, got.WorkUnit)
	}
}

func TestGRPCTransportExercisesHealthCapabilitiesInferVerifyAndArtifact(t *testing.T) {
	ctx := context.Background()
	server := newGRPCTestServer(t, &recordingModelManagementServer{
		artifactData: []byte("artifact-output"),
	})
	transport := NewGRPCTransportForClient(server.client)
	client := NewRemoteClient(transport)

	health, err := client.Health(ctx, HealthRequest{RequestID: "health-1", ModelServiceID: "svc-1"})
	if err != nil {
		t.Fatalf("Health returned error: %v", err)
	}
	if !health.Healthy || health.ModelServiceID != "svc-1" {
		t.Fatalf("Health = %#v", health)
	}

	caps, err := client.ListCapabilities(ctx, ListCapabilitiesRequest{RequestID: "caps-1", ModelServiceID: "svc-1"})
	if err != nil {
		t.Fatalf("ListCapabilities returned error: %v", err)
	}
	if len(caps.Capabilities) != 1 || caps.Capabilities[0].Capability != CapabilityLLMTextV1 ||
		caps.ResourceSnapshot.LoadedModels != 1 || caps.ResourceSnapshot.QueueDepth != 2 || caps.ResourceSnapshot.MaxConcurrency != 4 {
		t.Fatalf("ListCapabilities = %#v", caps)
	}

	details, err := client.GetModelDetails(ctx, GetModelDetailsRequest{
		RequestID:      "details-1",
		ModelServiceID: "svc-1",
		DeadlineMS:     5000,
		ModelID:        "model-a",
	})
	if err != nil {
		t.Fatalf("GetModelDetails returned error: %v", err)
	}
	if details.RequestID != "details-1" || details.ModelServiceID != "svc-1" {
		t.Fatalf("GetModelDetails envelope = %#v", details)
	}
	wantDetails := testModelDetailsFixture("model-a")
	if !reflect.DeepEqual(details.Details, wantDetails) || details.Error != nil {
		t.Fatalf("GetModelDetails = %#v, want %#v", details, wantDetails)
	}
	if details.Details.Metadata.LicenseFiles == nil {
		t.Fatal("GetModelDetails license_files = nil, want empty slice")
	}

	missing, err := client.GetModelDetails(ctx, GetModelDetailsRequest{RequestID: "details-2", ModelServiceID: "svc-1", ModelID: "missing"})
	if err != nil {
		t.Fatalf("GetModelDetails missing model returned transport error: %v", err)
	}
	if missing.Error == nil || missing.Error.Code != "MODEL_NOT_FOUND" || missing.Error.Retryable {
		t.Fatalf("GetModelDetails missing model error = %#v", missing.Error)
	}

	generation, generationDigest := generationContractFixture(t)
	infer, err := client.Infer(ctx, InferRequest{
		RequestID:      "infer-1",
		ModelServiceID: "svc-1",
		JobID:          "job-1",
		TaskID:         "task-1",
		ModelID:        "model-a",
		ProfileVersion: "1",
		Generation:     generation, GenerationParamsDigest: generationDigest,
		RequestDigest: []byte("request-digest"),
		Capability:    CapabilityLLMTextV1,
		Input:         []byte("prompt"),
	})
	if err != nil {
		t.Fatalf("Infer returned error: %v", err)
	}
	if infer.OutputRef == "" || infer.TraceRef == "" || infer.CheckpointRef == "" {
		t.Fatalf("Infer = %#v, want refs", infer)
	}

	verify, err := client.Verify(ctx, VerifyRequest{
		RequestID:      "verify-1",
		ModelServiceID: "svc-1",
		JobID:          "job-1",
		TaskID:         "task-1",
		ModelID:        "model-a",
		ProfileVersion: "1",
		Generation:     generation, GenerationParamsDigest: generationDigest,
		RequestDigest: []byte("request-digest"),
		Capability:    CapabilityLLMTextV1,
		Sample:        []byte("sample"),
		Evidence: map[string]VerifyEvidence{
			EvidenceKindWorkerValueOpening: {Trace: []byte("trace"), Checkpoint: []byte("checkpoint")},
		},
	})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if verify.MainMismatchCount != 2 || len(verify.SelectedPositionsOrCheckpoints) != 2 || len(verify.SampleDigest) == 0 || len(verify.MaterialDigest) == 0 {
		t.Fatalf("Verify = %#v", verify)
	}

	ref := NewArtifactRef("svc-1", []byte("artifact-output")).String()
	artifact, err := client.FetchArtifact(ctx, FetchArtifactRequest{RequestID: "fetch-1", ModelServiceID: "svc-1", Ref: ref})
	if err != nil {
		t.Fatalf("FetchArtifact returned error: %v", err)
	}
	if artifact.Ref != ref || !bytes.Equal(artifact.Data, []byte("artifact-output")) {
		t.Fatalf("artifact = %#v", artifact)
	}
}

func TestGRPCTransportArtifactSafety(t *testing.T) {
	ctx := context.Background()
	server := newGRPCTestServer(t, &recordingModelManagementServer{
		artifactData: []byte("wrong"),
	})
	client := NewRemoteClient(NewGRPCTransportForClient(server.client))
	ref := NewArtifactRef("svc-1", []byte("artifact-output")).String()

	_, err := client.FetchArtifact(ctx, FetchArtifactRequest{RequestID: "fetch-1", ModelServiceID: "svc-1", Ref: ref})
	if !errors.Is(err, ErrArtifactSizeMismatch) && !errors.Is(err, ErrArtifactDigestMismatch) {
		t.Fatalf("FetchArtifact mismatch error = %v, want digest or size mismatch", err)
	}
	_, err = client.FetchArtifact(ctx, FetchArtifactRequest{RequestID: "fetch-1", ModelServiceID: "svc-1", Ref: "https://provider.example/artifact"})
	if !errors.Is(err, ErrInvalidArtifactRef) {
		t.Fatalf("FetchArtifact invalid ref error = %v, want ErrInvalidArtifactRef", err)
	}
}

func TestGRPCTransportFetchArtifactRespectsSizeLimit(t *testing.T) {
	ctx := context.Background()
	server := newGRPCTestServer(t, &recordingModelManagementServer{
		artifactChunks: [][]byte{bytes.Repeat([]byte("a"), 8), bytes.Repeat([]byte("b"), 5)},
	})
	transport := NewGRPCTransportForClient(server.client)
	client := NewRemoteClient(transport)
	ref := NewArtifactRef("svc-1", append(bytes.Repeat([]byte("a"), 8), bytes.Repeat([]byte("b"), 5)...)).String()

	_, err := client.FetchArtifact(ctx, FetchArtifactRequest{
		RequestID:      "fetch-limit",
		ModelServiceID: "svc-1",
		Ref:            ref,
		SizeLimitBytes: 10,
		Kind:           "WORKER_VALUE_OPENING",
	})
	if !errors.Is(err, ErrArtifactSizeExceeded) {
		t.Fatalf("error = %v, want ErrArtifactSizeExceeded", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "kind=WORKER_VALUE_OPENING") {
		t.Fatalf("error does not name kind: %s", msg)
	}
	if !strings.Contains(msg, "bound=10") {
		t.Fatalf("error does not name bound: %s", msg)
	}
	if !strings.Contains(msg, "observed=13") {
		t.Fatalf("error does not name observed size: %s", msg)
	}
}

func TestGRPCTransportMapsDeadlineAndRetryableErrors(t *testing.T) {
	ctx := context.Background()
	server := newGRPCTestServer(t, &recordingModelManagementServer{
		healthError: status.Error(codes.Unavailable, "temporary outage"),
	})
	client := NewRemoteClient(NewGRPCTransportForClient(server.client))
	_, err := client.Health(ctx, HealthRequest{RequestID: "health-1", ModelServiceID: "svc-1"})
	if err == nil || !strings.Contains(err.Error(), "temporary outage") || !IsRetryable(err) {
		t.Fatalf("Health retryable error = %v, want retryable unavailable", err)
	}

	deadlineCtx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err = client.Health(deadlineCtx, HealthRequest{RequestID: "health-2", ModelServiceID: "svc-1"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Health deadline error = %v, want context deadline exceeded", err)
	}
}

func TestNewTransportReturnsLiveGRPCTransport(t *testing.T) {
	server := newGRPCTestServer(t, &recordingModelManagementServer{})
	transport, err := NewTransport(RuntimeTransportConfig{Kind: "grpc", Endpoint: server.endpoint})
	if err != nil {
		t.Fatalf("NewTransport returned error: %v", err)
	}
	client := NewRemoteClient(transport)
	health, err := client.Health(context.Background(), HealthRequest{RequestID: "health-1", ModelServiceID: "svc-1"})
	if err != nil {
		t.Fatalf("Health returned error: %v", err)
	}
	if !health.Healthy {
		t.Fatalf("Health = %#v", health)
	}
}

type grpcTestServer struct {
	endpoint string
	client   cortexv1.ModelManagementServiceClient
}

func newGRPCTestServer(t *testing.T, service cortexv1.ModelManagementServiceServer) grpcTestServer {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	cortexv1.RegisterModelManagementServiceServer(server, service)
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(RegisterGRPCTestDialer("bufnet", func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}))
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("DialContext returned error: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})
	return grpcTestServer{
		endpoint: "bufnet",
		client:   cortexv1.NewModelManagementServiceClient(conn),
	}
}

type recordingModelManagementServer struct {
	cortexv1.UnimplementedModelManagementServiceServer
	artifactData   []byte
	artifactChunks [][]byte
	healthError    error
}

func (s *recordingModelManagementServer) Health(context.Context, *cortexv1.HealthRequest) (*cortexv1.HealthResponse, error) {
	if s.healthError != nil {
		return nil, s.healthError
	}
	return &cortexv1.HealthResponse{RequestId: "health-1", ModelServiceId: "svc-1", Healthy: true}, nil
}

func (s *recordingModelManagementServer) ListCapabilities(context.Context, *cortexv1.ListCapabilitiesRequest) (*cortexv1.ListCapabilitiesResponse, error) {
	return &cortexv1.ListCapabilitiesResponse{
		RequestId:                  "caps-1",
		ModelServiceId:             "svc-1",
		ModelManagementApiVersions: []string{"cortex.model_management.v1"},
		Capabilities: []*cortexv1.ManagedModelCapability{{
			ModelId:            "model-a",
			Capability:         CapabilityLLMTextV1,
			SupportsTrace:      true,
			SupportsCheckpoint: true,
			SupportsBatchLog:   true,
		}},
		ResourceSnapshot: &cortexv1.ResourceSnapshot{LoadedModels: 1, QueueDepth: 2, MaxConcurrency: 4},
	}, nil
}

func (s *recordingModelManagementServer) GetModelDetails(_ context.Context, req *cortexv1.GetModelDetailsRequest) (*cortexv1.GetModelDetailsResponse, error) {
	resp := &cortexv1.GetModelDetailsResponse{
		RequestId:      req.GetRequestId(),
		ModelServiceId: req.GetModelServiceId(),
	}
	if req.GetModelId() == "missing" {
		resp.Error = &cortexv1.ModelServiceError{Code: "MODEL_NOT_FOUND", Message: "model not found"}
		return resp, nil
	}
	resp.Details = toProtoModelDetailsForTest(testModelDetailsFixture(req.GetModelId()))
	return resp, nil
}

func toProtoModelDetailsForTest(details ModelDetails) *cortexv1.ModelDetails {
	files := make([]*cortexv1.ModelArtifactFile, 0, len(details.Artifacts.Files))
	for _, file := range details.Artifacts.Files {
		files = append(files, &cortexv1.ModelArtifactFile{Digest: file.Digest, Path: file.Path, Role: file.Role, SizeBytes: file.SizeBytes})
	}
	return &cortexv1.ModelDetails{
		Artifacts: &cortexv1.ModelArtifacts{
			ChatTemplateHash:     details.Artifacts.ChatTemplateHash,
			FileManifestHash:     details.Artifacts.FileManifestHash,
			Files:                files,
			GenerationConfigHash: details.Artifacts.GenerationConfigHash,
			ModelConfigHash:      details.Artifacts.ModelConfigHash,
			ModelWeightDigest:    details.Artifacts.ModelWeightDigest,
			QuantConfigHash:      details.Artifacts.QuantConfigHash,
			TokenizerConfigHash:  details.Artifacts.TokenizerConfigHash,
			TokenizerHash:        details.Artifacts.TokenizerHash,
		},
		Derivation: &cortexv1.ModelDerivation{
			ArtifactSources: &cortexv1.ModelArtifactSources{
				ChatTemplateSource:   details.Derivation.ArtifactSources.ChatTemplateSource,
				ConfigPath:           details.Derivation.ArtifactSources.ConfigPath,
				GenerationConfigPath: details.Derivation.ArtifactSources.GenerationConfigPath,
				QuantConfigSource:    details.Derivation.ArtifactSources.QuantConfigSource,
				TokenizerConfigPath:  details.Derivation.ArtifactSources.TokenizerConfigPath,
				TokenizerPaths:       details.Derivation.ArtifactSources.TokenizerPaths,
				WeightPaths:          details.Derivation.ArtifactSources.WeightPaths,
			},
			Warnings: details.Derivation.Warnings,
		},
		Identity: &cortexv1.ModelIdentity{DisplayName: details.Identity.DisplayName, ModelId: details.Identity.ModelID},
		Metadata: &cortexv1.ModelMetadata{LicenseFiles: details.Metadata.LicenseFiles, LicenseRef: details.Metadata.LicenseRef},
		ModelConfigSummary: &cortexv1.ModelConfigSummary{
			ActiveParams:  details.ModelConfigSummary.ActiveParams,
			Architecture:  details.ModelConfigSummary.Architecture,
			ContextLength: details.ModelConfigSummary.ContextLength,
			Modality:      details.ModelConfigSummary.Modality,
			Moe: &cortexv1.ModelMOESummary{
				Enabled: details.ModelConfigSummary.MOE.Enabled, NumExperts: details.ModelConfigSummary.MOE.NumExperts, NumExpertsPerTok: details.ModelConfigSummary.MOE.NumExpertsPerTok,
			},
			Quantization: &cortexv1.ModelQuantizationSummary{Bits: details.ModelConfigSummary.Quantization.Bits, Method: details.ModelConfigSummary.Quantization.Method},
			TotalParams:  details.ModelConfigSummary.TotalParams,
		},
		ModelDir: details.ModelDir,
		ModelRef: details.ModelRef,
		Source: &cortexv1.ModelSource{
			Provider: details.Source.Provider, RepoId: details.Source.RepoID, RepoType: details.Source.RepoType,
			ResolverVersion: details.Source.ResolverVersion, Revision: details.Source.Revision, SourceUri: details.Source.SourceURI,
		},
	}
}

func (s *recordingModelManagementServer) LoadModel(context.Context, *cortexv1.LoadModelRequest) (*cortexv1.LoadModelResponse, error) {
	return &cortexv1.LoadModelResponse{RequestId: "load-1", ModelServiceId: "svc-1", ModelId: "model-a", Loaded: true}, nil
}

func (s *recordingModelManagementServer) Estimate(context.Context, *cortexv1.EstimateRequest) (*cortexv1.EstimateResponse, error) {
	return &cortexv1.EstimateResponse{RequestId: "estimate-1", ModelServiceId: "svc-1", EstimatedMs: 10, EstimatedBytes: 20}, nil
}

func (s *recordingModelManagementServer) Infer(_ context.Context, req *cortexv1.InferRequest) (*cortexv1.InferResponse, error) {
	return &cortexv1.InferResponse{
		RequestId:              req.GetRequestId(),
		ModelServiceId:         req.GetModelServiceId(),
		JobId:                  req.GetJobId(),
		TaskId:                 req.GetTaskId(),
		ModelId:                req.GetModelId(),
		ProfileVersion:         req.GetProfileVersion(),
		RequestDigest:          req.GetRequestDigest(),
		OutputRef:              NewArtifactRef("svc-1", []byte("artifact-output")).String(),
		TraceRef:               NewArtifactRef("svc-1", []byte("trace")).String(),
		CheckpointRef:          NewArtifactRef("svc-1", []byte("checkpoint")).String(),
		FinishReason:           "eos_token",
		GenerationParamsDigest: append([]byte(nil), req.GetGenerationParamsDigest()...),
	}, nil
}

func (s *recordingModelManagementServer) Verify(_ context.Context, req *cortexv1.VerifyRequest) (*cortexv1.VerifyResponse, error) {
	sampleDigest := sha256.Sum256(req.GetSample())
	var trace, checkpoint []byte
	for _, item := range req.GetEvidence() {
		if item.GetEvidenceKind() == EvidenceKindWorkerValueOpening {
			trace = item.GetTrace()
			checkpoint = item.GetCheckpoint()
			break
		}
	}
	materialDigest := sha256.Sum256(append(trace, checkpoint...))
	return &cortexv1.VerifyResponse{
		GenerationParamsDigest:         append([]byte(nil), req.GetGenerationParamsDigest()...),
		RequestId:                      req.GetRequestId(),
		ModelServiceId:                 req.GetModelServiceId(),
		JobId:                          req.GetJobId(),
		TaskId:                         req.GetTaskId(),
		ModelId:                        req.GetModelId(),
		ProfileVersion:                 req.GetProfileVersion(),
		RequestDigest:                  req.GetRequestDigest(),
		MainMismatchCount:              2,
		SelectedPositionsOrCheckpoints: []int32{1, 3},
		SampleValueSequenceRef:         NewArtifactRef("svc-1", []byte("values")).String(),
		SampleValueDigest:              sampleDigest[:],
		ResultCommitMaterialDigest:     materialDigest[:],
	}, nil
}

func (s *recordingModelManagementServer) FetchArtifact(req *cortexv1.FetchArtifactRequest, stream cortexv1.ModelManagementService_FetchArtifactServer) error {
	chunks := s.artifactChunks
	if chunks == nil {
		data := s.artifactData
		if data == nil {
			data = []byte("artifact-output")
		}
		chunks = [][]byte{data[:len(data)/2], data[len(data)/2:]}
	}
	offset := int64(0)
	for i, chunk := range chunks {
		digest := sha256.Sum256(chunk)
		if err := stream.Send(&cortexv1.ArtifactChunk{
			RequestId:   req.GetRequestId(),
			ArtifactId:  "artifact-output",
			Offset:      offset,
			Bytes:       chunk,
			FinalChunk:  i == len(chunks)-1,
			ChunkDigest: digest[:],
		}); err != nil {
			return err
		}
		offset += int64(len(chunk))
	}
	return nil
}

func recvAllArtifacts(stream cortexv1.ModelManagementService_FetchArtifactClient) ([]byte, error) {
	var out []byte
	for {
		chunk, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, chunk.GetBytes()...)
	}
}

func TestInferResponseGRPCRejectsAmbiguousStop(t *testing.T) {
	_, err := fromProtoInferResponse(&cortexv1.InferResponse{
		GeneratedTokenCount: 1,
		WorkUnit:            1,
		FinishReason:        "stop",
	})
	if err == nil {
		t.Fatal("fromProtoInferResponse() should reject bare stop finish reason")
	}
}
