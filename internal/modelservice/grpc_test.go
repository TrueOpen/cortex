package modelservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	cortexv1 "github.com/TrueOpen/cortex/proto/cortex/v1"
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

func (s *recordingModelManagementServer) Estimate(context.Context, *cortexv1.EstimateRequest) (*cortexv1.EstimateResponse, error) {
	return &cortexv1.EstimateResponse{RequestId: "estimate-1", ModelServiceId: "svc-1", EstimatedMs: 10, EstimatedBytes: 20}, nil
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
