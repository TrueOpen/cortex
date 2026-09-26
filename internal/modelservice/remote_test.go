package modelservice

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

type fakeTransport struct {
	method string
	req    any
	resp   any
	data   []byte
}

func (t *fakeTransport) Invoke(_ context.Context, method string, req any, resp any) error {
	t.method = method
	t.req = req
	t.resp = resp

	switch r := resp.(type) {
	case *HealthResponse:
		*r = HealthResponse{RequestID: "health-1", ModelServiceID: "svc-1", Healthy: true}
	case *ListCapabilitiesResponse:
		*r = ListCapabilitiesResponse{RequestID: "list-1", ModelServiceID: "svc-1"}
	case *GetModelDetailsResponse:
		*r = GetModelDetailsResponse{
			RequestID:      "details-1",
			ModelServiceID: "svc-1",
			Details:        testModelDetailsFixture("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"),
		}
	case *LoadModelResponse:
		*r = LoadModelResponse{RequestID: "load-1", ModelServiceID: "svc-1", Loaded: true}
	case *EstimateResponse:
		*r = EstimateResponse{RequestID: "estimate-1", ModelServiceID: "svc-1", EstimatedMS: 10}
	case *InferResponse:
		*r = InferResponse{RequestID: "infer-1", ModelServiceID: "svc-1", TaskID: "task-1", OutputRef: NewArtifactRef("svc-1", []byte("output")).String()}
		r.GenerationParamsDigest = append([]byte(nil), req.(InferRequest).GenerationParamsDigest...)
	case *VerifyResponse:
		*r = VerifyResponse{RequestID: "verify-1", ModelServiceID: "svc-1", VerifierID: "verifier-1"}
		r.GenerationParamsDigest = append([]byte(nil), req.(VerifyRequest).GenerationParamsDigest...)
	case *Artifact:
		data := t.data
		if data == nil {
			data = []byte("output")
		}
		*r = Artifact{Ref: req.(FetchArtifactRequest).Ref, MediaType: "application/octet-stream", Data: append([]byte(nil), data...)}
	}
	return nil
}

func TestRemoteClientMapsHealthMethod(t *testing.T) {
	transport := &fakeTransport{}
	client := NewRemoteClient(transport)
	resp, err := client.Health(context.Background(), HealthRequest{RequestID: "health-1", ModelServiceID: "svc-1"})
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if transport.method != "/cortex.v1.ModelManagementService/Health" {
		t.Fatalf("method = %q", transport.method)
	}
	if !resp.Healthy {
		t.Fatalf("Healthy = false, want true")
	}
}

func TestRemoteClientMapsNonHealthMethods(t *testing.T) {
	generation, generationDigest := generationContractFixture(t)
	tests := []struct {
		name       string
		call       func(context.Context, *RemoteClient) error
		wantMethod string
	}{
		{
			name: "ListCapabilities",
			call: func(ctx context.Context, client *RemoteClient) error {
				_, err := client.ListCapabilities(ctx, ListCapabilitiesRequest{RequestID: "list-1"})
				return err
			},
			wantMethod: "/cortex.v1.ModelManagementService/ListCapabilities",
		},
		{
			name: "LoadModel",
			call: func(ctx context.Context, client *RemoteClient) error {
				_, err := client.LoadModel(ctx, LoadModelRequest{RequestID: "load-1"})
				return err
			},
			wantMethod: "/cortex.v1.ModelManagementService/LoadModel",
		},
		{
			name: "GetModelDetails",
			call: func(ctx context.Context, client *RemoteClient) error {
				resp, err := client.GetModelDetails(ctx, GetModelDetailsRequest{RequestID: "details-1", ModelID: "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"})
				if err == nil && resp.Details.Identity.ModelID != "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a" {
					return errors.New("GetModelDetails response was not mapped")
				}
				return err
			},
			wantMethod: "/cortex.v1.ModelManagementService/GetModelDetails",
		},
		{
			name: "Estimate",
			call: func(ctx context.Context, client *RemoteClient) error {
				_, err := client.Estimate(ctx, EstimateRequest{RequestID: "estimate-1"})
				return err
			},
			wantMethod: "/cortex.v1.ModelManagementService/Estimate",
		},
		{
			name: "Infer",
			call: func(ctx context.Context, client *RemoteClient) error {
				_, err := client.Infer(ctx, InferRequest{RequestID: "infer-1", ModelID: "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", ProfileVersion: "1", Generation: generation, GenerationParamsDigest: generationDigest})
				return err
			},
			wantMethod: "/cortex.v1.ModelManagementService/Infer",
		},
		{
			name: "Verify",
			call: func(ctx context.Context, client *RemoteClient) error {
				_, err := client.Verify(ctx, VerifyRequest{RequestID: "verify-1", ModelID: "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", ProfileVersion: "1", Generation: generation, GenerationParamsDigest: generationDigest})
				return err
			},
			wantMethod: "/cortex.v1.ModelManagementService/Verify",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &fakeTransport{}
			client := NewRemoteClient(transport)
			if err := tt.call(context.Background(), client); err != nil {
				t.Fatalf("%s() error = %v", tt.name, err)
			}
			if transport.method != tt.wantMethod {
				t.Fatalf("method = %q, want %q", transport.method, tt.wantMethod)
			}
		})
	}
}

func TestRemoteClientFetchArtifactVerifiesDigestAndSize(t *testing.T) {
	transport := &fakeTransport{}
	client := NewRemoteClient(transport)
	ref := NewArtifactRef("svc-1", []byte("output")).String()
	artifact, err := client.FetchArtifact(context.Background(), FetchArtifactRequest{
		RequestID: "fetch-1", ModelServiceID: "svc-1", Ref: ref,
	})
	if err != nil {
		t.Fatalf("FetchArtifact() error = %v", err)
	}
	if transport.method != "/cortex.v1.ModelManagementService/FetchArtifact" {
		t.Fatalf("method = %q", transport.method)
	}
	if !bytes.Equal(artifact.Data, []byte("output")) {
		t.Fatalf("artifact data = %q", artifact.Data)
	}
}

func TestRemoteClientFetchArtifactRejectsDigestAndSizeMismatch(t *testing.T) {
	ref := NewArtifactRef("svc-1", []byte("output")).String()

	tests := []struct {
		name    string
		data    []byte
		wantErr error
	}{
		{name: "digest mismatch", data: []byte("Output"), wantErr: ErrArtifactDigestMismatch},
		{name: "size mismatch", data: []byte("output with extra bytes"), wantErr: ErrArtifactSizeMismatch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &fakeTransport{data: tt.data}
			client := NewRemoteClient(transport)
			_, err := client.FetchArtifact(context.Background(), FetchArtifactRequest{
				RequestID: "fetch-1", ModelServiceID: "svc-1", Ref: ref,
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("FetchArtifact() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestRemoteClientRequiresTransport(t *testing.T) {
	client := NewRemoteClient(nil)
	_, err := client.Health(context.Background(), HealthRequest{RequestID: "health-1"})
	if err == nil {
		t.Fatalf("Health() error = nil, want missing transport error")
	}
	if err.Error() != "modelservice transport is required" {
		t.Fatalf("Health() error = %q", err)
	}
}
