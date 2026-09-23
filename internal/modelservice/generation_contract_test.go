package modelservice

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/nodewire"
	cortexv1 "github.com/TrueOpen/cortex/proto/cortex/v1"
	"google.golang.org/protobuf/proto"
)

func generationContractFixture(t *testing.T) (*nodewire.GenerationContext, []byte) {
	t.Helper()
	g := &nodewire.GenerationContext{
		ModelID: "model-a", ProfileVersion: 1, TaskType: 2, OutputBudgetBucket: 4,
		Params: nodewire.GenerationParamsV1{
			SchemaVersion: 1, MaxOutputTokens: 256, MaxOutputDuration: 30000,
			DecodingParams: nodewire.DecodingParamsV1{
				SamplingEnabled: true, TemperatureMilli: 700, TopPPPM: 950000, TopK: 40, Seed: 8675309,
				PresencePenaltyMilli: -250, FrequencyPenaltyMilli: 125, RepetitionPenaltyPPM: 1050000,
				StopSequences: []string{"</s>", "STOP"}, StopTokenIDs: []uint32{11, 220},
			},
		},
	}
	digest, err := g.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return g, digest[:]
}

type generationRecordingServer struct {
	recordingModelManagementServer
	infer  chan *cortexv1.InferRequest
	verify chan *cortexv1.VerifyRequest
}

func (s *generationRecordingServer) Infer(ctx context.Context, req *cortexv1.InferRequest) (*cortexv1.InferResponse, error) {
	s.infer <- req
	return s.recordingModelManagementServer.Infer(ctx, req)
}

func (s *generationRecordingServer) Verify(ctx context.Context, req *cortexv1.VerifyRequest) (*cortexv1.VerifyResponse, error) {
	s.verify <- req
	return s.recordingModelManagementServer.Verify(ctx, req)
}

func TestGenerationContextGRPCTransportsEveryFieldAndEcho(t *testing.T) {
	g, digest := generationContractFixture(t)
	want := &cortexv1.GenerationContext{
		ModelId: "model-a", ProfileVersion: 1, TaskType: 2, OutputBudgetBucket: 4,
		Params: &cortexv1.GenerationParamsV1{
			GenerationParamsSchemaVersion: 1, MaxOutputTokens: 256, MaxOutputDuration: 30000,
			DecodingParams: &cortexv1.DecodingParamsV1{
				SamplingEnabled: true, TemperatureMilli: 700, TopPPpm: 950000, TopK: 40, Seed: 8675309,
				PresencePenaltyMilli: -250, FrequencyPenaltyMilli: 125, RepetitionPenaltyPpm: 1050000,
				StopSequences: []string{"</s>", "STOP"}, StopTokenIds: []uint32{11, 220},
			},
		},
	}
	s := &generationRecordingServer{infer: make(chan *cortexv1.InferRequest, 1), verify: make(chan *cortexv1.VerifyRequest, 1)}
	server := newGRPCTestServer(t, s)
	client := NewRemoteClient(NewGRPCTransportForClient(server.client))
	infer, err := client.Infer(context.Background(), InferRequest{
		ModelID: "model-a", ProfileVersion: "1", Capability: CapabilityLLMTextV1, Generation: g, GenerationParamsDigest: digest,
	})
	if err != nil {
		t.Fatal(err)
	}
	gotInfer := <-s.infer
	if !proto.Equal(gotInfer.GetGeneration(), want) || !bytes.Equal(gotInfer.GetGenerationParamsDigest(), digest) || !bytes.Equal(infer.GenerationParamsDigest, digest) {
		t.Fatalf("infer generation transport lost fields: request=%v response digest=%x", gotInfer, infer.GenerationParamsDigest)
	}
	verify, err := client.Verify(context.Background(), VerifyRequest{
		ModelID: "model-a", ProfileVersion: "1", Capability: CapabilityLLMTextV1, Generation: g, GenerationParamsDigest: digest,
	})
	if err != nil {
		t.Fatal(err)
	}
	gotVerify := <-s.verify
	if !proto.Equal(gotVerify.GetGeneration(), want) || !bytes.Equal(gotVerify.GetGenerationParamsDigest(), digest) || !bytes.Equal(verify.GenerationParamsDigest, digest) {
		t.Fatalf("verify generation transport lost fields: request=%v response digest=%x", gotVerify, verify.GenerationParamsDigest)
	}
}

type generationEchoTransport struct {
	called       bool
	echo         []byte
	serviceError *ServiceError
}

func (t *generationEchoTransport) Invoke(_ context.Context, _ string, _ any, resp any) error {
	t.called = true
	switch r := resp.(type) {
	case *InferResponse:
		r.GenerationParamsDigest, r.Error = t.echo, t.serviceError
	case *VerifyResponse:
		r.GenerationParamsDigest, r.Error = t.echo, t.serviceError
	}
	return nil
}

func TestRemoteGenerationResponseBindingFailsClosed(t *testing.T) {
	g, digest := generationContractFixture(t)
	for _, method := range []string{"Infer", "Verify"} {
		for _, tc := range []struct {
			name         string
			echo         []byte
			serviceError *ServiceError
			wantError    bool
		}{
			{"matching", digest, nil, false},
			{"missing support", nil, nil, true},
			{"wrong digest", bytes.Repeat([]byte{1}, 32), nil, true},
			{"truncated digest", digest[:31], nil, true},
			{"explicit service rejection", nil, &ServiceError{Code: "UNSUPPORTED_GENERATION_PARAMS"}, false},
		} {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				transport := &generationEchoTransport{echo: tc.echo, serviceError: tc.serviceError}
				client := NewRemoteClient(transport)
				var err error
				if method == "Infer" {
					_, err = client.Infer(context.Background(), InferRequest{ModelID: "model-a", ProfileVersion: "1", Generation: g, GenerationParamsDigest: digest})
				} else {
					_, err = client.Verify(context.Background(), VerifyRequest{ModelID: "model-a", ProfileVersion: "1", Generation: g, GenerationParamsDigest: digest})
				}
				if (err != nil) != tc.wantError || !transport.called {
					t.Fatalf("error=%v called=%v", err, transport.called)
				}
				if tc.wantError && !strings.Contains(err.Error(), "generation_params_digest") {
					t.Fatalf("error does not identify digest: %v", err)
				}
			})
		}
	}
}

func TestRemoteRejectsInvalidGenerationBeforeInvocation(t *testing.T) {
	for _, method := range []string{"Infer", "Verify"} {
		for _, tc := range []string{"missing", "digest only", "missing digest", "wrong digest", "wrong model", "wrong profile", "noncanonical profile", "invalid parameters"} {
			t.Run(method+"/"+tc, func(t *testing.T) {
				g, digest := generationContractFixture(t)
				modelID, profile := "model-a", "1"
				switch tc {
				case "missing":
					g, digest = nil, nil
				case "digest only":
					g = nil
				case "missing digest":
					digest = nil
				case "wrong digest":
					digest = bytes.Repeat([]byte{1}, 32)
				case "wrong model":
					modelID = "other"
				case "wrong profile":
					profile = "2"
				case "noncanonical profile":
					profile = "01"
				case "invalid parameters":
					g.Params.DecodingParams.TopPPPM = 0
				}
				transport := &generationEchoTransport{echo: digest}
				client := NewRemoteClient(transport)
				var err error
				if method == "Infer" {
					_, err = client.Infer(context.Background(), InferRequest{ModelID: modelID, ProfileVersion: profile, Generation: g, GenerationParamsDigest: digest})
				} else {
					_, err = client.Verify(context.Background(), VerifyRequest{ModelID: modelID, ProfileVersion: profile, Generation: g, GenerationParamsDigest: digest})
				}
				if err == nil || transport.called {
					t.Fatalf("invalid request reached service: err=%v called=%v", err, transport.called)
				}
			})
		}
	}
}

func TestFakeGenerationContextValidationAndEcho(t *testing.T) {
	g, digest := generationContractFixture(t)
	fake := NewFakeService()
	inferReq := InferRequest{ModelID: "model-a", ProfileVersion: "1", Capability: CapabilityLLMTextV1, Generation: g, GenerationParamsDigest: digest}
	verifyReq := VerifyRequest{ModelID: "model-a", ProfileVersion: "1", Capability: CapabilityLLMTextV1, Generation: g, GenerationParamsDigest: digest,
		Evidence: map[string]VerifyEvidence{EvidenceKindWorkerValueOpening: {Trace: []byte("trace"), Checkpoint: []byte("checkpoint")}},
	}
	infer, err := fake.Infer(context.Background(), inferReq)
	if err != nil || !bytes.Equal(infer.GenerationParamsDigest, digest) {
		t.Fatalf("infer echo=%x error=%v", infer.GenerationParamsDigest, err)
	}
	verify, err := fake.Verify(context.Background(), verifyReq)
	if err != nil || !bytes.Equal(verify.GenerationParamsDigest, digest) {
		t.Fatalf("verify echo=%x error=%v", verify.GenerationParamsDigest, err)
	}
	inferReq.GenerationParamsDigest, verifyReq.GenerationParamsDigest = nil, nil
	if _, err := fake.Infer(context.Background(), inferReq); err == nil {
		t.Fatal("fake inference accepted incomplete generation context")
	}
	if _, err := fake.Verify(context.Background(), verifyReq); err == nil {
		t.Fatal("fake verification accepted incomplete generation context")
	}
	inferReq.Generation, verifyReq.Generation = nil, nil
	if _, err := fake.Infer(context.Background(), inferReq); err != nil {
		t.Fatalf("explicit fake legacy request failed: %v", err)
	}
	if _, err := fake.Verify(context.Background(), verifyReq); err != nil {
		t.Fatalf("explicit fake legacy request failed: %v", err)
	}
}

func TestFakeBoundGenerationProducesVerifiableEvidence(t *testing.T) {
	g, _ := generationContractFixture(t)
	g.Params.DecodingParams.StopSequences, g.Params.DecodingParams.StopTokenIDs = nil, nil
	digest, err := g.Digest()
	if err != nil {
		t.Fatal(err)
	}
	fake := NewFakeService()
	resp, err := fake.Infer(context.Background(), InferRequest{
		ModelID: g.ModelID, ProfileVersion: "1", Capability: CapabilityLLMTextV1,
		Input: []byte("fixture prompt"), Generation: g, GenerationParamsDigest: digest[:],
	})
	if err != nil {
		t.Fatal(err)
	}
	artifacts := make([][]byte, 0, 3)
	for _, ref := range []string{resp.OutputRef, resp.TraceRef, resp.CheckpointRef} {
		artifact, err := fake.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: ref})
		if err != nil {
			t.Fatal(err)
		}
		artifacts = append(artifacts, artifact.Data)
	}
	count, reason, err := ValidateGenerationEvidence(g, digest[:], artifacts[0], artifacts[1], artifacts[2])
	if err != nil || count != resp.GeneratedTokenCount || reason != resp.FinishReason {
		t.Fatalf("bound fake evidence does not match response: count=%d reason=%v err=%v", count, reason, err)
	}
}
