package modelservice

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/TrueOpen/cortex/internal/metric"
	cortexv1 "github.com/TrueOpen/cortex/proto/cortex/v1"
	"google.golang.org/protobuf/proto"
)

// roundTripServer answers Infer and Verify and keeps what it was asked.
type roundTripServer struct {
	cortexv1.UnimplementedModelManagementServiceServer
	infer  *cortexv1.InferRequest
	verify *cortexv1.VerifyRequest
	values []byte
}

func (s *roundTripServer) Infer(_ context.Context, req *cortexv1.InferRequest) (*cortexv1.InferResponse, error) {
	s.infer = req
	return &cortexv1.InferResponse{
		RequestId: req.GetRequestId(), ModelServiceId: req.GetModelServiceId(), JobId: req.GetJobId(), TaskId: req.GetTaskId(),
		ModelId: req.GetModelId(), ProfileVersion: req.GetProfileVersion(), RequestDigest: req.GetRequestDigest(),
		OutputRef: "svc:output", TokenIdsRef: "svc:token-ids", PositionValuesRef: "svc:position-values",
		GeneratedTokenCount: 2, GenerationParamsDigest: req.GetGenerationParamsDigest(), FinishReason: "eos_token", WorkUnit: 2,
	}, nil
}

func (s *roundTripServer) Verify(_ context.Context, req *cortexv1.VerifyRequest) (*cortexv1.VerifyResponse, error) {
	s.verify = req
	var values cortexv1.PositionValuesV1
	if err := proto.Unmarshal(s.values, &values); err != nil {
		return nil, err
	}
	return &cortexv1.VerifyResponse{
		RequestId: req.GetRequestId(), ModelServiceId: req.GetModelServiceId(), JobId: req.GetJobId(), TaskId: req.GetTaskId(),
		ModelId: req.GetModelId(), ProfileVersion: req.GetProfileVersion(), RequestDigest: req.GetRequestDigest(),
		SampleValueSequenceRef: "svc:sample", SampleValueDigest: bytes.Repeat([]byte{1}, 32), ResultCommitMaterialDigest: bytes.Repeat([]byte{2}, 32),
		GenerationParamsDigest: req.GetGenerationParamsDigest(), VerifierValues: &values,
	}, nil
}

// Infer and Verify cross the gRPC boundary intact: the generation context,
// its digest and the Worker's token ids reach the model service, and the
// response's count, finish reason and Verifier values come back decoded.
func TestGRPCInferAndVerifyRoundTrip(t *testing.T) {
	want := []metric.PositionValue{
		{TokenID: 10, Logprob: -0.25, Rank: 1, TopK: []metric.TokenLogprob{{TokenID: 10, Logprob: -0.25}, {TokenID: 12, Logprob: -1.5}}},
		{TokenID: 11, Missing: true, TopK: []metric.TokenLogprob{}},
	}
	encoded, err := EncodePositionValuesArtifact(want)
	if err != nil {
		t.Fatal(err)
	}
	server := &roundTripServer{values: encoded}
	client := NewRemoteClient(NewGRPCTransportForClient(newGRPCTestServer(t, server).client))

	inferReq := boundLocalInferFixture(t, InferRequest{RequestID: "rt-infer", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1, Input: []byte("hi")})
	inferResp, err := client.Infer(context.Background(), inferReq)
	if err != nil {
		t.Fatal(err)
	}
	if server.infer == nil || !bytes.Equal(server.infer.GetGenerationParamsDigest(), inferReq.GenerationParamsDigest) ||
		server.infer.GetGeneration().GetParams().GetMaxOutputTokens() != inferReq.Generation.Params.MaxOutputTokens {
		t.Fatalf("infer request lost its generation context: %+v", server.infer)
	}
	if inferResp.GeneratedTokenCount != 2 || inferResp.TokenIDsRef != "svc:token-ids" || inferResp.PositionValuesRef != "svc:position-values" {
		t.Fatalf("infer response = %+v", inferResp)
	}

	verifyReq := boundLocalVerifyFixture(t, VerifyRequest{RequestID: "rt-verify", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1,
		Sample: []byte("seed"), TokenIDs: TokenIDs{Input: []uint32{1, 2, 3}, Generated: []uint32{10, 11}}})
	verifyResp, err := client.Verify(context.Background(), verifyReq)
	if err != nil {
		t.Fatal(err)
	}
	var sent *cortexv1.TokenIDsV1
	for _, item := range server.verify.GetEvidence() {
		if item.GetEvidenceKind() == EvidenceKindWorkerTokenOpening {
			sent = item.GetTokenIds()
		}
	}
	if sent == nil || !reflect.DeepEqual(sent.GetGeneratedTokenIds(), []uint32{10, 11}) || !reflect.DeepEqual(sent.GetInputTokenIds(), []uint32{1, 2, 3}) ||
		!bytes.Equal(server.verify.GetGenerationParamsDigest(), verifyReq.GenerationParamsDigest) {
		t.Fatalf("verify request = %+v, want the Worker token ids and the generation digest", server.verify)
	}
	if !reflect.DeepEqual(verifyResp.VerifierValues, want) {
		t.Fatalf("verifier values = %+v, want %+v", verifyResp.VerifierValues, want)
	}
}
