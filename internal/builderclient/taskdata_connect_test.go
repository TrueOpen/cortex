package builderclient

import (
	"bytes"
	"connectrpc.com/connect"
	"context"
	"encoding/hex"
	"errors"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/nodewire"
	"github.com/SingaXYZ/cortex/internal/signer"
	nexusv1 "github.com/SingaXYZ/cortex/proto/nexus/v1"
	nexusv1connect "github.com/SingaXYZ/cortex/proto/nexus/v1/nexusv1connect"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"google.golang.org/protobuf/proto"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type taskDataTestHandler struct {
	nexusv1connect.UnimplementedIngressAPIHandler
	metadata         func(context.Context, *connect.Request[nexusv1.GetTaskDataMetadataRequest]) (*connect.Response[nexusv1.GetTaskDataMetadataResponse], error)
	fetch            func(context.Context, *connect.Request[nexusv1.FetchTaskDataRequest], *connect.ServerStream[nexusv1.FetchTaskDataResponse]) error
	upload           func(context.Context, *connect.ClientStream[nexusv1.UploadTaskResultObjectRequest]) (*connect.Response[nexusv1.UploadTaskResultObjectResponse], error)
	output           func(context.Context, *connect.BidiStream[nexusv1.UploadTaskOutputStreamRequest, nexusv1.UploadTaskOutputStreamResponse]) error
	finalize         func(context.Context, *connect.Request[nexusv1.FinalizeTaskResultRequest]) (*connect.Response[nexusv1.FinalizeTaskResultResponse], error)
	finalizeVerifier func(context.Context, *connect.Request[nexusv1.FinalizeVerifierEvidenceRequest]) (*connect.Response[nexusv1.FinalizeVerifierEvidenceResponse], error)
	infer            func(context.Context, *connect.Request[nexusv1.SubmitInferReceiptRequest]) (*connect.Response[nexusv1.SubmitInferReceiptResponse], error)
	commit           func(context.Context, *connect.Request[nexusv1.SubmitVerifyCommitRequest]) (*connect.Response[nexusv1.SubmitVerifyCommitResponse], error)
	result           func(context.Context, *connect.Request[nexusv1.SubmitVerifyResultRequest]) (*connect.Response[nexusv1.SubmitVerifyResultResponse], error)
}

func (h *taskDataTestHandler) GetTaskDataMetadata(ctx context.Context, r *connect.Request[nexusv1.GetTaskDataMetadataRequest]) (*connect.Response[nexusv1.GetTaskDataMetadataResponse], error) {
	return h.metadata(ctx, r)
}
func (h *taskDataTestHandler) FetchTaskData(ctx context.Context, r *connect.Request[nexusv1.FetchTaskDataRequest], s *connect.ServerStream[nexusv1.FetchTaskDataResponse]) error {
	return h.fetch(ctx, r, s)
}
func (h *taskDataTestHandler) UploadTaskResultObject(ctx context.Context, s *connect.ClientStream[nexusv1.UploadTaskResultObjectRequest]) (*connect.Response[nexusv1.UploadTaskResultObjectResponse], error) {
	return h.upload(ctx, s)
}
func (h *taskDataTestHandler) UploadTaskOutputStream(ctx context.Context, s *connect.BidiStream[nexusv1.UploadTaskOutputStreamRequest, nexusv1.UploadTaskOutputStreamResponse]) error {
	return h.output(ctx, s)
}
func (h *taskDataTestHandler) FinalizeTaskResult(ctx context.Context, r *connect.Request[nexusv1.FinalizeTaskResultRequest]) (*connect.Response[nexusv1.FinalizeTaskResultResponse], error) {
	return h.finalize(ctx, r)
}
func (h *taskDataTestHandler) FinalizeVerifierEvidence(ctx context.Context, r *connect.Request[nexusv1.FinalizeVerifierEvidenceRequest]) (*connect.Response[nexusv1.FinalizeVerifierEvidenceResponse], error) {
	return h.finalizeVerifier(ctx, r)
}
func (h *taskDataTestHandler) SubmitInferReceipt(ctx context.Context, r *connect.Request[nexusv1.SubmitInferReceiptRequest]) (*connect.Response[nexusv1.SubmitInferReceiptResponse], error) {
	return h.infer(ctx, r)
}
func (h *taskDataTestHandler) SubmitVerifyCommit(ctx context.Context, r *connect.Request[nexusv1.SubmitVerifyCommitRequest]) (*connect.Response[nexusv1.SubmitVerifyCommitResponse], error) {
	return h.commit(ctx, r)
}
func (h *taskDataTestHandler) SubmitVerifyResult(ctx context.Context, r *connect.Request[nexusv1.SubmitVerifyResultRequest]) (*connect.Response[nexusv1.SubmitVerifyResultResponse], error) {
	return h.result(ctx, r)
}

func newTaskDataTestServer(t *testing.T, handler nexusv1connect.IngressAPIHandler) *httptest.Server {
	t.Helper()
	path, httpHandler := nexusv1connect.NewIngressAPIHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, httpHandler)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func newTestTaskDataClient(httpClient connect.HTTPClient, token string) *ConnectTaskDataClient {
	return NewConnectTaskDataClient(httpClient, token, TaskDataTransport{AllowInsecureEndpoint: true})
}

func TestNewConnectTaskDataClientWithDefaultsUsesHardenedHTTPClient(t *testing.T) {
	client := NewConnectTaskDataClientWithDefaults(" token ", TaskDataTransport{})
	httpClient, ok := client.httpClient.(*http.Client)
	if !ok {
		t.Fatalf("HTTP client type = %T, want *http.Client", client.httpClient)
	}
	if httpClient == http.DefaultClient {
		t.Fatal("HTTP client = http.DefaultClient, want dedicated production client")
	}
	if httpClient.Timeout != 60*time.Second {
		t.Fatalf("HTTP client timeout = %s, want 60s", httpClient.Timeout)
	}
	if httpClient.CheckRedirect == nil {
		t.Fatal("HTTP client redirect policy = nil")
	}
	if client.token != "token" {
		t.Fatalf("token = %q, want trimmed token", client.token)
	}
	if client.transport.AllowInsecureEndpoint {
		t.Fatal("AllowInsecureEndpoint = true; the production default must refuse plaintext")
	}
}

func TestConnectTaskDataClientEndpointPolicy(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		endpoint      string
		allowInsecure bool
		wantRefusal   bool
	}{
		{name: "plaintext refused by default", endpoint: "http://nexus.invalid", wantRefusal: true},
		{name: "plaintext accepted under the opt-in", endpoint: "http://nexus.invalid", allowInsecure: true},
		{name: "https always accepted", endpoint: "https://nexus.invalid"},
		{name: "https accepted under the opt-in", endpoint: "https://nexus.invalid", allowInsecure: true},
		// grpcs is the TLS spelling and grpc the plaintext one, so they take the
		// same two outcomes as https and http. Refusing them outright, which
		// this client used to do through a scheme check, rejected the secure
		// gRPC endpoint outright and gave the plaintext one a refusal the
		// operator switch could not relax.
		{name: "grpcs always accepted", endpoint: "grpcs://nexus.invalid"},
		{name: "grpcs accepted under the opt-in", endpoint: "grpcs://nexus.invalid", allowInsecure: true},
		{name: "grpc refused by default", endpoint: "grpc://nexus.invalid", wantRefusal: true},
		{name: "grpc accepted under the opt-in", endpoint: "grpc://nexus.invalid", allowInsecure: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			client := NewConnectTaskDataClient(&countingTaskDataHTTPClient{},
				"", TaskDataTransport{AllowInsecureEndpoint: testCase.allowInsecure})
			ingress, err := client.ingress(testCase.endpoint)
			switch {
			case testCase.wantRefusal && (err == nil || ingress != nil):
				t.Fatalf("ingress(%q) = (%v, %v), want a plaintext refusal", testCase.endpoint, ingress, err)
			case testCase.wantRefusal && !strings.Contains(err.Error(), "nexus.allow_insecure_descriptor"):
				t.Fatalf("refusal = %q, want it to name the operator switch", err)
			case !testCase.wantRefusal && (err != nil || ingress == nil):
				t.Fatalf("ingress(%q) = (%v, %v), want an accepted endpoint", testCase.endpoint, ingress, err)
			}
		})
	}
}

func TestNewConnectTaskDataClientPreservesInjectedHTTPClient(t *testing.T) {
	injected := &countingTaskDataHTTPClient{}
	client := NewConnectTaskDataClient(injected, "", TaskDataTransport{AllowInsecureEndpoint: true})
	if client.httpClient != injected {
		t.Fatalf("HTTP client = %T %p, want injected %p", client.httpClient, client.httpClient, injected)
	}
	if !client.transport.AllowInsecureEndpoint {
		t.Fatal("AllowInsecureEndpoint = false, want the stated policy preserved")
	}
}

type taskDataTestKeyPair struct {
	private *secp256k1.PrivateKey
	public  []byte
}

func newTaskDataTestKeyPair(t *testing.T) taskDataTestKeyPair {
	t.Helper()
	private, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	return taskDataTestKeyPair{private: private, public: private.PubKey().SerializeCompressed()}
}

func (k taskDataTestKeyPair) sign(t *testing.T, digest codec.Hash) []byte {
	t.Helper()
	signature := ecdsa.Sign(k.private, digest[:])
	r, s := signature.R(), signature.S()
	if s.IsOverHalfOrder() {
		s.Negate()
	}

	rBytes, sBytes := r.Bytes(), s.Bytes()
	out := make([]byte, 64)
	copy(out[:32], rBytes[:])
	copy(out[32:], sBytes[:])
	return out
}
func (k taskDataTestKeyPair) address(t *testing.T) string {
	t.Helper()
	address, err := signer.AddressFromCompressedPublicKey("trueopen", k.public)
	if err != nil {
		t.Fatalf("AddressFromCompressedPublicKey: %v", err)
	}
	return address
}

const taskDataTestTaskID = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

func taskDataTestObjectKey() TaskDataKey {
	return TaskDataKey{TaskHash: strings.Repeat("22", 32), SessionID: strings.Repeat("11", 32), TaskID: taskDataTestTaskID, Kind: DataKindOutput, ContentHash: strings.Repeat("44", 32)}
}
func taskDataTestReceipt(t *testing.T, keyPair taskDataTestKeyPair, chainID string, data []byte) SignedInferReceipt {
	t.Helper()
	outputHash, err := codec.OutputMMRRoot([][]byte{data})
	if err != nil {
		t.Fatal(err)
	}
	receipt := SignedInferReceipt{
		SchemaVersion:             nodewire.InferReceiptSchemaVersionV2,
		ChainID:                   chainID,
		TaskID:                    taskDataTestTaskID,
		TaskHash:                  strings.Repeat("22", 32),
		WorkerOperatorAddress:     keyPair.address(t),
		ServiceAuthorizationNonce: 9,
		GenerationParamsDigest:    strings.Repeat("33", 32),
		OutputHash:                hex.EncodeToString(outputHash[:]),
		OutputSizeBytes:           uint64(len(data)),
		OutputLeafCount:           1,
		RequiredEvidenceCommitments: []EvidenceCommitment{
			{
				EvidenceKind:       nodewire.EvidenceKindWorkerValueOpening,
				EvidenceHashOrRoot: codec.HashBytes([]byte("trace")),
				EncodedSizeBytes:   7,
			},
		},
		ExpiryHeight: 400, GeneratedTokenCount: 3,
	}
	digest, err := InferReceiptSigningDigest(receipt)
	if err != nil {
		t.Fatalf("InferReceiptSigningDigest: %v", err)
	}
	receipt.ServiceSignature = hex.EncodeToString(keyPair.sign(t, digest))
	return receipt
}
func taskDataTestRequestAuth(t *testing.T, keyPair taskDataTestKeyPair, method string, key TaskDataKey, body codec.Hash) TaskDataRequestAuth {
	t.Helper()
	auth := TaskDataRequestAuth{SchemaVersion: 1, ChainID: "chain-A", BuilderAddress: keyPair.address(t), Method: TaskDataProcedure(method), BodyDigest: body, RequesterKind: TaskDataRequesterCortexService, Requester: keyPair.address(t), ServiceAuthorizationNonce: 9, RequestNonce: bytes.Repeat([]byte{1}, 32), ExpiresAtHeight: 400}
	digest, err := TaskDataRequestSigningHash(auth)
	if err != nil {
		t.Fatal(err)
	}
	auth.Signature = keyPair.sign(t, digest)
	return auth
}
func taskDataTestUploadRequest(t *testing.T, keyPair taskDataTestKeyPair, data []byte) UploadTaskResultRequest {
	t.Helper()
	key := EvidenceObjectKey(strings.Repeat("22", 32), strings.Repeat("11", 32), taskDataTestTaskID, DataKindEvidenceArtifact, "", EvidenceProducerWorker, 1, keyPair.address(t))
	hash := codec.HashBytes(data)
	key.ContentHash = hex.EncodeToString(hash[:])
	digest, err := TaskDataUploadBodyDigest(key, uint64(len(data)), "")
	if err != nil {
		t.Fatal(err)
	}
	return UploadTaskResultRequest{Key: key, SizeBytes: uint64(len(data)), Auth: taskDataTestRequestAuth(t, keyPair, "UploadTaskResultObject", key, digest), Data: data}
}
func taskDataTestMetadata(key TaskDataKey, size uint64, readiness TaskDataReadiness) *nexusv1.TaskDataObjectMetadataV1 {
	media := "text/plain"
	if key.Kind == DataKindEvidenceArtifact {
		media = ""
	}
	metadata := &nexusv1.TaskDataObjectMetadataV1{ObjectRef: taskDataKeyToProto(key), SizeBytes: size, MediaType: media, Readiness: nexusv1.TaskDataObjectReadinessV1(readiness)}
	if key.Kind == DataKindOutput && readiness == TaskDataReady {
		metadata.ChunkLengths = []uint32{uint32(size)}
		metadata.OutputLeafCount = 1
	}
	return metadata
}
func taskDataTestUploadResponse(req UploadTaskResultRequest) *connect.Response[nexusv1.UploadTaskResultObjectResponse] {
	return connect.NewResponse(&nexusv1.UploadTaskResultObjectResponse{Accepted: true, Metadata: taskDataTestMetadata(req.Key, req.SizeBytes, TaskDataStored)})
}
func taskDataTestHeader(key TaskDataKey, total, offset, length uint64) *nexusv1.FetchTaskDataResponse {
	return &nexusv1.FetchTaskDataResponse{Frame: &nexusv1.FetchTaskDataResponse_Header{Header: &nexusv1.FetchTaskDataHeaderV1{ObjectRef: taskDataKeyToProto(key), TotalSizeBytes: total, ServedRange: &nexusv1.ByteRangeV1{Offset: offset, Length: length}}}}
}
func taskDataTestChunk(offset uint64, data string, eof bool) *nexusv1.FetchTaskDataResponse {
	return &nexusv1.FetchTaskDataResponse{Frame: &nexusv1.FetchTaskDataResponse_Chunk{Chunk: &nexusv1.FetchTaskDataChunkV1{Offset: offset, Data: []byte(data), Eof: eof}}}
}

type countingTaskDataHTTPClient struct{ calls int }

func (c *countingTaskDataHTTPClient) Do(*http.Request) (*http.Response, error) {
	c.calls++
	return nil, errors.New("network must not be called")
}

func TestV040MetadataRoundTripsObjectAndAcceptedReceipt(t *testing.T) {
	keyPair := newTaskDataTestKeyPair(t)
	key := taskDataTestObjectKey()
	receipt := taskDataTestReceipt(t, keyPair, "chain-A", []byte("answer"))
	key.ContentHash = receipt.OutputHash
	digest, err := TaskDataMetadataBodyDigest(key)
	if err != nil {
		t.Fatal(err)
	}
	server := newTaskDataTestServer(t, &taskDataTestHandler{metadata: func(_ context.Context, r *connect.Request[nexusv1.GetTaskDataMetadataRequest]) (*connect.Response[nexusv1.GetTaskDataMetadataResponse], error) {
		if r.Spec().Procedure != TaskDataProcedure("GetTaskDataMetadata") || r.Header().Get("Authorization") != "Bearer token" || !proto.Equal(r.Msg.ObjectRef, taskDataKeyToProto(key)) {
			t.Error("wrong procedure, bearer token or object ref")
		}
		return connect.NewResponse(&nexusv1.GetTaskDataMetadataResponse{Metadata: taskDataTestMetadata(key, 6, TaskDataReady), InferReceipt: signedInferReceiptToProto(receipt), RetainUntilHeight: 900}), nil
	}})
	metadata, err := newTestTaskDataClient(server.Client(), "token").GetTaskDataMetadata(context.Background(), server.URL, GetTaskDataMetadataRequest{Key: key, Auth: taskDataTestRequestAuth(t, keyPair, "GetTaskDataMetadata", key, digest)})
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Key != key || metadata.RetainUntilHeight != 900 || metadata.SignedInferReceipt.GeneratedTokenCount != 3 || metadata.Readiness != TaskDataReady {
		t.Fatalf("metadata lost fields: %+v", metadata)
	}
}

func TestV040UploadStoresWithoutFinalizing(t *testing.T) {
	keyPair := newTaskDataTestKeyPair(t)
	data := bytes.Repeat([]byte("a"), taskDataChunkSize+3)
	request := taskDataTestUploadRequest(t, keyPair, data)
	server := newTaskDataTestServer(t, &taskDataTestHandler{upload: func(_ context.Context, stream *connect.ClientStream[nexusv1.UploadTaskResultObjectRequest]) (*connect.Response[nexusv1.UploadTaskResultObjectResponse], error) {
		if !stream.Receive() {
			return nil, stream.Err()
		}
		header := stream.Msg().GetHeader()
		if header == nil || !proto.Equal(header.ObjectRef, taskDataKeyToProto(request.Key)) || header.RequestAuth.RpcMethod != TaskDataProcedure("UploadTaskResultObject") {
			t.Error("upload header lost signed fields")
		}
		var got []byte
		for stream.Receive() {
			chunk := stream.Msg().GetChunk()
			if len(chunk) > taskDataChunkSize {
				t.Error("chunk exceeds bound")
			}
			got = append(got, chunk...)
		}
		if !bytes.Equal(got, data) {
			t.Error("upload data changed")
		}
		return taskDataTestUploadResponse(request), stream.Err()
	}})
	metadata, err := newTestTaskDataClient(server.Client(), "").UploadTaskResultObject(context.Background(), server.URL, request)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Readiness != TaskDataStored {
		t.Fatal("upload claimed READY")
	}
	request.Data = []byte("tamper")
	denied := &countingTaskDataHTTPClient{}
	if _, err := newTestTaskDataClient(denied, "").UploadTaskResultObject(context.Background(), "http://invalid", request); err == nil || denied.calls != 0 {
		t.Fatal("tampered upload reached network")
	}
}

func TestV040FetchValidatesHeaderRangeAndFinalEOF(t *testing.T) {
	keyPair := newTaskDataTestKeyPair(t)
	key := taskDataTestObjectKey()
	bounds := &TaskDataRange{Offset: 2, Length: 4}
	digest, err := TaskDataFetchBodyDigest(key, bounds)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		frames []*nexusv1.FetchTaskDataResponse
		valid  bool
	}{
		{"valid", []*nexusv1.FetchTaskDataResponse{taskDataTestHeader(key, 8, 2, 4), taskDataTestChunk(2, "ab", false), taskDataTestChunk(4, "cd", true)}, true},
		{"missing header", []*nexusv1.FetchTaskDataResponse{taskDataTestChunk(2, "abcd", true)}, false},
		{"duplicate header", []*nexusv1.FetchTaskDataResponse{taskDataTestHeader(key, 8, 2, 4), taskDataTestHeader(key, 8, 2, 4)}, false},
		{"wrong range", []*nexusv1.FetchTaskDataResponse{taskDataTestHeader(key, 8, 0, 4), taskDataTestChunk(0, "abcd", true)}, false},
		{"range beyond total", []*nexusv1.FetchTaskDataResponse{taskDataTestHeader(key, 5, 2, 4)}, false},
		{"gap", []*nexusv1.FetchTaskDataResponse{taskDataTestHeader(key, 8, 2, 4), taskDataTestChunk(3, "abcd", true)}, false},
		{"early EOF", []*nexusv1.FetchTaskDataResponse{taskDataTestHeader(key, 8, 2, 4), taskDataTestChunk(2, "ab", true)}, false},
		{"missing EOF", []*nexusv1.FetchTaskDataResponse{taskDataTestHeader(key, 8, 2, 4), taskDataTestChunk(2, "abcd", false)}, false},
		{"after EOF", []*nexusv1.FetchTaskDataResponse{taskDataTestHeader(key, 8, 2, 4), taskDataTestChunk(2, "abcd", true), taskDataTestChunk(6, "", true)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := newTaskDataTestServer(t, &taskDataTestHandler{fetch: func(_ context.Context, r *connect.Request[nexusv1.FetchTaskDataRequest], stream *connect.ServerStream[nexusv1.FetchTaskDataResponse]) error {
				if r.Msg.Range == nil || r.Msg.Range.Offset != 2 || r.Msg.RequestAuth.BodyDigest != hex.EncodeToString(digest[:]) {
					t.Error("fetch signed range lost")
				}
				for _, frame := range tc.frames {
					if err := stream.Send(frame); err != nil {
						return err
					}
				}
				return nil
			}})
			tracking := &taskDataBodyTrackingTransport{next: server.Client()}
			var got []byte
			err := newTestTaskDataClient(tracking, "").FetchTaskData(context.Background(), server.URL, FetchTaskDataRequest{Key: key, Range: bounds, Auth: taskDataTestRequestAuth(t, keyPair, "FetchTaskData", key, digest)}, func(chunk TaskDataChunk) error { got = append(got, chunk.Data...); return nil })
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if tc.valid && string(got) != "abcd" {
				t.Fatalf("got %q", got)
			}
			opened, closed := tracking.bodyCounts()
			if opened != closed {
				t.Fatalf("response bodies opened=%d closed=%d", opened, closed)
			}
		})
	}
}

func TestV040FullFetchSignsAbsentRangeAndHandlesEmptyObject(t *testing.T) {
	keyPair := newTaskDataTestKeyPair(t)
	key := taskDataTestObjectKey()
	digest, err := TaskDataFetchBodyDigest(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := newTaskDataTestServer(t, &taskDataTestHandler{fetch: func(_ context.Context, r *connect.Request[nexusv1.FetchTaskDataRequest], s *connect.ServerStream[nexusv1.FetchTaskDataResponse]) error {
		if r.Msg.Range != nil {
			t.Error("full range became present")
		}
		if err := s.Send(taskDataTestHeader(key, 0, 0, 0)); err != nil {
			return err
		}
		return s.Send(taskDataTestChunk(0, "", true))
	}})
	if err := newTestTaskDataClient(server.Client(), "").FetchTaskData(context.Background(), server.URL, FetchTaskDataRequest{Key: key, Auth: taskDataTestRequestAuth(t, keyPair, "FetchTaskData", key, digest)}, func(TaskDataChunk) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestV040RelayCarriesImportedTaskMessageAndChecksDigest(t *testing.T) {
	keyPair := newTaskDataTestKeyPair(t)
	receipt := taskDataTestReceipt(t, keyPair, "chain-A", []byte("data"))
	digest, err := InferReceiptSigningDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted", true: "wrong digest"}[bad], func(t *testing.T) {
			server := newTaskDataTestServer(t, &taskDataTestHandler{infer: func(_ context.Context, r *connect.Request[nexusv1.SubmitInferReceiptRequest]) (*connect.Response[nexusv1.SubmitInferReceiptResponse], error) {
				if !proto.Equal(r.Msg.Receipt, signedInferReceiptToProto(receipt)) {
					t.Error("relay receipt changed")
				}
				echoed := digest
				if bad {
					echoed[0] ^= 1
				}
				return connect.NewResponse(&nexusv1.SubmitInferReceiptResponse{RelayAccepted: true, InferReceiptHash: hex.EncodeToString(echoed[:]), Idempotent: true}), nil
			}})
			err := newTestTaskDataClient(server.Client(), "").SubmitInferReceipt(context.Background(), server.URL, SubmitInferReceiptRequest{Receipt: receipt})
			if (err != nil) != bad {
				t.Fatalf("bad=%v err=%v", bad, err)
			}
		})
	}
}

type taskDataBodyTrackingTransport struct {
	next connect.HTTPClient
	// endRequestBody, once closed, breaks the outbound request pipe at the next
	// read and then reports a clean end of body. That reproduces a Nexus that
	// answers before the client finished uploading: further Send calls fail with
	// io.EOF while the server's Connect error is still delivered.
	endRequestBody <-chan struct{}

	mu     sync.Mutex
	opened int
	closed int
}

func (t *taskDataBodyTrackingTransport) Do(request *http.Request) (*http.Response, error) {
	if request.Body != nil && t.endRequestBody != nil {
		request.Body = &taskDataGatedRequestBody{ReadCloser: request.Body, end: t.endRequestBody}
	}
	response, err := t.next.Do(request)
	if err != nil || response == nil || response.Body == nil {
		return response, err
	}
	t.mu.Lock()
	t.opened++
	t.mu.Unlock()
	response.Body = &taskDataTrackedResponseBody{ReadCloser: response.Body, transport: t}
	return response, nil
}

func (t *taskDataBodyTrackingTransport) bodyCounts() (int, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.opened, t.closed
}

type taskDataTrackedResponseBody struct {
	io.ReadCloser
	transport *taskDataBodyTrackingTransport
	once      sync.Once
}

func (b *taskDataTrackedResponseBody) Close() error {
	b.once.Do(func() {
		b.transport.mu.Lock()
		b.transport.closed++
		b.transport.mu.Unlock()
	})
	return b.ReadCloser.Close()
}

type taskDataGatedRequestBody struct {
	io.ReadCloser
	end  <-chan struct{}
	once sync.Once
}

func (b *taskDataGatedRequestBody) Read(p []byte) (int, error) {
	select {
	case <-b.end:
		b.closeOnce()
		return 0, io.EOF
	default:
	}
	return b.ReadCloser.Read(p)
}

func (b *taskDataGatedRequestBody) Close() error {
	b.closeOnce()
	return nil
}

func (b *taskDataGatedRequestBody) closeOnce() {
	b.once.Do(func() { _ = b.ReadCloser.Close() })
}

func TestConnectTaskDataClientClassifiesMidStreamUploadFailureAsRetryable(t *testing.T) {
	keyPair := newTaskDataTestKeyPair(t)
	data := bytes.Repeat([]byte{0x5c}, 3*taskDataChunkSize)
	uploadRequest := taskDataTestUploadRequest(t, keyPair, data)

	headerSeen := make(chan struct{})
	handler := &taskDataTestHandler{upload: func(_ context.Context, stream *connect.ClientStream[nexusv1.UploadTaskResultObjectRequest]) (*connect.Response[nexusv1.UploadTaskResultObjectResponse], error) {
		if !stream.Receive() {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("upload header required"))
		}
		if stream.Msg().GetHeader() == nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("first upload frame must be header"))
		}
		close(headerSeen)
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("storage backend is draining"))
	}}
	server := newTaskDataTestServer(t, handler)
	transport := &taskDataBodyTrackingTransport{next: server.Client(), endRequestBody: headerSeen}

	_, err := newTestTaskDataClient(transport, "").UploadTaskResultObject(context.Background(), server.URL, uploadRequest)
	if err == nil {
		t.Fatal("error = nil, want the mid-stream upload failure")
	}
	if !IsRetryable(err) {
		t.Errorf("IsRetryable(error) = false, want true: %v", err)
	}
	if !strings.Contains(err.Error(), "storage backend is draining") {
		t.Errorf("error = %v, want the server-side Connect error", err)
	}
	opened, closed := transport.bodyCounts()
	if opened == 0 || closed != opened {
		t.Fatalf("upload response bodies opened = %d, closed = %d, want every body closed", opened, closed)
	}
}

func TestConnectTaskDataClientClosesUploadResponseBodyOnSuccess(t *testing.T) {
	keyPair := newTaskDataTestKeyPair(t)
	uploadRequest := taskDataTestUploadRequest(t, keyPair, []byte("closed upload body"))
	handler := &taskDataTestHandler{upload: func(_ context.Context, stream *connect.ClientStream[nexusv1.UploadTaskResultObjectRequest]) (*connect.Response[nexusv1.UploadTaskResultObjectResponse], error) {
		for stream.Receive() {
		}
		if err := stream.Err(); err != nil {
			return nil, err
		}
		return taskDataTestUploadResponse(uploadRequest), nil
	}}
	server := newTaskDataTestServer(t, handler)
	transport := &taskDataBodyTrackingTransport{next: server.Client()}

	if _, err := newTestTaskDataClient(transport, "").UploadTaskResultObject(context.Background(), server.URL, uploadRequest); err != nil {
		t.Fatalf("UploadTaskResultObject: %v", err)
	}
	opened, closed := transport.bodyCounts()
	if opened == 0 || closed != opened {
		t.Fatalf("upload response bodies opened = %d, closed = %d, want every body closed", opened, closed)
	}
}
