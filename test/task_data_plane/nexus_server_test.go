package task_data_plane_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/nodewire"
	"github.com/SingaXYZ/cortex/internal/signer"
	nexusv1 "github.com/SingaXYZ/cortex/proto/nexus/v1"
	nexusv1connect "github.com/SingaXYZ/cortex/proto/nexus/v1/nexusv1connect"
	sharedv1 "github.com/SingaXYZ/cortex/proto/shared/v1"
	taskv1 "github.com/SingaXYZ/cortex/proto/task/v1"
)

type nexusBehavior struct {
	interruptFetchOnce        bool
	failRelayAttempts         int
	failUploadAttempts        int
	receiptResponseMismatch   bool
	confirmationSignatureBad  bool
	blockUpload               bool
	declaredInputSemanticHash string
}

type authAttempt struct {
	method string
	nonce  []byte
	expiry uint64
}

type nexusProofServer struct {
	objects *builderclient.FakeClient
	nexusv1connect.UnimplementedIngressAPIHandler

	server          *httptest.Server
	chainID         string
	builderOperator string
	workerOperator  string
	servicePubkey   []byte
	builderPrivate  *secp256k1.PrivateKey
	input           []byte
	behavior        nexusBehavior
	currentHeight   atomic.Uint64

	mu                         sync.Mutex
	seenNonces                 map[string]string
	authExpiries               []uint64
	authAttempts               []authAttempt
	fetchOffsets               []uint64
	fetchNonces                [][]byte
	fetchChunkSizes            []int
	fetchInterrupted           bool
	relayCalls                 int
	relayAccepted              bool
	relayReceipts              []builderclient.SignedInferReceipt
	relayDigests               []codec.Hash
	uploadCalls                int
	completedUploads           int
	uploadDigests              []codec.Hash
	storedOutput               []byte
	outputFrames               []builderclient.OutputChunk
	storedEvidence             map[string][]byte
	evidenceUploads            int
	relayObservedBeforeRelease bool
	receipt                    builderclient.SignedInferReceipt
	receiptDigest              codec.Hash

	uploadStarted chan struct{}
	uploadRelease chan struct{}
	startedOnce   sync.Once
	releaseOnce   sync.Once
}

func newNexusProofServer(
	t *testing.T,
	chainID string,
	builderOperator string,
	workerOperator string,
	serviceAddress string,
	servicePubkey []byte,
	builderPrivate *secp256k1.PrivateKey,
	input []byte,
	currentHeight uint64,
	behavior nexusBehavior,
) *nexusProofServer {
	t.Helper()
	// Nexus's servicekey.Current requires the registered CORTEX service address to
	// be the address derived from the registered service pubkey; the fake registry
	// holds itself to the same invariant.
	derivedService, err := signer.AddressFromCompressedPublicKey("trueopen", servicePubkey)
	if err != nil || derivedService != serviceAddress {
		t.Fatalf("registered service key %x does not derive service address %q: %v", servicePubkey, serviceAddress, err)
	}
	nexus := &nexusProofServer{
		objects:         builderclient.NewFakeClient(),
		chainID:         chainID,
		builderOperator: builderOperator,
		workerOperator:  workerOperator,
		servicePubkey:   append([]byte(nil), servicePubkey...),
		builderPrivate:  builderPrivate,
		input:           append([]byte(nil), input...),
		behavior:        behavior,
		seenNonces:      make(map[string]string),
		uploadStarted:   make(chan struct{}),
		uploadRelease:   make(chan struct{}),
	}
	nexus.currentHeight.Store(currentHeight)
	path, handler := nexusv1connect.NewIngressAPIHandler(nexus)
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	nexus.server = httptest.NewUnstartedServer(mux)
	nexus.server.Config.Protocols = new(http.Protocols)
	nexus.server.Config.Protocols.SetHTTP1(true)
	nexus.server.Config.Protocols.SetUnencryptedHTTP2(true)
	nexus.server.Start()
	t.Cleanup(nexus.server.Close)
	return nexus
}

func (n *nexusProofServer) URL() string { return n.server.URL }

func (n *nexusProofServer) SetCurrentHeight(height uint64) { n.currentHeight.Store(height) }

func (n *nexusProofServer) ReleaseUpload() {
	n.releaseOnce.Do(func() { close(n.uploadRelease) })
}

func (n *nexusProofServer) WaitForUpload(t *testing.T) {
	t.Helper()
	select {
	case <-n.uploadStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Nexus upload")
	}
}

func (n *nexusProofServer) RelayCalls() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.relayCalls
}

func (n *nexusProofServer) CompletedUploads() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.completedUploads
}

func (n *nexusProofServer) UploadCalls() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.uploadCalls
}

func (n *nexusProofServer) RelayObservedBeforeUploadRelease() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.relayObservedBeforeRelease
}

func (n *nexusProofServer) Receipt() builderclient.SignedInferReceipt {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.receipt
}

// ReceiptDigest is the infer_receipt_hash this server derived from the receipt it
// accepted, not a value any caller supplied.
func (n *nexusProofServer) ReceiptDigest() codec.Hash {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.receiptDigest
}

func (n *nexusProofServer) RelayReceipts() []builderclient.SignedInferReceipt {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]builderclient.SignedInferReceipt(nil), n.relayReceipts...)
}

func (n *nexusProofServer) RelayDigests() []codec.Hash {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]codec.Hash(nil), n.relayDigests...)
}

func (n *nexusProofServer) UploadDigests() []codec.Hash {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]codec.Hash(nil), n.uploadDigests...)
}
func (n *nexusProofServer) AuthAttempts() []authAttempt {
	n.mu.Lock()
	defer n.mu.Unlock()
	attempts := make([]authAttempt, len(n.authAttempts))
	for i, attempt := range n.authAttempts {
		attempts[i] = authAttempt{
			method: attempt.method, nonce: append([]byte(nil), attempt.nonce...), expiry: attempt.expiry,
		}
	}
	return attempts
}

func (n *nexusProofServer) StoredOutputHash() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.outputFrames) == 0 {
		return ""
	}
	digest := n.outputFrames[len(n.outputFrames)-1].MMRRoot
	return hex.EncodeToString(digest[:])
}

func (n *nexusProofServer) FetchObservations() ([]uint64, [][]byte, []int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	nonces := make([][]byte, len(n.fetchNonces))
	for i := range n.fetchNonces {
		nonces[i] = append([]byte(nil), n.fetchNonces[i]...)
	}
	return append([]uint64(nil), n.fetchOffsets...), nonces, append([]int(nil), n.fetchChunkSizes...)
}

func (n *nexusProofServer) AuthExpiries() []uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]uint64(nil), n.authExpiries...)
}

func (n *nexusProofServer) GetTaskDataMetadata(_ context.Context, req *connect.Request[nexusv1.GetTaskDataMetadataRequest]) (*connect.Response[nexusv1.GetTaskDataMetadataResponse], error) {
	key, err := proofKeyFromProto(req.Msg.GetObjectRef())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	body, err := builderclient.TaskDataMetadataBodyDigest(key)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := n.verifyRequestAuth("GetTaskDataMetadata", key, body, req.Msg.GetRequestAuth()); err != nil {
		return nil, err
	}
	if key.Kind == builderclient.DataKindInput {
		if key.TaskID != proofTaskID {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("unknown task"))
		}
		ref := proofKeyToProto(key)
		if n.behavior.declaredInputSemanticHash != "" {
			ref.ContentHash = n.behavior.declaredInputSemanticHash
		}
		return connect.NewResponse(&nexusv1.GetTaskDataMetadataResponse{Metadata: &nexusv1.TaskDataObjectMetadataV1{ObjectRef: ref, SizeBytes: uint64(len(n.input)), MediaType: "application/octet-stream", Readiness: nexusv1.TaskDataObjectReadinessV1_TASK_DATA_OBJECT_READINESS_V1_READY}}), nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	metadata, err := n.objects.GetTaskDataMetadata(context.Background(), "", builderclient.GetTaskDataMetadataRequest{Key: key, Auth: proofAuthFromProto(req.Msg.RequestAuth)})
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	response := &nexusv1.GetTaskDataMetadataResponse{Metadata: proofMetadata(metadata)}
	if metadata.SignedInferReceipt != nil {
		response.InferReceipt = receiptToProto(*metadata.SignedInferReceipt)
	}
	if b := metadata.EvidenceBundle; b != nil {
		response.EvidenceBundle = &nexusv1.EvidenceBundleSummaryV1{EvidenceBundleHash: b.EvidenceBundleHash, EvidenceSchemaHash: b.EvidenceSchemaHash, ArtifactCount: b.ArtifactCount, ArtifactTotalSizeBytes: b.ArtifactTotalSizeBytes, ManifestSizeBytes: b.ManifestSizeBytes}
	}
	return connect.NewResponse(response), nil
}

func (n *nexusProofServer) FetchTaskData(_ context.Context, req *connect.Request[nexusv1.FetchTaskDataRequest], stream *connect.ServerStream[nexusv1.FetchTaskDataResponse]) error {
	key, err := proofKeyFromProto(req.Msg.GetObjectRef())
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	var bounds *builderclient.TaskDataRange
	if req.Msg.Range != nil {
		bounds = &builderclient.TaskDataRange{Offset: req.Msg.Range.Offset, Length: req.Msg.Range.Length}
	}
	body, err := builderclient.TaskDataFetchBodyDigest(key, bounds)
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := n.verifyRequestAuth("FetchTaskData", key, body, req.Msg.RequestAuth); err != nil {
		return err
	}
	if key.Kind != builderclient.DataKindInput {
		n.mu.Lock()
		defer n.mu.Unlock()
		metadata, ok := n.objects.TaskDataMetadata[key]
		if !ok || metadata.Readiness != builderclient.TaskDataReady {
			return connect.NewError(connect.CodeFailedPrecondition, errors.New("object is not READY"))
		}
		offset, length := uint64(0), metadata.SizeBytes
		if bounds != nil {
			offset, length = bounds.Offset, bounds.Length
		}
		if err := stream.Send(proofFetchHeader(key, metadata.SizeBytes, offset, length)); err != nil {
			return err
		}
		err := n.objects.FetchTaskData(context.Background(), "", builderclient.FetchTaskDataRequest{Key: key, Range: bounds}, func(c builderclient.TaskDataChunk) error {
			return stream.Send(proofFetchChunk(c.Offset, c.Data, c.EOF))
		})
		if err != nil {
			return connect.NewError(connect.CodeFailedPrecondition, err)
		}
		return nil
	}
	if key.TaskID != proofTaskID {
		return connect.NewError(connect.CodeNotFound, errors.New("unknown task"))
	}
	offset, length := uint64(0), uint64(len(n.input))
	if bounds != nil {
		offset, length = bounds.Offset, bounds.Length
	}
	if offset > uint64(len(n.input)) || length > uint64(len(n.input))-offset {
		return connect.NewError(connect.CodeOutOfRange, errors.New("range exceeds input"))
	}
	if err := stream.Send(proofFetchHeader(key, uint64(len(n.input)), offset, length)); err != nil {
		return err
	}
	n.mu.Lock()
	n.fetchOffsets = append(n.fetchOffsets, offset)
	n.fetchNonces = append(n.fetchNonces, append([]byte(nil), req.Msg.RequestAuth.RequestNonce...))
	interrupt := n.behavior.interruptFetchOnce && !n.fetchInterrupted
	if interrupt {
		n.fetchInterrupted = true
	}
	n.mu.Unlock()
	end := offset + length
	plan := []uint64{3, 7, length}
	if offset != 0 {
		plan = []uint64{5, 8, length}
	}
	for _, size := range plan {
		if offset == end {
			break
		}
		if size > end-offset {
			size = end - offset
		}
		data := append([]byte(nil), n.input[offset:offset+size]...)
		if err := stream.Send(proofFetchChunk(offset, data, offset+size == end)); err != nil {
			return err
		}
		n.mu.Lock()
		n.fetchChunkSizes = append(n.fetchChunkSizes, len(data))
		n.mu.Unlock()
		offset += size
		if interrupt {
			return connect.NewError(connect.CodeUnavailable, errors.New("injected fetch interruption"))
		}
	}
	return nil
}

func (n *nexusProofServer) SubmitInferReceipt(_ context.Context, req *connect.Request[nexusv1.SubmitInferReceiptRequest]) (*connect.Response[nexusv1.SubmitInferReceiptResponse], error) {
	receipt, err := receiptFromProto(req.Msg.GetReceipt())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	digest, err := n.verifyReceipt(receipt)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}
	n.mu.Lock()
	n.relayCalls++
	n.relayReceipts = append(n.relayReceipts, receipt)
	n.relayDigests = append(n.relayDigests, digest)
	n.receipt, n.receiptDigest = receipt, digest
	fail := n.behavior.failRelayAttempts > 0
	if fail {
		n.behavior.failRelayAttempts--
	}
	mismatch := n.behavior.receiptResponseMismatch
	if !fail && !mismatch {
		n.relayAccepted = true
	}
	n.mu.Unlock()
	if fail {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("injected receipt relay failure"))
	}
	hash := digest.String()
	if mismatch {
		hash = strings.Repeat("ff", 32)
	}
	return connect.NewResponse(&nexusv1.SubmitInferReceiptResponse{RelayAccepted: true, InferReceiptHash: hash}), nil
}

func (n *nexusProofServer) UploadTaskResultObject(ctx context.Context, stream *connect.ClientStream[nexusv1.UploadTaskResultObjectRequest]) (*connect.Response[nexusv1.UploadTaskResultObjectResponse], error) {
	if stream == nil || !stream.Receive() || stream.Msg().GetHeader() == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("upload header is missing"))
	}
	header := stream.Msg().GetHeader()
	key, err := proofKeyFromProto(header.ObjectRef)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	body, err := builderclient.TaskDataUploadBodyDigest(key, header.SizeBytes, header.MediaType)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := n.verifyRequestAuth("UploadTaskResultObject", key, body, header.RequestAuth); err != nil {
		return nil, err
	}
	if key.Kind == builderclient.DataKindOutput {
		n.mu.Lock()
		n.uploadCalls++
		n.uploadDigests = append(n.uploadDigests, body)
		n.relayObservedBeforeRelease = n.relayObservedBeforeRelease || n.relayAccepted
		n.mu.Unlock()
		n.startedOnce.Do(func() { close(n.uploadStarted) })
		if n.behavior.blockUpload {
			select {
			case <-n.uploadRelease:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	var data []byte
	for stream.Receive() {
		if stream.Msg().GetHeader() != nil || len(stream.Msg().GetChunk()) == 0 {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("malformed upload frame"))
		}
		data = append(data, stream.Msg().GetChunk()...)
	}
	if err := stream.Err(); err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if key.Kind == builderclient.DataKindOutput && n.behavior.failUploadAttempts > 0 {
		n.behavior.failUploadAttempts--
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("injected upload failure"))
	}
	metadata, err := n.objects.UploadTaskResultObject(ctx, "", builderclient.UploadTaskResultRequest{Key: key, SizeBytes: header.SizeBytes, MediaType: header.MediaType, Data: data, Auth: proofAuthFromProto(header.RequestAuth)})
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if key.Kind == builderclient.DataKindOutput {
		n.storedOutput = append([]byte(nil), data...)
		n.completedUploads++
	} else {
		n.evidenceUploads++
	}
	return connect.NewResponse(&nexusv1.UploadTaskResultObjectResponse{Accepted: true, Metadata: proofMetadata(metadata)}), nil
}

func (n *nexusProofServer) FinalizeTaskResult(ctx context.Context, req *connect.Request[nexusv1.FinalizeTaskResultRequest]) (*connect.Response[nexusv1.FinalizeTaskResultResponse], error) {
	receipt, err := receiptFromProto(req.Msg.Receipt)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	request := builderclient.FinalizeTaskResultRequest{TaskHash: req.Msg.TaskHash, SessionID: req.Msg.SessionId, TaskID: req.Msg.TaskId, Receipt: receipt, Auth: proofAuthFromProto(req.Msg.RequestAuth)}
	body, err := builderclient.TaskDataFinalizeResultBodyDigest(request)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := n.verifyRequestAuth("FinalizeTaskResult", builderclient.TaskDataKey{}, body, req.Msg.RequestAuth); err != nil {
		return nil, err
	}
	if _, err := n.verifyReceipt(receipt); err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}
	n.mu.Lock()
	result, err := n.objects.FinalizeTaskResult(ctx, "", request)
	n.mu.Unlock()
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	output, err := n.signedConfirmation(result.OutputConfirmation)
	if err != nil {
		return nil, err
	}
	response := &nexusv1.FinalizeTaskResultResponse{Accepted: true, Idempotent: result.Idempotent, OutputConfirmation: output}
	for _, c := range result.EvidenceBundleConfirmations {
		confirmation, err := n.signedConfirmation(c)
		if err != nil {
			return nil, err
		}
		response.EvidenceBundleConfirmations = append(response.EvidenceBundleConfirmations, confirmation)
	}
	return connect.NewResponse(response), nil
}

func (n *nexusProofServer) signedConfirmation(c builderclient.StorageConfirmation) (*nexusv1.BuilderStorageConfirmationV1, error) {
	c.RetentionUntilHeight = n.currentHeight.Load() + 100
	digest, err := builderclient.StorageConfirmationSigningHash(c)
	if err != nil {
		return nil, err
	}
	signature := compactSignature(n.builderPrivate, digest)
	if n.behavior.confirmationSignatureBad {
		signature[0] ^= 0xff
	}
	return &nexusv1.BuilderStorageConfirmationV1{SchemaVersion: 1, ChainId: c.ChainID, BuilderOperatorAddress: c.BuilderOperator, ServiceAuthorizationNonce: 1, ObjectRef: proofKeyToProto(c.Key), SizeBytes: c.SizeBytes, ArtifactTotalSizeBytes: c.ArtifactTotalSizeBytes, RetentionUntilHeight: c.RetentionUntilHeight, ServiceSignature: signature}, nil
}

func (n *nexusProofServer) verifyRequestAuth(method string, key builderclient.TaskDataKey, body codec.Hash, wire *nexusv1.TaskDataRequestAuthV1) error {
	if wire == nil {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("request auth is missing"))
	}
	auth := proofAuthFromProto(wire)
	n.recordAuthAttempt(method, auth.RequestNonce, auth.ExpiresAtHeight)
	if auth.ChainID != n.chainID || auth.BuilderAddress != n.builderOperator || auth.Method != builderclient.TaskDataProcedure(method) || auth.BodyDigest != body {
		return n.authFailure(connect.CodeUnauthenticated, errors.New("request scope or body digest mismatch"))
	}
	if err := n.authorizeRequester(auth.Requester); err != nil {
		return n.authFailure(connect.CodeUnauthenticated, err)
	}
	if auth.ServiceAuthorizationNonce != proofServiceAuthorizationNonce {
		return n.authFailure(connect.CodeUnauthenticated, errors.New("stale service authorization nonce"))
	}
	if auth.ExpiresAtHeight < n.currentHeight.Load() {
		return n.authFailure(connect.CodeDeadlineExceeded, errors.New("request expired"))
	}
	digest, err := builderclient.TaskDataRequestSigningHash(auth)
	if err != nil {
		return n.authFailure(connect.CodeUnauthenticated, err)
	}
	if err := n.verifyServiceSignature(auth.Requester, n.servicePubkey, digest, auth.Signature); err != nil {
		return n.authFailure(connect.CodeUnauthenticated, err)
	}
	if err := n.claimNonce(method, auth.RequestNonce, auth.ExpiresAtHeight); err != nil {
		return n.authFailure(connect.CodeAlreadyExists, err)
	}
	return nil
}

func proofKeyFromProto(ref *nexusv1.TaskDataObjectRefV1) (builderclient.TaskDataKey, error) {
	if ref == nil {
		return builderclient.TaskDataKey{}, errors.New("object ref is missing")
	}
	key := builderclient.TaskDataKey{TaskHash: ref.TaskHash, SessionID: ref.SessionId, TaskID: ref.TaskId, Kind: builderclient.DataKind(ref.ObjectKind), ContentHash: ref.ContentHash, EvidenceProducerKind: builderclient.EvidenceProducerKind(ref.EvidenceProducerKind), VerifyRound: ref.VerifyRound, ProducerOperator: ref.GetProducerOperator()}
	return key, builderclient.ValidateTaskDataKey(key)
}
func proofFetchHeader(key builderclient.TaskDataKey, total, offset, length uint64) *nexusv1.FetchTaskDataResponse {
	return &nexusv1.FetchTaskDataResponse{Frame: &nexusv1.FetchTaskDataResponse_Header{Header: &nexusv1.FetchTaskDataHeaderV1{ObjectRef: proofKeyToProto(key), TotalSizeBytes: total, ServedRange: &nexusv1.ByteRangeV1{Offset: offset, Length: length}}}}
}
func proofFetchChunk(offset uint64, data []byte, eof bool) *nexusv1.FetchTaskDataResponse {
	return &nexusv1.FetchTaskDataResponse{Frame: &nexusv1.FetchTaskDataResponse_Chunk{Chunk: &nexusv1.FetchTaskDataChunkV1{Offset: offset, Data: data, Eof: eof}}}
}
func proofHex(s string) []byte { data, _ := hex.DecodeString(s); return data }
func proofKeyToProto(key builderclient.TaskDataKey) *nexusv1.TaskDataObjectRefV1 {
	ref := &nexusv1.TaskDataObjectRefV1{TaskHash: key.TaskHash, SessionId: key.SessionID, TaskId: key.TaskID, ObjectKind: nexusv1.TaskDataObjectKind(key.Kind), ContentHash: key.ContentHash, EvidenceProducerKind: nexusv1.EvidenceProducerKindV1(key.EvidenceProducerKind), VerifyRound: key.VerifyRound}
	if key.ProducerOperator != "" {
		operator := key.ProducerOperator
		ref.ProducerOperator = &operator
	}
	return ref
}
func proofMetadata(m builderclient.TaskDataMetadata) *nexusv1.TaskDataObjectMetadataV1 {
	return &nexusv1.TaskDataObjectMetadataV1{ObjectRef: proofKeyToProto(m.Key), SizeBytes: m.SizeBytes, MediaType: m.MediaType, Readiness: nexusv1.TaskDataObjectReadinessV1(m.Readiness), ChunkLengths: m.ChunkLengths, OutputLeafCount: m.OutputLeafCount}
}

func (n *nexusProofServer) UploadTaskOutputStream(ctx context.Context, stream *connect.BidiStream[nexusv1.UploadTaskOutputStreamRequest, nexusv1.UploadTaskOutputStreamResponse]) error {
	first, err := stream.Receive()
	if err != nil {
		return err
	}
	header := first.GetHeader()
	if header == nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("output stream header required"))
	}
	body, err := builderclient.TaskDataOutputStreamBodyDigest(header.TaskHash, header.SessionId, header.TaskId)
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := n.verifyRequestAuth("UploadTaskOutputStream", builderclient.TaskDataKey{}, body, header.RequestAuth); err != nil {
		return err
	}
	n.mu.Lock()
	n.uploadCalls++
	n.uploadDigests = append(n.uploadDigests, body)
	n.relayObservedBeforeRelease = n.relayObservedBeforeRelease || n.relayAccepted
	request := builderclient.OutputStreamRequest{TaskHash: header.TaskHash, SessionID: header.SessionId, TaskID: header.TaskId, Auth: proofAuthFromProto(header.RequestAuth), ReplayChunks: append([]builderclient.OutputChunk(nil), n.outputFrames...)}
	inner, err := n.objects.OpenTaskOutputStream(ctx, "", request)
	progress := &nexusv1.OutputStreamProgressV1{}
	if len(n.outputFrames) > 0 {
		last := n.outputFrames[len(n.outputFrames)-1]
		progress.LastSeq = &last.Seq
		progress.MmrRoot = last.MMRRoot[:]
	}
	n.mu.Unlock()
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	defer inner.Close()
	if err := stream.Send(&nexusv1.UploadTaskOutputStreamResponse{Reply: &nexusv1.UploadTaskOutputStreamResponse_Progress{Progress: progress}}); err != nil {
		return err
	}
	n.startedOnce.Do(func() { close(n.uploadStarted) })
	for {
		frame, err := stream.Receive()
		if err != nil {
			return err
		}
		if chunk := frame.GetChunk(); chunk != nil {
			digest, err := nodewire.OutputChunkSigningDigest(n.chainID, proofHex(header.TaskHash), chunk.Seq, chunk.MmrRoot)
			if err != nil {
				return connect.NewError(connect.CodeInvalidArgument, err)
			}
			if err := n.verifyServiceSignature(n.workerOperator, n.servicePubkey, digest, chunk.WorkerSignature); err != nil {
				return connect.NewError(connect.CodeUnauthenticated, err)
			}
			var root codec.Hash
			copy(root[:], chunk.MmrRoot)
			converted := builderclient.OutputChunk{Seq: chunk.Seq, Text: chunk.Text, MMRRoot: root, WorkerSignature: chunk.WorkerSignature, Attachment: chunk.Attachment, AttachmentSignature: chunk.AttachmentSignature}
			n.mu.Lock()
			err = inner.SendChunk(converted)
			if err == nil {
				n.outputFrames = append(n.outputFrames, converted)
			}
			n.mu.Unlock()
			if err != nil {
				return connect.NewError(connect.CodeInvalidArgument, err)
			}
			continue
		}
		fin := frame.GetFin()
		if fin == nil {
			return connect.NewError(connect.CodeInvalidArgument, errors.New("chunk or Fin required"))
		}
		if n.behavior.blockUpload {
			select {
			case <-n.uploadRelease:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		n.mu.Lock()
		if n.behavior.failUploadAttempts > 0 {
			n.behavior.failUploadAttempts--
			n.mu.Unlock()
			return connect.NewError(connect.CodeUnavailable, errors.New("injected upload failure"))
		}
		finishReason := nodewire.FinishReasonV1(fin.FinishReason)
		finDigest, err := nodewire.OutputFinSigningDigest(n.chainID, proofHex(header.TaskHash), fin.FinalSeq, fin.OutputMmrRoot, finishReason)
		if err == nil {
			err = n.verifyServiceSignature(n.workerOperator, n.servicePubkey, finDigest, fin.WorkerSignature)
		}
		var result builderclient.OutputStreamResult
		if err == nil {
			result, err = inner.Finish(builderclient.OutputFin{FinishReason: finishReason, WorkerSignature: fin.WorkerSignature})
		}
		if err == nil && (fin.FinalSeq != result.LastSeq || !bytes.Equal(fin.OutputMmrRoot, result.OutputMMRRoot[:])) {
			err = errors.New("Fin mismatch")
		}
		if err == nil {
			n.storedOutput = nil
			for _, chunk := range n.outputFrames {
				n.storedOutput = append(n.storedOutput, chunk.Text...)
			}
			n.completedUploads++
		}
		n.mu.Unlock()
		if err != nil {
			return connect.NewError(connect.CodeInvalidArgument, err)
		}
		return stream.Send(&nexusv1.UploadTaskOutputStreamResponse{Reply: &nexusv1.UploadTaskOutputStreamResponse_Result{Result: &nexusv1.OutputStreamResultV1{Accepted: true, LastSeq: result.LastSeq, OutputMmrRoot: result.OutputMMRRoot[:], LeafCount: result.LeafCount}}})
	}
}
func proofAuthFromProto(w *nexusv1.TaskDataRequestAuthV1) builderclient.TaskDataRequestAuth {
	if w == nil {
		return builderclient.TaskDataRequestAuth{}
	}
	body, _ := hex.DecodeString(w.BodyDigest)
	var hash codec.Hash
	copy(hash[:], body)
	return builderclient.TaskDataRequestAuth{SchemaVersion: w.SchemaVersion, ChainID: w.ChainId, BuilderAddress: w.BuilderOperatorAddress, Method: w.RpcMethod, BodyDigest: hash, RequesterKind: builderclient.TaskDataRequesterKind(w.RequesterKind), Requester: w.RequesterAddress, ServiceAuthorizationNonce: w.ServiceAuthorizationNonce, RequestNonce: w.RequestNonce, ExpiresAtHeight: w.ExpiryHeight, Signature: w.Signature}
}

// verifyReceipt holds the relayed receipt to the frozen §5.14 contract and
// returns the digest the server DERIVES from it. The frozen wire carries no
// self-asserted infer_receipt_hash, so there is nothing to cross-check a
// caller-supplied copy against: the derived digest is simultaneously the value
// the Worker's service key must have signed and the value this server echoes as
// infer_receipt_hash.
//
// The frozen SHAPE is not re-litigated here. InferReceiptSigningDigest cannot
// derive a digest from a receipt whose schema_version is wrong, whose Hash32
// fields are not canonical lowercase 64-hex, whose replay counter, output size or
// expiry is zero, or whose evidence commitments are incomplete, duplicated or out
// of order -- so a second copy of those rules here would be an unreachable
// duplicate that silently drifts. What is left is what only this server knows.
func (n *nexusProofServer) verifyReceipt(receipt builderclient.SignedInferReceipt) (codec.Hash, error) {
	if receipt.ChainID != n.chainID {
		return codec.Hash{}, fmt.Errorf("receipt chain id %q does not match this chain %q", receipt.ChainID, n.chainID)
	}
	// The receipt's worker_operator_address is bound below rather than here: the
	// signature is verified against that operator's registered CORTEX service key,
	// and verifyServiceSignature refuses any operator this task did not select.

	// Cortex's own library now refuses an empty list before it will produce a
	// digest, so a receipt reaching here with none came from something that is not
	// the Cortex client -- a hostile Builder stripping wire field 10, or another
	// implementation. This gate is the backstop for exactly that, and it stays
	// whether or not the client-side refusal shadows it: admission requires the
	// locked Verification Profile's required evidence kinds, and a receipt
	// committing to none of them is inadmissible however well it is signed.
	if len(receipt.RequiredEvidenceCommitments) == 0 {
		return codec.Hash{}, errors.New("receipt commits to no required_evidence_commitments")
	}
	digest, err := builderclient.InferReceiptSigningDigest(receipt)
	if err != nil {
		return codec.Hash{}, err
	}
	signature, err := hex.DecodeString(receipt.ServiceSignature)
	if err != nil {
		return codec.Hash{}, fmt.Errorf("decode receipt service signature: %w", err)
	}
	// Nexus verifies the relayed receipt against the CORTEX-domain current service
	// key of the receipt's Worker operator, not against the presented envelope key.
	if err := n.verifyServiceSignature(receipt.WorkerOperatorAddress, n.servicePubkey, digest, signature); err != nil {
		return codec.Hash{}, err
	}
	return digest, nil
}

// authorizeRequester mirrors Nexus permissionsFor: the signed Requester/Recipient
// must be an operator address the task grants access to. This fake task is
// assigned to exactly one Worker.
func (n *nexusProofServer) authorizeRequester(address string) error {
	if address == "" || address != n.workerOperator {
		return fmt.Errorf("requester %q is not the selected Worker operator %q", address, n.workerOperator)
	}
	return nil
}

// verifyServiceSignature mirrors Nexus verifyRequesterKey: the presented key is
// legal when it derives the operator address itself, or when it is byte-equal to
// that operator's registered CORTEX-domain current service key.
func (n *nexusProofServer) verifyServiceSignature(operator string, publicKey []byte, digest codec.Hash, signature []byte) error {
	if err := n.authorizeRequester(operator); err != nil {
		return err
	}
	separator := strings.LastIndexByte(operator, '1')
	if separator <= 0 {
		return errors.New("operator address is malformed")
	}
	if len(publicKey) != 33 {
		return errors.New("presented key must be a 33-byte compressed secp256k1 key")
	}
	derived, err := signer.AddressFromCompressedPublicKey(operator[:separator], publicKey)
	if err != nil {
		return err
	}
	if derived != operator && !bytes.Equal(publicKey, n.servicePubkey) {
		return errors.New("presented key is neither the operator key nor its current CORTEX service key")
	}
	return signer.VerifyDigestSignature(hex.EncodeToString(publicKey), digest, signature)
}

func (n *nexusProofServer) claimNonce(method string, nonce []byte, expiry uint64) error {
	if len(nonce) != 32 {
		return errors.New("request nonce must be 32 bytes")
	}
	encoded := hex.EncodeToString(nonce)
	n.mu.Lock()
	defer n.mu.Unlock()
	if prior, exists := n.seenNonces[encoded]; exists {
		return fmt.Errorf("request nonce was already used by %s", prior)
	}
	n.seenNonces[encoded] = method
	n.authExpiries = append(n.authExpiries, expiry)
	return nil
}

func (*nexusProofServer) authFailure(code connect.Code, err error) error {
	return connect.NewError(code, err)
}

func (n *nexusProofServer) recordAuthAttempt(method string, nonce []byte, expiry uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.authAttempts = append(n.authAttempts, authAttempt{
		method: method, nonce: append([]byte(nil), nonce...), expiry: expiry,
	})
}

// receiptFromProto decodes the frozen task.v1.InferReceiptV2 mirror. The
// evidence list is part of the receipt now, so it is decoded here rather than
// from a request-level field: a request-level list could never be covered by
// service_signature, which is why field 5 of SubmitInferReceiptRequest is
// reserved.
func receiptFromProto(receipt *taskv1.InferReceiptV2) (builderclient.SignedInferReceipt, error) {
	if receipt == nil {
		return builderclient.SignedInferReceipt{}, errors.New("signed infer receipt is missing")
	}
	wireCommitments := receipt.GetRequiredEvidenceCommitments()
	commitments := make([]builderclient.EvidenceCommitment, 0, len(wireCommitments))
	for index, item := range wireCommitments {
		if item == nil {
			return builderclient.SignedInferReceipt{}, fmt.Errorf("required_evidence_commitments[%d] is missing", index)
		}
		// evidence_hash_or_root is a raw Hash32 on the wire, not hex text.
		root := item.GetEvidenceHashOrRoot()
		if len(root) != len(codec.Hash{}) {
			return builderclient.SignedInferReceipt{}, fmt.Errorf(
				"required_evidence_commitments[%d] evidence_hash_or_root is %d bytes, want raw 32", index, len(root),
			)
		}
		commitments = append(commitments, builderclient.EvidenceCommitment{
			EvidenceKind:       nodewire.EvidenceKind(item.GetEvidenceKind()),
			EvidenceHashOrRoot: codec.Hash(root),
			EncodedSizeBytes:   item.GetEncodedSizeBytes(),
		})
	}
	return builderclient.SignedInferReceipt{
		SchemaVersion:               receipt.GetSchemaVersion(),
		ChainID:                     receipt.GetChainId(),
		TaskID:                      hex.EncodeToString(receipt.GetTaskId()),
		TaskHash:                    hex.EncodeToString(receipt.GetTaskHash()),
		WorkerOperatorAddress:       receipt.GetWorkerOperatorAddress(),
		ServiceAuthorizationNonce:   receipt.GetServiceAuthorizationNonce(),
		GenerationParamsDigest:      hex.EncodeToString(receipt.GetGenerationParamsDigest()),
		OutputHash:                  hex.EncodeToString(receipt.GetOutputHash()),
		OutputLeafCount:             receipt.GetOutputLeafCount(),
		OutputSizeBytes:             receipt.GetOutputSizeBytes(),
		GeneratedTokenCount:         receipt.GetGeneratedTokenCount(),
		RequiredEvidenceCommitments: commitments,
		ExpiryHeight:                receipt.GetExpiryHeight(),
		ServiceSignature:            hex.EncodeToString(receipt.GetServiceSignature()),
	}, nil
}

// receiptToProto is the encoding direction receiptFromProto decodes. The real
// client owns an unexported copy of it; this one exists so a test can put a
// request on the wire that the real client refuses to build, which is the only
// way to reach the server-side rules that guard against a hostile Builder.
func receiptToProto(receipt builderclient.SignedInferReceipt) *taskv1.InferReceiptV2 {
	commitments := make([]*taskv1.EvidenceCommitmentV1, 0, len(receipt.RequiredEvidenceCommitments))
	for _, commitment := range receipt.RequiredEvidenceCommitments {
		root := commitment.EvidenceHashOrRoot
		commitments = append(commitments, &taskv1.EvidenceCommitmentV1{
			EvidenceKind:       sharedv1.EvidenceKind(commitment.EvidenceKind),
			EvidenceHashOrRoot: append([]byte(nil), root[:]...),
			EncodedSizeBytes:   commitment.EncodedSizeBytes,
		})
	}
	return &taskv1.InferReceiptV2{
		SchemaVersion:               receipt.SchemaVersion,
		ChainId:                     receipt.ChainID,
		TaskId:                      proofHex(receipt.TaskID),
		TaskHash:                    proofHex(receipt.TaskHash),
		WorkerOperatorAddress:       receipt.WorkerOperatorAddress,
		ServiceAuthorizationNonce:   receipt.ServiceAuthorizationNonce,
		GenerationParamsDigest:      proofHex(receipt.GenerationParamsDigest),
		OutputHash:                  proofHex(receipt.OutputHash),
		OutputLeafCount:             receipt.OutputLeafCount,
		OutputSizeBytes:             receipt.OutputSizeBytes,
		GeneratedTokenCount:         receipt.GeneratedTokenCount,
		RequiredEvidenceCommitments: commitments,
		ExpiryHeight:                receipt.ExpiryHeight,
		ServiceSignature:            proofHex(receipt.ServiceSignature),
	}
}

func authToProto(a builderclient.TaskDataRequestAuth) *nexusv1.TaskDataRequestAuthV1 {
	return &nexusv1.TaskDataRequestAuthV1{SchemaVersion: a.SchemaVersion, ChainId: a.ChainID, BuilderOperatorAddress: a.BuilderAddress, RpcMethod: a.Method, BodyDigest: a.BodyDigest.String(), RequesterKind: nexusv1.TaskDataRequesterKindV1(a.RequesterKind), RequesterAddress: a.Requester, ServiceAuthorizationNonce: a.ServiceAuthorizationNonce, RequestNonce: a.RequestNonce, ExpiryHeight: a.ExpiresAtHeight, Signature: a.Signature}
}

func compactSignature(private *secp256k1.PrivateKey, digest codec.Hash) []byte {
	signature := ecdsa.Sign(private, digest[:])
	r, s := signature.R(), signature.S()
	rBytes, sBytes := r.Bytes(), s.Bytes()
	out := make([]byte, 64)
	copy(out[:32], rBytes[:])
	copy(out[32:], sBytes[:])
	return out
}
