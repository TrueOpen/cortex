package builderclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	nexusv1connect "github.com/TrueOpen/cortex/proto/nexus/v1/nexusv1connect"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

const taskDataChunkSize = 256 << 10

const submitInferReceiptMethod = "SubmitInferReceipt"

// TaskDataTransport is the transport policy every Nexus task-data call runs
// under. It is a constructor argument rather than a default because a Cortex
// node that talks plaintext to a Builder puts V1 Task payloads — prompts and
// outputs — on the wire in the clear, and that has to be a stated deployment
// decision.
type TaskDataTransport struct {
	// AllowInsecureEndpoint admits an http:// Builder endpoint. It mirrors
	// nexus.allow_insecure_descriptor, which is the same switch that lets
	// builderdirectory accept a plaintext http:// endpoint out of the on-chain
	// descriptor in the first place
	// (internal/builderdirectory.ErrPlaintextEndpoint). Leaving the two out of
	// step is how a descriptor-refused endpoint would still get dialled.
	AllowInsecureEndpoint bool
	// DowngradeEndpointTLS dials an https:// or grpcs:// Builder endpoint at its
	// plaintext origin instead. It mirrors nexus.downgrade_descriptor_tls, the
	// devnet compatibility switch for a BuilderSet that publishes a TLS scheme
	// in front of an ingress that terminates no TLS.
	//
	// It does NOT stand in for AllowInsecureEndpoint: a downgraded endpoint is
	// plaintext by definition, so it still has to clear the plaintext gate. That
	// coupling is what keeps this from dialling in the clear an endpoint
	// builderdirectory would have refused, and internal/config states it up
	// front rather than leaving the refusal to the first task.
	DowngradeEndpointTLS bool
}

type ConnectTaskDataClient struct {
	httpClient       connect.HTTPClient
	outputHTTPClient connect.HTTPClient
	outputIOTimeout  time.Duration
	token            string
	transport        TaskDataTransport
}

func NewConnectTaskDataClient(httpClient connect.HTTPClient, token string, transport TaskDataTransport) *ConnectTaskDataClient {
	timeout := nexusDataTimeout
	if client, ok := httpClient.(*http.Client); ok && client.Timeout > 0 {
		timeout = client.Timeout
	}
	return &ConnectTaskDataClient{httpClient: httpClient, outputHTTPClient: newOutputHTTPClient(httpClient), outputIOTimeout: timeout, token: strings.TrimSpace(token), transport: transport}
}

// NewConnectTaskDataClientWithDefaults constructs the production task-data
// client with the shared bounded, same-origin, TLS-floored Nexus HTTP client.
func NewConnectTaskDataClientWithDefaults(token string, transport TaskDataTransport) *ConnectTaskDataClient {
	return NewConnectTaskDataClient(newNexusHTTPClient(nil, nexusDataTimeout), token, transport)
}

func (c *ConnectTaskDataClient) GetTaskDataMetadata(ctx context.Context, endpoint string, request GetTaskDataMetadataRequest) (TaskDataMetadata, error) {
	digest, err := TaskDataMetadataBodyDigest(request.Key)
	if err != nil {
		return TaskDataMetadata{}, err
	}
	if err := validateSignedTaskDataRequest(request.Auth, "GetTaskDataMetadata", digest); err != nil {
		return TaskDataMetadata{}, err
	}
	client, err := c.ingress(endpoint)
	if err != nil {
		return TaskDataMetadata{}, err
	}
	req := connect.NewRequest(&nexusv1.GetTaskDataMetadataRequest{ObjectRef: taskDataKeyToProto(request.Key), RequestAuth: taskDataRequestAuthToProto(request.Auth)})
	c.authorize(req.Header())
	response, err := client.GetTaskDataMetadata(ctx, req)
	if err != nil {
		return TaskDataMetadata{}, classifyConnectError(nexusv1connect.IngressAPIGetTaskDataMetadataProcedure, err)
	}
	if response == nil || response.Msg == nil {
		return TaskDataMetadata{}, fmt.Errorf("task metadata response is empty")
	}
	result, err := taskDataMetadataFromProto(response.Msg.Metadata)
	if err != nil {
		return TaskDataMetadata{}, err
	}
	if result.Key != request.Key {
		return TaskDataMetadata{}, fmt.Errorf("task metadata object ref does not match request")
	}
	result.RetainUntilHeight = response.Msg.RetainUntilHeight
	if response.Msg.EvidenceBundle != nil {
		b := response.Msg.EvidenceBundle
		// A Worker manifest is addressed by its typed commitment, not by the hash
		// of its bytes; only a Verifier manifest's content hash is the manifest
		// hash itself.
		if request.Key.Kind != DataKindEvidenceManifest || (request.Key.EvidenceProducerKind != EvidenceProducerWorker && b.EvidenceManifestHash != request.Key.ContentHash) || b.ManifestSizeBytes != result.SizeBytes || b.ArtifactCount == 0 {
			return TaskDataMetadata{}, fmt.Errorf("evidence bundle summary does not match manifest")
		}
		if _, err := taskDataHash("evidence_manifest_hash", b.EvidenceManifestHash); err != nil {
			return TaskDataMetadata{}, err
		}
		if _, err := taskDataHash("evidence_schema_hash", b.EvidenceSchemaHash); err != nil {
			return TaskDataMetadata{}, err
		}
		result.EvidenceBundle = &EvidenceBundleSummary{EvidenceManifestHash: b.EvidenceManifestHash, EvidenceSchemaHash: b.EvidenceSchemaHash, ArtifactCount: b.ArtifactCount, ArtifactTotalSizeBytes: b.ArtifactTotalSizeBytes, ManifestSizeBytes: b.ManifestSizeBytes}
	} else if request.Key.Kind == DataKindEvidenceManifest {
		return TaskDataMetadata{}, fmt.Errorf("manifest metadata requires bundle summary")
	}
	if response.Msg.InferReceipt != nil {
		receipt, err := signedInferReceiptFromProto(response.Msg.InferReceipt)
		if err != nil {
			return TaskDataMetadata{}, err
		}
		if receipt.TaskID != request.Key.TaskID || receipt.TaskHash != request.Key.TaskHash {
			return TaskDataMetadata{}, fmt.Errorf("metadata infer receipt task identity mismatch")
		}
		if request.Key.Kind != DataKindOutput || receipt.OutputHash != request.Key.ContentHash || receipt.OutputSizeBytes != result.SizeBytes || (result.Readiness == TaskDataReady && receipt.OutputLeafCount != result.OutputLeafCount) {
			return TaskDataMetadata{}, fmt.Errorf("metadata infer receipt output identity mismatch")
		}
		result.SignedInferReceipt = &receipt
	}
	return result, nil
}

func (c *ConnectTaskDataClient) FetchTaskData(ctx context.Context, endpoint string, request FetchTaskDataRequest, receive func(TaskDataChunk) error) error {
	if receive == nil {
		return fmt.Errorf("fetch task data callback is required")
	}
	digest, err := TaskDataFetchBodyDigest(request.Key, request.Range)
	if err != nil {
		return err
	}
	if err := validateSignedTaskDataRequest(request.Auth, "FetchTaskData", digest); err != nil {
		return err
	}
	client, err := c.ingress(endpoint)
	if err != nil {
		return err
	}
	req := connect.NewRequest(&nexusv1.FetchTaskDataRequest{ObjectRef: taskDataKeyToProto(request.Key), Range: taskDataRangeToProto(request.Range), RequestAuth: taskDataRequestAuthToProto(request.Auth)})
	c.authorize(req.Header())
	stream, err := client.FetchTaskData(ctx, req)
	if err != nil {
		return classifyConnectError(nexusv1connect.IngressAPIFetchTaskDataProcedure, err)
	}
	defer func() { _ = stream.Close() }()
	var next, end uint64
	headerSeen, eof := false, false
	for stream.Receive() {
		frame := stream.Msg()
		if frame == nil || eof {
			return fmt.Errorf("fetch stream contains empty frame or continued after EOF")
		}
		if header := frame.GetHeader(); header != nil {
			if headerSeen {
				return fmt.Errorf("fetch stream repeats its header")
			}
			key, err := taskDataKeyFromProto(header.ObjectRef)
			if err != nil {
				return err
			}
			if key != request.Key || header.ServedRange == nil {
				return fmt.Errorf("fetch header object or served range does not match request")
			}
			if key.Kind == DataKindEvidenceArtifact && header.MediaType != "" {
				return fmt.Errorf("evidence artifact header must omit media_type")
			}
			bounds := header.ServedRange
			if bounds.Offset > header.TotalSizeBytes || bounds.Length > header.TotalSizeBytes-bounds.Offset {
				return fmt.Errorf("fetch served range exceeds object")
			}
			if request.Range == nil {
				if bounds.Offset != 0 || bounds.Length != header.TotalSizeBytes {
					return fmt.Errorf("whole-object fetch returned a partial range")
				}
			} else if bounds.Offset != request.Range.Offset || bounds.Length != request.Range.Length {
				return fmt.Errorf("fetch served range differs from signed range")
			}
			next, end = bounds.Offset, bounds.Offset+bounds.Length
			headerSeen = true
			continue
		}
		chunk := frame.GetChunk()
		if !headerSeen || chunk == nil {
			return fmt.Errorf("fetch requires one header before chunks")
		}
		if chunk.Offset != next || uint64(len(chunk.Data)) > end-next {
			return fmt.Errorf("fetch chunk offset or size exceeds served range")
		}
		next += uint64(len(chunk.Data))
		if len(chunk.Data) == 0 && !(chunk.Eof && next == end) {
			return fmt.Errorf("fetch contains empty nonterminal chunk")
		}
		if chunk.Eof && next != end {
			return fmt.Errorf("fetch EOF precedes served boundary")
		}
		if err := receive(TaskDataChunk{Offset: chunk.Offset, Data: chunk.Data, EOF: chunk.Eof}); err != nil {
			return err
		}
		eof = chunk.Eof
	}
	if err := stream.Err(); err != nil {
		return classifyConnectError(nexusv1connect.IngressAPIFetchTaskDataProcedure, err)
	}
	if !headerSeen || !eof || next != end {
		return fmt.Errorf("fetch stream ended before final EOF at served boundary")
	}
	return nil
}

func validateUploadTaskResultRequest(request UploadTaskResultRequest) (codec.Hash, error) {
	if request.Key.Kind == DataKindOutput {
		return codec.Hash{}, fmt.Errorf("OUTPUT requires UploadTaskOutputStream")
	}
	digest, err := TaskDataUploadBodyDigest(request.Key, request.SizeBytes, request.MediaType)
	if err != nil {
		return codec.Hash{}, err
	}
	if uint64(len(request.Data)) != request.SizeBytes {
		return codec.Hash{}, fmt.Errorf("upload bytes differ from signed size")
	}
	var hash codec.Hash
	switch request.Key.Kind {
	case DataKindEvidenceManifest:
		if request.Key.EvidenceProducerKind == EvidenceProducerWorker {
			// Worker references carry the typed commitment; Finalize binds the
			// independently hashed manifest and its four artifacts to that value.
			raw, _ := taskDataHash("content_hash", request.Key.ContentHash)
			copy(hash[:], raw)
		} else {
			hash = codec.HashV1("TRUEOPEN_EVIDENCE_BUNDLE_MANIFEST_V1", request.Data)
		}
	case DataKindEvidenceArtifact:
		hash = codec.HashBytes(request.Data)
	default:
		return codec.Hash{}, fmt.Errorf("unsupported result upload kind")
	}
	if hex.EncodeToString(hash[:]) != request.Key.ContentHash {
		return codec.Hash{}, fmt.Errorf("upload bytes differ from signed content hash")
	}
	if err := validateSignedTaskDataRequest(request.Auth, "UploadTaskResultObject", digest); err != nil {
		return codec.Hash{}, err
	}
	return digest, nil
}

func (c *ConnectTaskDataClient) UploadTaskResultObject(ctx context.Context, endpoint string, request UploadTaskResultRequest) (TaskDataMetadata, error) {
	if _, err := validateUploadTaskResultRequest(request); err != nil {
		return TaskDataMetadata{}, err
	}
	client, err := c.ingress(endpoint)
	if err != nil {
		return TaskDataMetadata{}, err
	}
	stream := client.UploadTaskResultObject(ctx)
	c.authorize(stream.RequestHeader())
	header := &nexusv1.UploadTaskResultObjectHeaderV1{ObjectRef: taskDataKeyToProto(request.Key), SizeBytes: request.SizeBytes, MediaType: request.MediaType, RequestAuth: taskDataRequestAuthToProto(request.Auth)}
	send := func(frame *nexusv1.UploadTaskResultObjectRequest) error {
		if err := stream.Send(frame); err != nil {
			if _, closeErr := stream.CloseAndReceive(); closeErr != nil {
				return classifyConnectError(nexusv1connect.IngressAPIUploadTaskResultObjectProcedure, closeErr)
			}
			return classifyConnectError(nexusv1connect.IngressAPIUploadTaskResultObjectProcedure, err)
		}
		return nil
	}
	if err := send(&nexusv1.UploadTaskResultObjectRequest{Frame: &nexusv1.UploadTaskResultObjectRequest_Header{Header: header}}); err != nil {
		return TaskDataMetadata{}, err
	}
	for start := 0; start < len(request.Data); start += taskDataChunkSize {
		end := min(start+taskDataChunkSize, len(request.Data))
		if err := send(&nexusv1.UploadTaskResultObjectRequest{Frame: &nexusv1.UploadTaskResultObjectRequest_Chunk{Chunk: request.Data[start:end]}}); err != nil {
			return TaskDataMetadata{}, err
		}
	}
	response, err := stream.CloseAndReceive()
	if err != nil {
		return TaskDataMetadata{}, classifyConnectError(nexusv1connect.IngressAPIUploadTaskResultObjectProcedure, err)
	}
	if response == nil || response.Msg == nil || !response.Msg.Accepted {
		return TaskDataMetadata{}, fmt.Errorf("object upload was not accepted")
	}
	metadata, err := taskDataMetadataFromProto(response.Msg.Metadata)
	if err != nil {
		return TaskDataMetadata{}, err
	}
	if metadata.Key != request.Key || metadata.SizeBytes != request.SizeBytes || metadata.MediaType != request.MediaType || metadata.Readiness != TaskDataStored {
		return TaskDataMetadata{}, fmt.Errorf("upload response does not describe the stored object")
	}
	return metadata, nil
}

func (c *ConnectTaskDataClient) FinalizeTaskResult(ctx context.Context, endpoint string, request FinalizeTaskResultRequest) (FinalizeTaskResultResponse, error) {
	digest, err := TaskDataFinalizeResultBodyDigest(request)
	if err != nil {
		return FinalizeTaskResultResponse{}, err
	}
	if err := validateSignedTaskDataRequest(request.Auth, "FinalizeTaskResult", digest); err != nil {
		return FinalizeTaskResultResponse{}, err
	}
	if request.Auth.Requester != request.Receipt.WorkerOperatorAddress || request.Auth.ChainID != request.Receipt.ChainID {
		return FinalizeTaskResultResponse{}, fmt.Errorf("finalize requester does not match worker receipt")
	}
	client, err := c.ingress(endpoint)
	if err != nil {
		return FinalizeTaskResultResponse{}, err
	}
	req := connect.NewRequest(&nexusv1.FinalizeTaskResultRequest{TaskHash: request.TaskHash, SessionId: request.SessionID, TaskId: request.TaskID, Receipt: signedInferReceiptToProto(request.Receipt), RequestAuth: taskDataRequestAuthToProto(request.Auth), EvidenceKind: sharedv1.EvidenceKind(request.EvidenceKind)})
	c.authorize(req.Header())
	response, err := client.FinalizeTaskResult(ctx, req)
	if err != nil {
		return FinalizeTaskResultResponse{}, classifyConnectError(nexusv1connect.IngressAPIFinalizeTaskResultProcedure, err)
	}
	if response == nil || response.Msg == nil || !response.Msg.Accepted {
		return FinalizeTaskResultResponse{}, fmt.Errorf("task result finalization was not accepted")
	}
	key := TaskDataKey{TaskHash: request.TaskHash, SessionID: request.SessionID, TaskID: request.TaskID, Kind: DataKindOutput, ContentHash: request.Receipt.OutputHash}
	output, err := validateFinalizeConfirmation(response.Msg.OutputConfirmation, request.Auth, key, request.Receipt.OutputSizeBytes)
	if err != nil {
		return FinalizeTaskResultResponse{}, err
	}
	// One finalize closes one Worker bundle, so exactly one bundle confirmation
	// comes back: the one for the requested kind's commitment.
	confirmations := response.Msg.EvidenceBundleConfirmations
	if len(confirmations) != 1 {
		return FinalizeTaskResultResponse{}, fmt.Errorf("finalize of one Worker bundle requires exactly one bundle confirmation, got %d", len(confirmations))
	}
	var commitment *EvidenceCommitment
	for i := range request.Receipt.RequiredEvidenceCommitments {
		if request.Receipt.RequiredEvidenceCommitments[i].EvidenceKind == request.EvidenceKind {
			commitment = &request.Receipt.RequiredEvidenceCommitments[i]
		}
	}
	if commitment == nil {
		return FinalizeTaskResultResponse{}, fmt.Errorf("receipt commits no evidence of kind %d", request.EvidenceKind)
	}
	key = EvidenceObjectKey(request.TaskHash, request.SessionID, request.TaskID, DataKindEvidenceManifest, hex.EncodeToString(commitment.EvidenceHashOrRoot[:]), EvidenceProducerWorker, 1, request.Receipt.WorkerOperatorAddress, commitment.EvidenceKind)
	// artifact_total_size_bytes counts every artifact, so for the A-level bundle
	// it also counts generation_params, which the committed encoded_size_bytes
	// does not. The caller checks the exact total against its own manifest.
	if confirmations[0] == nil || confirmations[0].SizeBytes == 0 || confirmations[0].ArtifactTotalSizeBytes < commitment.EncodedSizeBytes {
		return FinalizeTaskResultResponse{}, fmt.Errorf("Worker bundle confirmation must bind manifest size and cover the committed artifacts")
	}
	confirmation, err := validateFinalizeConfirmation(confirmations[0], request.Auth, key, confirmations[0].SizeBytes)
	if err != nil {
		return FinalizeTaskResultResponse{}, err
	}
	return FinalizeTaskResultResponse{Idempotent: response.Msg.Idempotent, OutputConfirmation: output, EvidenceBundleConfirmations: []StorageConfirmation{confirmation}}, nil
}

func (c *ConnectTaskDataClient) FinalizeVerifierEvidence(ctx context.Context, endpoint string, request FinalizeVerifierEvidenceRequest) (FinalizeVerifierEvidenceResponse, error) {
	digest, err := TaskDataFinalizeVerifierBodyDigest(request)
	if err != nil {
		return FinalizeVerifierEvidenceResponse{}, err
	}
	if err := validateSignedTaskDataRequest(request.Auth, "FinalizeVerifierEvidence", digest); err != nil {
		return FinalizeVerifierEvidenceResponse{}, err
	}
	if request.Auth.Requester != request.VerifierOperator || request.Auth.ChainID != request.Receipt.ChainID {
		return FinalizeVerifierEvidenceResponse{}, fmt.Errorf("finalize requester does not match verifier receipt")
	}
	receipt, err := ResultReceiptProto(request.Receipt)
	if err != nil {
		return FinalizeVerifierEvidenceResponse{}, err
	}
	client, err := c.ingress(endpoint)
	if err != nil {
		return FinalizeVerifierEvidenceResponse{}, err
	}
	req := connect.NewRequest(&nexusv1.FinalizeVerifierEvidenceRequest{TaskHash: request.TaskHash, SessionId: request.SessionID, TaskId: request.TaskID, VerifyRound: request.VerifyRound, VerifierOperator: request.VerifierOperator, Receipt: receipt, RequestAuth: taskDataRequestAuthToProto(request.Auth)})
	c.authorize(req.Header())
	response, err := client.FinalizeVerifierEvidence(ctx, req)
	if err != nil {
		return FinalizeVerifierEvidenceResponse{}, classifyConnectError(nexusv1connect.IngressAPIFinalizeVerifierEvidenceProcedure, err)
	}
	if response == nil || response.Msg == nil || !response.Msg.Accepted {
		return FinalizeVerifierEvidenceResponse{}, fmt.Errorf("verifier evidence finalization was not accepted")
	}
	key := EvidenceObjectKey(request.TaskHash, request.SessionID, request.TaskID, DataKindEvidenceManifest, hex.EncodeToString(request.Receipt.VerifierEvidenceBundleHash), EvidenceProducerVerifier, request.VerifyRound, request.VerifierOperator, nodewire.EvidenceKindVerifierValueOpening)
	confirmation, err := validateFinalizeConfirmation(response.Msg.EvidenceBundleConfirmation, request.Auth, key, request.Receipt.VerifierEvidenceManifestSizeBytes)
	if err != nil {
		return FinalizeVerifierEvidenceResponse{}, err
	}
	return FinalizeVerifierEvidenceResponse{Idempotent: response.Msg.Idempotent, EvidenceBundleConfirmation: confirmation}, nil
}

func validateFinalizeConfirmation(wire *nexusv1.BuilderStorageConfirmationV1, auth TaskDataRequestAuth, key TaskDataKey, size uint64) (StorageConfirmation, error) {
	confirmation, err := storageConfirmationFromProto(wire)
	if err != nil {
		return StorageConfirmation{}, err
	}
	if confirmation.ChainID != auth.ChainID || confirmation.BuilderOperator != auth.BuilderAddress || confirmation.Key != key || confirmation.SizeBytes != size {
		return StorageConfirmation{}, fmt.Errorf("finalize storage confirmation does not match requested object")
	}
	return confirmation, nil
}

func (c *ConnectTaskDataClient) SubmitInferReceipt(ctx context.Context, endpoint string, request SubmitInferReceiptRequest) error {
	if err := validateSubmitInferReceiptRequest(request); err != nil {
		return err
	}
	digest, err := InferReceiptSigningDigest(request.Receipt)
	if err != nil {
		return err
	}
	client, err := c.ingress(endpoint)
	if err != nil {
		return err
	}
	req := connect.NewRequest(&nexusv1.SubmitInferReceiptRequest{Receipt: signedInferReceiptToProto(request.Receipt)})
	c.authorize(req.Header())
	response, err := client.SubmitInferReceipt(ctx, req)
	if err != nil {
		return classifyConnectError(nexusv1connect.IngressAPISubmitInferReceiptProcedure, err)
	}
	if response == nil || response.Msg == nil || !response.Msg.RelayAccepted || response.Msg.InferReceiptHash != hex.EncodeToString(digest[:]) {
		return fmt.Errorf("infer receipt relay acknowledgment has wrong material digest")
	}
	return nil
}

func (c *ConnectTaskDataClient) SubmitVerifyCommit(ctx context.Context, endpoint string, request SubmitVerifyCommitRequest) (VerifyRelayAck, error) {
	if err := ValidateSignedVerifyCommit(request.Commit); err != nil {
		return VerifyRelayAck{}, err
	}
	digest, err := nodewire.VerifyCommitSigningDigest(request.Commit)
	if err != nil {
		return VerifyRelayAck{}, err
	}
	client, err := c.ingress(endpoint)
	if err != nil {
		return VerifyRelayAck{}, err
	}
	req := connect.NewRequest(&nexusv1.SubmitVerifyCommitRequest{Commit: signedVerifyCommitToProto(request.Commit)})
	c.authorize(req.Header())
	response, err := client.SubmitVerifyCommit(ctx, req)
	if err != nil {
		return VerifyRelayAck{}, classifyConnectError(nexusv1connect.IngressAPISubmitVerifyCommitProcedure, err)
	}
	if response == nil || response.Msg == nil || !response.Msg.RelayAccepted || response.Msg.VerifyCommitSigningDigest != hex.EncodeToString(digest[:]) {
		return VerifyRelayAck{}, fmt.Errorf("verify commit relay acknowledgment has wrong material digest")
	}
	raw, err := taskDataHash("commit_key", response.Msg.CommitKey)
	if err != nil {
		return VerifyRelayAck{}, err
	}
	var key codec.Hash
	copy(key[:], raw)
	expectedKey, err := nodewire.VerifyCommitKey(request.Commit.ChainID, request.Commit.TaskID, request.Commit.VerifyRound, request.Commit.VerifierOperatorAddress)
	if err != nil {
		return VerifyRelayAck{}, err
	}
	if key != expectedKey {
		return VerifyRelayAck{}, fmt.Errorf("verify commit relay acknowledgment has wrong commit key")
	}
	return VerifyRelayAck{Idempotent: response.Msg.Idempotent, CommitKey: key, SigningDigest: digest}, nil
}

func (c *ConnectTaskDataClient) SubmitVerifyResult(ctx context.Context, endpoint string, request SubmitVerifyResultRequest) (VerifyRelayAck, error) {
	receipt, err := ResultReceiptProto(request.Receipt)
	if err != nil {
		return VerifyRelayAck{}, err
	}
	digest, err := nodewire.ResultReceiptSigningDigest(request.Receipt)
	if err != nil {
		return VerifyRelayAck{}, err
	}
	client, err := c.ingress(endpoint)
	if err != nil {
		return VerifyRelayAck{}, err
	}
	req := connect.NewRequest(&nexusv1.SubmitVerifyResultRequest{Receipt: receipt})
	c.authorize(req.Header())
	response, err := client.SubmitVerifyResult(ctx, req)
	if err != nil {
		return VerifyRelayAck{}, classifyConnectError(nexusv1connect.IngressAPISubmitVerifyResultProcedure, err)
	}
	if response == nil || response.Msg == nil || !response.Msg.RelayAccepted || response.Msg.ResultReceiptSigningDigest != hex.EncodeToString(digest[:]) {
		return VerifyRelayAck{}, fmt.Errorf("verify result relay acknowledgment has wrong material digest")
	}
	raw, err := taskDataHash("result_payload_hash", response.Msg.ResultPayloadHash)
	if err != nil {
		return VerifyRelayAck{}, err
	}
	var payload codec.Hash
	copy(payload[:], raw)
	return VerifyRelayAck{Idempotent: response.Msg.Idempotent, SigningDigest: digest, ResultPayloadHash: payload}, nil
}

func signedVerifyCommitToProto(commit nodewire.VerifyCommitV1) *taskv1.VerifyCommitV1 {
	return &taskv1.VerifyCommitV1{SchemaVersion: commit.SchemaVersion, ChainId: commit.ChainID, TaskId: append([]byte(nil), commit.TaskID...), VerifyRound: commit.VerifyRound, VerifierOperatorAddress: commit.VerifierOperatorAddress, ServiceAuthorizationNonce: commit.ServiceAuthorizationNonce, CommitHash: append([]byte(nil), commit.CommitHash...), ExpiryHeight: commit.ExpiryHeight, ServiceSignature: append([]byte(nil), commit.ServiceSignature...)}
}

func (c *ConnectTaskDataClient) ingress(endpoint string) (nexusv1connect.IngressAPIClient, error) {
	if c == nil || c.httpClient == nil {
		return nil, fmt.Errorf("task data HTTP client is required")
	}
	baseURL, err := c.dialOrigin(endpoint)
	if err != nil {
		return nil, err
	}
	return nexusv1connect.NewIngressAPIClient(c.httpClient, baseURL, connect.WithReadMaxBytes(maxNexusResponseBytes)), nil
}

// dialOrigin resolves one published endpoint to the origin this client dials,
// or refuses it. It is separate from ingress so the transport decision is
// observable on its own: the Connect client ingress returns does not expose the
// base URL it was built with.
func (c *ConnectTaskDataClient) dialOrigin(endpoint string) (string, error) {
	parsed, err := ParseNexusEndpoint(endpoint)
	if err != nil {
		return "", fmt.Errorf("task data endpoint: %w", err)
	}
	// grpc:// and grpcs:// are dialled at their http(s) origin. The deployed
	// ingress is connect-go, so the Connect protocol reaches it over HTTP/1.1
	// with no protocol option; the scheme only chose TLS or plaintext.
	//
	// The downgrade runs before the plaintext gate, never instead of it: a
	// descriptor that asked for TLS and is dialled in the clear is exactly the
	// case the gate exists for.
	if c.transport.DowngradeEndpointTLS {
		parsed = parsed.WithoutTLS()
	}
	baseURL := parsed.DialURI
	if parsed.Plaintext && !c.transport.AllowInsecureEndpoint {
		return "", fmt.Errorf("task data endpoint %s is plaintext: set nexus.allow_insecure_descriptor to accept it", baseURL)
	}
	return baseURL, nil
}

func (c *ConnectTaskDataClient) authorize(header http.Header) {
	if c.token != "" {
		header.Set("Authorization", "Bearer "+c.token)
	}
}

func validateSignedTaskDataRequest(auth TaskDataRequestAuth, method string, body codec.Hash) error {
	if auth.Method != TaskDataProcedure(method) || auth.BodyDigest != body {
		return fmt.Errorf("task data authentication does not match RPC body")
	}
	if _, err := TaskDataRequestSigningHash(auth); err != nil {
		return err
	}
	return validateCompactSignature(auth.Signature)
}

func validateSubmitInferReceiptRequest(request SubmitInferReceiptRequest) error {
	return validateSignedInferReceipt(request.Receipt)
}

func taskDataMetadataFromProto(wire *nexusv1.TaskDataObjectMetadataV1) (TaskDataMetadata, error) {
	if wire == nil {
		return TaskDataMetadata{}, fmt.Errorf("task metadata is missing")
	}
	key, err := taskDataKeyFromProto(wire.ObjectRef)
	if err != nil {
		return TaskDataMetadata{}, err
	}
	readiness := TaskDataReadiness(wire.Readiness)
	if readiness != TaskDataStored && readiness != TaskDataReady {
		return TaskDataMetadata{}, fmt.Errorf("task metadata readiness is unspecified or unknown")
	}
	if key.Kind == DataKindEvidenceArtifact && wire.MediaType != "" {
		return TaskDataMetadata{}, fmt.Errorf("evidence artifact metadata must omit media_type")
	}
	if key.Kind == DataKindOutput && readiness == TaskDataReady && wire.OutputLeafCount == 0 {
		return TaskDataMetadata{}, fmt.Errorf("READY OUTPUT requires signed chunk boundaries and leaf count")
	}
	if len(wire.ChunkLengths) > 0 || wire.OutputLeafCount > 0 {
		if key.Kind != DataKindOutput || readiness != TaskDataReady || uint64(len(wire.ChunkLengths)) != wire.OutputLeafCount {
			return TaskDataMetadata{}, fmt.Errorf("chunk boundaries are only valid for READY OUTPUT")
		}
		var total uint64
		for _, length := range wire.ChunkLengths {
			if total > ^uint64(0)-uint64(length) {
				return TaskDataMetadata{}, fmt.Errorf("output chunk lengths overflow")
			}
			total += uint64(length)
		}
		if total != wire.SizeBytes {
			return TaskDataMetadata{}, fmt.Errorf("output chunk lengths do not match size")
		}
	}
	return TaskDataMetadata{Key: key, SizeBytes: wire.SizeBytes, MediaType: wire.MediaType, Readiness: readiness, ChunkLengths: append([]uint32(nil), wire.ChunkLengths...), OutputLeafCount: wire.OutputLeafCount}, nil
}

func storageConfirmationFromProto(wire *nexusv1.BuilderStorageConfirmationV1) (StorageConfirmation, error) {
	if wire == nil {
		return StorageConfirmation{}, fmt.Errorf("storage confirmation is missing")
	}
	key, err := taskDataKeyFromProto(wire.ObjectRef)
	if err != nil {
		return StorageConfirmation{}, err
	}
	c := StorageConfirmation{SchemaVersion: wire.SchemaVersion, ChainID: wire.ChainId, BuilderOperator: wire.BuilderOperatorAddress, ServiceAuthorizationNonce: wire.ServiceAuthorizationNonce, Key: key, SizeBytes: wire.SizeBytes, ArtifactTotalSizeBytes: wire.ArtifactTotalSizeBytes, RetentionUntilHeight: wire.RetentionUntilHeight, Signature: append([]byte(nil), wire.ServiceSignature...)}
	if _, err := StorageConfirmationSigningHash(c); err != nil {
		return StorageConfirmation{}, err
	}
	if err := validateCompactSignature(c.Signature); err != nil {
		return StorageConfirmation{}, err
	}
	return c, nil
}

func taskDataKeyToProto(key TaskDataKey) *nexusv1.TaskDataObjectRefV1 {
	result := &nexusv1.TaskDataObjectRefV1{TaskHash: key.TaskHash, SessionId: key.SessionID, TaskId: key.TaskID, ObjectKind: nexusv1.TaskDataObjectKind(key.Kind), ContentHash: key.ContentHash, EvidenceProducerKind: nexusv1.EvidenceProducerKindV1(key.EvidenceProducerKind), VerifyRound: key.VerifyRound, EvidenceKind: sharedv1.EvidenceKind(key.EvidenceKind)}
	if key.ProducerOperator != "" {
		operator := key.ProducerOperator
		result.ProducerOperator = &operator
	}
	return result
}

func taskDataKeyFromProto(wire *nexusv1.TaskDataObjectRefV1) (TaskDataKey, error) {
	if wire == nil {
		return TaskDataKey{}, fmt.Errorf("task data object ref is required")
	}
	key := TaskDataKey{TaskHash: wire.TaskHash, SessionID: wire.SessionId, TaskID: wire.TaskId, Kind: DataKind(wire.ObjectKind), ContentHash: wire.ContentHash, EvidenceProducerKind: EvidenceProducerKind(wire.EvidenceProducerKind), VerifyRound: wire.VerifyRound, ProducerOperator: wire.GetProducerOperator(), EvidenceKind: nodewire.EvidenceKind(wire.EvidenceKind)}
	if wire.ProducerOperator != nil && key.ProducerOperator == "" {
		return TaskDataKey{}, fmt.Errorf("present producer operator cannot be empty")
	}
	if err := ValidateTaskDataKey(key); err != nil {
		return TaskDataKey{}, err
	}
	return key, nil
}

func taskDataRangeToProto(bounds *TaskDataRange) *nexusv1.ByteRangeV1 {
	if bounds == nil {
		return nil
	}
	return &nexusv1.ByteRangeV1{Offset: bounds.Offset, Length: bounds.Length}
}

func taskDataRequestAuthToProto(auth TaskDataRequestAuth) *nexusv1.TaskDataRequestAuthV1 {
	return &nexusv1.TaskDataRequestAuthV1{SchemaVersion: auth.SchemaVersion, ChainId: auth.ChainID, BuilderOperatorAddress: auth.BuilderAddress, RpcMethod: auth.Method, BodyDigest: hex.EncodeToString(auth.BodyDigest[:]), RequesterKind: nexusv1.TaskDataRequesterKindV1(auth.RequesterKind), RequesterAddress: auth.Requester, ServiceAuthorizationNonce: auth.ServiceAuthorizationNonce, RequestNonce: append([]byte(nil), auth.RequestNonce...), ExpiryHeight: auth.ExpiresAtHeight, Signature: append([]byte(nil), auth.Signature...)}
}

func signedInferReceiptToProto(receipt SignedInferReceipt) *taskv1.InferReceiptV3 {
	taskID, _ := hex.DecodeString(receipt.TaskID)
	taskHash, _ := hex.DecodeString(receipt.TaskHash)
	generation, _ := hex.DecodeString(receipt.GenerationParamsDigest)
	output, _ := hex.DecodeString(receipt.OutputHash)
	signature, _ := hex.DecodeString(receipt.ServiceSignature)
	zero := make([]byte, 32)
	result := &taskv1.InferReceiptV3{SchemaVersion: receipt.SchemaVersion, ChainId: receipt.ChainID, TaskId: taskID, TaskHash: taskHash, WorkerOperatorAddress: receipt.WorkerOperatorAddress, ServiceAuthorizationNonce: receipt.ServiceAuthorizationNonce, GenerationParamsDigest: generation, OutputHash: output, OutputSizeBytes: receipt.OutputSizeBytes, OutputLeafCount: receipt.OutputLeafCount, ExpiryHeight: receipt.ExpiryHeight, ServiceSignature: signature, GeneratedTokenCount: receipt.GeneratedTokenCount,
		OutputKeyCommitment: zero, WorkerTokenKeyCommitment: zero, WorkerValueKeyCommitment: zero, CiphertextOutputRoot: zero}
	for _, item := range receipt.RequiredEvidenceCommitments {
		result.RequiredEvidenceCommitments = append(result.RequiredEvidenceCommitments, &taskv1.EvidenceCommitmentV1{EvidenceKind: sharedv1.EvidenceKind(item.EvidenceKind), EvidenceHashOrRoot: append([]byte(nil), item.EvidenceHashOrRoot[:]...), EncodedSizeBytes: item.EncodedSizeBytes})
	}
	return result
}

func signedInferReceiptFromProto(wire *taskv1.InferReceiptV3) (SignedInferReceipt, error) {
	if wire == nil {
		return SignedInferReceipt{}, fmt.Errorf("infer receipt is missing")
	}
	// The key slots are not carried by SignedInferReceipt, so a non-zero one
	// would be silently dropped; refuse it instead.
	for name, slot := range map[string][]byte{"output_key_commitment": wire.OutputKeyCommitment, "worker_token_key_commitment": wire.WorkerTokenKeyCommitment, "worker_value_key_commitment": wire.WorkerValueKeyCommitment, "ciphertext_output_root": wire.CiphertextOutputRoot} {
		if len(slot) != 32 || !bytes.Equal(slot, make([]byte, 32)) {
			return SignedInferReceipt{}, fmt.Errorf("infer receipt %s must be ZERO32 while only PLAINTEXT is accepted", name)
		}
	}
	receipt := SignedInferReceipt{SchemaVersion: wire.SchemaVersion, ChainID: wire.ChainId, TaskID: hex.EncodeToString(wire.TaskId), TaskHash: hex.EncodeToString(wire.TaskHash), WorkerOperatorAddress: wire.WorkerOperatorAddress, ServiceAuthorizationNonce: wire.ServiceAuthorizationNonce, GenerationParamsDigest: hex.EncodeToString(wire.GenerationParamsDigest), OutputHash: hex.EncodeToString(wire.OutputHash), OutputSizeBytes: wire.OutputSizeBytes, OutputLeafCount: wire.OutputLeafCount, ExpiryHeight: wire.ExpiryHeight, ServiceSignature: hex.EncodeToString(wire.ServiceSignature), GeneratedTokenCount: wire.GeneratedTokenCount}
	for _, item := range wire.RequiredEvidenceCommitments {
		if item == nil || len(item.EvidenceHashOrRoot) != 32 {
			return SignedInferReceipt{}, fmt.Errorf("infer evidence commitment has invalid hash")
		}
		var hash codec.Hash
		copy(hash[:], item.EvidenceHashOrRoot)
		receipt.RequiredEvidenceCommitments = append(receipt.RequiredEvidenceCommitments, EvidenceCommitment{EvidenceKind: nodewire.EvidenceKind(item.EvidenceKind), EvidenceHashOrRoot: hash, EncodedSizeBytes: item.EncodedSizeBytes})
	}
	if err := validateSignedInferReceipt(receipt); err != nil {
		return SignedInferReceipt{}, err
	}
	return receipt, nil
}
