package builderclient

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	"google.golang.org/protobuf/proto"
)

func taskDataTestConfirmation(t *testing.T, pair taskDataTestKeyPair, auth TaskDataRequestAuth, key TaskDataKey, size, total uint64) *nexusv1.BuilderStorageConfirmationV1 {
	t.Helper()
	c := StorageConfirmation{SchemaVersion: 1, ChainID: auth.ChainID, BuilderOperator: auth.BuilderAddress, ServiceAuthorizationNonce: 17, Key: key, SizeBytes: size, ArtifactTotalSizeBytes: total, RetentionUntilHeight: 900}
	digest, err := StorageConfirmationSigningHash(c)
	if err != nil {
		t.Fatal(err)
	}
	return &nexusv1.BuilderStorageConfirmationV1{SchemaVersion: c.SchemaVersion, ChainId: c.ChainID, BuilderOperatorAddress: c.BuilderOperator, ServiceAuthorizationNonce: c.ServiceAuthorizationNonce, ObjectRef: taskDataKeyToProto(c.Key), SizeBytes: c.SizeBytes, ArtifactTotalSizeBytes: c.ArtifactTotalSizeBytes, RetentionUntilHeight: c.RetentionUntilHeight, ServiceSignature: pair.sign(t, digest)}
}

func TestV040FinalizeResultRequiresCompleteScopedConfirmations(t *testing.T) {
	pair := newTaskDataTestKeyPair(t)
	receipt := taskDataTestReceipt(t, pair, "chain-A", []byte("result"))
	request := FinalizeTaskResultRequest{TaskHash: receipt.TaskHash, SessionID: strings.Repeat("11", 32), TaskID: receipt.TaskID, Receipt: receipt, EvidenceKind: nodewire.EvidenceKindWorkerValueOpening}
	digest, err := TaskDataFinalizeResultBodyDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	outputKey := TaskDataKey{TaskHash: request.TaskHash, SessionID: request.SessionID, TaskID: request.TaskID, Kind: DataKindOutput, ContentHash: receipt.OutputHash}
	request.Auth = taskDataTestRequestAuth(t, pair, "FinalizeTaskResult", outputKey, digest)
	commitment := receipt.RequiredEvidenceCommitments[0]
	bundleKey := EvidenceObjectKey(request.TaskHash, request.SessionID, request.TaskID, DataKindEvidenceManifest, hex.EncodeToString(commitment.EvidenceHashOrRoot[:]), EvidenceProducerWorker, 1, receipt.WorkerOperatorAddress, nodewire.EvidenceKindWorkerValueOpening)
	base := &nexusv1.FinalizeTaskResultResponse{Accepted: true, Idempotent: true, OutputConfirmation: taskDataTestConfirmation(t, pair, request.Auth, outputKey, receipt.OutputSizeBytes, 0), EvidenceBundleConfirmations: []*nexusv1.BuilderStorageConfirmationV1{taskDataTestConfirmation(t, pair, request.Auth, bundleKey, 512, commitment.EncodedSizeBytes)}}
	cases := map[string]func(*nexusv1.FinalizeTaskResultResponse){
		"valid":          func(*nexusv1.FinalizeTaskResultResponse) {},
		"not accepted":   func(r *nexusv1.FinalizeTaskResultResponse) { r.Accepted = false },
		"missing output": func(r *nexusv1.FinalizeTaskResultResponse) { r.OutputConfirmation = nil },
		"missing bundle": func(r *nexusv1.FinalizeTaskResultResponse) { r.EvidenceBundleConfirmations = nil },
		"extra bundle": func(r *nexusv1.FinalizeTaskResultResponse) {
			r.EvidenceBundleConfirmations = append(r.EvidenceBundleConfirmations, r.EvidenceBundleConfirmations[0])
		},
		"wrong object hash": func(r *nexusv1.FinalizeTaskResultResponse) {
			r.OutputConfirmation.ObjectRef.ContentHash = strings.Repeat("99", 32)
		},
		"wrong task hash": func(r *nexusv1.FinalizeTaskResultResponse) {
			r.OutputConfirmation.ObjectRef.TaskHash = strings.Repeat("99", 32)
		},
		"wrong size":     func(r *nexusv1.FinalizeTaskResultResponse) { r.OutputConfirmation.SizeBytes++ },
		"empty manifest": func(r *nexusv1.FinalizeTaskResultResponse) { r.EvidenceBundleConfirmations[0].SizeBytes = 0 },
		// The total may exceed the committed size (generation_params is not
		// committed) but never fall short of it.
		"short artifact total": func(r *nexusv1.FinalizeTaskResultResponse) {
			r.EvidenceBundleConfirmations[0].ArtifactTotalSizeBytes = commitment.EncodedSizeBytes - 1
		},
		"wrong producer": func(r *nexusv1.FinalizeTaskResultResponse) {
			operator := "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"
			r.EvidenceBundleConfirmations[0].ObjectRef.ProducerOperator = &operator
		},
		"wrong builder": func(r *nexusv1.FinalizeTaskResultResponse) {
			r.OutputConfirmation.BuilderOperatorAddress = "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"
		},
		"zero nonce":     func(r *nexusv1.FinalizeTaskResultResponse) { r.OutputConfirmation.ServiceAuthorizationNonce = 0 },
		"zero signature": func(r *nexusv1.FinalizeTaskResultResponse) { r.OutputConfirmation.ServiceSignature = make([]byte, 64) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			answer := proto.Clone(base).(*nexusv1.FinalizeTaskResultResponse)
			mutate(answer)
			server := newTaskDataTestServer(t, &taskDataTestHandler{finalize: func(_ context.Context, r *connect.Request[nexusv1.FinalizeTaskResultRequest]) (*connect.Response[nexusv1.FinalizeTaskResultResponse], error) {
				if !proto.Equal(r.Msg.Receipt, signedInferReceiptToProto(receipt)) || r.Msg.RequestAuth.BodyDigest != hex.EncodeToString(digest[:]) {
					t.Error("finalize receipt or authentication changed")
				}
				return connect.NewResponse(answer), nil
			}})
			got, err := newTestTaskDataClient(server.Client(), "").FinalizeTaskResult(context.Background(), server.URL, request)
			if (err == nil) != (name == "valid") {
				t.Fatalf("result=%+v error=%v", got, err)
			}
			if err == nil && (!got.Idempotent || got.OutputConfirmation.ServiceAuthorizationNonce != 17 || got.EvidenceBundleConfirmations[0].ArtifactTotalSizeBytes != commitment.EncodedSizeBytes) {
				t.Fatal("finalize response fields were lost")
			}
		})
	}
}

func taskDataTestResultReceipt(t *testing.T, pair taskDataTestKeyPair) nodewire.ResultReceiptV3 {
	t.Helper()
	receipt := nodewire.ResultReceiptV3{SchemaVersion: nodewire.ResultReceiptSchemaVersionV3, ChainID: "chain-A", TaskID: mustDecodeHex(t, taskDataTestTaskID), VerifyRound: 2, VerifierOperatorAddress: pair.address(t), ServiceAuthorizationNonce: 9, GenerationParamsDigest: mustDecodeHex(t, strings.Repeat("33", 32)), MetricRoot: mustDecodeHex(t, strings.Repeat("44", 32)), MetricSummary: nodewire.MetricSummaryV1{FiniteCount: 3}, AggregateProofHash: mustDecodeHex(t, strings.Repeat("55", 32)), VerifierEvidenceBundleHash: mustDecodeHex(t, strings.Repeat("66", 32)), VerifierEvidenceManifestSizeBytes: 512, Salt: mustDecodeHex(t, strings.Repeat("77", 32)), ExpiryHeight: 400, VerifierValueRoot: mustDecodeHex(t, strings.Repeat("88", 32)), MetricLeafCount: 3, VerifierEvidenceKeyCommitment: make([]byte, 32)}
	digest, err := nodewire.ResultReceiptSigningDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.ServiceSignature = pair.sign(t, digest)
	return receipt
}

func TestV040FinalizeVerifierBindsRoundProducerReceiptAndSignature(t *testing.T) {
	pair := newTaskDataTestKeyPair(t)
	receipt := taskDataTestResultReceipt(t, pair)
	request := FinalizeVerifierEvidenceRequest{TaskHash: strings.Repeat("22", 32), SessionID: strings.Repeat("11", 32), TaskID: taskDataTestTaskID, VerifyRound: receipt.VerifyRound, VerifierOperator: receipt.VerifierOperatorAddress, Receipt: receipt}
	digest, err := TaskDataFinalizeVerifierBodyDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	key := EvidenceObjectKey(request.TaskHash, request.SessionID, request.TaskID, DataKindEvidenceManifest, hex.EncodeToString(receipt.VerifierEvidenceBundleHash), EvidenceProducerVerifier, receipt.VerifyRound, receipt.VerifierOperatorAddress, nodewire.EvidenceKindVerifierValueOpening)
	request.Auth = taskDataTestRequestAuth(t, pair, "FinalizeVerifierEvidence", key, digest)
	server := newTaskDataTestServer(t, &taskDataTestHandler{finalizeVerifier: func(_ context.Context, r *connect.Request[nexusv1.FinalizeVerifierEvidenceRequest]) (*connect.Response[nexusv1.FinalizeVerifierEvidenceResponse], error) {
		expected, err := ResultReceiptProto(receipt)
		if err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(r.Msg.Receipt, expected) || r.Msg.VerifyRound != 2 || r.Msg.VerifierOperator != receipt.VerifierOperatorAddress {
			t.Error("verifier finalize lost imported receipt scope")
		}
		return connect.NewResponse(&nexusv1.FinalizeVerifierEvidenceResponse{Accepted: true, EvidenceBundleConfirmation: taskDataTestConfirmation(t, pair, request.Auth, key, 512, 100)}), nil
	}})
	result, err := newTestTaskDataClient(server.Client(), "").FinalizeVerifierEvidence(context.Background(), server.URL, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.EvidenceBundleConfirmation.Key != key {
		t.Fatal("verifier confirmation key changed")
	}
	for name, mutate := range map[string]func(*FinalizeVerifierEvidenceRequest){
		"round": func(r *FinalizeVerifierEvidenceRequest) { r.VerifyRound = 1 },
		"operator": func(r *FinalizeVerifierEvidenceRequest) {
			r.VerifierOperator = "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"
		},
		"signature": func(r *FinalizeVerifierEvidenceRequest) {
			r.Receipt.ServiceSignature = append([]byte(nil), r.Receipt.ServiceSignature...)
			r.Receipt.ServiceSignature[0] ^= 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := request
			mutate(&bad)
			transport := &countingTaskDataHTTPClient{}
			if _, err := newTestTaskDataClient(transport, "").FinalizeVerifierEvidence(context.Background(), "http://invalid", bad); err == nil || transport.calls != 0 {
				t.Fatal("mismatched finalize reached network")
			}
		})
	}
}

func TestV040VerifyCommitRelayChecksBothReturnedIdentities(t *testing.T) {
	pair := newTaskDataTestKeyPair(t)
	commit := nodewire.VerifyCommitV1{SchemaVersion: 1, ChainID: "chain-A", TaskID: mustDecodeHex(t, taskDataTestTaskID), VerifyRound: 1, VerifierOperatorAddress: pair.address(t), ServiceAuthorizationNonce: 9, CommitHash: mustDecodeHex(t, strings.Repeat("33", 32)), ExpiryHeight: 400}
	digest, err := nodewire.VerifyCommitSigningDigest(commit)
	if err != nil {
		t.Fatal(err)
	}
	commit.ServiceSignature = pair.sign(t, digest)
	key, err := nodewire.VerifyCommitKey(commit.ChainID, commit.TaskID, commit.VerifyRound, commit.VerifierOperatorAddress)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "digest", "key"} {
		t.Run("response "+bad, func(t *testing.T) {
			server := newTaskDataTestServer(t, &taskDataTestHandler{commit: func(_ context.Context, r *connect.Request[nexusv1.SubmitVerifyCommitRequest]) (*connect.Response[nexusv1.SubmitVerifyCommitResponse], error) {
				if !proto.Equal(r.Msg.Commit, signedVerifyCommitToProto(commit)) {
					t.Error("commit changed")
				}
				gotDigest, gotKey := digest, key
				if bad == "digest" {
					gotDigest[0] ^= 1
				}
				if bad == "key" {
					gotKey[0] ^= 1
				}
				return connect.NewResponse(&nexusv1.SubmitVerifyCommitResponse{RelayAccepted: true, CommitKey: hex.EncodeToString(gotKey[:]), VerifyCommitSigningDigest: hex.EncodeToString(gotDigest[:]), Idempotent: true}), nil
			}})
			ack, err := newTestTaskDataClient(server.Client(), "").SubmitVerifyCommit(context.Background(), server.URL, SubmitVerifyCommitRequest{Commit: commit})
			if (err == nil) != (bad == "") {
				t.Fatalf("ack=%+v err=%v", ack, err)
			}
		})
	}
}

func TestV040AuthenticationRejectsMalformedSignatureBeforeNetwork(t *testing.T) {
	pair := newTaskDataTestKeyPair(t)
	key := taskDataTestObjectKey()
	digest, err := TaskDataMetadataBodyDigest(key)
	if err != nil {
		t.Fatal(err)
	}
	auth := taskDataTestRequestAuth(t, pair, "GetTaskDataMetadata", key, digest)
	for _, signature := range [][]byte{nil, make([]byte, 64), make([]byte, 65)} {
		auth.Signature = signature
		transport := &countingTaskDataHTTPClient{}
		if _, err := newTestTaskDataClient(transport, "").GetTaskDataMetadata(context.Background(), "http://invalid", GetTaskDataMetadataRequest{Key: key, Auth: auth}); err == nil || transport.calls != 0 {
			t.Fatal("malformed signature reached network")
		}
	}
	changed := auth
	changed.BodyDigest = codec.Hash{}
	if _, err := TaskDataRequestSigningHash(changed); err == nil {
		t.Fatal("unsigned body digest accepted")
	}
}
