package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/evidence"
	"github.com/SingaXYZ/cortex/internal/identity"
	"github.com/SingaXYZ/cortex/internal/modelservice"
	"github.com/SingaXYZ/cortex/internal/nodewire"
	"github.com/SingaXYZ/cortex/internal/store"
	"github.com/SingaXYZ/cortex/internal/store/layout"
	"github.com/SingaXYZ/cortex/internal/taskfacts"
	"github.com/SingaXYZ/cortex/internal/worker"
	"google.golang.org/protobuf/proto"
)

type fakeProfileReceiptRelay struct {
	*builderclient.FakeClient
	receipts    []builderclient.SignedInferReceipt
	err         error
	finalizeErr error
}

func (c *fakeProfileReceiptRelay) SubmitInferReceipt(_ context.Context, _ string, request builderclient.SubmitInferReceiptRequest) error {
	c.receipts = append(c.receipts, request.Receipt)
	return c.err
}

func (c *fakeProfileReceiptRelay) FinalizeTaskResult(ctx context.Context, endpoint string, req builderclient.FinalizeTaskResultRequest) (builderclient.FinalizeTaskResultResponse, error) {
	if c.finalizeErr != nil {
		return builderclient.FinalizeTaskResultResponse{}, c.finalizeErr
	}
	return c.FakeClient.FinalizeTaskResult(ctx, endpoint, req)
}

func TestFakeInferWithoutProfileReaderBuildsV2Receipt(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(t.TempDir(), "evidence"), db)
	if err != nil {
		t.Fatal(err)
	}
	packages, err := builderclient.NewFixtureOutputPackageStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	auth, signing := evidenceAuth(t)
	_, binding := localInputServiceSigner(t)
	stopAtRelay := errors.New("receipt captured before finalization")
	data := &fakeProfileReceiptRelay{FakeClient: builderclient.NewFakeClient(), err: stopAtRelay}
	input := []byte("resolved input")
	sessionID := strings.Repeat("ab", 32)
	signedOrder, _ := testSignedOrderProto(t, outputTestChainID, "fake-llm-text", sessionID, 1, 230)
	inputHash := codec.HashBytes(input)
	signedOrder.Order.InputHash = inputHash[:]
	signedOrder.Order.InputSizeBytes = uint64(len(input))
	signedOrder.Order.GenerationParams.MaxOutputTokens = 1024
	rawOrder, err := proto.Marshal(signedOrder)
	if err != nil {
		t.Fatal(err)
	}
	taskHash, orderFacts, err := nodewire.TaskOrderHashAndFactsEnvelope(hex.EncodeToString(rawOrder))
	if err != nil {
		t.Fatal(err)
	}
	generationDigest, err := orderFacts.Generation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if err := layout.AdmissionBatch(ctx, db, sessionID, 1, layout.StoredHash(taskHash), layout.CandidateAdmission{
		SchemaVersion: layout.CandidateAdmissionSchemaVersion, SignedOrder: rawOrder,
	}); err != nil {
		t.Fatal(err)
	}
	task := store.InferTask{
		TaskID: identity.TaskIDString(sessionID, 1), SessionID: sessionID, OrderSequence: 1,
		OrderDigest: codec.HashBytes([]byte("order")), WorkerAddress: inputTestOperator,
		BuilderOperatorAddress: inputTestBuilder, ModelID: "fake-llm-text", ProfileVersion: 1,
		Capability: modelservice.CapabilityLLMTextV1, InputDigest: codec.HashBytes(input),
		WinnerConfirmHeight: 100, DeadlineHeight: 230, Stage: string(layout.StageQueued),
	}
	snapshot := chainclient.TaskSnapshot{Status: "ASSIGNED", CurrentContract: true, Assignment: chainclient.AssignmentSnapshot{
		SessionID: task.SessionID, TaskID: task.TaskID, SelectedWorker: task.WorkerAddress,
		AcceptedOrderPayloadHash: chainclient.HexHash(task.InputDigest),
	}}
	executor := newProductionInferExecutor(TaskRunnerConfig{
		Store: db, Evidence: evidenceStore, FakeOutput: true, FakeBus: true,
		LocalWorkerAddress: inputTestOperator, ModelServiceID: "fake-model-service", Model: modelservice.NewFakeService(),
		Builder: builderclient.NewFakeClient(), TaskData: data, TaskDataAuth: auth, OutputPackages: packages,
		ChainID: outputTestChainID, Signer: signing, SignerKeyRef: inputTestKeyRef,
		SignerAddress: binding.ServiceAddress, SignerPubkey: binding.ServicePubkey,
		TaskReader: staticKeeperTaskReader{snapshot: snapshot},
		TaskFacts: taskfacts.ReaderFunc(func(context.Context, string) (taskfacts.Facts, error) {
			return taskfacts.Facts{TaskID: task.TaskID, TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
				AcceptedTaskHash: chainclient.ProtoBytes32(taskHash[:]), GenerationParamsDigest: chainclient.ProtoBytes32(generationDigest[:]),
			}}, nil
		}),
		ReceivingBuilder: worker.ReceivingBuilderFunc(func(context.Context, worker.ReceivingBuilderRef) (worker.BuilderEndpoint, error) {
			return worker.BuilderEndpoint{OperatorAddress: inputTestBuilder, Endpoint: "https://builder.example",
				ServicePubkey: binding.ServicePubkey, AuthorizationNonce: 1, CurrentHeight: inputTestHeight}, nil
		}),
		InputResolver: taskInputResolverFunc(func(context.Context, TaskInputRef) ([]byte, error) {
			return input, nil
		}),
	}, func(context.Context, codec.Hash, store.InferTask, layout.Evidence) error { return nil })

	if _, _, err := executor.RunInfer(ctx, taskHash, task); !errors.Is(err, stopAtRelay) {
		t.Fatalf("RunInfer() error = %v, want receipt relay sentinel", err)
	}
	if len(data.receipts) != 1 {
		t.Fatalf("relayed receipts = %d, want 1", len(data.receipts))
	}
	receipt := data.receipts[0]
	if receipt.SchemaVersion != nodewire.InferReceiptSchemaVersionV2 || receipt.OutputLeafCount == 0 || receipt.GeneratedTokenCount == 0 {
		t.Fatalf("receipt does not carry V2 output commitments: %+v", receipt)
	}
	if len(receipt.RequiredEvidenceCommitments) != 1 || receipt.RequiredEvidenceCommitments[0].EvidenceKind != nodewire.EvidenceKindWorkerValueOpening ||
		receipt.RequiredEvidenceCommitments[0].EvidenceHashOrRoot == (codec.Hash{}) || receipt.RequiredEvidenceCommitments[0].EncodedSizeBytes == 0 {
		t.Fatalf("receipt lacks required Worker opening: %+v", receipt.RequiredEvidenceCommitments)
	}
	read := func(kind string) []byte {
		t.Helper()
		data, err := evidenceStore.ReadTaskKind(ctx, taskHash, "worker-"+kind)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if receipt.OutputLeafCount != 1 {
		t.Fatalf("fake output should be one signed chunk, got %d", receipt.OutputLeafCount)
	}
	schemaHash := codec.HashWithDomain("CORTEX_FAKE_EVIDENCE_SCHEMA_V1", []byte(task.ModelID), codec.Uint64Bytes(uint64(task.ProfileVersion)))
	fixture := evidenceFixture{
		Trace: read("trace"), Checkpoint: read("checkpoint"), Manifest: read("evidence-manifest"),
		InputTokenIDs: read("input_token_ids"), GeneratedTokenIDs: read("generated_token_ids"),
		Commitments: EvidenceCommitments{SessionID: task.SessionID, TaskID: task.TaskID, BuilderOperatorAddress: inputTestBuilder,
			Receipt: receipt, EvidenceSchemaHash: schemaHash.String(), Output: read("output"),
			OutputChunkLengths: []uint64{receipt.OutputSizeBytes}, MaxEncodedSizeBytes: 1 << 30},
	}
	confirmed, err := newEvidenceConfirmer(t, &evidenceTaskDataClient{objects: fixture.objects()}).ConfirmWorkerValueEvidence(ctx, fixture.Commitments)
	if err != nil {
		t.Fatalf("Verifier rejected fake Worker evidence: %v", err)
	}
	generation, err := modelservice.GenerationContextFromTrace(confirmed.Trace)
	if err != nil {
		t.Fatal(err)
	}
	gotDigest, err := generation.Digest()
	if err != nil || gotDigest != generationDigest || generation.Params.MaxOutputTokens != 1024 {
		t.Fatalf("fake evidence lost the accepted generation parameters: %+v, %v", generation, err)
	}
	// Resume through the production persistence adapter after the relay recovers.
	// The first Fin must be created even though other artifacts already exist.
	data.err = nil
	stopAtFinalize := errors.New("Fin stored before finalization")
	data.finalizeErr = stopAtFinalize
	if _, _, err := executor.RunInfer(ctx, taskHash, task); !errors.Is(err, stopAtFinalize) {
		t.Fatalf("resume through first Fin: %v", err)
	}
	fin, err := evidenceStore.ReadTaskKind(ctx, taskHash, worker.OutputStreamFinKind)
	if err != nil || len(fin) == 0 {
		t.Fatalf("signed Fin was not persisted: %v", err)
	}
	if _, err := evidenceStore.ReadTaskKind(ctx, taskHash, "worker-output-stream-stored"); err != nil {
		t.Fatalf("Fin did not reach STORED: %v", err)
	}
	if _, _, err := executor.RunInfer(ctx, taskHash, task); !errors.Is(err, stopAtFinalize) {
		t.Fatalf("replay completed output: %v", err)
	}
	replay, err := evidenceStore.ReadTaskKind(ctx, taskHash, worker.OutputStreamFinKind)
	if err != nil || !bytes.Equal(fin, replay) {
		t.Fatalf("Fin replay changed persisted bytes: %v", err)
	}

}
