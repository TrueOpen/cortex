package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/evidencebundle"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/worker"
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
	// The Phase 1 source of every pre-record fact: a ticket accepted, its input
	// committed by the Dispatcher, and the record observed on chain.
	x, task, taskHash := seedDispatchedInfer(t)
	rec := x.record(t)
	db, evidenceStore := x.st, x.ev
	packages, err := builderclient.NewFixtureOutputPackageStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	auth, signing := evidenceAuth(t)
	_, binding := localInputServiceSigner(t)
	stopAtRelay := errors.New("receipt captured before finalization")
	data := &fakeProfileReceiptRelay{FakeClient: builderclient.NewFakeClient(), err: stopAtRelay}
	// The order's generation parameters, which the record carries; the ticket's
	// task_hash and the order's digest are the facts the receipt signs.
	raw, err := dispatchwire.Raw(x.fx.order)
	if err != nil {
		t.Fatal(err)
	}
	_, orderFacts, err := nodewire.TaskOrderHashAndFactsSignedOrderHex(hex.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	generation := *orderFacts.Generation
	generationDigest := dpGenerationDigest(t, x.fx)
	executor := newProductionInferExecutor(TaskRunnerConfig{
		Store: db, Evidence: evidenceStore, FakeOutput: true,
		GenerationReader: generationReaderFunc(func(context.Context, string, codec.Hash) (nodewire.GenerationContext, error) {
			return generation.Clone(), nil
		}),
		LocalWorkerAddress: hrCortex, ModelServiceID: "fake-model-service", Model: modelservice.NewFakeService(),
		Builder: builderclient.NewFakeClient(), TaskData: data, TaskDataAuth: auth, OutputPackages: packages,
		ChainID: outputTestChainID, Signer: signing, SignerKeyRef: inputTestKeyRef,
		SignerAddress: binding.ServiceAddress, SignerPubkey: binding.ServicePubkey,
		TaskReader: streamLimitedTaskReader{},
		ReceivingBuilder: worker.ReceivingBuilderFunc(func(context.Context, worker.ReceivingBuilderRef) (worker.BuilderEndpoint, error) {
			return worker.BuilderEndpoint{OperatorAddress: rec.Builder, Endpoint: "https://builder.example",
				ServicePubkey: binding.ServicePubkey, AuthorizationNonce: 1, CurrentHeight: inputTestHeight}, nil
		}),
	}, func(context.Context, codec.Hash, store.InferTask, layout.Evidence) error { return nil })
	scope := codec.Hash(layout.DispatchEvidenceScope(layout.StoredHash(taskHash), rec.TicketHash))

	if _, _, err := executor.RunInfer(ctx, taskHash, task); !errors.Is(err, stopAtRelay) {
		t.Fatalf("RunInfer() error = %v, want receipt relay sentinel", err)
	}
	if len(data.receipts) != 1 {
		t.Fatalf("relayed receipts = %d, want 1", len(data.receipts))
	}
	receipt := data.receipts[0]
	if receipt.SchemaVersion != nodewire.InferReceiptSchemaVersionV3 || receipt.OutputLeafCount == 0 || receipt.GeneratedTokenCount == 0 {
		t.Fatalf("receipt does not carry V3 output commitments: %+v", receipt)
	}
	if err := nodewire.RequireWorkerEvidenceCommitmentsV3(receiptCommitmentsForTest(receipt.RequiredEvidenceCommitments)); err != nil {
		t.Fatalf("receipt lacks the Worker openings: %v", err)
	}
	if receipt.OutputLeafCount != 1 {
		t.Fatalf("fake output should be one signed chunk, got %d", receipt.OutputLeafCount)
	}
	output, err := evidenceStore.ReadTaskKind(ctx, scope, "worker-output")
	if err != nil {
		t.Fatal(err)
	}
	bundle := func(id evidence.BundleID) ([]byte, map[string][]byte) {
		t.Helper()
		manifestBytes, _, err := evidenceStore.ReadBundleManifest(id)
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := evidencebundle.Decode(manifestBytes)
		if err != nil {
			t.Fatal(err)
		}
		artifacts := map[string][]byte{}
		for _, artifact := range manifest.Artifacts {
			digest, err := decodeCanonicalHash(artifact.ContentHash, "content_hash")
			if err != nil {
				t.Fatal(err)
			}
			size, _ := artifact.SizeBytes()
			if artifacts[artifact.ID], err = evidenceStore.ReadBundleArtifact(id, digest, int64(size)); err != nil {
				t.Fatal(err)
			}
		}
		return manifestBytes, artifacts
	}
	valueManifest, valueArtifacts := bundle(evidence.WorkerValueBundle(scope))
	tokenManifest, tokenArtifacts := bundle(evidence.WorkerTokenBundle(scope))
	schemaHash := codec.HashWithDomain("CORTEX_FAKE_EVIDENCE_SCHEMA_V1", []byte(task.ModelID), codec.Uint64Bytes(uint64(task.ProfileVersion)))
	fixture := evidenceFixture{
		WorkerValues: valueArtifacts["worker_values"], ValueManifest: valueManifest, TokenManifest: tokenManifest,
		InputTokenIDs: tokenArtifacts["input_token_ids"], GeneratedTokenIDs: tokenArtifacts["generated_token_ids"],
		GenerationParams: tokenArtifacts["generation_params"],
		Commitments: EvidenceCommitments{SessionID: task.SessionID, TaskID: task.TaskID, BuilderOperatorAddress: rec.Builder,
			Receipt: receipt, EvidenceSchemaHash: schemaHash.String(), Output: output,
			OutputChunkLengths: []uint64{receipt.OutputSizeBytes}, RequiredTopK: fakeRequiredTopK,
			MaxEncodedSizeBytes: map[nodewire.EvidenceKind]uint64{nodewire.EvidenceKindWorkerValueOpening: 1 << 30, nodewire.EvidenceKindWorkerTokenOpening: 1 << 30}},
	}
	confirmed, err := newEvidenceConfirmer(t, &evidenceTaskDataClient{objects: fixture.objects()}).ConfirmWorkerEvidence(ctx, fixture.Commitments)
	if err != nil {
		t.Fatalf("Verifier rejected fake Worker evidence: %v", err)
	}
	if confirmed.FinishReason == nodewire.FinishReasonV1Unspecified || len(confirmed.WorkerValues) == 0 {
		t.Fatalf("confirmed evidence = %+v", confirmed)
	}
	_ = generationDigest
	// Resume through the production persistence adapter after the relay recovers.
	// The first Fin must be created even though other artifacts already exist.
	data.err = nil
	stopAtFinalize := errors.New("Fin stored before finalization")
	data.finalizeErr = stopAtFinalize
	if _, _, err := executor.RunInfer(ctx, taskHash, task); !errors.Is(err, stopAtFinalize) {
		t.Fatalf("resume through first Fin: %v", err)
	}
	fin, err := evidenceStore.ReadTaskKind(ctx, scope, worker.OutputStreamFinKind)
	if err != nil || len(fin) == 0 {
		t.Fatalf("signed Fin was not persisted: %v", err)
	}
	if _, err := evidenceStore.ReadTaskKind(ctx, scope, "worker-output-stream-stored"); err != nil {
		t.Fatalf("Fin did not reach STORED: %v", err)
	}
	if _, _, err := executor.RunInfer(ctx, taskHash, task); !errors.Is(err, stopAtFinalize) {
		t.Fatalf("replay completed output: %v", err)
	}
	replay, err := evidenceStore.ReadTaskKind(ctx, scope, worker.OutputStreamFinKind)
	if err != nil || !bytes.Equal(fin, replay) {
		t.Fatalf("Fin replay changed persisted bytes: %v", err)
	}

}

func receiptCommitmentsForTest(items []builderclient.EvidenceCommitment) []nodewire.EvidenceCommitmentV1 {
	out := make([]nodewire.EvidenceCommitmentV1, len(items))
	for i, item := range items {
		root := item.EvidenceHashOrRoot
		out[i] = nodewire.EvidenceCommitmentV1{EvidenceKind: item.EvidenceKind, EvidenceHashOrRoot: root[:], EncodedSizeBytes: item.EncodedSizeBytes}
	}
	return out
}

type generationReaderFunc func(context.Context, string, codec.Hash) (nodewire.GenerationContext, error)

func (f generationReaderFunc) TaskGeneration(ctx context.Context, taskID string, hash codec.Hash) (nodewire.GenerationContext, error) {
	return f(ctx, taskID, hash)
}

// streamLimitedTaskReader also serves the governed output stream limits, which
// the Worker reads before it opens its output stream.
type streamLimitedTaskReader struct {
	staticKeeperTaskReader
}

func (streamLimitedTaskReader) OutputStreamLimits(context.Context) (chainclient.OutputStreamLimitsSnapshot, error) {
	return chainclient.OutputStreamLimitsSnapshot{MinOutputStreamFrameBytes: 256, MaxOutputMMRLeaves: 65536}, nil
}
