package builderclient

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/evidencebundle"
	"github.com/SingaXYZ/cortex/internal/nodewire"
)

func fakeFinalizeFixture(t *testing.T, mutate func(*evidencebundle.Manifest)) (*FakeClient, taskDataTestKeyPair, FinalizeTaskResultRequest, []UploadTaskResultRequest) {
	t.Helper()
	pair := newTaskDataTestKeyPair(t)
	output, checkpoint, trace := []byte("output"), []byte("checkpoint"), []byte("trace")
	input, _ := nodewire.EncodeTokenIDs([]uint32{7})
	generated, _ := nodewire.EncodeTokenIDs([]uint32{1, 2, 3})
	receipt := taskDataTestReceipt(t, pair, "chain-A", output)
	req := FinalizeTaskResultRequest{TaskHash: receipt.TaskHash, SessionID: strings.Repeat("11", 32), TaskID: receipt.TaskID, Receipt: receipt}
	manifest := evidencebundle.Manifest{Artifacts: []evidencebundle.Artifact{evidencebundle.NewArtifact("checkpoint", checkpoint), evidencebundle.NewArtifact("generated_token_ids", generated), evidencebundle.NewArtifact("input_token_ids", input), evidencebundle.NewArtifact("trace", trace)}, ChainID: receipt.ChainID, EvidenceKind: "WORKER_VALUE_OPENING", EvidenceSchemaHash: strings.Repeat("22", 32), Version: 1, ProducerKind: "WORKER", ProducerOperator: receipt.WorkerOperatorAddress, TaskHash: receipt.TaskHash, TaskID: receipt.TaskID, VerifyRound: 1}
	inputHash, _ := nodewire.InputTokenIDsHash([]uint32{7})
	generatedHash, _ := nodewire.GeneratedTokenIDsHash([]uint32{1, 2, 3})
	commitment, err := WorkerValueEvidenceCommitment(WorkerValueEvidenceFacts{ChainID: receipt.ChainID, TaskID: receipt.TaskID, AcceptedTaskHash: receipt.TaskHash, WorkerOperatorAddress: receipt.WorkerOperatorAddress, GenerationParamsDigest: receipt.GenerationParamsDigest, EvidenceSchemaHash: manifest.EvidenceSchemaHash, OutputHash: mustHash(t, receipt.OutputHash), OutputSizeBytes: receipt.OutputSizeBytes, OutputLeafCount: 1, GeneratedTokenCount: 3, FinishReason: nodewire.FinishReasonV1EosToken, TraceRoot: codec.HashBytes(trace), TraceEncodedSizeBytes: uint64(len(trace)), CheckpointRoot: codec.HashBytes(checkpoint), CheckpointEncodedSizeBytes: uint64(len(checkpoint)), InputTokenIDsHash: inputHash, GeneratedTokenIDsHash: generatedHash, InputTokenIDsSizeBytes: uint64(len(input)), GeneratedTokenIDsSizeBytes: uint64(len(generated))})
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(&manifest)
	}
	encoded, err := manifest.Encode()
	if err != nil {
		t.Fatal(err)
	}
	req.Receipt.RequiredEvidenceCommitments[0] = commitment
	signFakeFinalize(t, pair, &req)
	outputKey := TaskDataKey{TaskHash: req.TaskHash, SessionID: req.SessionID, TaskID: req.TaskID, Kind: DataKindOutput, ContentHash: receipt.OutputHash}
	objects := []struct {
		key  TaskDataKey
		data []byte
	}{{outputKey, output}}
	for i, data := range [][]byte{checkpoint, trace, encoded, input, generated} {
		kind, hash := DataKindEvidenceArtifact, codec.HashBytes(data)
		if i == 2 {
			kind, hash = DataKindEvidenceManifest, commitment.EvidenceHashOrRoot
		}
		objects = append(objects, struct {
			key  TaskDataKey
			data []byte
		}{EvidenceObjectKey(req.TaskHash, req.SessionID, req.TaskID, kind, hash.String(), EvidenceProducerWorker, 1, receipt.WorkerOperatorAddress), data})
	}
	uploads := make([]UploadTaskResultRequest, 0, len(objects))
	for _, object := range objects {
		digest, err := TaskDataUploadBodyDigest(object.key, uint64(len(object.data)), "")
		if err != nil {
			t.Fatal(err)
		}
		uploads = append(uploads, UploadTaskResultRequest{Key: object.key, Data: object.data, SizeBytes: uint64(len(object.data)), Auth: taskDataTestRequestAuth(t, pair, "UploadTaskResultObject", object.key, digest)})
	}
	return NewFakeClient(), pair, req, uploads
}

func signFakeFinalize(t *testing.T, pair taskDataTestKeyPair, req *FinalizeTaskResultRequest) {
	t.Helper()
	digest, err := InferReceiptSigningDigest(req.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	req.Receipt.ServiceSignature = hex.EncodeToString(pair.sign(t, digest))
	body, err := TaskDataFinalizeResultBodyDigest(*req)
	if err != nil {
		t.Fatal(err)
	}
	req.Auth = taskDataTestRequestAuth(t, pair, "FinalizeTaskResult", TaskDataKey{}, body)
}

func fakeUploadFixture(t *testing.T, f *FakeClient, pair taskDataTestKeyPair, upload UploadTaskResultRequest) (TaskDataMetadata, error) {
	t.Helper()
	if upload.Key.Kind != DataKindOutput {
		return f.UploadTaskResultObject(context.Background(), "", upload)
	}
	root, _ := codec.OutputMMRRoot([][]byte{upload.Data})
	digest, err := nodewire.OutputChunkSigningDigest(upload.Auth.ChainID, mustDecodeHex(t, upload.Key.TaskHash), 0, root[:])
	if err != nil {
		t.Fatal(err)
	}
	body, err := TaskDataOutputStreamBodyDigest(upload.Key.TaskHash, upload.Key.SessionID, upload.Key.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	request := OutputStreamRequest{TaskHash: upload.Key.TaskHash, SessionID: upload.Key.SessionID, TaskID: upload.Key.TaskID, Auth: taskDataTestRequestAuth(t, pair, "UploadTaskOutputStream", upload.Key, body), ReplayChunks: []OutputChunk{{Text: upload.Data, MMRRoot: root, WorkerSignature: pair.sign(t, digest)}}}
	finDigest, digestErr := nodewire.OutputFinSigningDigest(upload.Auth.ChainID, mustDecodeHex(t, upload.Key.TaskHash), 0, root[:], nodewire.FinishReasonV1EosToken)
	if digestErr != nil {
		t.Fatal(digestErr)
	}
	_, err = f.UploadTaskOutputStream(context.Background(), "", request, OutputFin{FinishReason: nodewire.FinishReasonV1EosToken, WorkerSignature: pair.sign(t, finDigest)})
	return f.TaskDataMetadata[upload.Key], err
}

func TestFakeFinalizeIsAtomicAndIdempotent(t *testing.T) {
	f, pair, req, uploads := fakeFinalizeFixture(t, nil)
	ctx := context.Background()
	for i, upload := range uploads {
		if i == 1 {
			continue
		}
		metadata, err := fakeUploadFixture(t, f, pair, upload)
		if err != nil || metadata.Readiness != TaskDataStored {
			t.Fatalf("stage=%+v err=%v", metadata, err)
		}
	}
	if _, err := f.FinalizeTaskResult(ctx, "", req); err == nil {
		t.Fatal("finalized with missing artifact")
	}
	for _, metadata := range f.TaskDataMetadata {
		if metadata.Readiness != TaskDataStored {
			t.Fatal("failed finalize partially made objects READY")
		}
	}
	if err := f.FetchTaskData(ctx, "", FetchTaskDataRequest{Key: uploads[0].Key}, func(TaskDataChunk) error { return nil }); err == nil {
		t.Fatal("STORED output was fetchable")
	}
	if _, err := f.UploadTaskResultObject(ctx, "", uploads[1]); err != nil {
		t.Fatal(err)
	}
	result, err := f.FinalizeTaskResult(ctx, "", req)
	if err != nil || result.Idempotent || len(result.EvidenceBundleConfirmations) != 1 {
		t.Fatalf("finalize=%+v err=%v", result, err)
	}
	if result.EvidenceBundleConfirmations[0].ArtifactTotalSizeBytes != req.Receipt.RequiredEvidenceCommitments[0].EncodedSizeBytes {
		t.Fatal("bundle total incorrect")
	}
	for _, metadata := range f.TaskDataMetadata {
		if metadata.Readiness != TaskDataReady {
			t.Fatal("finalize did not make all objects READY")
		}
	}
	result.EvidenceBundleConfirmations[0].Key.ContentHash = strings.Repeat("ff", 32)
	result.OutputConfirmation.Signature[0] ^= 1
	result, err = f.FinalizeTaskResult(ctx, "", req)
	if err != nil || !result.Idempotent || len(f.FinalizedTaskResults) != 1 {
		t.Fatal("identical finalize not idempotent")
	}
	if result.EvidenceBundleConfirmations[0].Key != uploads[3].Key || result.OutputConfirmation.Signature[0] != 1 {
		t.Fatal("caller mutated the cached finalization")
	}
	req.Receipt.GeneratedTokenCount++
	signFakeFinalize(t, pair, &req)
	if _, err := f.FinalizeTaskResult(ctx, "", req); err == nil {
		t.Fatal("conflicting receipt accepted after finalize")
	}
}

func TestFakeFinalizeRejectsManifestScopeAndStoredTampering(t *testing.T) {
	for _, name := range []string{"chain", "task hash", "producer", "output tamper", "artifact tamper", "noncanonical"} {
		t.Run(name, func(t *testing.T) {
			mutate := func(m *evidencebundle.Manifest) {
				switch name {
				case "chain":
					m.ChainID = "other"
				case "task hash":
					m.TaskHash = strings.Repeat("99", 32)
				case "producer":
					m.ProducerOperator = otherFixtureWorkerAddress
				}
			}
			f, pair, req, uploads := fakeFinalizeFixture(t, mutate)
			if name == "noncanonical" {
				upload := &uploads[3]
				upload.Data = append(upload.Data, '\n')
				upload.SizeBytes = uint64(len(upload.Data))
				upload.Key.ContentHash = evidencebundle.Hash(upload.Data).String()
				digest, err := TaskDataUploadBodyDigest(upload.Key, upload.SizeBytes, "")
				if err != nil {
					t.Fatal(err)
				}
				upload.Auth = taskDataTestRequestAuth(t, pair, "UploadTaskResultObject", upload.Key, digest)
				signFakeFinalize(t, pair, &req)
			}
			for _, upload := range uploads {
				if _, err := fakeUploadFixture(t, f, pair, upload); err != nil {
					t.Fatal(err)
				}
			}
			if name == "output tamper" {
				f.TaskData[uploads[0].Key][0] ^= 1
			}
			if name == "artifact tamper" {
				f.TaskData[uploads[1].Key][0] ^= 1
			}
			if _, err := f.FinalizeTaskResult(context.Background(), "", req); err == nil {
				t.Fatal("invalid bundle finalized")
			}
			for _, metadata := range f.TaskDataMetadata {
				if metadata.Readiness != TaskDataStored {
					t.Fatal("invalid bundle became READY")
				}
			}
		})
	}
}
