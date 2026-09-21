package verifier

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/modelservice"
	"github.com/SingaXYZ/cortex/internal/nodewire"
)

func bindWorkerReceiptForTest(t *testing.T, v *Verifier, state *TaskState) {
	t.Helper()
	inputRaw, generatedRaw, err := modelservice.TokenIDArtifacts(state.ConfirmedTrace, state.ConfirmedCheckpoint)
	if err != nil {
		t.Fatal(err)
	}
	state.ConfirmedInputTokenIDs, state.ConfirmedGeneratedTokenIDs = inputRaw, generatedRaw
	input, _ := nodewire.DecodeTokenIDs(inputRaw)
	generated, _ := nodewire.DecodeTokenIDs(generatedRaw)
	inputHash, _ := nodewire.InputTokenIDsHash(input)
	generatedHash, _ := nodewire.GeneratedTokenIDsHash(generated)
	facts, err := v.taskFacts(context.Background(), state.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	profile, _, err := v.lockedProfile(context.Background(), *state)
	if err != nil {
		t.Fatal(err)
	}
	schemaHash, err := keeperEvidenceSchemaHash(profile)
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := builderclient.WorkerValueEvidenceCommitment(builderclient.WorkerValueEvidenceFacts{
		ChainID: v.cfg.ChainID, TaskID: state.TaskID, AcceptedTaskHash: hex.EncodeToString(facts.AcceptedTaskHash),
		WorkerOperatorAddress: state.WorkerAddress, GenerationParamsDigest: hex.EncodeToString(facts.GenerationParamsDigest),
		EvidenceSchemaHash: schemaHash, OutputHash: state.OutputPackage.OutputHash, OutputSizeBytes: uint64(len(state.ConfirmedOutput)),
		OutputLeafCount: uint64(len(state.ConfirmedOutputChunkLengths)), GeneratedTokenCount: uint64(len(generated)), FinishReason: state.ConfirmedFinishReason,
		TraceRoot: codec.HashBytes(state.ConfirmedTrace), TraceEncodedSizeBytes: uint64(len(state.ConfirmedTrace)),
		CheckpointRoot: codec.HashBytes(state.ConfirmedCheckpoint), CheckpointEncodedSizeBytes: uint64(len(state.ConfirmedCheckpoint)),
		InputTokenIDsHash: inputHash, GeneratedTokenIDsHash: generatedHash, InputTokenIDsSizeBytes: uint64(len(inputRaw)), GeneratedTokenIDsSizeBytes: uint64(len(generatedRaw)),
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt := builderclient.SignedInferReceipt{SchemaVersion: 2, ChainID: v.cfg.ChainID, TaskID: state.TaskID,
		TaskHash: hex.EncodeToString(facts.AcceptedTaskHash), WorkerOperatorAddress: state.WorkerAddress,
		ServiceAuthorizationNonce: 1, GenerationParamsDigest: hex.EncodeToString(facts.GenerationParamsDigest),
		OutputHash: state.OutputPackage.OutputHash.String(), OutputSizeBytes: uint64(len(state.ConfirmedOutput)),
		OutputLeafCount: uint64(len(state.ConfirmedOutputChunkLengths)), GeneratedTokenCount: uint64(len(generated)),
		RequiredEvidenceCommitments: []builderclient.EvidenceCommitment{commitment}, ExpiryHeight: 300}
	state.InferReceiptHash, err = builderclient.InferReceiptSigningDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	state.ConfirmedInferReceipt = &receipt
}

func TestVerifierRejectsUnboundV2ArtifactsBeforeScoring(t *testing.T) {
	for _, name := range []string{"missing lengths", "rechunked output", "missing receipt", "receipt count", "receipt leaf count", "receipt commitment", "input token bytes", "generated token bytes", "missing token artifact", "trace bytes", "checkpoint bytes", "accepted count mismatch", "accepted leaf mismatch", "accepted evidence size"} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			state, _, _ := generationEvidenceFixture(t, h)
			switch name {
			case "missing lengths":
				state.ConfirmedOutputChunkLengths = nil
			case "rechunked output":
				state.ConfirmedOutputChunkLengths = []uint64{1, uint64(len(state.ConfirmedOutput) - 1)}
			case "missing receipt":
				state.ConfirmedInferReceipt = nil
			case "receipt count":
				state.ConfirmedInferReceipt.GeneratedTokenCount++
			case "receipt leaf count":
				state.ConfirmedInferReceipt.OutputLeafCount++
			case "receipt commitment":
				state.ConfirmedInferReceipt.RequiredEvidenceCommitments[0].EvidenceHashOrRoot[0] ^= 1
			case "input token bytes":
				state.ConfirmedInputTokenIDs[len(state.ConfirmedInputTokenIDs)-1] ^= 1
			case "generated token bytes":
				state.ConfirmedGeneratedTokenIDs[len(state.ConfirmedGeneratedTokenIDs)-1] ^= 1
			case "missing token artifact":
				state.ConfirmedGeneratedTokenIDs = nil
			case "trace bytes":
				state.ConfirmedTrace = append(state.ConfirmedTrace, ' ')
			case "checkpoint bytes":
				state.ConfirmedCheckpoint = append(state.ConfirmedCheckpoint, ' ')
			case "accepted count mismatch":
				state.ConfirmedInferReceipt.GeneratedTokenCount++
				state.InferReceiptHash, _ = builderclient.InferReceiptSigningDigest(*state.ConfirmedInferReceipt)
			case "accepted leaf mismatch":
				state.ConfirmedInferReceipt.OutputLeafCount++
				state.InferReceiptHash, _ = builderclient.InferReceiptSigningDigest(*state.ConfirmedInferReceipt)
			case "accepted evidence size":
				state.ConfirmedInferReceipt.RequiredEvidenceCommitments[0].EncodedSizeBytes++
				state.InferReceiptHash, _ = builderclient.InferReceiptSigningDigest(*state.ConfirmedInferReceipt)
			}
			if _, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state); err == nil || h.model.VerifyCalls != 0 {
				t.Fatalf("accepted %s or scored unbound evidence: err=%v calls=%d", name, err, h.model.VerifyCalls)
			}
		})
	}
}
