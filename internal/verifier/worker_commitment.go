package verifier

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// Recheck the accepted receipt and all four artifacts before model scoring;
// the caller's confirmation is not a substitute for this commitment boundary.
func (v *Verifier) validateAcceptedWorkerEvidence(ctx context.Context, state TaskState, profile chainclient.CurrentModelProfileSnapshot, limit uint64, output, trace, checkpoint []byte) error {
	receipt := state.ConfirmedInferReceipt
	if receipt == nil {
		return fmt.Errorf("confirmed Worker InferReceiptV2 is required")
	}
	digest, err := builderclient.InferReceiptSigningDigest(*receipt)
	if err != nil {
		return err
	}
	if digest != state.InferReceiptHash || receipt.TaskID != state.TaskID || receipt.ChainID != v.cfg.ChainID || receipt.WorkerOperatorAddress != state.WorkerAddress {
		return fmt.Errorf("confirmed Worker receipt differs from accepted task facts")
	}
	facts, err := v.taskFacts(ctx, state.TaskID)
	if err != nil {
		return err
	}
	if receipt.TaskHash != hex.EncodeToString(facts.AcceptedTaskHash) || receipt.GenerationParamsDigest != hex.EncodeToString(facts.GenerationParamsDigest) {
		return fmt.Errorf("confirmed Worker receipt differs from accepted generation or task hash")
	}
	if receipt.OutputHash != state.OutputPackage.OutputHash.String() || receipt.OutputSizeBytes != uint64(len(output)) || receipt.OutputLeafCount != uint64(len(state.ConfirmedOutputChunkLengths)) {
		return fmt.Errorf("confirmed Worker receipt differs from output MMR size or leaf count")
	}
	if len(receipt.RequiredEvidenceCommitments) != 1 {
		return fmt.Errorf("Worker receipt requires one typed evidence commitment")
	}
	committed := receipt.RequiredEvidenceCommitments[0]
	if committed.EncodedSizeBytes > limit {
		return fmt.Errorf("Worker evidence exceeds locked profile bound")
	}
	if err := modelservice.ValidateTokenIDArtifacts(trace, checkpoint, state.ConfirmedInputTokenIDs, state.ConfirmedGeneratedTokenIDs); err != nil {
		return fmt.Errorf("Worker token artifacts: %w", err)
	}
	input, err := nodewire.DecodeTokenIDs(state.ConfirmedInputTokenIDs)
	if err != nil {
		return err
	}
	generated, err := nodewire.DecodeTokenIDs(state.ConfirmedGeneratedTokenIDs)
	if err != nil {
		return err
	}
	inputHash, err := nodewire.InputTokenIDsHash(input)
	if err != nil {
		return err
	}
	generatedHash, err := nodewire.GeneratedTokenIDsHash(generated)
	if err != nil {
		return err
	}
	schemaHash, err := keeperEvidenceSchemaHash(profile)
	if err != nil {
		return err
	}
	reason, err := builderclient.ConfirmWorkerValueEvidence(builderclient.WorkerValueEvidenceFacts{
		ChainID: receipt.ChainID, TaskID: receipt.TaskID, AcceptedTaskHash: receipt.TaskHash,
		WorkerOperatorAddress: receipt.WorkerOperatorAddress, GenerationParamsDigest: receipt.GenerationParamsDigest,
		EvidenceSchemaHash: schemaHash, OutputHash: state.OutputPackage.OutputHash,
		OutputSizeBytes: receipt.OutputSizeBytes, OutputLeafCount: receipt.OutputLeafCount, GeneratedTokenCount: receipt.GeneratedTokenCount,
		TraceRoot: codec.HashBytes(trace), TraceEncodedSizeBytes: uint64(len(trace)),
		CheckpointRoot: codec.HashBytes(checkpoint), CheckpointEncodedSizeBytes: uint64(len(checkpoint)),
		InputTokenIDsHash: inputHash, GeneratedTokenIDsHash: generatedHash,
		InputTokenIDsSizeBytes: uint64(len(state.ConfirmedInputTokenIDs)), GeneratedTokenIDsSizeBytes: uint64(len(state.ConfirmedGeneratedTokenIDs)),
	}, committed)
	if err != nil {
		return err
	}
	if reason != state.ConfirmedFinishReason {
		return fmt.Errorf("Worker evidence finish reason differs from typed commitment")
	}
	return nil
}

func keeperEvidenceSchemaHash(profile chainclient.CurrentModelProfileSnapshot) (string, error) {
	value := profile.Profile.VerificationProfile.EvidenceSchemaHash
	if len(value) != 32 {
		return "", fmt.Errorf("locked profile evidence schema hash must be raw32")
	}
	return hex.EncodeToString(value), nil
}
