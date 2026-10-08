package verifier

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// validateAcceptedWorkerEvidence rechecks the accepted receipt and both Worker
// bundles before model scoring; the caller's confirmation is not a substitute
// for this commitment boundary. It returns the Worker's value leaves, decoded
// strictly under this task's binding.
func (v *Verifier) validateAcceptedWorkerEvidence(ctx context.Context, state TaskState, profile chainclient.CurrentModelProfileSnapshot, limits map[nodewire.EvidenceKind]uint64, output []byte, evidence workerEvidenceArtifacts) error {
	receipt := state.ConfirmedInferReceipt
	if receipt == nil {
		return fmt.Errorf("confirmed Worker InferReceiptV3 is required")
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
	if err := nodewire.RequireWorkerEvidenceCommitmentsV3(receiptCommitments(receipt.RequiredEvidenceCommitments)); err != nil {
		return err
	}
	for _, committed := range receipt.RequiredEvidenceCommitments {
		if committed.EncodedSizeBytes > limits[committed.EvidenceKind] {
			return fmt.Errorf("Worker evidence of kind %d exceeds locked profile bound", committed.EvidenceKind)
		}
	}
	input, err := nodewire.DecodeTokenIDs(evidence.inputTokenIDs)
	if err != nil {
		return err
	}
	generated, err := nodewire.DecodeTokenIDs(evidence.generatedTokenIDs)
	if err != nil {
		return err
	}
	receiptFacts := builderclient.WorkerEvidenceFacts{
		ChainID: receipt.ChainID, TaskID: receipt.TaskID, AcceptedTaskHash: receipt.TaskHash,
		WorkerOperatorAddress: receipt.WorkerOperatorAddress, GenerationParamsDigest: receipt.GenerationParamsDigest,
		OutputHash: state.OutputPackage.OutputHash, OutputSizeBytes: receipt.OutputSizeBytes, OutputLeafCount: receipt.OutputLeafCount,
		GeneratedTokenCount:    receipt.GeneratedTokenCount,
		InputTokenIDsSizeBytes: uint64(len(evidence.inputTokenIDs)), GeneratedTokenIDsSizeBytes: uint64(len(evidence.generatedTokenIDs)),
		WorkerValueRoot: evidence.workerValueRoot, WorkerValuesEncodedSizeBytes: uint64(len(evidence.workerValues)),
	}
	if receiptFacts.EvidenceSchemaHash, err = keeperEvidenceSchemaHash(profile); err != nil {
		return err
	}
	if receiptFacts.InputTokenIDsHash, err = nodewire.InputTokenIDsHash(input); err != nil {
		return err
	}
	if receiptFacts.GeneratedTokenIDsHash, err = nodewire.GeneratedTokenIDsHash(generated); err != nil {
		return err
	}
	reason, err := builderclient.ConfirmWorkerEvidence(receiptFacts, receipt.RequiredEvidenceCommitments)
	if err != nil {
		return err
	}
	if state.ConfirmedFinishReason != nodewire.FinishReasonV1Unspecified && reason != state.ConfirmedFinishReason {
		return fmt.Errorf("Worker evidence finish reason differs from typed commitment")
	}
	// Last, with every commitment re-established: the output bytes must be the
	// decode of the token ids this verifier is about to score (issue #35).
	// Until here the text was bound to output_hash and the tokens to the
	// A-level commitment, but nothing tied the two to each other.
	return v.checkOutputDecodesFromTokens(ctx, state, generated, output)
}

// checkOutputDecodesFromTokens refuses to score a Worker whose MMR-confirmed
// output is not the decode of its committed generated token ids: decode(T
// minus one trailing EOS) under the profile manifest's output_decoding,
// compared byte for byte after folding ill-formed sequences to U+FFFD on both
// sides (CanonicalUTF8 -- the decode side already arrives folded, so the fold
// only ever touches a raw output whose generation was cut mid-character).
//
// The decode comes from the local model service's calibrated /detokenize
// (modelservice.OutputDetokenizer). A model service without that capability --
// the cortex.v1 gRPC client, until wire grows a Detokenize RPC -- skips the
// check, as does a profile with no declared output_decoding; a mismatch under
// a declared decoding is a Worker evidence fault and stops the round before
// any scoring.
func (v *Verifier) checkOutputDecodesFromTokens(ctx context.Context, state TaskState, generated []uint32, output []byte) error {
	detok, ok := v.cfg.Model.(modelservice.OutputDetokenizer)
	if !ok {
		return nil
	}
	decoded, err := detok.DetokenizeCommitted(ctx, state.ModelID, fmt.Sprintf("%d", state.ProfileVersion), generated)
	if err != nil {
		if errors.Is(err, modelservice.ErrNoOutputDecoding) {
			return nil
		}
		return fmt.Errorf("decode the Worker's committed token ids: %w", err)
	}
	if bytes.Equal(decoded, modelservice.CanonicalUTF8(output)) {
		return nil
	}
	return fmt.Errorf("verifier evidence rejected: WORKER_EVIDENCE_FAULT: the confirmed output (%d bytes) is not the decode of the %d committed generated token ids (%d bytes)",
		len(output), len(generated), len(decoded))
}

func receiptCommitments(items []builderclient.EvidenceCommitment) []nodewire.EvidenceCommitmentV1 {
	out := make([]nodewire.EvidenceCommitmentV1, len(items))
	for i, item := range items {
		root := item.EvidenceHashOrRoot
		out[i] = nodewire.EvidenceCommitmentV1{EvidenceKind: item.EvidenceKind, EvidenceHashOrRoot: root[:], EncodedSizeBytes: item.EncodedSizeBytes}
	}
	return out
}

func keeperEvidenceSchemaHash(profile chainclient.CurrentModelProfileSnapshot) (string, error) {
	value := profile.Profile.VerificationProfile.EvidenceSchemaHash
	if len(value) != 32 {
		return "", fmt.Errorf("locked profile evidence schema hash must be raw32")
	}
	return hex.EncodeToString(value), nil
}
