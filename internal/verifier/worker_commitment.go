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

// ErrWorkerEvidenceInvalid marks Worker evidence that reproduces its
// commitment but is not legal content (CD §6.2 V7b/V14b reason
// WORKER_EVIDENCE_INVALID), as opposed to evidence that could not be had.
var ErrWorkerEvidenceInvalid = errors.New("Worker evidence matches its commitment but is invalid")

// validateWorkerTokenEvidence rechecks the accepted receipt and the A-level
// bundle before the prefill (CD §6.2 V7a); the caller's confirmation is not a
// substitute for this commitment boundary.
func (v *Verifier) validateWorkerTokenEvidence(ctx context.Context, state TaskState, profile chainclient.CurrentModelProfileSnapshot, limits map[nodewire.EvidenceKind]uint64, output []byte, tokens workerTokenArtifacts) error {
	receipt, err := v.acceptedWorkerReceipt(ctx, state, limits)
	if err != nil {
		return err
	}
	if receipt.OutputHash != state.OutputPackage.OutputHash.String() || receipt.OutputSizeBytes != uint64(len(output)) || receipt.OutputLeafCount != uint64(len(state.ConfirmedOutputChunkLengths)) {
		return fmt.Errorf("confirmed Worker receipt differs from output MMR size or leaf count")
	}
	input, err := nodewire.DecodeTokenIDs(tokens.inputTokenIDs)
	if err != nil {
		return err
	}
	generated, err := nodewire.DecodeTokenIDs(tokens.generatedTokenIDs)
	if err != nil {
		return err
	}
	facts := builderclient.WorkerEvidenceFacts{
		ChainID: receipt.ChainID, TaskID: receipt.TaskID, AcceptedTaskHash: receipt.TaskHash,
		WorkerOperatorAddress: receipt.WorkerOperatorAddress, GenerationParamsDigest: receipt.GenerationParamsDigest,
		OutputHash: state.OutputPackage.OutputHash, OutputSizeBytes: receipt.OutputSizeBytes, OutputLeafCount: receipt.OutputLeafCount,
		GeneratedTokenCount:    receipt.GeneratedTokenCount,
		InputTokenIDsSizeBytes: uint64(len(tokens.inputTokenIDs)), GeneratedTokenIDsSizeBytes: uint64(len(tokens.generatedTokenIDs)),
	}
	if facts.EvidenceSchemaHash, err = keeperEvidenceSchemaHash(profile); err != nil {
		return err
	}
	if facts.InputTokenIDsHash, err = nodewire.InputTokenIDsHash(input); err != nil {
		return err
	}
	if facts.GeneratedTokenIDsHash, err = nodewire.GeneratedTokenIDsHash(generated); err != nil {
		return err
	}
	reason, err := builderclient.ConfirmWorkerTokenEvidence(facts, receipt.RequiredEvidenceCommitments[1])
	if err != nil {
		return err
	}
	if state.ConfirmedFinishReason != nodewire.FinishReasonV1Unspecified && reason != state.ConfirmedFinishReason {
		return fmt.Errorf("Worker evidence finish reason differs from typed commitment")
	}
	// Last, with the commitment re-established: the output bytes must be the
	// decode of the token ids this verifier is about to score (issue #35).
	return v.checkOutputDecodesFromTokens(ctx, state, generated, output)
}

// validateWorkerValueEvidence rechecks the B-level bundle against the same
// receipt's value commitment, in REVEALING only (CD §6.2 V14a).
func (v *Verifier) validateWorkerValueEvidence(ctx context.Context, state TaskState, profile chainclient.CurrentModelProfileSnapshot, limits map[nodewire.EvidenceKind]uint64, values workerValueArtifacts) error {
	receipt, err := v.acceptedWorkerReceipt(ctx, state, limits)
	if err != nil {
		return err
	}
	facts := builderclient.WorkerEvidenceFacts{
		ChainID: receipt.ChainID, TaskID: receipt.TaskID, AcceptedTaskHash: receipt.TaskHash,
		WorkerOperatorAddress: receipt.WorkerOperatorAddress, GenerationParamsDigest: receipt.GenerationParamsDigest,
		WorkerValueRoot: values.workerValueRoot, WorkerValuesEncodedSizeBytes: uint64(len(values.workerValues)),
	}
	if facts.EvidenceSchemaHash, err = keeperEvidenceSchemaHash(profile); err != nil {
		return err
	}
	if uint64(len(values.workerLeaves)) != receipt.GeneratedTokenCount {
		return fmt.Errorf("Worker values cover %d positions, not the signed generated_token_count %d", len(values.workerLeaves), receipt.GeneratedTokenCount)
	}
	return builderclient.ConfirmWorkerValueEvidence(facts, receipt.RequiredEvidenceCommitments[0])
}

// acceptedWorkerReceipt is the receipt checks both phases share.
func (v *Verifier) acceptedWorkerReceipt(ctx context.Context, state TaskState, limits map[nodewire.EvidenceKind]uint64) (*builderclient.SignedInferReceipt, error) {
	receipt := state.ConfirmedInferReceipt
	if receipt == nil {
		return nil, fmt.Errorf("confirmed Worker InferReceiptV3 is required")
	}
	digest, err := builderclient.InferReceiptSigningDigest(*receipt)
	if err != nil {
		return nil, err
	}
	if digest != state.InferReceiptHash || receipt.TaskID != state.TaskID || receipt.ChainID != v.cfg.ChainID || receipt.WorkerOperatorAddress != state.WorkerAddress {
		return nil, fmt.Errorf("confirmed Worker receipt differs from accepted task facts")
	}
	facts, err := v.taskFacts(ctx, state.TaskID)
	if err != nil {
		return nil, err
	}
	if receipt.TaskHash != hex.EncodeToString(facts.AcceptedTaskHash) || receipt.GenerationParamsDigest != hex.EncodeToString(facts.GenerationParamsDigest) {
		return nil, fmt.Errorf("confirmed Worker receipt differs from accepted generation or task hash")
	}
	if err := nodewire.RequireWorkerEvidenceCommitmentsV3(receiptCommitments(receipt.RequiredEvidenceCommitments)); err != nil {
		return nil, err
	}
	for _, committed := range receipt.RequiredEvidenceCommitments {
		if committed.EncodedSizeBytes > limits[committed.EvidenceKind] {
			return nil, fmt.Errorf("Worker evidence of kind %d exceeds locked profile bound", committed.EvidenceKind)
		}
	}
	return receipt, nil
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
	return fmt.Errorf("%w: verifier evidence rejected: WORKER_EVIDENCE_FAULT: the confirmed output (%d bytes) is not the decode of the %d committed generated token ids (%d bytes)",
		ErrWorkerEvidenceInvalid, len(output), len(generated), len(decoded))
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
