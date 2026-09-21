package worker

import (
	"context"
	"fmt"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/taskfacts"
)

// taskFacts reads the two immutable Task facts the frozen InferReceiptV1 signs
// and Cortex cannot derive, for the assignment this Worker is acting on.
//
// The read is the single chainclient.KeeperABCIClient.TaskReceiptFacts call the
// TaskFacts seam wraps; there is no second query mechanism and no fallback. Two
// outcomes are kept apart on purpose:
//
//   - The reader failed. The error is returned as it came, so a transport
//     failure that the Keeper client marked retryable stays retryable and the
//     task runner retries it like any other Keeper read. fmt.Errorf's %w keeps
//     that marker reachable through errors.As.
//   - The reader answered, but the answer is unusable: it is for another task,
//     it lacks a fact, or a fact is 32 zero bytes. That is a fail-closed refusal
//     and it is permanent, because retrying a well-formed answer cannot change
//     it.
//
// The identity cross-check here is Facts.Validate's first clause: the assignment
// in hand names the task, and a second query that answered for a different one
// must not populate this receipt. It compares the identity the READER stated
// against the assignment's, which is why Facts carries the answered task rather
// than a copy of the id the seam was asked with; internal/daemon's adapter
// refuses the same disagreement one layer earlier, at the read.
func (w *Worker) taskFacts(ctx context.Context, taskID string) (taskfacts.Facts, error) {
	if w.cfg.TaskFacts == nil {
		return taskfacts.Facts{}, fmt.Errorf("Keeper task facts reader is required")
	}
	facts, err := w.cfg.TaskFacts.TaskFacts(ctx, taskID)
	if err != nil {
		return taskfacts.Facts{}, fmt.Errorf("read Keeper task %s receipt facts: %w", taskID, err)
	}
	if err := facts.Validate(taskID); err != nil {
		return taskfacts.Facts{}, err
	}
	return facts, nil
}

// preparedReceiptInputs is everything one prepared output contributes to the
// frozen receipt: the two consensus facts the Keeper served, the local values
// this pass produced, and the two TRUEOPEN_WORKER_VALUE_COMMITMENT_V1 inputs Cortex
// still has no source for.
type preparedReceiptInputs struct {
	event                      chainclient.AssignmentFinalized
	facts                      taskfacts.Facts
	local                      workerValueEvidenceInputs
	serviceAuthorizationNonce  uint64
	outputHash                 codec.Hash
	outputSizeBytes            uint64
	traceRoot                  codec.Hash
	traceSizeBytes             uint64
	checkpointRoot             codec.Hash
	checkpointSizeBytes        uint64
	generatedTokenCount        uint64
	outputLeafCount            uint64
	inputTokenIDsHash          codec.Hash
	generatedTokenIDsHash      codec.Hash
	inputTokenIDsSizeBytes     uint64
	generatedTokenIDsSizeBytes uint64
}

// workerValueEvidenceFacts and inferReceiptFacts are the only two places a
// served consensus fact becomes a signed field, which is why they are functions
// rather than inline literals: the Worker's own test seed builds its prepared
// output through them too, so a substitution here - hex(event.OrderDigest) under
// task_hash is the tempting one, and the frozen contract forbids it - cannot
// slip past by only existing on the path the seed skips.
func (w *Worker) workerValueEvidenceFacts(in preparedReceiptInputs) builderclient.WorkerValueEvidenceFacts {
	return builderclient.WorkerValueEvidenceFacts{
		ChainID:                    w.cfg.ChainID,
		TaskID:                     in.event.TaskID,
		AcceptedTaskHash:           in.facts.AcceptedTaskHash.Hex(),
		WorkerOperatorAddress:      w.cfg.WorkerAddress,
		GenerationParamsDigest:     in.facts.GenerationParamsDigest.Hex(),
		EvidenceSchemaHash:         in.local.EvidenceSchemaHash,
		OutputHash:                 in.outputHash,
		OutputSizeBytes:            in.outputSizeBytes,
		FinishReason:               in.local.FinishReason,
		TraceRoot:                  in.traceRoot,
		TraceEncodedSizeBytes:      in.traceSizeBytes,
		CheckpointRoot:             in.checkpointRoot,
		CheckpointEncodedSizeBytes: in.checkpointSizeBytes,
		GeneratedTokenCount:        in.generatedTokenCount, OutputLeafCount: in.outputLeafCount,
		InputTokenIDsHash: in.inputTokenIDsHash, GeneratedTokenIDsHash: in.generatedTokenIDsHash,
		InputTokenIDsSizeBytes: in.inputTokenIDsSizeBytes, GeneratedTokenIDsSizeBytes: in.generatedTokenIDsSizeBytes,
	}
}

// inferReceiptFacts maps the same inputs onto the frozen InferReceiptV1's signed
// fields. profileRequirements is a parameter rather than part of the input set
// because it is the one value production genuinely cannot supply: it stays nil
// on the Worker path and the seed passes the locked Profile's shape.
func (w *Worker) inferReceiptFacts(
	in preparedReceiptInputs,
	evidence builderclient.EvidenceCommitment,
	profileRequirements []builderclient.InferEvidenceRequirement,
) builderclient.InferReceiptFacts {
	return builderclient.InferReceiptFacts{
		ChainID:                   w.cfg.ChainID,
		TaskID:                    in.event.TaskID,
		TaskHash:                  in.facts.AcceptedTaskHash.Hex(),
		WorkerOperatorAddress:     w.cfg.WorkerAddress,
		ServiceAuthorizationNonce: in.serviceAuthorizationNonce,
		GenerationParamsDigest:    in.facts.GenerationParamsDigest.Hex(),
		GeneratedTokenCount:       in.generatedTokenCount,
		OutputLeafCount:           in.outputLeafCount,
		OutputHash:                in.outputHash,
		OutputSizeBytes:           in.outputSizeBytes,
		// Node checks both height <= receipt.expiry_height and
		// height <= assignment.infer_deadline_height, so anchoring the credential
		// to the infer deadline is exactly as permissive as admission allows.
		ExpiryHeight:                in.event.InferDeadlineHeight,
		RequiredEvidenceCommitments: []builderclient.EvidenceCommitment{evidence},
		ProfileEvidenceRequirements: profileRequirements,
	}
}
