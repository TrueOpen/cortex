// Package taskfacts is the consumer seam for the two immutable Task facts the
// frozen task.v1 Task wires sign and Cortex cannot derive:
// TaskCoreState.accepted_task_hash (TrueOpen/node d8792e6
// proto/task/v1/assignment.proto:202) and
// TaskAssignmentViewV1.generation_params_digest (d8792e6
// proto/task/v1/query_task.proto:106).
//
// The one production producer is
// chainclient.KeeperABCIClient.TaskReceiptFacts, which reads both from the
// frozen section 16.2 Task query surface. This package exists so
// internal/worker and internal/verifier consume that read through a single
// identity-carrying contract instead of two copies of it, and so internal/daemon
// has exactly one place to adapt the Keeper client.
package taskfacts

import (
	"context"
	"fmt"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

// Facts is one answer, and it carries the task it answers for.
//
// The embedded snapshot is chainclient's, so absent and zero stay distinct
// exactly as that type documents: an absent fact is a nil slice reporting
// IsSet() == false, and an all-zero 32-byte value reports IsSet() == true and
// is a positive claim about consensus state.
//
// TaskID is not decoration. A receipt path already holds an assignment from the
// Keeper snapshot it is acting on, and these facts arrive from a SECOND query.
// Without the answered identity a reader pointed at the wrong task - a stale
// cache key, an adapter closing over the wrong id, a fake serving one fixed
// task - would populate a receipt with another task's consensus bytes, and no
// downstream check could catch it: the bytes are perfectly well formed, and the
// Keeper would simply reject the signature at
// msg_server_receipt.go's core.AcceptedTaskHash comparison with no attribution.
//
// It is therefore the task the READER answered for, carried through
// chainclient.TaskReceiptFactsAnswer, and never the id the caller of the seam
// asked with. Those two are compared - by internal/daemon's adapter at the read
// and by Validate at the consumer - and a value re-stamped from the request
// would turn both comparisons into a value checked against itself.
type Facts struct {
	// TaskID is the canonical lowercase 64-hex task the served facts belong to.
	TaskID string
	chainclient.TaskReceiptFactsSnapshot
}

// Reader reads both facts for one Task. internal/daemon adapts
// chainclient.KeeperABCIClient onto it; there is deliberately no second query
// mechanism.
//
// A transport failure and a well-formed answer that lacks a fact are different
// outcomes and must stay different. An implementation reports the first as an
// error - retryable when the underlying read was - and the second as a Facts
// value whose field reports IsSet() == false, which Validate refuses.
//
// Facts.TaskID must be the task the implementation actually served, which is not
// necessarily the taskID argument: an implementation that cannot answer for the
// requested task must return an error, and one that answers from the wrong
// source must say so, so that the mismatch is visible instead of relabelled.
type Reader interface {
	TaskFacts(ctx context.Context, taskID string) (Facts, error)
}

// ReaderFunc adapts a plain function to Reader, so a caller with nothing to
// hold onto does not need a named type.
type ReaderFunc func(context.Context, string) (Facts, error)

func (f ReaderFunc) TaskFacts(ctx context.Context, taskID string) (Facts, error) {
	return f(ctx, taskID)
}

// Validate refuses an answer no receipt path may use, for one of three reasons
// that are deliberately never collapsed:
//
//   - the answer is for a different task than the assignment in hand;
//   - a fact is absent, which means the served view did not carry the key at
//     all and Cortex does not know the value;
//   - a fact is 32 zero bytes, which is not "unknown". The frozen Hash32 has no
//     absent encoding, so zeros are a positive claim about consensus state and
//     are shape-valid all the way to a signature.
//
// taskID is the identity the caller already believes, which for the Worker is
// the finalized assignment's task and for the Verifier is the verify
// responsibility's task.
func (f Facts) Validate(taskID string) error {
	if taskID == "" {
		return fmt.Errorf("Keeper task facts need the task identity the caller is acting on")
	}
	if f.TaskID != taskID {
		return fmt.Errorf(
			"Keeper task facts answer for task %q, not the task %q the caller is acting on: "+
				"a receipt must not carry another task's accepted_task_hash or generation_params_digest",
			f.TaskID, taskID)
	}
	for _, field := range [...]struct {
		name   string
		source string
		value  chainclient.ProtoBytes32
	}{
		{
			"accepted_task_hash",
			"TaskCoreState.accepted_task_hash from task.v1.Query/Task (TaskViewV1.active.core)",
			f.AcceptedTaskHash,
		},
		{
			"generation_params_digest",
			"TaskAssignmentViewV1.generation_params_digest (field 16) from task.v1.Query/TaskAssignment",
			f.GenerationParamsDigest,
		},
	} {
		if !field.value.IsSet() {
			return fmt.Errorf(
				"Keeper task %s carries no %s: %s did not serve the value, and the frozen Hash32 "+
					"has no absent encoding to substitute for it",
				taskID, field.name, field.source)
		}
		if isZeroHash32(field.value) {
			return fmt.Errorf(
				"Keeper task %s served an all-zero %s from %s: 32 zero bytes is a positive claim "+
					"about consensus state rather than a missing value, and signing it would "+
					"authorize bytes the Keeper can only reject",
				taskID, field.name, field.source)
		}
	}
	return nil
}

func isZeroHash32(value chainclient.ProtoBytes32) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}
