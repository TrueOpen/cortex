package daemon

import (
	"context"
	"fmt"

	"github.com/SingaXYZ/cortex/internal/chainclient"
)

// taskSnapshotReader adapts Keeper's (session_id, task_id) query to the
// single-argument, task_id-keyed interface the Worker wants.
//
// The Worker re-reads the on-chain assignment both before starting work and when
// assembling the receipt, to stop forged events and stale assignments (the comment
// on worker.Config.SnapshotReader says as much). It holds only the task_id while
// Keeper's query needs the composite key, so session_id is bound here from the local
// task record: both belong to the same task, so the bound value and the queried
// value necessarily agree.
//
// SnapshotReader previously had no assignment site anywhere in production code, so
// the Worker could never pass its own precondition ("task snapshot reader is
// required") and inference never took a single step.
type taskSnapshotReader struct {
	reader    KeeperTaskReader
	sessionID string
}

func newTaskSnapshotReader(reader KeeperTaskReader, sessionID string) *taskSnapshotReader {
	if reader == nil || sessionID == "" {
		return nil
	}
	return &taskSnapshotReader{reader: reader, sessionID: sessionID}
}

func (r *taskSnapshotReader) TaskSnapshot(ctx context.Context, taskID string) (chainclient.TaskSnapshot, error) {
	if r == nil || r.reader == nil {
		return chainclient.TaskSnapshot{}, fmt.Errorf("Keeper task reader is not configured")
	}
	return r.reader.Task(ctx, r.sessionID, taskID)
}
