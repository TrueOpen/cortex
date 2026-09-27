package verifier

import (
	"context"
	"fmt"

	"github.com/TrueOpen/cortex/internal/taskfacts"
)

// taskFacts reads the Task facts the frozen result credential signs for the
// task this verify responsibility is for. Only generation_params_digest reaches
// the ResultReceiptV3 body, but the read is the same single
// chainclient.KeeperABCIClient.TaskReceiptFacts call the Worker's receipt path
// uses; there is no second query mechanism and no fallback.
//
// The two failure modes stay apart. A reader error is returned as it came, so a
// retryable Keeper read stays retryable through errors.As and the task runner
// retries it. An answer that is for another task, lacks the fact, or serves 32
// zero bytes is refused here as a permanent, attributable input gap, because
// retrying it cannot change the answer.
//
// That refusal is this function's own, matching the Worker's helper, rather than
// something left to resultReceiptWire. resultReceiptWire checks it too - it is a
// pure assembler that tests and any future caller can reach with arbitrary facts,
// so it validates its own inputs - but a served answer must not be usable
// anywhere in this package just because today there happens to be one consumer.
func (v *Verifier) taskFacts(ctx context.Context, taskID string) (taskfacts.Facts, error) {
	if v.cfg.TaskFacts == nil {
		return taskfacts.Facts{}, fmt.Errorf(
			"%w: verify result generation_params_digest needs the Keeper task facts reader, "+
				"which this verifier was built without",
			ErrResultReceiptInputUnavailable)
	}
	facts, err := v.cfg.TaskFacts.TaskFacts(ctx, taskID)
	if err != nil {
		return taskfacts.Facts{}, fmt.Errorf("read Keeper task %s receipt facts: %w", taskID, err)
	}
	if err := facts.Validate(taskID); err != nil {
		return taskfacts.Facts{}, fmt.Errorf("%w: verify result generation_params_digest: %w",
			ErrResultReceiptInputUnavailable, err)
	}
	return facts, nil
}
