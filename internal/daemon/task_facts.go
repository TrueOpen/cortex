package daemon

import (
	"context"
	"fmt"
	"strings"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/taskfacts"
)

// TaskReceiptFactsReader is the Keeper capability behind the Worker's and
// Verifier's task-facts seam. It is a capability rather than a member of
// KeeperClient because KeeperClient is the runtime's injection point and is
// implemented by height-only stubs; widening it would force every one of those
// to grow a method it has no use for.
//
// The narrowing that discovers this capability is therefore a type switch, and
// the assertion below is what keeps that switch from being a silent branch: the
// only Keeper client BuildRuntime constructs on its own must satisfy it, or this
// package does not compile.
type TaskReceiptFactsReader interface {
	TaskReceiptFacts(ctx context.Context, taskID string) (chainclient.TaskReceiptFactsAnswer, error)
}

// The production construction site, proven statically. runtime.go builds
// exactly this type when no Keeper is injected (BuildRuntimeWithOptions, the
// cfg.UsesRealDependencies() branch), and cmd/cortexd never injects one, so on
// the shipped path NewTaskFacts always takes the first switch arm below.
var _ TaskReceiptFactsReader = (*chainclient.KeeperABCIClient)(nil)

// NewTaskFacts adapts the runtime's Keeper client onto the task-facts seam.
//
// There are exactly three outcomes, and they are deliberately three rather than
// two, because "no Keeper", "a Keeper that cannot do this" and "a Keeper that
// answered without the value" send an operator to three different places:
//
//   - No Keeper at all (config.ModeFake leaves Dependencies.Keeper nil) yields a
//     nil provider, and the Worker and Verifier refuse with "Keeper task facts
//     reader is required" before any inference or signature.
//   - A Keeper that does not serve the frozen section 16.2 Task reads yields
//     unsupportedTaskFacts, NOT nil. A nil here would be indistinguishable from
//     the case above and would read like a missing config line rather than a
//     Keeper client that cannot do the job.
//   - Otherwise the real reader, whose absent-value refusals come from
//     taskfacts.Facts.Validate and name the served task and field.
//
// A fourth input - an interface value holding a typed nil pointer - would take
// the capability arm and panic on first use, because a method set belongs to the
// type rather than the value. It is not a case here: BuildDependencies refuses
// it with ErrTypedNilKeeperClient at the single point such a value can enter the
// daemon, so no Keeper reaching this function can be one.
func NewTaskFacts(keeper KeeperClient) taskfacts.Reader {
	switch reader := keeper.(type) {
	case nil:
		return nil
	case TaskReceiptFactsReader:
		return keeperTaskFacts{keeper: reader}
	default:
		return unsupportedTaskFacts{keeper: keeper}
	}
}

// unsupportedTaskFacts is the fail-closed reader for a Keeper client that cannot
// serve the frozen Task reads. Every call fails by name, permanently, and the
// message says this is a Cortex wiring fault rather than a chain that does not
// carry the value - the distinction requirement 3 of the receipt-facts brief
// turns on, since retrying the first is pointless and retrying the second is
// wrong for a different reason.
type unsupportedTaskFacts struct{ keeper KeeperClient }

func (r unsupportedTaskFacts) TaskFacts(context.Context, string) (taskfacts.Facts, error) {
	return taskfacts.Facts{}, fmt.Errorf(
		"configured Keeper client %T cannot serve the frozen task.v1 Query/Task and "+
			"Query/TaskAssignment reads that chainclient.KeeperABCIClient.TaskReceiptFacts "+
			"performs, so accepted_task_hash and generation_params_digest were never queried; "+
			"this is a Cortex wiring fault, not a chain state that lacks the value",
		r.keeper)
}

type keeperTaskFacts struct{ keeper TaskReceiptFactsReader }

// TaskFacts performs the one frozen section 16.2 read and passes on the identity
// the reader says it answered for.
//
// The label is NOT the id this adapter asked with. Stamping the requested id
// would make the consumer's identity check vacuous: it would compare the
// caller's own belief against a copy of itself, and a reader that answered with
// another task's values - a snapshot cached under a stale key, a fake serving
// one fixed task - would sail through with well-formed bytes belonging to the
// wrong Task. So the reader states which task it served and this adapter refuses
// a disagreement here, at the read, where the fault is attributable. On the
// shipped path chainclient.TaskReceiptFacts has already checked that identity
// against the served TaskCoreState.task_id and TaskAssignmentViewV1.task_id, so
// an answer that survives both checks is one consensus agreed is about T.
//
// A failed read is reported as an error and keeps its retryability: a Keeper
// transport failure becomes a builderclient-retryable error, exactly as
// taskdataauth does for the service-key read, so the task runner retries it
// instead of treating it as a permanent refusal. A well-formed answer that lacks
// a fact is not an error in this adapter - it comes back as an unset field, and
// taskfacts.Facts.Validate refuses it at the consumer as the permanent gap it
// is. (The shipped reader refuses it one layer earlier still, in
// chainclient.TaskReceiptFactsSnapshot.Validate; an injected one need not.)
func (r keeperTaskFacts) TaskFacts(ctx context.Context, taskID string) (taskfacts.Facts, error) {
	canonical := strings.TrimSpace(taskID)
	if canonical == "" || canonical != taskID {
		return taskfacts.Facts{}, fmt.Errorf("Keeper task facts need a canonical task id, got %q", taskID)
	}
	answer, err := r.keeper.TaskReceiptFacts(ctx, canonical)
	if err != nil {
		wrapped := fmt.Errorf("query Keeper task %s receipt facts: %w", canonical, err)
		if chainclient.IsRetryable(err) {
			return taskfacts.Facts{}, builderclient.Retryable(wrapped)
		}
		return taskfacts.Facts{}, wrapped
	}
	if answer.TaskID != canonical {
		return taskfacts.Facts{}, fmt.Errorf(
			"Keeper task facts reader %T answered for task %q, not the task %q it was asked about; "+
				"no facts may be used from a read that is about another Task",
			r.keeper, answer.TaskID, canonical)
	}
	return taskfacts.Facts{TaskID: answer.TaskID, TaskReceiptFactsSnapshot: answer.TaskReceiptFactsSnapshot}, nil
}
