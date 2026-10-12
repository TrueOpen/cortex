package worker

import (
	"time"

	"github.com/TrueOpen/cortex/internal/tasktrace"
)

// preparationTiming records how long each external step between an admitted
// assignment and the generation request took.
//
// The span exists because nothing in the preparation is local: it reads the
// task's immutable facts, the task snapshot, the input, the selected Task
// Builders and each of their endpoints, and then opens an output stream to
// every one of them -- all serially, all against services that may be nowhere
// near this node. Deployed away from the chain it has measured 6.7s, which is
// most of what a caller waits for before seeing any output, and until this
// existed none of it appeared in the log: it could only be recovered by
// subtracting the two different clocks that happen to bracket it.
//
// Durations are summed rather than listed, because a step that runs twice is
// itself the finding -- see taskGenerationCalls.
type preparationTiming struct {
	startedAt time.Time
	// taskGeneration is every read of the locked generation parameters, which
	// re-reads the task's immutable facts each time. taskGenerationCalls counts
	// them, so a step that runs more than once says so rather than hiding inside
	// a total.
	taskGeneration      time.Duration
	taskGenerationCalls int
	taskSnapshot        time.Duration
	input               time.Duration
	// outputStream covers resolving the receiving Builders and opening a stream
	// to each, which is the one step whose cost scales with the Builder count.
	outputStream time.Duration
	builders     int
}

// observe adds one step's duration to total. It takes the instant the step
// started rather than returning a closure, so the measured span is visible at
// the call site instead of depending on where a defer happens to run.
func (p *preparationTiming) observe(total *time.Duration, startedAt time.Time) {
	if p == nil {
		return
	}
	*total += time.Since(startedAt)
}

// sincePrepareStarted is the second baseline for a first-output milestone: how
// long the caller had been waiting on this node, rather than on the engine
// alone. It is absent when there was no preparation to measure from -- a
// resumed task, or a recorder a test drove directly -- rather than reported as
// a duration counted from the zero time.
func (r *outputStreamRecorder) sincePrepareStarted(at time.Time) tasktrace.Field {
	if r.prepareStartedAt.IsZero() {
		return tasktrace.Field{}
	}
	return tasktrace.Millis("since_prepare_started_ms", at.Sub(r.prepareStartedAt))
}

// emit reports the breakdown once, at the end of preparation. It is emitted for
// a resumed task too: the preparation ran either way, and a resume that was
// slow is worth seeing even though no generation follows it.
func (w *Worker) tracePreparationCompleted(taskID string) {
	if w.prepare.startedAt.IsZero() {
		return
	}
	w.cfg.Trace.Event("infer_prepare_completed",
		tasktrace.Str("task", taskID),
		tasktrace.Millis("total_ms", time.Since(w.prepare.startedAt)),
		tasktrace.Millis("task_generation_ms", w.prepare.taskGeneration),
		tasktrace.Int("task_generation_calls", w.prepare.taskGenerationCalls),
		tasktrace.Millis("task_snapshot_ms", w.prepare.taskSnapshot),
		tasktrace.Millis("input_ms", w.prepare.input),
		tasktrace.Millis("output_stream_ms", w.prepare.outputStream),
		tasktrace.Int("builders", w.prepare.builders))
}
