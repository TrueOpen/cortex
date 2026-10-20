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
// There is one timer per external call rather than per stage, because a stage
// that bundles two different calls cannot say which of them was slow. The first
// measurement on a node deployed away from the chain made that concrete: a
// single stage held 81% of the preparation, and it covered both the Builder
// handshakes and a chain read.
//
// Durations are summed rather than listed, because a call that runs more than
// once is itself the finding -- see taskFactsCalls. total is wall clock, so the
// difference between it and the sum of the parts is this node's own work.
type preparationTiming struct {
	startedAt time.Time
	// taskFacts is every read of the task's immutable facts, counted across all
	// of its callers: the value cannot change for a task, so a count above one
	// is a re-read of something already known.
	taskFacts      time.Duration
	taskFactsCalls int
	// generationParams is the separate chain read of the locked generation
	// parameters. It travels with taskFacts but is its own query.
	generationParams time.Duration
	taskSnapshot     time.Duration
	input            time.Duration
	// openStream is the Builder handshakes alone, which is the one cost that
	// scales with the Builder count -- each is a TLS handshake plus a round trip
	// for the header acknowledgement.
	openStream time.Duration
	builders   int
	// resolveBuilders is finding the Task Builders and their endpoints before
	// the streams open: the selected-Builder read plus one endpoint resolution
	// per Builder.
	resolveBuilders time.Duration
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
		tasktrace.Millis("task_facts_ms", w.prepare.taskFacts),
		tasktrace.Int("task_facts_calls", w.prepare.taskFactsCalls),
		tasktrace.Millis("generation_params_ms", w.prepare.generationParams),
		tasktrace.Millis("task_snapshot_ms", w.prepare.taskSnapshot),
		tasktrace.Millis("input_ms", w.prepare.input),
		tasktrace.Millis("resolve_builders_ms", w.prepare.resolveBuilders),
		tasktrace.Millis("open_stream_ms", w.prepare.openStream),
		tasktrace.Int("builders", w.prepare.builders))
}
