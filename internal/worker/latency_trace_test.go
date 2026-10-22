package worker

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/observability"
	"github.com/TrueOpen/cortex/internal/tasktrace"
)

// traceLines collects the milestone lines cortexd would log, so a test can read
// the trace the way an operator does.
// It is safe for concurrent emitters: the output stream opens beside the
// generation and traces from its own goroutine.
type traceLines struct {
	mu    sync.Mutex
	lines []string
}

func (c *traceLines) trace() *tasktrace.Trace {
	return &tasktrace.Trace{Emit: func(record observability.LogRecord) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.lines = append(c.lines, record.Message)
	}}
}

func (c *traceLines) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.lines...)
}

// one returns the single line for a milestone, and fails when the milestone was
// reached twice: a first-output latency that is emitted again mid-stream would
// read as a second, far slower first frame.
func (c *traceLines) one(t *testing.T, name string) string {
	t.Helper()
	prefix := "task trace event=" + name + " "
	found := ""
	lines := c.snapshot()
	for _, line := range lines {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		if found != "" {
			t.Fatalf("event %q emitted more than once:\n%s", name, strings.Join(lines, "\n"))
		}
		found = line
	}
	if found == "" {
		t.Fatalf("event %q was never emitted:\n%s", name, strings.Join(lines, "\n"))
	}
	return found
}

func (c *traceLines) absent(t *testing.T, name string) {
	t.Helper()
	prefix := "task trace event=" + name + " "
	lines := c.snapshot()
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			t.Fatalf("event %q was emitted before its milestone:\n%s", name, strings.Join(lines, "\n"))
		}
	}
}

// TestFirstOutputLatenciesAreTracedSeparately pins the distinction the two
// events exist to make. The engine's first delta and this node's first
// committed frame are different instants: a delta is held in `pending` until it
// reaches min_output_stream_frame_bytes, so a reader waiting on the output
// stream waits for the second one. Tracing only one of them would attribute
// this node's chunking delay to the engine, or hide it entirely.
func TestFirstOutputLatenciesAreTracedSeparately(t *testing.T) {
	h := newHarness(t)
	collected := &traceLines{}
	h.worker.cfg.Trace = collected.trace()
	h.worker.cfg.StreamLimits.MinOutputStreamFrameBytes = 16

	event := finalizedTask()
	recorder, err := h.worker.newOutputRecorder(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	// The stream opens beside the generation; these tests drive the
	// recorder directly and want it up before the first frame.
	recorder.awaitOpen()
	defer recorder.release()
	recorder.inferStartedAt = time.Now()

	observe := func(text string) {
		t.Helper()
		if err := recorder.ObserveInferFrame(context.Background(), modelservice.InferStreamFrame{
			TaskID: event.TaskID, RequestID: "infer-" + event.TaskID, TextDelta: text,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Below the minimum frame size: the engine has spoken, but nothing is
	// committed and nothing has left this node.
	observe("short")
	first := collected.one(t, "output_first_delta")
	if !strings.Contains(first, "delta_bytes=5") || !strings.Contains(first, "since_infer_started_ms=") {
		t.Fatalf("output_first_delta = %q, want the delta size and a latency", first)
	}
	collected.absent(t, "output_first_frame")

	// Crossing the minimum commits frame 0, which is the first output a reader
	// can see.
	observe("enough text to cross the minimum")
	frame := collected.one(t, "output_first_frame")
	for _, want := range []string{"seq=0", "since_infer_started_ms=", "since_first_delta_ms=", "min_frame_bytes=16", "transport_attached=true"} {
		if !strings.Contains(frame, want) {
			t.Fatalf("output_first_frame = %q, want it to carry %q", frame, want)
		}
	}

	// Later frames are not first frames.
	observe("another frame of text that also crosses the minimum")
	collected.one(t, "output_first_frame")
	collected.one(t, "output_first_delta")
}

// TestResumedTaskClaimsNoFirstFrame keeps the latency honest across a restart.
// A resumed task re-sends frames it signed in an earlier run; measuring "first
// frame" from this run's clock would report a latency that no request ever
// waited, and there is no start instant to measure from anyway.
func TestResumedTaskClaimsNoFirstFrame(t *testing.T) {
	h := newHarness(t)
	h.worker.cfg.StreamLimits.MinOutputStreamFrameBytes = 16
	event := finalizedTask()

	// First run: commit one frame.
	recorder, err := h.worker.newOutputRecorder(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	// The stream opens beside the generation; these tests drive the
	// recorder directly and want it up before the first frame.
	recorder.awaitOpen()
	recorder.inferStartedAt = time.Now()
	if err := recorder.ObserveInferFrame(context.Background(), modelservice.InferStreamFrame{
		TaskID: event.TaskID, RequestID: "infer-" + event.TaskID, TextDelta: "enough text to cross the minimum",
	}); err != nil {
		t.Fatal(err)
	}
	if len(recorder.frames) != 1 {
		t.Fatalf("frames = %d, want the first run to have committed one", len(recorder.frames))
	}
	_ = recorder.stream.Close()

	// Second run resumes from the journal, with the trace watching.
	collected := &traceLines{}
	h.worker.cfg.Trace = collected.trace()
	resumed, err := h.worker.resumeOutputRecorder(context.Background(), event, completedModelInference{
		TaskHash: recorder.taskHash, FrameCount: 1, ObservedBytes: recorder.total,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resumed.stream != nil {
		defer resumed.stream.Close()
	}
	if !resumed.firstFrameTraced {
		t.Fatal("a resumed recorder must already consider its first frame reported")
	}
	if _, err := resumed.finish(context.Background(), []byte("enough text to cross the minimum")); err != nil {
		t.Fatal(err)
	}
	collected.absent(t, "output_first_frame")
	collected.absent(t, "output_first_delta")
}
