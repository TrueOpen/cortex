package worker

import (
	"context"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/modelservice"
)

// TestFrameMinimumDoublesUntilTheCap pins the shape of the ramp, including both
// of its ends. The chain parameter is the minimum of frame 0 rather than of
// every frame, and the cap is a protocol constant, so this function is the only
// place either end is stated on this side.
func TestFrameMinimumDoublesUntilTheCap(t *testing.T) {
	for _, test := range []struct {
		name  string
		floor uint32
		seq   uint64
		want  uint64
	}{
		{name: "frame 0 is the chain parameter itself", floor: 16, seq: 0, want: 16},
		{name: "frame 1 doubles it", floor: 16, seq: 1, want: 32},
		{name: "frame 2 doubles again", floor: 16, seq: 2, want: 64},
		{name: "frame 3 doubles again", floor: 16, seq: 3, want: 128},
		{name: "frame 4 reaches the cap", floor: 16, seq: 4, want: 256},
		{name: "the bulk of the stream stays at the cap", floor: 16, seq: 5, want: 256},

		// The ramp climbs to the cap; it never descends to it. A chain carrying a
		// floor at or above the cap is asking for frames at least that large, and
		// capping it would emit frames the Builder is entitled to reject.
		{name: "a chain still carrying the cap sees no ramp", floor: 256, seq: 0, want: 256},
		{name: "a chain still carrying the cap stays flat", floor: 256, seq: 3, want: 256},
		{name: "a floor above the cap is never lowered to it", floor: 512, seq: 0, want: 512},
		{name: "a floor above the cap does not ramp either", floor: 512, seq: 9, want: 512},

		// seq is bounded only by max_output_mmr_leaves, so the arithmetic has to
		// survive a sequence far past the point the ramp has flattened.
		{name: "a long stream does not overflow the shift", floor: 16, seq: 65535, want: 256},
		{name: "the smallest usable floor still terminates", floor: 1, seq: 65535, want: 256},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := minFrameBytes(test.floor, test.seq); got != test.want {
				t.Fatalf("minFrameBytes(%d, %d) = %d, want %d", test.floor, test.seq, got, test.want)
			}
		})
	}
}

// TestEarlyFramesCommitBeforeReachingTheCap is the point of the ramp: the first
// frames leave this node after a fraction of the bytes the bulk of the stream
// needs, so a reader sees the start of an answer without waiting out a full cap
// of generation. The flat floor this replaces would have committed every one of
// these frames at the same size.
func TestEarlyFramesCommitBeforeReachingTheCap(t *testing.T) {
	h := newHarness(t)
	h.worker.cfg.StreamLimits.MinOutputStreamFrameBytes = 16

	event := finalizedTask()
	recorder, err := h.worker.newOutputRecorder(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.stream.Close()

	// observe feeds exactly n bytes of generated text and reports how many frames
	// stand committed afterwards.
	observe := func(n int) int {
		t.Helper()
		if err := recorder.ObserveInferFrame(context.Background(), modelservice.InferStreamFrame{
			TaskID: event.TaskID, RequestID: "infer-" + event.TaskID, TextDelta: strings.Repeat("a", n),
		}); err != nil {
			t.Fatal(err)
		}
		return len(recorder.frames)
	}

	if got := observe(16); got != 1 {
		t.Fatalf("frames after 16 bytes = %d, want frame 0 committed at the chain floor", got)
	}

	// Frame 1 wants 32. The flat floor would have committed this one too.
	if got := observe(16); got != 1 {
		t.Fatalf("frames after another 16 bytes = %d, want frame 1 still held below its own minimum", got)
	}
	if got := observe(16); got != 2 {
		t.Fatalf("frames after 32 pending bytes = %d, want frame 1 committed", got)
	}

	// Frame 2 wants 64.
	if got := observe(32); got != 2 {
		t.Fatalf("frames after 32 pending bytes at seq 2 = %d, want frame 2 still held", got)
	}
	if got := observe(32); got != 3 {
		t.Fatalf("frames after 64 pending bytes = %d, want frame 2 committed", got)
	}

	for seq, want := range map[int]int{0: 16, 1: 32, 2: 64} {
		if got := len(recorder.frames[seq].Text); got != want {
			t.Fatalf("frame %d is %d bytes, want %d", seq, got, want)
		}
	}
}

// TestResumedStreamContinuesTheRampWhereItStopped keeps the ramp out of the
// journal. It is a function of the frame's seq, which the restored MMR already
// carries, so a restart must not start the stream over at the chain floor: the
// Builder holds the real seq and would reject a frame sized for seq 0 arriving
// as seq 2.
func TestResumedStreamContinuesTheRampWhereItStopped(t *testing.T) {
	h := newHarness(t)
	h.worker.cfg.StreamLimits.MinOutputStreamFrameBytes = 16
	event := finalizedTask()

	// First run commits frames 0 and 1, at 16 and 32 bytes.
	recorder, err := h.worker.newOutputRecorder(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{16, 32} {
		if err := recorder.ObserveInferFrame(context.Background(), modelservice.InferStreamFrame{
			TaskID: event.TaskID, RequestID: "infer-" + event.TaskID, TextDelta: strings.Repeat("a", n),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if len(recorder.frames) != 2 {
		t.Fatalf("frames = %d, want the first run to have committed two", len(recorder.frames))
	}
	_ = recorder.stream.Close()

	resumed, err := h.worker.resumeOutputRecorder(context.Background(), event, completedModelInference{
		TaskHash: recorder.taskHash, FrameCount: 2, ObservedBytes: recorder.total,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resumed.stream != nil {
		defer resumed.stream.Close()
	}

	// Frame 2 wants 64, not the 16 a restarted ramp would have accepted.
	if err := resumed.ObserveInferFrame(context.Background(), modelservice.InferStreamFrame{
		TaskID: event.TaskID, RequestID: "infer-" + event.TaskID, TextDelta: strings.Repeat("a", 32),
	}); err != nil {
		t.Fatal(err)
	}
	if got := len(resumed.frames); got != 2 {
		t.Fatalf("frames after resuming = %d, want frame 2 held to seq 2's minimum rather than the chain floor", got)
	}
	if err := resumed.ObserveInferFrame(context.Background(), modelservice.InferStreamFrame{
		TaskID: event.TaskID, RequestID: "infer-" + event.TaskID, TextDelta: strings.Repeat("a", 32),
	}); err != nil {
		t.Fatal(err)
	}
	if got := len(resumed.frames); got != 3 {
		t.Fatalf("frames after 64 pending bytes = %d, want frame 2 committed", got)
	}
}
