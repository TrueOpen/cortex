package worker

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/modelservice"
)

// gatedOpenTaskData holds every output stream open until release is closed,
// and records every frame the opened streams carry. It is safe for the
// concurrent opens of a fan-out.
type gatedOpenTaskData struct {
	*recordingTaskData
	release chan struct{}
	refuse  error
	mu      sync.Mutex
	sent    []uint64
	opens   int
}

func (g *gatedOpenTaskData) OpenTaskOutputStream(ctx context.Context, endpoint string, request builderclient.OutputStreamRequest) (builderclient.TaskOutputStream, error) {
	select {
	case <-g.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(10 * time.Second):
		return nil, errors.New("open was never released")
	}
	if g.refuse != nil {
		return nil, g.refuse
	}
	stream, err := g.recordingTaskData.OpenTaskOutputStream(ctx, endpoint, request)
	if err != nil {
		return nil, err
	}
	g.mu.Lock()
	g.opens++
	first := g.opens == 1
	g.mu.Unlock()
	return &gatedStream{TaskOutputStream: stream, owner: g, record: first}, nil
}

func (g *gatedOpenTaskData) sentSeqs() []uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]uint64(nil), g.sent...)
}

type gatedStream struct {
	builderclient.TaskOutputStream
	owner *gatedOpenTaskData
	// record is set on the first Builder's stream only, so the recorded
	// sequence is one Builder's view of the frames.
	record bool
}

func (s *gatedStream) SendChunk(chunk builderclient.OutputChunk) error {
	if s.record {
		s.owner.mu.Lock()
		s.owner.sent = append(s.owner.sent, chunk.Seq)
		s.owner.mu.Unlock()
	}
	return s.TaskOutputStream.SendChunk(chunk)
}

func observeText(t *testing.T, recorder *outputStreamRecorder, text string) {
	t.Helper()
	if err := recorder.ObserveInferFrame(context.Background(), modelservice.InferStreamFrame{
		TaskID: recorder.event.TaskID, RequestID: "infer-" + recorder.event.TaskID, TextDelta: text,
	}); err != nil {
		t.Fatal(err)
	}
}

// The recorder is ready before the stream is: frames signed while the open is
// still in flight are journaled and kept, and the moment the stream is up they
// go out on it in seq order, each exactly once, followed by the frames signed
// afterwards.
func TestFramesSignedBeforeTheStreamOpensAreSentInOrderOnce(t *testing.T) {
	h := newHarness(t)
	h.worker.cfg.StreamLimits.MinOutputStreamFrameBytes = 4
	gated := &gatedOpenTaskData{recordingTaskData: h.taskData, release: make(chan struct{})}
	h.worker.cfg.TaskData = gated
	event := finalizedTask()

	recorder, err := h.worker.newOutputRecorder(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.release()
	recorder.inferStartedAt = time.Now()

	observeText(t, recorder, "frame zero")
	observeText(t, recorder, "frame one, longer")
	if len(recorder.frames) != 2 {
		t.Fatalf("frames = %d, want two signed while the stream was opening", len(recorder.frames))
	}
	journaled := 0
	for _, record := range h.persistence.evidence {
		if strings.HasPrefix(record.Kind, OutputStreamFramePrefix) {
			journaled++
		}
	}
	if journaled != 2 {
		t.Fatalf("journaled frames = %d, want both frames durable before any transport", journaled)
	}
	if sent := gated.sentSeqs(); len(sent) != 0 {
		t.Fatalf("frames sent before the stream opened: %v", sent)
	}

	close(gated.release)
	recorder.awaitOpen()
	if recorder.stream == nil {
		t.Fatalf("stream did not attach: %v", recorder.transportErr)
	}
	observeText(t, recorder, "frame two, after the open")
	output := "frame zeroframe one, longerframe two, after the open"
	if _, err := recorder.finish(context.Background(), []byte(output), 0); err != nil {
		t.Fatal(err)
	}
	sent := gated.sentSeqs()
	if len(sent) != len(recorder.frames) {
		t.Fatalf("sent seqs = %v, want each of the %d frames exactly once", sent, len(recorder.frames))
	}
	for i, seq := range sent {
		if seq != uint64(i) {
			t.Fatalf("sent seqs = %v, want 0..%d in order", sent, len(sent)-1)
		}
	}
}

// A stream that cannot be opened does not stop the generation: every frame is
// still signed and journaled, and finishing succeeds with the transport error
// kept for the storing step, which reopens the stream with the journaled
// frames as replay. Failing the attempt instead would leave signed frames
// that may never be regenerated.
func TestAFailedConcurrentOpenKeepsGeneratingAndJournaling(t *testing.T) {
	h := newHarness(t)
	h.worker.cfg.StreamLimits.MinOutputStreamFrameBytes = 4
	release := make(chan struct{})
	close(release)
	refused := errors.New("builder refused the stream")
	gated := &gatedOpenTaskData{recordingTaskData: h.taskData, release: release, refuse: refused}
	h.worker.cfg.TaskData = gated
	event := finalizedTask()

	recorder, err := h.worker.newOutputRecorder(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.release()
	observeText(t, recorder, "frame zero")
	observeText(t, recorder, "frame one")
	if _, err := recorder.finish(context.Background(), []byte("frame zeroframe one"), 0); err != nil {
		t.Fatalf("finish = %v, want success with the transport error kept", err)
	}
	if !errors.Is(recorder.transportErr, refused) {
		t.Fatalf("transport error = %v, want the refused open", recorder.transportErr)
	}
	if len(recorder.frames) != 2 || h.worker.outputStream != nil {
		t.Fatalf("frames = %d, handed-over stream = %v; want two frames and no stream", len(recorder.frames), h.worker.outputStream)
	}
}

// Releasing a recorder whose open is still in flight cancels the open and
// waits for it, so nothing outlives the attempt.
func TestReleasingTheRecorderCancelsAPendingOpen(t *testing.T) {
	h := newHarness(t)
	gated := &gatedOpenTaskData{recordingTaskData: h.taskData, release: make(chan struct{})}
	h.worker.cfg.TaskData = gated
	recorder, err := h.worker.newOutputRecorder(context.Background(), finalizedTask())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { recorder.release(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("release did not cancel the pending open")
	}
	if !errors.Is(recorder.transportErr, context.Canceled) {
		t.Fatalf("transport error = %v, want the cancelled open", recorder.transportErr)
	}
}

// startSignalModel reports when the generation request reaches the model.
type startSignalModel struct {
	modelservice.Client
	started chan struct{}
	once    sync.Once
}

func (m *startSignalModel) Infer(ctx context.Context, request modelservice.InferRequest) (modelservice.InferResponse, error) {
	m.once.Do(func() { close(m.started) })
	return m.Client.Infer(ctx, request)
}

// The generation request leaves before the output stream is open: the open
// below is released only by the model being called, so an attempt that still
// opened the stream first would wait out the gate and fail.
func TestGenerationStartsBeforeTheOutputStreamIsOpen(t *testing.T) {
	h := newHarness(t)
	enableEvidenceSchema(&h)
	model := &startSignalModel{Client: h.worker.cfg.Model, started: make(chan struct{})}
	h.worker.cfg.Model = model
	gated := &gatedOpenTaskData{recordingTaskData: h.taskData, release: model.started}
	h.worker.cfg.TaskData = gated
	collected := &traceLines{}
	h.worker.cfg.Trace = collected.trace()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := h.worker.HandleAssignmentFinalized(ctx, finalizedTask()); err != nil {
		t.Fatalf("HandleAssignmentFinalized = %v", err)
	}
	if sent := gated.sentSeqs(); len(sent) == 0 {
		t.Fatal("no frame reached the output stream")
	}
	prepared := collected.one(t, "infer_prepare_completed")
	if !strings.Contains(prepared, "output_stream_concurrent=true") {
		t.Fatalf("infer_prepare_completed = %q, want the concurrent open flagged", prepared)
	}
	opened := collected.one(t, "output_stream_opened")
	for _, want := range []string{"open_stream_ms=", "resolve_builders_ms=", "transport_attached=true"} {
		if !strings.Contains(opened, want) {
			t.Fatalf("output_stream_opened = %q, want %s", opened, want)
		}
	}
}

// failFirstOpenTaskData refuses the first output stream open and lets later
// ones through, recording the replay frames each later open carries.
type failFirstOpenTaskData struct {
	*recordingTaskData
	mu      sync.Mutex
	opens   int
	replays [][]builderclient.OutputChunk
}

func (f *failFirstOpenTaskData) OpenTaskOutputStream(ctx context.Context, endpoint string, request builderclient.OutputStreamRequest) (builderclient.TaskOutputStream, error) {
	f.mu.Lock()
	f.opens++
	first := f.opens == 1
	if !first {
		f.replays = append(f.replays, append([]builderclient.OutputChunk(nil), request.ReplayChunks...))
	}
	f.mu.Unlock()
	if first {
		return nil, errors.New("builder refused the stream")
	}
	return f.recordingTaskData.OpenTaskOutputStream(ctx, endpoint, request)
}

// When the stream opened beside the generation fails, the attempt still
// completes: the output is stored over a reopened stream that replays every
// journaled frame, in order.
func TestAFailedConcurrentOpenIsReplayedWhenTheOutputIsStored(t *testing.T) {
	h := newHarness(t)
	enableEvidenceSchema(&h)
	failing := &failFirstOpenTaskData{recordingTaskData: h.taskData}
	h.worker.cfg.TaskData = failing
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := h.worker.HandleAssignmentFinalized(ctx, finalizedTask()); err != nil {
		t.Fatalf("HandleAssignmentFinalized = %v, want the output stored over a reopened stream", err)
	}
	frames, err := h.worker.cfg.Persistence.OutputStreamFrames(context.Background(), finalizedTask().TaskID)
	if err != nil || len(frames) == 0 {
		t.Fatalf("journaled frames = %d, %v", len(frames), err)
	}
	failing.mu.Lock()
	defer failing.mu.Unlock()
	if failing.opens < 2 || len(failing.replays) == 0 {
		t.Fatalf("opens = %d, want the failed open followed by a reopen", failing.opens)
	}
	replay := failing.replays[0]
	if len(replay) != len(frames) {
		t.Fatalf("reopen replayed %d frames, want all %d journaled frames", len(replay), len(frames))
	}
	for i, chunk := range replay {
		if chunk.Seq != uint64(i) || chunk.MMRRoot != frames[i].MMRRoot {
			t.Fatalf("replayed frame %d = seq %d, want the journaled frame %d", i, chunk.Seq, i)
		}
	}
}
