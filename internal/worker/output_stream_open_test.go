package worker

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
)

// failingTaskData refuses one Builder and records what was opened and closed, so
// a test can check that a partial open leaves nothing behind.
type failingTaskData struct {
	*recordingTaskData
	refuse string
	mu     sync.Mutex
	opened []*countingStream
}

type countingStream struct {
	builderclient.TaskOutputStream
	closed bool
	mu     sync.Mutex
}

func (s *countingStream) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return s.TaskOutputStream.Close()
}

func (s *countingStream) wasClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (f *failingTaskData) OpenTaskOutputStream(ctx context.Context, endpoint string, request builderclient.OutputStreamRequest) (builderclient.TaskOutputStream, error) {
	if endpoint == f.refuse {
		return nil, errors.New("task data plane refused the stream")
	}
	stream, err := f.recordingTaskData.OpenTaskOutputStream(ctx, endpoint, request)
	if err != nil {
		return nil, err
	}
	counting := &countingStream{TaskOutputStream: stream}
	f.mu.Lock()
	f.opened = append(f.opened, counting)
	f.mu.Unlock()
	return counting, nil
}

type openStreamTask struct {
	event chainclient.AssignmentFinalized
	hash  codec.Hash
}

func openStreamHarness(t *testing.T) (harness, taskBuilderSet, openStreamTask) {
	t.Helper()
	h := newHarness(t)
	set := withTaskBuilderSet(t, h)
	return h, set, openStreamTask{event: finalizedTask(), hash: codec.HashBytes([]byte("open-stream-task"))}
}

// TestOutputStreamOpensOnlyToTheDispatchingBuilder: the frames go to the
// Builder that dispatched the ticket (CD §5.2 W11, C1), never to the rest of
// the Task Builder group, which before the record cannot authenticate them.
func TestOutputStreamOpensOnlyToTheDispatchingBuilder(t *testing.T) {
	h, set, task := openStreamHarness(t)
	stream, err := h.worker.openOutputStream(context.Background(), task.event, task.hash, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	fanOut, ok := stream.(*fanOutOutputStream)
	if !ok {
		t.Fatalf("stream is %T, want the fan-out", stream)
	}
	if len(fanOut.builders) != 1 || fanOut.builders[0] != set.endpoints[0].OperatorAddress {
		t.Fatalf("stream goes to %v, want only the dispatching Builder %s", fanOut.builders, set.endpoints[0].OperatorAddress)
	}
	if n := len(h.taskData.UploadedOutputStreams); n != 1 {
		t.Fatalf("opened %d streams, want one", n)
	}
}

// TestRefusedDispatchingBuilderFailsTheOpen: the dispatching Builder refusing
// the stream fails the open and leaves nothing behind; another group member
// refusing does not matter, since it is never asked.
func TestRefusedDispatchingBuilderFailsTheOpen(t *testing.T) {
	h, set, task := openStreamHarness(t)
	failing := &failingTaskData{recordingTaskData: h.taskData, refuse: set.endpoints[0].Endpoint}
	h.worker.cfg.TaskData = failing
	stream, err := h.worker.openOutputStream(context.Background(), task.event, task.hash, nil)
	if err == nil {
		_ = stream.Close()
		t.Fatal("the open succeeded while the dispatching Builder was refusing")
	}
	if !strings.Contains(err.Error(), set.endpoints[0].OperatorAddress) {
		t.Fatalf("error = %v, want it to name the Builder that refused", err)
	}
	failing.mu.Lock()
	opened := len(failing.opened)
	failing.mu.Unlock()
	if opened != 0 {
		t.Fatalf("%d streams were opened", opened)
	}

	other := &failingTaskData{recordingTaskData: h.taskData, refuse: set.endpoints[len(set.endpoints)-1].Endpoint}
	h.worker.cfg.TaskData = other
	stream, err = h.worker.openOutputStream(context.Background(), task.event, task.hash, nil)
	if err != nil {
		t.Fatalf("a refusing group member that is not the dispatching Builder failed the open: %v", err)
	}
	_ = stream.Close()
}
