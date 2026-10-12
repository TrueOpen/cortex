package worker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
)

// barrierTaskData holds every open until all of them have arrived. A serial
// loop can never get past the first one, so the barrier is the proof that the
// opens overlap rather than a timing comparison that a slow machine could flip.
type barrierTaskData struct {
	*recordingTaskData
	want    int
	mu      sync.Mutex
	arrived int
	release chan struct{}
	once    sync.Once
}

func (b *barrierTaskData) OpenTaskOutputStream(ctx context.Context, endpoint string, request builderclient.OutputStreamRequest) (builderclient.TaskOutputStream, error) {
	b.mu.Lock()
	b.arrived++
	arrived := b.arrived
	b.mu.Unlock()
	if arrived >= b.want {
		b.once.Do(func() { close(b.release) })
	}
	select {
	case <-b.release:
	case <-time.After(5 * time.Second):
		return nil, fmt.Errorf("opens ran one after another: %d of %d had started", arrived, b.want)
	}
	return b.recordingTaskData.OpenTaskOutputStream(ctx, endpoint, request)
}

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

// TestBuilderStreamsOpenTogether is the point of the change. Each open is a TLS
// handshake plus a round trip for the header acknowledgement, and on a node
// deployed away from the Builders that measured about 2.3s each -- so three of
// them in turn held 81% of everything between an admitted task and its first
// generated token. They have nothing to do with each other: separate endpoints,
// separate authorisation, the same header signature and the same replay frames.
func TestBuilderStreamsOpenTogether(t *testing.T) {
	h, set, task := openStreamHarness(t)
	barrier := &barrierTaskData{recordingTaskData: h.taskData, want: len(set.endpoints), release: make(chan struct{})}
	if barrier.want < 2 {
		t.Fatalf("the harness has %d Builders, which cannot show concurrency", barrier.want)
	}
	h.worker.cfg.TaskData = barrier

	stream, err := h.worker.openOutputStream(context.Background(), task.event, task.hash, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
}

// TestOneRefusedBuilderFailsTheWholeOpen keeps the contract the serial loop
// had. Streaming to a subset needs per-Builder liveness tracking that does not
// exist, so a Builder that cannot be opened fails the open -- and the streams
// that did open must be closed rather than left to the garbage collector with
// their connections still up.
func TestOneRefusedBuilderFailsTheWholeOpen(t *testing.T) {
	h, set, task := openStreamHarness(t)
	for _, refused := range []int{0, len(set.endpoints) - 1} {
		t.Run(fmt.Sprintf("builder %d refuses", refused), func(t *testing.T) {
			h := h
			failing := &failingTaskData{recordingTaskData: h.taskData, refuse: set.endpoints[refused].Endpoint}
			h.worker.cfg.TaskData = failing

			stream, err := h.worker.openOutputStream(context.Background(), task.event, task.hash, nil)
			if err == nil {
				_ = stream.Close()
				t.Fatal("the open succeeded while a Builder was refusing")
			}
			if !strings.Contains(err.Error(), set.endpoints[refused].OperatorAddress) {
				t.Fatalf("error = %v, want it to name the Builder that refused", err)
			}
			failing.mu.Lock()
			defer failing.mu.Unlock()
			for i, opened := range failing.opened {
				if !opened.wasClosed() {
					t.Fatalf("stream %d was left open after the failed open", i)
				}
			}
		})
	}
}

// TestStreamsStayInBuilderOrder keeps the fan-out able to name the right
// Builder. The two slices are paired by index, and SendChunk reports a failure
// by looking the address up at the stream's index, so opens that finish out of
// order must still land where they started.
func TestStreamsStayInBuilderOrder(t *testing.T) {
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
	if len(fanOut.builders) != len(set.endpoints) {
		t.Fatalf("fan-out holds %d Builders, want %d", len(fanOut.builders), len(set.endpoints))
	}
	for i, endpoint := range set.endpoints {
		if fanOut.builders[i] != endpoint.OperatorAddress {
			t.Fatalf("slot %d holds %q, want %q", i, fanOut.builders[i], endpoint.OperatorAddress)
		}
	}
}
