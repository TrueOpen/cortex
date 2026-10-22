package daemon

import (
	"context"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	busv1 "github.com/TrueOpen/cortex/proto/bus/v1"
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/builderclient"
)

func prefetchTestRef(input []byte) TaskInputRef {
	return TaskInputRef{
		SessionID: strings.Repeat("ab", 32), TaskID: identity.TaskIDString(strings.Repeat("ab", 32), 1),
		TaskHash: codec.HashBytes([]byte("task-hash")), PayloadHash: chainclient.HexHash(codec.HashBytes(input)),
		BuilderOperatorAddress: "trueopen1builder", InputSizeBytes: uint64(len(input)),
	}
}

// countingResolver answers from a queue of results and counts the calls. It
// never touches the network.
type countingResolver struct {
	calls   atomic.Int64
	results []func(context.Context) ([]byte, error)
}

func (r *countingResolver) ResolveTaskInput(ctx context.Context, _ TaskInputRef) ([]byte, error) {
	n := int(r.calls.Add(1)) - 1
	if n >= len(r.results) {
		n = len(r.results) - 1
	}
	return r.results[n](ctx)
}

func answer(input []byte, err error) func(context.Context) ([]byte, error) {
	return func(context.Context) ([]byte, error) { return input, err }
}

func newTestPrefetches() *inputPrefetches {
	s := newInputPrefetches(nil)
	s.backoff = time.Millisecond
	return s
}

// A prefetch made for exactly the executor's reference is handed over once;
// the entry is gone afterwards.
func TestInputPrefetchIsTakenOnceForTheSameReference(t *testing.T) {
	input := []byte("prefetched input")
	ref := prefetchTestRef(input)
	resolver := &countingResolver{results: []func(context.Context) ([]byte, error){answer(input, nil)}}
	s := newTestPrefetches()
	defer s.close()
	if started, reason := s.start(context.Background(), resolver, ref); !started {
		t.Fatalf("start refused: %s", reason)
	}
	got, _, status := s.take(context.Background(), ref)
	if status != "used" || string(got) != string(input) {
		t.Fatalf("take = %q, %s; want the prefetched input", got, status)
	}
	if _, _, status := s.take(context.Background(), ref); status != "none" {
		t.Fatalf("second take = %s, want none: a prefetch is used at most once", status)
	}
	if calls := resolver.calls.Load(); calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", calls)
	}
}

// Any difference between the reference the prefetch was made for and the
// one the executor builds from the chain drops the prefetch.
func TestInputPrefetchForAnotherReferenceIsDropped(t *testing.T) {
	input := []byte("prefetched input")
	ref := prefetchTestRef(input)
	for name, mutate := range map[string]func(*TaskInputRef){
		"builder": func(r *TaskInputRef) { r.BuilderOperatorAddress = "trueopen1other" },
		"payload": func(r *TaskInputRef) { r.PayloadHash = chainclient.HexHash(codec.HashBytes([]byte("other"))) },
		"size":    func(r *TaskInputRef) { r.InputSizeBytes++ },
		"session": func(r *TaskInputRef) { r.SessionID = strings.Repeat("cd", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestPrefetches()
			defer s.close()
			resolver := &countingResolver{results: []func(context.Context) ([]byte, error){answer(input, nil)}}
			if started, reason := s.start(context.Background(), resolver, ref); !started {
				t.Fatalf("start refused: %s", reason)
			}
			other := ref
			mutate(&other)
			if got, _, status := s.take(context.Background(), other); got != nil || status != "ref_mismatch" {
				t.Fatalf("take = %q, %s; want ref_mismatch", got, status)
			}
		})
	}
}

// A Builder whose chain view lags refuses the first downloads; the prefetch
// retries a bounded number of times and then gives up without an error to
// anyone: the executor fetches for itself.
func TestInputPrefetchRetriesABoundedNumberOfTimes(t *testing.T) {
	input := []byte("prefetched input")
	ref := prefetchTestRef(input)
	// The Builder's answer while its chain view has not reached the
	// assignment: PermissionDenied naming the download role.
	refused := connect.NewError(connect.CodePermissionDenied, errors.New("NEXUS_DATA_UNAUTHORIZED: download role"))

	t.Run("succeeds after refusals", func(t *testing.T) {
		s := newTestPrefetches()
		defer s.close()
		resolver := &countingResolver{results: []func(context.Context) ([]byte, error){answer(nil, refused), answer(nil, refused), answer(input, nil)}}
		s.start(context.Background(), resolver, ref)
		// Retries happen while nobody waits; a take stops them (see
		// TestInputPrefetchStopsRetryingOnceTaken).
		s.mu.Lock()
		entry := s.entries[ref.TaskHash]
		s.mu.Unlock()
		<-entry.done
		if got, _, status := s.take(context.Background(), ref); status != "used" || string(got) != string(input) {
			t.Fatalf("take = %q, %s; want the input after two refusals", got, status)
		}
		if calls := resolver.calls.Load(); calls != 3 {
			t.Fatalf("resolver calls = %d, want 3", calls)
		}
	})
	t.Run("gives up", func(t *testing.T) {
		s := newTestPrefetches()
		defer s.close()
		resolver := &countingResolver{results: []func(context.Context) ([]byte, error){answer(nil, refused)}}
		s.start(context.Background(), resolver, ref)
		s.mu.Lock()
		entry := s.entries[ref.TaskHash]
		s.mu.Unlock()
		<-entry.done
		if got, _, status := s.take(context.Background(), ref); got != nil || status != "failed" {
			t.Fatalf("take = %q, %s; want failed", got, status)
		}
		if calls := resolver.calls.Load(); calls != int64(s.attempts) {
			t.Fatalf("resolver calls = %d, want the bound %d", calls, s.attempts)
		}
	})
	t.Run("bytes that do not hash to the order's input hash", func(t *testing.T) {
		s := newTestPrefetches()
		defer s.close()
		resolver := &countingResolver{results: []func(context.Context) ([]byte, error){answer([]byte("tampered"), nil)}}
		s.start(context.Background(), resolver, ref)
		if got, _, status := s.take(context.Background(), ref); got != nil || status != "failed" {
			t.Fatalf("take = %q, %s; want failed", got, status)
		}
	})
}

// Once the executor waits on the prefetch the assignment is confirmed, and a
// failed download is not retried: the executor's own fetch is the retry.
func TestInputPrefetchStopsRetryingOnceTaken(t *testing.T) {
	input := []byte("prefetched input")
	ref := prefetchTestRef(input)
	release := make(chan struct{})
	refused := builderclient.Retryable(errors.New("builder unavailable"))
	resolver := &countingResolver{results: []func(context.Context) ([]byte, error){
		func(context.Context) ([]byte, error) { <-release; return nil, refused },
	}}
	s := newTestPrefetches()
	s.backoff = time.Hour
	defer s.close()
	s.start(context.Background(), resolver, ref)
	result := make(chan string, 1)
	go func() {
		_, _, status := s.take(context.Background(), ref)
		result <- status
	}()
	// Let the take close the entry's taken channel before the attempt fails.
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		_, pending := s.entries[ref.TaskHash]
		s.mu.Unlock()
		if !pending || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	select {
	case status := <-result:
		if status != "failed" {
			t.Fatalf("take = %s, want failed", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("take waited out the retry backoff")
	}
	if calls := resolver.calls.Load(); calls != 1 {
		t.Fatalf("resolver calls = %d, want no retry after the take", calls)
	}
}

// The memory a prefetch can hold is bounded: inputs above the size bound or
// of unknown size, and prefetches beyond the entry bound, are not started.
func TestInputPrefetchIsBounded(t *testing.T) {
	s := newTestPrefetches()
	s.maxEntries = 1
	defer s.close()
	block := func(ctx context.Context) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() }
	resolver := &countingResolver{results: []func(context.Context) ([]byte, error){block}}
	ref := prefetchTestRef([]byte("input"))
	large := ref
	large.InputSizeBytes = s.maxBytes + 1
	if started, reason := s.start(context.Background(), resolver, large); started || reason != "input_size" {
		t.Fatalf("large input: started=%v reason=%s", started, reason)
	}
	unknown := ref
	unknown.InputSizeBytes = 0
	if started, reason := s.start(context.Background(), resolver, unknown); started || reason != "input_size" {
		t.Fatalf("unknown size: started=%v reason=%s", started, reason)
	}
	if started, _ := s.start(context.Background(), resolver, ref); !started {
		t.Fatal("first prefetch was refused")
	}
	if started, reason := s.start(context.Background(), resolver, ref); started || reason != "duplicate" {
		t.Fatalf("duplicate: started=%v reason=%s", started, reason)
	}
	second := ref
	second.TaskHash = codec.HashBytes([]byte("second"))
	if started, reason := s.start(context.Background(), resolver, second); started || reason != "capacity" {
		t.Fatalf("over capacity: started=%v reason=%s", started, reason)
	}
}

// Discarding, expiry and close all cancel the download, and close waits for
// it, so no prefetch outlives the runner.
func TestInputPrefetchDownloadsEndWithTheirEntry(t *testing.T) {
	block := func(ctx context.Context) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() }
	ref := prefetchTestRef([]byte("input"))

	t.Run("discard", func(t *testing.T) {
		s := newTestPrefetches()
		s.start(context.Background(), &countingResolver{results: []func(context.Context) ([]byte, error){block}}, ref)
		s.discard(ref.TaskHash, "assigned_elsewhere")
		waitPrefetchesIdle(t, s)
		if _, _, status := s.take(context.Background(), ref); status != "none" {
			t.Fatalf("take after discard = %s, want none", status)
		}
	})
	t.Run("expiry", func(t *testing.T) {
		s := newTestPrefetches()
		s.ttl = 20 * time.Millisecond
		s.start(context.Background(), &countingResolver{results: []func(context.Context) ([]byte, error){block}}, ref)
		waitPrefetchesIdle(t, s)
		deadline := time.Now().Add(5 * time.Second)
		for {
			s.mu.Lock()
			n := len(s.entries)
			s.mu.Unlock()
			if n == 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("expired prefetch was never dropped")
			}
			time.Sleep(time.Millisecond)
		}
	})
	t.Run("close", func(t *testing.T) {
		s := newTestPrefetches()
		s.start(context.Background(), &countingResolver{results: []func(context.Context) ([]byte, error){block}}, ref)
		done := make(chan struct{})
		go func() { s.close(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("close did not cancel and wait for the download")
		}
		if started, reason := s.start(context.Background(), &countingResolver{results: []func(context.Context) ([]byte, error){block}}, ref); started || reason != "closed" {
			t.Fatalf("start after close: started=%v reason=%s", started, reason)
		}
	})
	t.Run("handler context", func(t *testing.T) {
		s := newTestPrefetches()
		ctx, cancel := context.WithCancel(context.Background())
		s.start(ctx, &countingResolver{results: []func(context.Context) ([]byte, error){block}}, ref)
		cancel()
		waitPrefetchesIdle(t, s)
	})
}

func waitPrefetchesIdle(t *testing.T, s *inputPrefetches) {
	t.Helper()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("prefetch download did not stop")
	}
}

// prefetchNotifyFixture is a runner that bid on a real signed order: its
// candidate admission carries the order and the broadcasting Builder.
type prefetchNotifyFixture struct {
	runner   *TaskRunner
	db       *store.Store
	taskHash codec.Hash
	taskID   string
	input    []byte
	resolver *countingResolver
	message  *busv1.WorkerAssignmentNotifyV1
}

func newPrefetchNotifyFixture(t *testing.T) prefetchNotifyFixture {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	input := []byte(`{"messages":[{"role":"user","content":"hi"}]}`)
	session := strings.Repeat("12", 32)
	signed, _ := testSignedOrderProto(t, "chain", testModelID, session, 0, 200)
	inputHash := codec.HashBytes(input)
	signed.Order.InputHash = inputHash[:]
	signed.Order.InputSizeBytes = uint64(len(input))
	raw, err := proto.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	taskHash, _, err := admittedOrderFacts(layout.CandidateAdmission{SignedOrder: raw})
	if err != nil {
		t.Fatal(err)
	}
	if err := layout.AdmissionBatch(ctx, db, session, 0, layout.StoredHash(taskHash), layout.CandidateAdmission{
		SchemaVersion: layout.CandidateAdmissionSchemaVersion, SignedOrder: raw,
		InputSizeBytes: uint64(len(input)), BroadcastingBuilder: "trueopen1builder",
	}); err != nil {
		t.Fatal(err)
	}
	resolver := &countingResolver{results: []func(context.Context) ([]byte, error){answer(input, nil)}}
	runner := NewTaskRunner(TaskRunnerConfig{Store: db, LocalWorkerAddress: notifyWinner, InputResolver: resolver})
	runner.prefetches = newTestPrefetches()
	t.Cleanup(runner.prefetches.close)
	taskID := identity.TaskIDString(session, 0)
	rawTaskID, _ := hex.DecodeString(taskID)
	return prefetchNotifyFixture{
		runner: runner, db: db, taskHash: taskHash, taskID: taskID, input: input, resolver: resolver,
		message: &busv1.WorkerAssignmentNotifyV1{
			TaskId: rawTaskID, TaskHash: taskHash[:], WinnerOperatorAddress: notifyWinner,
			FinalizedHeight: 50, InputHash: inputHash[:],
		},
	}
}

func (f prefetchNotifyFixture) ref() TaskInputRef {
	return TaskInputRef{
		SessionID: strings.Repeat("12", 32), TaskID: f.taskID, TaskHash: f.taskHash,
		PayloadHash: chainclient.HexHash(codec.HashBytes(f.input)), BuilderOperatorAddress: "trueopen1builder",
		InputSizeBytes: uint64(len(f.input)),
	}
}

// The notification starts the download before the assignment is recorded,
// with the reference rebuilt from the node's own candidate admission, and
// writes nothing: the bytes wait in memory.
func TestAssignmentNotifyPrefetchesTheInputBeforeTheAssignmentIsRecorded(t *testing.T) {
	f := newPrefetchNotifyFixture(t)
	f.runner.prefetchAssignedInput(context.Background(), f.taskID, f.message)
	got, _, status := f.runner.prefetches.take(context.Background(), f.ref())
	if status != "used" || string(got) != string(f.input) {
		t.Fatalf("take = %q, %s; want the input prefetched with the admission's reference", got, status)
	}
	if _, err := layout.GetInferRecord(context.Background(), f.db, layout.StoredHash(f.taskHash)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("infer record after prefetch: %v, want none", err)
	}
}

// The prefetch is skipped when the frame's input hash disagrees with the
// order this node bid on, when the node never bid, and when the assignment is
// already recorded (the executor is about to fetch for itself).
func TestAssignmentNotifyPrefetchIsSkippedWithoutAMatchingAdmission(t *testing.T) {
	t.Run("input hash", func(t *testing.T) {
		f := newPrefetchNotifyFixture(t)
		other := codec.HashBytes([]byte("other"))
		f.message.InputHash = other[:]
		f.runner.prefetchAssignedInput(context.Background(), f.taskID, f.message)
		if n := f.resolver.calls.Load(); n != 0 {
			t.Fatalf("resolver calls = %d, want none", n)
		}
	})
	t.Run("no admission", func(t *testing.T) {
		f := newPrefetchNotifyFixture(t)
		otherHash := codec.HashBytes([]byte("never admitted"))
		f.message.TaskHash = otherHash[:]
		f.runner.prefetchAssignedInput(context.Background(), f.taskID, f.message)
		if n := f.resolver.calls.Load(); n != 0 {
			t.Fatalf("resolver calls = %d, want none", n)
		}
	})
	t.Run("task id", func(t *testing.T) {
		f := newPrefetchNotifyFixture(t)
		f.runner.prefetchAssignedInput(context.Background(), notifyTaskIDHex, f.message)
		if n := f.resolver.calls.Load(); n != 0 {
			t.Fatalf("resolver calls = %d, want none", n)
		}
	})
	t.Run("already recorded", func(t *testing.T) {
		f := newPrefetchNotifyFixture(t)
		if err := layout.InferAssignmentBatch(context.Background(), f.db, layout.StoredHash(f.taskHash),
			layout.TaskRecord{SessionID: strings.Repeat("12", 32), WorkerAddress: notifyWinner},
			layout.InferRecord{TaskID: f.taskID, Stage: layout.StageQueued, WinnerConfirmHeight: 50, DeadlineHeight: 500}); err != nil {
			t.Fatal(err)
		}
		f.runner.prefetchAssignedInput(context.Background(), f.taskID, f.message)
		if n := f.resolver.calls.Load(); n != 0 {
			t.Fatalf("resolver calls = %d, want none", n)
		}
	})
}

// The chain naming another Worker drops the prefetched input unused.
func TestPrefetchedInputIsDroppedWhenTheChainAssignsAnotherWorker(t *testing.T) {
	f := newPrefetchNotifyFixture(t)
	f.runner.prefetchAssignedInput(context.Background(), f.taskID, f.message)
	effect := ReconcilerEffect{Type: ReconcilerEffectAssignment, TaskHash: f.taskHash, TaskID: f.taskID,
		Snapshot: chainclient.TaskSnapshot{Assignment: chainclient.AssignmentSnapshot{
			TaskID: f.taskID, SessionID: strings.Repeat("12", 32), OrderSequence: chainclient.NewUint64String(0),
			SelectedWorker: "trueopen1someoneelse",
		}}}
	if err := f.runner.ApplyReconcilerEffects(context.Background(), []ReconcilerEffect{effect}); err != nil {
		t.Fatal(err)
	}
	if got, _, status := f.runner.prefetches.take(context.Background(), f.ref()); got != nil || status != "none" {
		t.Fatalf("take after another Worker was assigned = %q, %s; want none", got, status)
	}
}

// The executor uses the prefetched input instead of downloading it, and
// persists it the way a downloaded input is persisted: only inside the
// attempt, after the assignment is recorded.
func TestInferExecutorUsesThePrefetchedInput(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(t.TempDir(), "evidence"), db)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("prefetched input")
	ref := prefetchTestRef(input)
	prefetches := newTestPrefetches()
	defer prefetches.close()
	prefetches.start(ctx, &countingResolver{results: []func(context.Context) ([]byte, error){answer(input, nil)}}, ref)

	trace := &collectTrace{}
	var persisted atomic.Int64
	executor := &productionInferExecutor{cfg: TaskRunnerConfig{
		Store: db, Evidence: evidenceStore, FakeOutput: true, FakeBus: true,
		LocalWorkerAddress: "worker-1", Trace: trace.trace(),
		InputResolver: taskInputResolverFunc(func(context.Context, TaskInputRef) ([]byte, error) {
			t.Error("the executor downloaded an input it had prefetched")
			return nil, errors.New("unexpected download")
		}),
	}, persist: func(context.Context, codec.Hash, store.InferTask, layout.Evidence) error {
		persisted.Add(1)
		return nil
	}, prefetches: prefetches}
	task := store.InferTask{
		TaskID: ref.TaskID, SessionID: ref.SessionID, OrderSequence: 1,
		OrderDigest: codec.HashBytes([]byte("order")), WorkerAddress: "worker-1",
		ModelID: testModelID, ProfileVersion: 1, Capability: modelservice.CapabilityLLMTextV1,
		InputDigest: codec.Hash(ref.PayloadHash), DeadlineHeight: 10, Stage: string(layout.StageQueued),
		BuilderOperatorAddress: ref.BuilderOperatorAddress, InputSizeBytes: ref.InputSizeBytes,
	}
	if _, _, err := executor.RunInfer(ctx, ref.TaskHash, task); err == nil || err.Error() != "model client is required" {
		t.Fatalf("RunInfer() error = %v, want the downstream model dependency", err)
	}
	line := trace.event(t, "infer_started")
	for _, want := range []string{`input_source="prefetch"`, `input_prefetch="used"`, `input_error=""`} {
		if !strings.Contains(line, want) {
			t.Fatalf("infer_started = %q, want %s", line, want)
		}
	}
	persistence := &evidenceWorkerPersistence{taskHash: ref.TaskHash, task: &task, evidence: evidenceStore, store: db}
	stored, err := persistence.ReadArtifact(ctx, task.TaskID, "task-input")
	if err != nil || string(stored) != string(input) {
		t.Fatalf("persisted task input = %q, %v; want the prefetched bytes", stored, err)
	}
	if persisted.Load() == 0 {
		t.Fatal("the prefetched input was not checkpointed by the attempt")
	}
}

// A prefetch that failed leaves the executor to download the input itself.
func TestInferExecutorFetchesWhenThePrefetchFailed(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(t.TempDir(), "evidence"), db)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("fetched input")
	ref := prefetchTestRef(input)
	prefetches := newTestPrefetches()
	defer prefetches.close()
	prefetches.start(ctx, &countingResolver{results: []func(context.Context) ([]byte, error){answer(nil, errors.New("refused"))}}, ref)

	trace := &collectTrace{}
	var downloads atomic.Int64
	executor := &productionInferExecutor{cfg: TaskRunnerConfig{
		Store: db, Evidence: evidenceStore, FakeOutput: true, FakeBus: true,
		LocalWorkerAddress: "worker-1", Trace: trace.trace(),
		InputResolver: taskInputResolverFunc(func(context.Context, TaskInputRef) ([]byte, error) {
			downloads.Add(1)
			return input, nil
		}),
	}, persist: func(context.Context, codec.Hash, store.InferTask, layout.Evidence) error { return nil }, prefetches: prefetches}
	task := store.InferTask{
		TaskID: ref.TaskID, SessionID: ref.SessionID, OrderSequence: 1,
		OrderDigest: codec.HashBytes([]byte("order")), WorkerAddress: "worker-1",
		ModelID: testModelID, ProfileVersion: 1, Capability: modelservice.CapabilityLLMTextV1,
		InputDigest: codec.Hash(ref.PayloadHash), DeadlineHeight: 10, Stage: string(layout.StageQueued),
		BuilderOperatorAddress: ref.BuilderOperatorAddress, InputSizeBytes: ref.InputSizeBytes,
	}
	if _, _, err := executor.RunInfer(ctx, ref.TaskHash, task); err == nil || err.Error() != "model client is required" {
		t.Fatalf("RunInfer() error = %v, want the downstream model dependency", err)
	}
	if downloads.Load() != 1 {
		t.Fatalf("downloads = %d, want the executor's own fetch", downloads.Load())
	}
	line := trace.event(t, "infer_started")
	for _, want := range []string{`input_source="fetch"`, `input_prefetch="failed"`} {
		if !strings.Contains(line, want) {
			t.Fatalf("infer_started = %q, want %s", line, want)
		}
	}
}

// Only failures that can clear are retried: a retryable transport answer, or
// the Builder refusing the download role while its chain view lags. Every
// other refusal, and bytes that do not match the order, end the prefetch after
// one signed request.
func TestInputPrefetchRetriesOnlyFailuresThatCanClear(t *testing.T) {
	input := []byte("prefetched input")
	ref := prefetchTestRef(input)
	for name, tc := range map[string]struct {
		err       error
		bytes     []byte
		wantCalls int64
	}{
		"retryable":     {err: builderclient.Retryable(errors.New("unavailable")), wantCalls: inputPrefetchAttempts},
		"role not yet":  {err: connect.NewError(connect.CodePermissionDenied, errors.New("NEXUS_DATA_UNAUTHORIZED: download role")), wantCalls: inputPrefetchAttempts},
		"other refusal": {err: connect.NewError(connect.CodePermissionDenied, errors.New("NEXUS_DATA_UNAUTHORIZED: request signature")), wantCalls: 1},
		"permanent":     {err: builderclient.Permanent(builderclient.Retryable(errors.New("descriptor scheme mismatch"))), wantCalls: 1},
		"unclassified":  {err: errors.New("task-data size 99 exceeds input limit 8"), wantCalls: 1},
		"hash mismatch": {bytes: []byte("tampered"), wantCalls: 1},
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestPrefetches()
			defer s.close()
			resolver := &countingResolver{results: []func(context.Context) ([]byte, error){answer(tc.bytes, tc.err)}}
			s.start(context.Background(), resolver, ref)
			s.mu.Lock()
			entry := s.entries[ref.TaskHash]
			s.mu.Unlock()
			<-entry.done
			if calls := resolver.calls.Load(); calls != tc.wantCalls {
				t.Fatalf("resolver calls = %d, want %d", calls, tc.wantCalls)
			}
			if got, _, status := s.take(context.Background(), ref); got != nil || status != "failed" {
				t.Fatalf("take = %q, %s; want failed", got, status)
			}
		})
	}
}

// A download that hangs holds the executor for at most takeWait; the
// prefetch is then cancelled and the executor fetches for itself.
func TestInputPrefetchTakeWaitIsBounded(t *testing.T) {
	ref := prefetchTestRef([]byte("input"))
	s := newTestPrefetches()
	s.takeWait = 30 * time.Millisecond
	defer s.close()
	s.start(context.Background(), &countingResolver{results: []func(context.Context) ([]byte, error){
		func(ctx context.Context) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() },
	}}, ref)
	startedAt := time.Now()
	got, _, status := s.take(context.Background(), ref)
	if got != nil || status != "timeout" {
		t.Fatalf("take = %q, %s; want timeout", got, status)
	}
	if elapsed := time.Since(startedAt); elapsed > 2*time.Second {
		t.Fatalf("take waited %s, want about takeWait", elapsed)
	}
	waitPrefetchesIdle(t, s)
}

// PayloadCID is a location hint the bytes are not bound by; a prefetch made
// without one is used by an executor whose record carries one.
func TestInputPrefetchIgnoresThePayloadLocationHint(t *testing.T) {
	input := []byte("prefetched input")
	ref := prefetchTestRef(input)
	s := newTestPrefetches()
	defer s.close()
	s.start(context.Background(), &countingResolver{results: []func(context.Context) ([]byte, error){answer(input, nil)}}, ref)
	withCID := ref
	withCID.PayloadCID = "bafy-location-hint"
	if got, _, status := s.take(context.Background(), withCID); status != "used" || string(got) != string(input) {
		t.Fatalf("take = %q, %s; want the prefetch used", got, status)
	}
}

// A replaced order (RBF) changes the task hash. The prefetch made for the old
// hash is never handed to the new one: the executor for the new hash finds
// none and fetches for itself, and the old entry waits out its TTL.
func TestInputPrefetchForAReplacedOrderIsNotUsed(t *testing.T) {
	input := []byte("prefetched input")
	old := prefetchTestRef(input)
	s := newTestPrefetches()
	s.ttl = 50 * time.Millisecond
	defer s.close()
	s.start(context.Background(), &countingResolver{results: []func(context.Context) ([]byte, error){answer(input, nil)}}, old)
	replaced := old
	replaced.TaskHash = codec.HashBytes([]byte("replacement order"))
	if got, _, status := s.take(context.Background(), replaced); got != nil || status != "none" {
		t.Fatalf("take for the replacement = %q, %s; want none", got, status)
	}
	s.mu.Lock()
	_, kept := s.entries[old.TaskHash]
	s.mu.Unlock()
	if !kept {
		t.Fatal("the old order's prefetch was dropped by a take for another task hash")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		_, kept = s.entries[old.TaskHash]
		s.mu.Unlock()
		if !kept {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the old order's prefetch outlived its TTL")
		}
		time.Sleep(time.Millisecond)
	}
}

// A notification naming another winner downloads nothing, even though this
// node bid on the order.
func TestAssignmentNotifyForAnotherWinnerDownloadsNothing(t *testing.T) {
	f := newPrefetchNotifyFixture(t)
	f.message.WinnerOperatorAddress = "trueopen1someoneelse"
	envelope := builderclient.BusEnvelope{Subject: builderclient.NATSWorkerAssignmentSubject(f.taskID), Kind: builderclient.KindWorkerAssignmentNotify}
	if err := f.runner.recordAssignNotify(context.Background(), envelope, f.message); err != nil {
		t.Fatalf("recordAssignNotify = %v, want nil for a loser", err)
	}
	if n := f.resolver.calls.Load(); n != 0 {
		t.Fatalf("resolver calls = %d, want none", n)
	}
	f.runner.prefetches.mu.Lock()
	defer f.runner.prefetches.mu.Unlock()
	if len(f.runner.prefetches.entries) != 0 {
		t.Fatal("a loser started a prefetch")
	}
}

// A download that has finished is used even with a bound that has already
// expired: the bound only cuts a wait for a download still running.
func TestInputPrefetchFinishedDownloadBeatsAnExpiredBound(t *testing.T) {
	input := []byte("prefetched input")
	ref := prefetchTestRef(input)
	for i := 0; i < 50; i++ {
		s := newTestPrefetches()
		s.takeWait = 0
		s.start(context.Background(), &countingResolver{results: []func(context.Context) ([]byte, error){answer(input, nil)}}, ref)
		s.mu.Lock()
		entry := s.entries[ref.TaskHash]
		s.mu.Unlock()
		<-entry.done
		if got, _, status := s.take(context.Background(), ref); status != "used" || string(got) != string(input) {
			t.Fatalf("take = %q, %s; want the finished download used", got, status)
		}
		s.close()
	}
}
