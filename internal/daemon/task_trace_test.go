package daemon

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/observability"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/tasktrace"
)

// collectTrace is the sink cortexd supplies in production, captured instead of
// logged.
//
// The sink it stands in for is a logger, which several goroutines may write to
// at once: the scheduling pass emits milestones while every responsibility it
// launched emits its own. Collecting into a slice has to take that seriously,
// so the append is guarded and readers take a copy -- a test that reads the
// records while a responsibility is still running would otherwise race rather
// than simply see fewer of them.
type collectTrace struct {
	mu      sync.Mutex
	records []observability.LogRecord
	lines   []string
}

func (c *collectTrace) trace() *tasktrace.Trace {
	return &tasktrace.Trace{Emit: func(record observability.LogRecord) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.records = append(c.records, record)
		c.lines = append(c.lines, record.Message)
	}}
}

// allRecords and allLines are the only way to read what was collected. They
// copy, so a caller ranging over the result cannot be overtaken by an emitter.
func (c *collectTrace) allRecords() []observability.LogRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]observability.LogRecord(nil), c.records...)
}

func (c *collectTrace) allLines() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.lines...)
}

// event returns the single line for one milestone, failing when the milestone
// was never reached -- which is the failure mode worth catching: a trace that
// silently stops is worse than none, because an operator reads its absence as
// "that step did not run".
func (c *collectTrace) event(t *testing.T, name string) string {
	return c.eventRecord(t, name).Message
}

func (c *collectTrace) eventRecord(t *testing.T, name string) observability.LogRecord {
	t.Helper()
	prefix := "task trace event=" + name + " "
	records := c.allRecords()
	var found observability.LogRecord
	foundOne := false
	for _, record := range records {
		line := record.Message
		if strings.HasPrefix(line, prefix) {
			if foundOne {
				t.Fatalf("event %q emitted more than once: %#v", name, records)
			}
			found = record
			foundOne = true
		}
	}
	if !foundOne {
		t.Fatalf("event %q was never emitted; records: %#v", name, records)
	}
	return found
}

func requireTraceLevel(t *testing.T, trace *collectTrace, name string, want slog.Level) {
	t.Helper()
	if got := trace.eventRecord(t, name).Level; got != want {
		t.Fatalf("event %q level = %s, want %s", name, got, want)
	}
}

func requireTraceFields(t *testing.T, line string, fields ...string) {
	t.Helper()
	for _, field := range fields {
		if !strings.Contains(line, field) {
			t.Fatalf("trace line\n%s\ndoes not carry %q", line, field)
		}
	}
}

// TestOutputConfirmationAcceptsAnAbsentPackageHashAndNamesAnAbsentOutputHash
// pins both halves of the §13 hard boundary (cortex-detailed-design.md:1032). A missing
// package hash is the normal chain and must not refuse -- that refusal was what
// every real-mode OPEN_VERIFY reached. A missing output hash is a real fault and
// the refusal has to name the value it did not get.
func TestOutputConfirmationAcceptsAnAbsentPackageHashAndNamesAnAbsentOutputHash(t *testing.T) {
	outputHash := codec.HashBytes([]byte("output"))
	base := OutputCommitments{
		SessionID: "session-1", TaskID: "task-1",
		BuilderOperatorAddress: "trueopen1builder", WorkerOperatorAddress: "trueopen1worker",
		OutputHash: outputHash, TaskHash: codec.HashBytes([]byte("accepted-task")),
	}
	if err := validateOutputCommitments(base); err != nil {
		t.Fatalf("commitments with no package hash were refused: %v", err)
	}

	missing := base
	missing.OutputHash = codec.Hash{}
	err := validateOutputCommitments(missing)
	if err == nil {
		t.Fatal("a zero output hash must refuse the confirmation")
	}
	if !strings.Contains(err.Error(), "output_hash=zero") {
		t.Fatalf("refusal %q does not name the missing output hash", err)
	}
}

// TestOutputConfirmerTracesWhatTheBuilderAnsweredAgainstTheCommitments proves
// the values on both sides of the confirmation reach the log on the success
// path too. Every refusal inside the confirmer names one field; the trace is
// what makes the other side of that comparison visible.
func TestOutputConfirmerTracesWhatTheBuilderAnsweredAgainstTheCommitments(t *testing.T) {
	fixture := newOutputFixture(t)
	client := &inputTaskDataClient{metadata: fixture.Metadata}
	confirmer := newOutputConfirmer(t, outputTestChainID, client, outputPackagesFor(fixture.Package))
	trace := &collectTrace{}
	confirmer.cfg.Trace = trace.trace()

	if _, err := confirmer.ConfirmOutput(context.Background(), fixture.Commitments); err != nil {
		t.Fatalf("ConfirmOutput: %v", err)
	}

	requireTraceFields(t, trace.event(t, "output_confirm_metadata"),
		"committed_output_hash="+fixture.Commitments.OutputHash.String(),
		"committed_package_hash="+fixture.Commitments.PackageHash.String(),
		"content_hash="+fixture.Metadata.Key.ContentHash,
		"object_ready=true",
		"keeper_output_hash="+fixture.Snapshot.OutputHash.String(),
		"derived_receipt_hash=")
}

func TestInferStartedTraceIsErrorOnlyWhenTheDispatchedInputIsMissing(t *testing.T) {
	ctx := context.Background()
	x, task, taskHash := seedDispatchedInfer(t)
	// An evidence store that never received the Dispatcher's committed input.
	empty, err := evidence.NewStore(filepath.Join(t.TempDir(), "evidence"), x.st)
	if err != nil {
		t.Fatal(err)
	}
	trace := &collectTrace{}
	executor := newProductionInferExecutor(TaskRunnerConfig{
		Store: x.st, Evidence: empty, FakeOutput: true, LocalWorkerAddress: hrCortex, Trace: trace.trace(),
	}, func(context.Context, codec.Hash, store.InferTask, layout.Evidence) error { return nil })

	if _, _, err := executor.RunInfer(ctx, taskHash, task); err == nil || !strings.Contains(err.Error(), "is not committed under the task hash") {
		t.Fatalf("RunInfer() error = %v, want the missing dispatched input", err)
	}
	requireTraceLevel(t, trace, "infer_started", slog.LevelError)
}

func TestInferStartedTraceIsInfoWhenTheDispatchedInputIsCommitted(t *testing.T) {
	ctx := context.Background()
	x, task, taskHash := seedDispatchedInfer(t)
	trace := &collectTrace{}
	executor := newProductionInferExecutor(TaskRunnerConfig{
		Store: x.st, Evidence: x.ev, FakeOutput: true,
		LocalWorkerAddress: hrCortex, Trace: trace.trace(),
		TaskReader: streamLimitedTaskReader{},
	}, func(context.Context, codec.Hash, store.InferTask, layout.Evidence) error { return nil })

	if _, _, err := executor.RunInfer(ctx, taskHash, task); err == nil || err.Error() != "model client is required" {
		t.Fatalf("RunInfer() error = %v, want the downstream model dependency after the committed input was read", err)
	}
	requireTraceLevel(t, trace, "infer_started", slog.LevelInfo)
	if line := trace.event(t, "infer_started"); !strings.Contains(line, `input_error=""`) || !strings.Contains(line, `input_source="local"`) {
		t.Fatalf("infer_started = %q, want the input read locally from the Dispatcher's commit", line)
	}
}

func TestOutputConfirmationFailureTraceIsError(t *testing.T) {
	trace := &collectTrace{}
	wantErr := errors.New("builder refused output")
	executor := newProductionVerifyExecutor(TaskRunnerConfig{
		OutputConfirmer: &recordingOutputConfirmer{err: wantErr},
		Trace:           trace.trace(),
	})
	task := store.VerifyTask{
		TaskID: "task-1", SessionID: "session-1", WorkerAddress: "worker-1",
		BuilderOperatorAddress: "builder-1", OutputDigest: codec.HashBytes([]byte("output")),
		Stage: string(layout.StageQueued),
	}

	if _, _, err := executor.RunVerify(context.Background(), codec.HashBytes([]byte("task-hash")), task); !errors.Is(err, wantErr) {
		t.Fatalf("RunVerify() error = %v, want %v", err, wantErr)
	}
	requireTraceLevel(t, trace, "output_confirm_failed", slog.LevelError)
}
