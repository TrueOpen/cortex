package daemon

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/observability"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/tasktrace"
)

// collectTrace is the sink cortexd supplies in production, captured instead of
// logged.
type collectTrace struct {
	records []observability.LogRecord
	lines   []string
}

func (c *collectTrace) trace() *tasktrace.Trace {
	return &tasktrace.Trace{Emit: func(record observability.LogRecord) {
		c.records = append(c.records, record)
		c.lines = append(c.lines, record.Message)
	}}
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
	var found observability.LogRecord
	foundOne := false
	for _, record := range c.records {
		line := record.Message
		if strings.HasPrefix(line, prefix) {
			if foundOne {
				t.Fatalf("event %q emitted more than once: %#v", name, c.records)
			}
			found = record
			foundOne = true
		}
	}
	if !foundOne {
		t.Fatalf("event %q was never emitted; records: %#v", name, c.records)
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

// TestAdmittedOrderTracesTheTaskHashAndTheHandraiseItSigned covers the first two
// milestones of a task on this node: what the signed order said, and what this
// node signed in reply. Both are digests a Builder and Keeper derive
// independently, so a handraise the chain does not recognize is diagnosable only
// if the value this node used is recoverable from its own log.
func TestAdmittedOrderTracesTheTaskHashAndTheHandraiseItSigned(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	trace := &collectTrace{}
	runner := NewTaskRunner(TaskRunnerConfig{
		Store: db, Builder: &admissionBuilder{}, LocalWorkerAddress: "worker", ChainID: "chain",
		FakeOutput: true, FakeBus: true,
		ProfileCapabilities:  map[string]string{"model\x001": modelservice.CapabilityLLMTextV1},
		HandraiseEligibility: staticEligibility{input: acceptingEligibility(), expiry: 100},
		TaskDataAuth:         taskRunnerTaskDataAuth(t),
		SignerAddress:        "service", SignerKeyRef: "key",
		Signer: signer.DigestSignerFunc(func(context.Context, signer.DigestRequest) ([]byte, error) {
			return bytes.Repeat([]byte{1}, 64), nil
		}),
		Trace: trace.trace(),
	})

	message, taskHash := orderMessageWithSequence(t, 0)
	if err := runner.HandleNexusMessage(ctx, message); err != nil {
		t.Fatalf("HandleNexusMessage() error = %v", err)
	}

	requireTraceFields(t, trace.event(t, "order_broadcast"),
		"task_hash="+taskHash.String(), `model="model"`, "profile_version=1", "order_expire_height=")

	handraise := trace.event(t, "worker_handraise")
	admission, err := layout.GetCandidateAdmission(ctx, db, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatalf("GetCandidateAdmission() error = %v", err)
	}
	requireTraceFields(t, handraise,
		"signed=true", "accepted=true",
		"handraise_digest="+codec.HashBytes(admission.HandraisePayload).String(),
		"task_hash="+taskHash.String())
	requireTraceLevel(t, trace, "worker_handraise", slog.LevelInfo)
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

func TestInferStartedTraceIsErrorOnlyWhenInputResolutionFails(t *testing.T) {
	trace := &collectTrace{}
	wantErr := errors.New("builder input unavailable")
	executor := newProductionInferExecutor(TaskRunnerConfig{
		FakeOutput: true,
		Trace:      trace.trace(),
		InputResolver: taskInputResolverFunc(func(context.Context, TaskInputRef) ([]byte, error) {
			return nil, wantErr
		}),
	}, nil)
	taskHash := codec.HashBytes([]byte("task-hash"))
	task := store.InferTask{
		TaskID: "task-1", SessionID: "session-1", ModelID: "model-1", ProfileVersion: 1,
		InputDigest: codec.HashBytes([]byte("input")), Stage: string(layout.StageQueued),
	}

	if _, _, err := executor.RunInfer(context.Background(), taskHash, task); !errors.Is(err, wantErr) {
		t.Fatalf("RunInfer() error = %v, want %v", err, wantErr)
	}
	requireTraceLevel(t, trace, "infer_started", slog.LevelError)
}

func TestInferStartedTraceIsInfoWhenInputResolutionSucceeds(t *testing.T) {
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
	input := []byte("resolved input")
	trace := &collectTrace{}
	executor := newProductionInferExecutor(TaskRunnerConfig{
		Store: db, Evidence: evidenceStore, FakeOutput: true, FakeBus: true,
		LocalWorkerAddress: "worker-1", Trace: trace.trace(),
		InputResolver: taskInputResolverFunc(func(context.Context, TaskInputRef) ([]byte, error) {
			return input, nil
		}),
	}, func(context.Context, codec.Hash, store.InferTask, layout.Evidence) error { return nil })
	sessionID := strings.Repeat("ab", 32)
	taskHash := codec.HashBytes([]byte("task-hash"))
	task := store.InferTask{
		TaskID: identity.TaskIDString(sessionID, 1), SessionID: sessionID, OrderSequence: 1,
		OrderDigest: codec.HashBytes([]byte("order")), WorkerAddress: "worker-1",
		ModelID: "model-1", ProfileVersion: 1, Capability: modelservice.CapabilityLLMTextV1,
		InputDigest: codec.HashBytes(input), DeadlineHeight: 10, Stage: string(layout.StageQueued),
	}

	if _, _, err := executor.RunInfer(ctx, taskHash, task); err == nil || err.Error() != "model client is required" {
		t.Fatalf("RunInfer() error = %v, want the downstream model dependency after successful input resolution", err)
	}
	requireTraceLevel(t, trace, "infer_started", slog.LevelInfo)
	if line := trace.event(t, "infer_started"); !strings.Contains(line, `input_error=""`) {
		t.Fatalf("infer_started = %q, want successful input resolution", line)
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
