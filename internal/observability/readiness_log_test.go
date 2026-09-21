package observability

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/SingaXYZ/cortex/internal/diagnostics"
)

type readinessLogRecorder struct {
	records []LogRecord
	now     time.Time
}

func newReadinessLogRecorder(restate time.Duration) (*ReadinessLog, *readinessLogRecorder) {
	recorder := &readinessLogRecorder{now: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)}
	return &ReadinessLog{
		Emit:    func(record LogRecord) { recorder.records = append(recorder.records, record) },
		Restate: restate,
		Now:     func() time.Time { return recorder.now },
	}, recorder
}

func (r *readinessLogRecorder) advance(d time.Duration) {
	r.now = r.now.Add(d)
}

func (r *readinessLogRecorder) only(t *testing.T) LogRecord {
	t.Helper()
	if len(r.records) != 1 {
		t.Fatalf("emitted %d records, want exactly 1: %v", len(r.records), r.records)
	}
	return r.records[0]
}

func (r *readinessLogRecorder) reset() {
	r.records = nil
}

func notReadyStatus(name string, endpoint string, reason string) diagnostics.DependencyStatus {
	return diagnostics.DependencyStatus{Name: name, Endpoint: endpoint, Configured: true, Ready: false, Error: reason}
}

func readyStatus(name string, endpoint string) diagnostics.DependencyStatus {
	return diagnostics.DependencyStatus{Name: name, Endpoint: endpoint, Configured: true, Ready: true}
}

// The reason a node is not serving must be in the log, named by module, without
// an operator having to know that an admin socket exists.
func TestReadinessLogNamesTheDependencyAndTheReasonItIsNotReady(t *testing.T) {
	readinessLog, recorder := newReadinessLogRecorder(0)

	readinessLog.Observe(false, []diagnostics.DependencyStatus{
		readyStatus("chain", "http://127.0.0.1:26657"),
		notReadyStatus("model_service", "http://127.0.0.1:8000", "modelservice health unhealthy: VLLM_HEALTH_UNAVAILABLE retryable"),
	})

	if len(recorder.records) != 2 {
		t.Fatalf("emitted %d records, want a dependency line and a workload line: %v", len(recorder.records), recorder.records)
	}
	dependencyLine := recorder.records[0].Message
	for _, want := range []string{
		`dependency not ready`,
		`dep="model_service"`,
		`endpoint="http://127.0.0.1:8000"`,
		`configured=true`,
		`reason="modelservice health unhealthy: VLLM_HEALTH_UNAVAILABLE retryable"`,
	} {
		if !strings.Contains(dependencyLine, want) {
			t.Fatalf("dependency line %q missing %q", dependencyLine, want)
		}
	}
	workloadLine := recorder.records[1].Message
	if !strings.Contains(workloadLine, "workload not started") || !strings.Contains(workloadLine, `not_ready="model_service"`) {
		t.Fatalf("workload line %q does not name the blocking dependency", workloadLine)
	}
	if strings.Contains(workloadLine, "chain") {
		t.Fatalf("workload line %q names a ready dependency", workloadLine)
	}
	if recorder.records[0].Level != slog.LevelError || recorder.records[1].Level != slog.LevelError {
		t.Fatalf("not-ready levels = %s, %s, want ERROR", recorder.records[0].Level, recorder.records[1].Level)
	}
}

// A dependency that is ready from the first pass has nothing to explain, so it
// must not produce a line: the log is for what is wrong.
func TestReadinessLogStaysQuietWhileEverythingIsReady(t *testing.T) {
	readinessLog, recorder := newReadinessLogRecorder(0)

	readinessLog.Observe(true, []diagnostics.DependencyStatus{readyStatus("chain", "http://127.0.0.1:26657")})
	first := recorder.only(t)
	if !strings.Contains(first.Message, "workload dependencies ready") {
		t.Fatalf("first line %q does not report the gate is open", first)
	}
	if strings.Contains(first.Message, "dep=") {
		t.Fatalf("first line %q reports a per-dependency transition that never happened", first)
	}
	if first.Level != slog.LevelInfo {
		t.Fatalf("gate-open level = %s, want INFO", first.Level)
	}

	recorder.reset()
	recorder.advance(time.Second)
	readinessLog.Observe(true, []diagnostics.DependencyStatus{readyStatus("chain", "http://127.0.0.1:26657")})
	if len(recorder.records) != 0 {
		t.Fatalf("emitted %v on an unchanged ready pass, want silence", recorder.records)
	}
}

// The control loop re-probes on every poll interval. Logging the same reason on
// every pass would make the log useless, so an unchanged reason is silent until
// the restatement interval elapses.
func TestReadinessLogRepeatsAnUnchangedReasonOnlyAfterTheRestateInterval(t *testing.T) {
	readinessLog, recorder := newReadinessLogRecorder(5 * time.Minute)
	status := notReadyStatus("nexus", "nats://127.0.0.1:4222", "nexus readiness probe failed")

	readinessLog.Observe(false, []diagnostics.DependencyStatus{status})
	recorder.reset()

	for range 10 {
		recorder.advance(time.Second)
		readinessLog.Observe(false, []diagnostics.DependencyStatus{status})
	}
	if len(recorder.records) != 0 {
		t.Fatalf("emitted %v while the reason was unchanged, want silence until the restate interval", recorder.records)
	}

	recorder.advance(5 * time.Minute)
	readinessLog.Observe(false, []diagnostics.DependencyStatus{status})
	if len(recorder.records) != 2 {
		t.Fatalf("emitted %d records at the restate interval, want a dependency and a workload restatement: %v", len(recorder.records), recorder.records)
	}
	restated := recorder.records[0].Message
	for _, want := range []string{
		`dependency still not ready`,
		`dep="nexus"`,
		`reason="nexus readiness probe failed"`,
		`for=5m10s`,
		`checks=12`,
	} {
		if !strings.Contains(restated, want) {
			t.Fatalf("restated line %q missing %q", restated, want)
		}
	}
	if recorder.records[0].Level != slog.LevelError || recorder.records[1].Level != slog.LevelError {
		t.Fatalf("still-not-ready levels = %s, %s, want ERROR", recorder.records[0].Level, recorder.records[1].Level)
	}
}

// Zero restatement means each reason is stated once. A node with a stable
// failure must not be able to fill a disk with it.
func TestReadinessLogWithoutRestateStatesEachReasonOnce(t *testing.T) {
	readinessLog, recorder := newReadinessLogRecorder(0)
	status := notReadyStatus("store", "/var/lib/cortex/store", "ping store: closed")

	for range 100 {
		recorder.advance(time.Hour)
		readinessLog.Observe(false, []diagnostics.DependencyStatus{status})
	}
	if len(recorder.records) != 2 {
		t.Fatalf("emitted %d records, want one dependency line and one workload line: %v", len(recorder.records), recorder.records)
	}
}

// A different reason for the same dependency is a different fact -- "connection
// refused" and "model still loading" call for different operator actions -- so
// it gets its own line while the outage clock keeps running.
func TestReadinessLogReportsAChangedReasonWithoutResettingTheOutageClock(t *testing.T) {
	readinessLog, recorder := newReadinessLogRecorder(time.Hour)

	readinessLog.Observe(false, []diagnostics.DependencyStatus{
		notReadyStatus("model_service", "http://127.0.0.1:8000", "modelservice health unhealthy: VLLM_HEALTH_UNAVAILABLE retryable"),
	})
	recorder.reset()
	recorder.advance(30 * time.Second)
	readinessLog.Observe(false, []diagnostics.DependencyStatus{
		notReadyStatus("model_service", "http://127.0.0.1:8000", "modelservice health unhealthy: VLLM_HEALTH_UNHEALTHY"),
	})

	if len(recorder.records) == 0 {
		t.Fatal("a changed reason emitted nothing")
	}
	changed := recorder.records[0].Message
	if !strings.Contains(changed, `reason="modelservice health unhealthy: VLLM_HEALTH_UNHEALTHY"`) {
		t.Fatalf("changed line %q does not carry the new reason", changed)
	}

	recorder.reset()
	recorder.advance(30 * time.Second)
	readinessLog.Observe(true, []diagnostics.DependencyStatus{readyStatus("model_service", "http://127.0.0.1:8000")})
	recovered := recorder.records[0].Message
	if !strings.Contains(recovered, `dependency ready dep="model_service"`) {
		t.Fatalf("recovery line %q does not report the dependency ready", recovered)
	}
	if !strings.Contains(recovered, "not_ready_for=1m0s") {
		t.Fatalf("recovery line %q lost the outage duration across the reason change", recovered)
	}
}

// Recovery has to be logged too. Without it a log tail shows the failure and
// nothing else, and an operator cannot tell a resolved outage from a live one.
func TestReadinessLogReportsRecoveryAndTheReopenedGate(t *testing.T) {
	readinessLog, recorder := newReadinessLogRecorder(0)
	down := []diagnostics.DependencyStatus{notReadyStatus("keeper", "http://127.0.0.1:26657", "query Keeper chain height: connection refused")}

	readinessLog.Observe(false, down)
	recorder.reset()
	recorder.advance(90 * time.Second)
	readinessLog.Observe(true, []diagnostics.DependencyStatus{readyStatus("keeper", "http://127.0.0.1:26657")})

	if len(recorder.records) != 2 {
		t.Fatalf("emitted %d records on recovery, want a dependency and a workload line: %v", len(recorder.records), recorder.records)
	}
	if !strings.Contains(recorder.records[0].Message, `dependency ready dep="keeper"`) || !strings.Contains(recorder.records[0].Message, "not_ready_for=1m30s") {
		t.Fatalf("recovery line %q does not report the recovered dependency and how long it was down", recorder.records[0].Message)
	}
	if !strings.Contains(recorder.records[1].Message, "workload dependencies ready") {
		t.Fatalf("gate line %q does not report the gate reopening", recorder.records[1].Message)
	}
	if recorder.records[0].Level != slog.LevelInfo || recorder.records[1].Level != slog.LevelInfo {
		t.Fatalf("recovery levels = %s, %s, want INFO", recorder.records[0].Level, recorder.records[1].Level)
	}
}

// A snapshot with no failing dependency but a closed gate must still say the
// workload is not starting. Reporting nothing would be the silence this log
// exists to remove.
func TestReadinessLogReportsAClosedGateEvenWithNoFailingDependency(t *testing.T) {
	readinessLog, recorder := newReadinessLogRecorder(0)

	readinessLog.Observe(false, []diagnostics.DependencyStatus{readyStatus("chain", "http://127.0.0.1:26657")})

	line := recorder.only(t)
	if !strings.Contains(line.Message, "workload not started") {
		t.Fatalf("line %q does not report the closed gate", line)
	}
	if !strings.Contains(line.Message, "no dependency reported a failure") {
		t.Fatalf("line %q does not admit that no dependency explained the closed gate", line)
	}
}

// A not-ready dependency whose probe reported no error is a gap in the probe,
// and saying so is more useful than an empty reason field.
func TestReadinessLogSaysSoWhenADependencyReportsNoReason(t *testing.T) {
	readinessLog, recorder := newReadinessLogRecorder(0)

	readinessLog.Observe(false, []diagnostics.DependencyStatus{{Name: "tx_broadcaster", Ready: false}})

	if !strings.Contains(recorder.records[0].Message, `reason="not ready without a reported reason"`) {
		t.Fatalf("line %q does not report the missing reason", recorder.records[0].Message)
	}
	if !strings.Contains(recorder.records[0].Message, "configured=false") {
		t.Fatalf("line %q drops the configured flag that distinguishes an unconfigured boundary", recorder.records[0].Message)
	}
}

// An unnamed status cannot be acted on and must not be reported as a module.
func TestReadinessLogSkipsUnnamedStatuses(t *testing.T) {
	readinessLog, recorder := newReadinessLogRecorder(0)

	readinessLog.Observe(false, []diagnostics.DependencyStatus{{Name: "  ", Ready: false, Error: "boom"}})

	line := recorder.only(t)
	if strings.Contains(line.Message, "dep=") {
		t.Fatalf("line %q reported an unnamed dependency", line)
	}
}

// A reason arrives from a remote boundary. It must not be able to break the
// line format or dump an unbounded payload into the log.
func TestReadinessLogQuotesAndBoundsRemoteReasons(t *testing.T) {
	readinessLog, recorder := newReadinessLogRecorder(0)

	readinessLog.Observe(false, []diagnostics.DependencyStatus{
		notReadyStatus("nexus", "nats://127.0.0.1:4222", "line one\nreason=\"forged\" "+strings.Repeat("x", 500)),
	})

	line := recorder.records[0].Message
	if strings.Contains(line, "\n") {
		t.Fatalf("line %q was split by a remote newline", line)
	}
	if !strings.Contains(line, `\n`) {
		t.Fatalf("line %q did not escape the remote newline", line)
	}
	if !strings.Contains(line, "...") {
		t.Fatalf("line %q did not truncate an oversized reason", line)
	}
	if len(line) > 1024 {
		t.Fatalf("line is %d bytes, want a bounded line: %q", len(line), line)
	}
}

// A nil Emit is the "logging not wired" case and must not panic on the hot
// readiness path.
func TestReadinessLogWithoutEmitIsInert(t *testing.T) {
	var readinessLog *ReadinessLog
	readinessLog.Observe(false, []diagnostics.DependencyStatus{notReadyStatus("chain", "", "boom")})
	(&ReadinessLog{}).Observe(false, []diagnostics.DependencyStatus{notReadyStatus("chain", "", "boom")})
}

// TestReadinessLogStatesAnOptionalDependencyOnceAndNeverRestatesIt pins the
// noise half of the devnet tx_broadcaster report.
//
// tx_broadcaster is optional unless an enabled workload path submits a Cosmos
// transaction, and on devnet none did. The restatement loop still repeated it
// every five minutes for 30 minutes - 1186 checks - and named it as the reason
// the workload had not started, which it was not: the workload gate ignores an
// optional dependency. So an optional boundary is stated once, so an operator
// can see it is unavailable, and then never again, and it never appears in the
// blocking set.
func TestReadinessLogStatesAnOptionalDependencyOnceAndNeverRestatesIt(t *testing.T) {
	readinessLog, recorder := newReadinessLogRecorder(5 * time.Minute)
	optional := notReadyStatus("tx_broadcaster", "http://127.0.0.1:1317",
		"tx_broadcaster readiness probe failed: signer cannot produce Cosmos transactions")
	optional.Optional = true
	blocking := notReadyStatus("nexus", "nats://127.0.0.1:4222", "nexus readiness probe failed")

	readinessLog.Observe(false, []diagnostics.DependencyStatus{optional, blocking})
	firstMessages := make([]string, 0, len(recorder.records))
	for _, record := range recorder.records {
		firstMessages = append(firstMessages, record.Message)
	}
	first := strings.Join(firstMessages, "\n")
	if !strings.Contains(first, `dep="tx_broadcaster"`) {
		t.Fatalf("first pass %q does not state the optional dependency at all", first)
	}
	if !strings.Contains(first, "optional=true") {
		t.Fatalf("first pass %q does not mark the dependency optional", first)
	}
	if !strings.Contains(first, `not_ready="nexus"`) {
		t.Fatalf("gate line in %q does not name nexus as the blocker", first)
	}
	if strings.Contains(first, `not_ready="tx_broadcaster,nexus"`) || strings.Contains(first, "tx_broadcaster,") {
		t.Fatalf("gate line in %q blames an optional dependency for the closed gate", first)
	}

	recorder.reset()
	for range 12 {
		recorder.advance(5 * time.Minute)
		readinessLog.Observe(false, []diagnostics.DependencyStatus{optional, blocking})
	}
	for _, record := range recorder.records {
		if strings.Contains(record.Message, `dep="tx_broadcaster"`) {
			t.Fatalf("restated an optional dependency: %q", record.Message)
		}
	}
	if len(recorder.records) == 0 {
		t.Fatal("restated nothing at all; the blocking dependency must still be restated")
	}
}

// Going ready is a state change worth one line even for an optional
// dependency: it is how an operator learns the boundary came back.
func TestReadinessLogReportsAnOptionalDependencyBecomingReady(t *testing.T) {
	readinessLog, recorder := newReadinessLogRecorder(5 * time.Minute)
	optional := notReadyStatus("tx_broadcaster", "http://127.0.0.1:1317", "signer cannot produce Cosmos transactions")
	optional.Optional = true

	readinessLog.Observe(false, []diagnostics.DependencyStatus{optional})
	recorder.reset()
	recorder.advance(time.Minute)
	ready := readyStatus("tx_broadcaster", "http://127.0.0.1:1317")
	ready.Optional = true
	readinessLog.Observe(false, []diagnostics.DependencyStatus{ready})

	if len(recorder.records) == 0 || !strings.Contains(recorder.records[0].Message, "dependency ready") {
		t.Fatalf("records = %v, want the optional dependency's recovery reported", recorder.records)
	}
}
