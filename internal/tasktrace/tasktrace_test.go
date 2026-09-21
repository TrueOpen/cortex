package tasktrace

import (
	"errors"
	"log/slog"
	"runtime"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/observability"
)

func TestTraceEventKeepsFieldOrderAndPrintsDigestsInHex(t *testing.T) {
	var records []observability.LogRecord
	trace := &Trace{Emit: func(record observability.LogRecord) { records = append(records, record) }}

	outputHash := codec.HashBytes([]byte("output"))
	trace.Event("output_confirmed",
		Str("task", "task-1"), Hash("output_hash", outputHash),
		Hash("package_hash", codec.Hash{}), Uint("size_bytes", 12), Bool("accepted", true))

	if len(records) != 1 {
		t.Fatalf("emitted %d records, want exactly one: %#v", len(records), records)
	}
	want := `task trace event=output_confirmed task="task-1" output_hash=` + outputHash.String() +
		` package_hash=zero size_bytes=12 accepted=true`
	if records[0].Message != want {
		t.Fatalf("message =\n%s\nwant\n%s", records[0].Message, want)
	}
	if records[0].Level != slog.LevelInfo {
		t.Fatalf("level = %s, want INFO", records[0].Level)
	}
}

func TestTraceErrorEventPreservesMessageAndUsesErrorLevel(t *testing.T) {
	var records []observability.LogRecord
	trace := &Trace{Emit: func(record observability.LogRecord) { records = append(records, record) }}

	trace.ErrorEvent("output_confirm_failed", Err("error", errors.New("package hash is zero")))

	if len(records) != 1 {
		t.Fatalf("emitted %d records, want exactly one: %#v", len(records), records)
	}
	if records[0].Message != `task trace event=output_confirm_failed error="package hash is zero"` {
		t.Fatalf("message = %q", records[0].Message)
	}
	if records[0].Level != slog.LevelError {
		t.Fatalf("level = %s, want ERROR", records[0].Level)
	}
}

func TestTraceEventAttributesTheBusinessCaller(t *testing.T) {
	var records []observability.LogRecord
	trace := &Trace{Emit: func(record observability.LogRecord) { records = append(records, record) }}

	emitTraceEvent(trace)

	if len(records) != 1 {
		t.Fatalf("emitted %d records, want exactly one: %#v", len(records), records)
	}
	function := runtime.FuncForPC(records[0].PC)
	if function == nil {
		t.Fatal("record has no caller function")
	}
	if !strings.HasSuffix(function.Name(), ".emitTraceEvent") {
		t.Fatalf("caller = %q, want helper that called Trace.Event", function.Name())
	}
}

func emitTraceEvent(trace *Trace) {
	trace.Event("accepted", Str("task", "task-1"))
}

// A zero digest is the answer this trace exists to make visible: the chain
// carrying no canonical_output_package_hash and the chain carrying a different
// one are two different faults that produced one refusal message.
func TestZeroDigestIsNamedRatherThanPrintedAsSixtyFourZeros(t *testing.T) {
	if got := HashForLog(codec.Hash{}); got != "zero" {
		t.Fatalf("HashForLog(zero) = %q, want %q", got, "zero")
	}
	filled := codec.HashBytes([]byte("filled"))
	if got := HashForLog(filled); got != filled.String() || strings.Contains(got, "zero") {
		t.Fatalf("HashForLog(filled) = %q, want the hex digest", got)
	}
}

func TestHexNamesAnAbsentDigestAndQuotesAValueThatIsNotHex(t *testing.T) {
	line := traceOneLine(t, "metadata", Hex("semantic_hash", ""), Hex("accepted_receipt_hash", "AB12"),
		Hex("media_type", "text/plain; charset=utf-8"))
	if !strings.Contains(line, "semantic_hash=absent") {
		t.Fatalf("line %q does not name the absent digest", line)
	}
	if !strings.Contains(line, "accepted_receipt_hash=AB12") {
		t.Fatalf("line %q dropped or requoted a hex digest", line)
	}
	// A value that is not a digest must not be able to split the line into two
	// fields, so it is quoted rather than passed through.
	if !strings.Contains(line, `media_type="text/plain; charset=utf-8"`) {
		t.Fatalf("line %q did not quote a non-hex value", line)
	}
}

func TestErrFieldRendersARefusalOnTheSameLineShapeAsASuccess(t *testing.T) {
	line := traceOneLine(t, "output_confirm_failed", Err("error", errors.New("package hash is zero")))
	if !strings.Contains(line, `error="package hash is zero"`) {
		t.Fatalf("line %q does not carry the error", line)
	}
	if empty := traceOneLine(t, "done", Err("error", nil)); !strings.Contains(empty, `error=""`) {
		t.Fatalf("line %q should render a nil error as an empty value", empty)
	}
}

// Nothing here builds a logger of its own: a runner constructed by a test, or by
// any caller that supplies no sink, must behave exactly as it did before the
// trace existed.
func TestTraceWithoutAnEmitterIsSilentAndNilSafe(t *testing.T) {
	var absent *Trace
	absent.Event("order_broadcast", Str("task", "task-1"))
	if absent.Enabled() {
		t.Fatal("a nil trace reports itself enabled")
	}
	unwired := &Trace{}
	unwired.Event("order_broadcast", Str("task", "task-1"))
	if unwired.Enabled() {
		t.Fatal("a trace with no Emit reports itself enabled")
	}
}

func traceOneLine(t *testing.T, event string, fields ...Field) string {
	t.Helper()
	var records []observability.LogRecord
	(&Trace{Emit: func(record observability.LogRecord) { records = append(records, record) }}).Event(event, fields...)
	if len(records) != 1 {
		t.Fatalf("emitted %d records, want exactly one: %#v", len(records), records)
	}
	return records[0].Message
}
