package observability

import (
	"bytes"
	"fmt"
	"log"
	"log/slog"
	"runtime"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/observability/logtest"
)

func TestTextLoggerIncludesLevelRelativeSourceAndMessage(t *testing.T) {
	var output bytes.Buffer
	logtest.Install(t, NewTextLogger(&output), log.Default())

	Emit(NewLogRecord(slog.LevelInfo, "ready", 0), slog.String("component", "keeper"))
	line := output.String()
	for _, want := range []string{"level=INFO", "source=internal/observability/logging_test.go:", "msg=ready", "component=keeper"} {
		if !strings.Contains(line, want) {
			t.Fatalf("log %q missing %q", line, want)
		}
	}
	if strings.Contains(line, "/Users/") {
		t.Fatalf("log leaks absolute source path: %q", line)
	}
}

func TestTextLoggerIncludesErrorLevel(t *testing.T) {
	var output bytes.Buffer
	logtest.Install(t, NewTextLogger(&output), log.Default())

	Emit(NewLogRecord(slog.LevelError, "failed", 0))
	if !strings.Contains(output.String(), "level=ERROR") {
		t.Fatalf("log %q missing error level", output.String())
	}
}

func TestLogAtDepthUsesCallbackCallSite(t *testing.T) {
	var output bytes.Buffer
	logtest.Install(t, NewTextLogger(&output), log.Default())

	_, _, callerLine, _ := runtime.Caller(0)
	emitFromLoggingTestHelper()
	line := output.String()
	if !strings.Contains(line, fmt.Sprintf("source=internal/observability/logging_test.go:%d", callerLine+1)) {
		t.Fatalf("log %q missing precise callback source", line)
	}
	if strings.Contains(line, "source=internal/observability/logging.go:") {
		t.Fatalf("log attributed to logging implementation: %q", line)
	}
}

func TestCallerPCZeroUsesImmediateCallSite(t *testing.T) {
	_, _, callerLine, _ := runtime.Caller(0)
	pc := CallerPC(0)
	frame, _ := runtime.CallersFrames([]uintptr{pc}).Next()
	if !strings.HasSuffix(frame.File, "internal/observability/logging_test.go") || frame.Line != callerLine+1 {
		t.Fatalf("CallerPC(0) resolved to %s:%d, want logging_test.go:%d", frame.File, frame.Line, callerLine+1)
	}
}

func TestNewLogRecordNegativeCallerSkipUsesImmediateCallSite(t *testing.T) {
	record := newLogRecordWithNegativeCallerSkip()
	function := runtime.FuncForPC(record.PC)
	if function == nil || !strings.HasSuffix(function.Name(), ".newLogRecordWithNegativeCallerSkip") {
		name := "<nil>"
		if function != nil {
			name = function.Name()
		}
		t.Fatalf("NewLogRecord negative caller skip resolved to %q, want immediate helper callsite", name)
	}
}

func TestTrimSourcePathUsesRepositorySegmentsAndSafeFallback(t *testing.T) {
	tests := []struct {
		name string
		file string
		want string
	}{
		{name: "repository segment", file: "/repo/internal/observability/logging.go", want: "internal/observability/logging.go"},
		{name: "false marker", file: "/repo/myinternal/logging.go", want: "logging.go"},
		{name: "unknown absolute path", file: "/other/repo/test/logging.go", want: "logging.go"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := trimSourcePath(test.file); got != test.want {
				t.Fatalf("trimSourcePath(%q) = %q, want %q", test.file, got, test.want)
			}
		})
	}
}

func emitFromLoggingTestHelper() {
	LogAtDepth(slog.LevelInfo, 1, "callback")
}

//go:noinline
func newLogRecordWithNegativeCallerSkip() LogRecord {
	return newLogRecordForTest(slog.LevelInfo, "negative skip", -1)
}

var newLogRecordForTest = NewLogRecord
