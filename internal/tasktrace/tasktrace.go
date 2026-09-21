// Package tasktrace is the per-task protocol trace: one `key=value` line at
// every milestone a task passes through, carrying in full every digest that
// milestone decided on.
//
// It exists because the digests that decide whether a task can proceed --
// accepted_task_hash, output_hash, infer_receipt_hash, the receipt result hash
// -- were visible only inside a refusal message, and a refusal names the check
// that failed rather than the values that failed it. During joint debugging
// with Nexus and Keeper the values are the entire question.
//
// canonical_output_package_hash is traced too, but as an observation rather than
// a commitment: the chain deleted the field and cortex-detailed-design.md §13 forbids
// deriving a replacement, so package_hash=zero is the normal chain and the only
// thing a non-zero one tells you is that the node is running the fake model
// transport.
//
// It is its own package rather than a type in internal/daemon because the three
// packages that produce these digests -- daemon, worker, verifier -- are already
// a one-way chain of imports, so a trace owned by any of them could not be used
// by the others.
package tasktrace

import (
	"log/slog"
	"strconv"
	"strings"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/observability"
)

// Trace emits the milestone lines. A nil Trace, or one with no Emit, is silent:
// no package here builds a logger of its own -- cortexd supplies the sink,
// exactly as it does for the readiness log and the publish observer -- so every
// test constructs its subject without one and the traced paths behave
// identically.
type Trace struct {
	// Emit receives one formatted record, already escaped. A nil Emit disables
	// the trace without changing any call site.
	Emit func(observability.LogRecord)
}

// Enabled reports whether anything would be emitted, for the one caller that
// has to assemble an expensive field set before it can trace it.
func (t *Trace) Enabled() bool { return t != nil && t.Emit != nil }

// Event emits one milestone line: `task trace event=<name> key=value ...`.
// Fields keep the order the caller wrote them in, because that order is the
// story the line tells -- what the frame said, then what the chain said, then
// what this node derived.
func (t *Trace) Event(name string, fields ...Field) {
	t.emit(slog.LevelInfo, name, fields...)
}

// ErrorEvent emits one failed milestone line at ERROR level.
func (t *Trace) ErrorEvent(name string, fields ...Field) {
	t.emit(slog.LevelError, name, fields...)
}

func (t *Trace) emit(level slog.Level, name string, fields ...Field) {
	if !t.Enabled() {
		return
	}
	var line strings.Builder
	line.WriteString("task trace event=")
	line.WriteString(name)
	for _, field := range fields {
		if field.key == "" {
			continue
		}
		line.WriteByte(' ')
		line.WriteString(field.key)
		line.WriteByte('=')
		line.WriteString(field.value)
	}
	// Event and ErrorEvent are called at the protocol decision point; retain
	// that caller rather than attributing the record to this formatter.
	t.Emit(observability.NewLogRecord(level, line.String(), 2))
}

// Field is one already-rendered key=value pair. The value is escaped by the
// constructor rather than by Event so that a hash, a height and an operator
// address can share one line without one of them needing quotes it does not
// have.
type Field struct {
	key   string
	value string
}

// Str quotes with the same rule as every other key=value line cortexd emits, so
// an address or a reject code containing a space cannot split a field.
func Str(key, value string) Field {
	return Field{key: key, value: observability.QuoteLogValue(value)}
}

// Hash prints a digest as lowercase hex, and prints the unset digest as `zero`
// rather than as 64 zeros. Telling "the chain carries no package hash" apart
// from "the chain carries a package hash that disagrees" is the single most
// common question this trace answers, and 64 zeros is exactly the value an eye
// skips over.
func Hash(key string, hash codec.Hash) Field {
	return Field{key: key, value: HashForLog(hash)}
}

// Hex prints a digest that arrived as hex text -- the bus payloads and the
// task-data receipt spell theirs that way -- beside the ones that arrived as
// bytes, in the same unquoted form so the two can be compared by eye. An empty
// value is `absent`, and anything that is not hex is quoted rather than trusted
// to keep to its own field.
func Hex(key, value string) Field {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return Field{key: key, value: "absent"}
	}
	for _, r := range trimmed {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return Str(key, value)
		}
	}
	return Field{key: key, value: trimmed}
}

func Uint(key string, value uint64) Field {
	return Field{key: key, value: strconv.FormatUint(value, 10)}
}

func Int(key string, value int) Field {
	return Field{key: key, value: strconv.Itoa(value)}
}

func Bool(key string, value bool) Field {
	return Field{key: key, value: strconv.FormatBool(value)}
}

// Err renders a failure into the same line shape as a success, so the trace of
// a task that refused reads like the trace of one that did not.
func Err(key string, err error) Field {
	if err == nil {
		return Field{key: key, value: `""`}
	}
	return Str(key, err.Error())
}

// HashForLog is the one spelling of a digest this daemon puts in an operator's
// hands, in a trace line or in a refusal message. It is exported because the
// refusals that report a missing commitment must spell the same value the same
// way the trace does.
func HashForLog(hash codec.Hash) string {
	if hash.IsZero() {
		return "zero"
	}
	return hash.String()
}
