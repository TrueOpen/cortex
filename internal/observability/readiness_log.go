package observability

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TrueOpen/cortex/internal/diagnostics"
)

// ReadinessLog turns readiness snapshots into operator-facing log lines.
//
// The readiness control loop used to be silent. A node whose model service was
// down probed it on every poll interval, kept its workload stopped, and said
// nothing: the only record of which boundary was holding it down lived in the
// admin socket's diagnostics snapshot and in `/readyz`, which name the
// dependency but not the reason. An operator had to already suspect a problem,
// and know those two surfaces exist, to find out why the node was not serving.
// Fail-closed readiness is where the decision not to work gets made, so it has
// to say so on its own.
//
// Every line carries the module and the reason. Lines are emitted on state
// change rather than on every pass, with an optional restatement interval so a
// node stuck for hours keeps repeating why without one line per poll.
type ReadinessLog struct {
	// Emit receives one formatted record. A nil Emit disables logging entirely,
	// which is the "not wired" case rather than an error.
	Emit func(LogRecord)
	// Restate repeats the current reason for a dependency that stays not ready.
	// Zero states each reason once, which is what a test or a short-lived
	// process wants; a daemon should set it.
	Restate time.Duration
	// Now defaults to time.Now.
	Now func() time.Time

	mu           sync.Mutex
	dependencies map[string]readinessLogEntry
	gate         readinessLogEntry
	gateObserved bool
}

// readinessLogEntry is the last state this log reported for one dependency, or
// for the workload gate. `since` is when the current ready/not-ready state
// began, `stated` when the log last said so, and `checks` how many snapshots
// have observed the current not-ready state -- an operator reading a
// restatement wants to know the difference between a boundary that flapped and
// one that has been down for two thousand consecutive probes.
type readinessLogEntry struct {
	ready  bool
	reason string
	since  time.Time
	stated time.Time
	checks int
}

const readinessLogNoReason = "not ready without a reported reason"

const readinessLogNoBlocker = "unknown (no dependency reported a failure)"

// Observe reports one readiness snapshot. gateReady is whether the workload is
// allowed to activate; dependencies are the boundaries the snapshot probed, in
// the order they should be reported.
func (l *ReadinessLog) Observe(gateReady bool, dependencies []diagnostics.DependencyStatus) {
	if l == nil || l.Emit == nil {
		return
	}
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.dependencies == nil {
		l.dependencies = make(map[string]readinessLogEntry, len(dependencies))
	}
	notReady := make([]string, 0, len(dependencies))
	for _, status := range dependencies {
		name := strings.TrimSpace(status.Name)
		// An unnamed status cannot be acted on, and reporting it as a module
		// would put a blank name in front of an operator.
		if name == "" {
			continue
		}
		status.Name = name
		// An optional boundary never holds the gate closed, so it must not be
		// named as the reason it is closed. tx_broadcaster was reported as a
		// blocker on every devnet node while the gate itself
		// (workloadDependenciesReady) had already excluded it.
		if !status.Ready && !status.Optional {
			notReady = append(notReady, name)
		}
		l.observeDependency(now, status)
	}
	l.observeGate(now, gateReady, notReady)
}

func (l *ReadinessLog) observeDependency(now time.Time, status diagnostics.DependencyStatus) {
	previous, observed := l.dependencies[status.Name]
	if status.Ready {
		if observed && !previous.ready {
			l.emitInfo(fmt.Sprintf("dependency ready dep=%s endpoint=%s not_ready_for=%s checks=%d",
				QuoteLogValue(status.Name), QuoteLogValue(status.Endpoint),
				formatReadinessDuration(now.Sub(previous.since)), previous.checks))
		}
		if !observed || !previous.ready {
			l.dependencies[status.Name] = readinessLogEntry{ready: true, since: now, stated: now}
		}
		return
	}

	reason := readinessReason(status)
	stillDown := observed && !previous.ready
	if stillDown && previous.reason == reason {
		previous.checks++
		// An optional dependency is stated once and then left alone. Restating
		// a boundary that is not stopping this node from serving is how a log
		// teaches its readers to skip readiness lines: on devnet this was 1186
		// consecutive checks of a dependency no enabled path needed. A change
		// of reason, and recovery, still get their line below.
		if l.Restate > 0 && !status.Optional && now.Sub(previous.stated) >= l.Restate {
			l.emitError(fmt.Sprintf("dependency still not ready dep=%s endpoint=%s reason=%s for=%s checks=%d",
				QuoteLogValue(status.Name), QuoteLogValue(status.Endpoint), QuoteLogValue(reason),
				formatReadinessDuration(now.Sub(previous.since)), previous.checks))
			previous.stated = now
		}
		l.dependencies[status.Name] = previous
		return
	}

	// optional= is appended rather than always present: it is the exception,
	// and the answer an operator needs from an optional line ("do I care?") is
	// only interesting when it is yes.
	optional := ""
	if status.Optional {
		optional = " optional=true"
	}
	l.emitError(fmt.Sprintf("dependency not ready dep=%s endpoint=%s configured=%t reason=%s%s",
		QuoteLogValue(status.Name), QuoteLogValue(status.Endpoint), status.Configured, QuoteLogValue(reason), optional))
	entry := readinessLogEntry{reason: reason, since: now, stated: now, checks: 1}
	if stillDown {
		// The reason changed while the dependency stayed down. That is a new
		// fact and gets its own line, but the outage started earlier and the
		// duration must not restart with the new explanation.
		entry.since = previous.since
		entry.checks = previous.checks + 1
	}
	l.dependencies[status.Name] = entry
}

// observeGate reports the workload gate itself. The per-dependency lines
// already say what is broken; this line says what it costs -- that the node is
// not taking work -- and names the whole blocking set at once, so an operator
// does not have to reassemble it from a log tail.
func (l *ReadinessLog) observeGate(now time.Time, ready bool, notReady []string) {
	previous := l.gate
	observed := l.gateObserved
	l.gateObserved = true

	if ready {
		if observed && previous.ready {
			return
		}
		line := "workload dependencies ready: the workload gate is open"
		if observed {
			line += fmt.Sprintf(" not_ready_for=%s", formatReadinessDuration(now.Sub(previous.since)))
		}
		l.emitInfo(line)
		l.gate = readinessLogEntry{ready: true, since: now, stated: now}
		return
	}

	reason := strings.Join(notReady, ",")
	if reason == "" {
		reason = readinessLogNoBlocker
	}
	stillClosed := observed && !previous.ready
	if stillClosed && previous.reason == reason {
		previous.checks++
		if l.Restate > 0 && now.Sub(previous.stated) >= l.Restate {
			l.emitError(fmt.Sprintf("workload still not started: not_ready=%s for=%s checks=%d",
				QuoteLogValue(reason), formatReadinessDuration(now.Sub(previous.since)), previous.checks))
			previous.stated = now
		}
		l.gate = previous
		return
	}

	l.emitError(fmt.Sprintf("workload not started: not_ready=%s", QuoteLogValue(reason)))
	entry := readinessLogEntry{reason: reason, since: now, stated: now, checks: 1}
	if stillClosed {
		entry.since = previous.since
		entry.checks = previous.checks + 1
	}
	l.gate = entry
}

func (l *ReadinessLog) emitInfo(message string) {
	l.Emit(NewLogRecord(slog.LevelInfo, message, 0))
}

func (l *ReadinessLog) emitError(message string) {
	l.Emit(NewLogRecord(slog.LevelError, message, 0))
}

func (l *ReadinessLog) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

// readinessReason keeps an empty error from becoming an empty reason field. A
// probe that reports not-ready without saying why is a gap in that probe, and
// naming the gap is more useful to whoever reads the line than `reason=""`.
func readinessReason(status diagnostics.DependencyStatus) string {
	if reason := strings.TrimSpace(status.Error); reason != "" {
		return reason
	}
	return readinessLogNoReason
}

func formatReadinessDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}

// maxLogValueRunes bounds one log value. Reasons come from remote boundaries,
// so their length is not ours to trust.
const maxLogValueRunes = 128

// QuoteLogValue renders a value for a key=value log line: quoted, escaped to
// ASCII and bounded. A reason carrying a newline or a quote must not be able to
// break the line format or forge a second field.
func QuoteLogValue(value string) string {
	end := len(value)
	runes := 0
	for index := range value {
		if runes == maxLogValueRunes {
			end = index
			break
		}
		runes++
	}
	if end < len(value) {
		value = value[:end] + "..."
	}
	return strconv.QuoteToASCII(strings.ToValidUTF8(value, "?"))
}
