package observability

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/TrueOpen/cortex/internal/diagnostics"
)

var ErrUnknownDependency = errors.New("unknown health dependency")

// DependencyWorkload reports whether the Worker/Verifier runners are actually
// running. Every other dependency describes something the node talks to, so a
// node whose workload had stopped still answered /readyz with 200: each
// boundary it depended on was reachable, and nothing described the node's own
// ability to take work. A scheduler or operator reading readiness has no way to
// tell that apart from a node that is serving.
const DependencyWorkload = "workload"

// DependencyChainSync reports whether consumed Keeper events have caught up to
// the chain tip. A node replaying a backlog after downtime must not take new
// work, but it must keep consuming events so it can catch up, so staleness
// gates readiness here rather than stopping the poller.
const DependencyChainSync = "chain_sync"

// DependencyNATSIdentity reports whether this node can still sign the on-chain
// binding it presents to NATS (ADR-0016 decision three).
const DependencyNATSIdentity = "nexus_nats_identity"

type Health struct {
	mu           sync.RWMutex
	dependencies map[string]bool
	order        []string
	required     map[string]bool
	warnings     []string
	metrics      *MetricsRegistry
}

func (h *Health) SetWarning(warning string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, existing := range h.warnings {
		if existing == warning {
			return
		}
	}
	if warning != "" {
		h.warnings = append(h.warnings, warning)
	}
}

func NewHealth() *Health {
	return newHealth([]string{"chain", "model", "store"}, nil)
}

func NewIntegrationHealth() *Health {
	return NewIntegrationHealthWithRuntimeRequirements(true, true, true)
}

func NewIntegrationHealthWithTxRequirement(requireTxBroadcaster bool) *Health {
	return NewIntegrationHealthWithRuntimeRequirements(requireTxBroadcaster, true, true)
}

// NewIntegrationHealthWithRuntimeRequirements makes lifecycle-only
// dependencies optional when the selected runtime does not own that lifecycle.
// Fake mode, for example, has no dynamically gated Worker/Verifier workload.
func NewIntegrationHealthWithRuntimeRequirements(requireTxBroadcaster, requireChainSync, requireWorkload bool) *Health {
	optional := map[string]bool{}
	if !requireTxBroadcaster {
		optional["tx_broadcaster"] = true
	}
	if !requireChainSync {
		optional[DependencyChainSync] = true
	}
	if !requireWorkload {
		optional[DependencyWorkload] = true
	}
	// The on-chain NATS identity is registered here only so its status has a
	// known name; it is never required. Whether a node must hold a signable
	// binding depends on its configuration -- a node on the creds/token path has
	// no binding at all -- so that judgement lives in the workload readiness
	// gate, which can see the configuration. This map cannot, and marking it
	// required here would hold /readyz down forever on the creds path.
	optional[DependencyNATSIdentity] = true
	return newHealth([]string{"chain", "model_service", "store", "keeper", "keeper_identity", "model_support", "nexus", "nexus_envelope_auth", DependencyNATSIdentity, "builder_descriptor", "tx_broadcaster", DependencyChainSync, DependencyWorkload}, optional)
}

func newHealth(names []string, optional map[string]bool) *Health {
	deps := make(map[string]bool, len(names))
	required := make(map[string]bool, len(names))
	for _, name := range names {
		deps[name] = false
		required[name] = !optional[name]
	}
	return &Health{dependencies: deps, order: append([]string(nil), names...), required: required}
}

func (h *Health) SetDependency(name string, healthy bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.dependencies[name]; !ok {
		return ErrUnknownDependency
	}
	h.dependencies[name] = healthy
	return nil
}

// DependencyReady reports the current readiness of one dependency. It exists so
// callers and tests can assert on a single lifecycle dependency rather than
// inferring it from the aggregate /readyz result.
func (h *Health) DependencyReady(name string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.dependencies[name]
}

func (h *Health) Apply(statuses []diagnostics.DependencyStatus) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, status := range statuses {
		if _, ok := h.dependencies[status.Name]; !ok {
			return ErrUnknownDependency
		}
	}
	for _, status := range statuses {
		h.dependencies[status.Name] = status.Ready
	}
	return nil
}

// AttachMetrics exposes a registry on the health server's /metrics route. Until
// this existed the registry was unreachable: the projector filled it in on every
// pass and no surface could read it, so an operator had no way to see counts such
// as cortex_task_queue_failed from the process health endpoint.
func (h *Health) AttachMetrics(metrics *MetricsRegistry) {
	h.mu.Lock()
	h.metrics = metrics
	h.mu.Unlock()
}

func (h *Health) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", h.handleHealthz)
	mux.HandleFunc("/readyz", h.handleReadyz)
	mux.HandleFunc("/metrics", h.handleMetrics)
	return mux
}

func (h *Health) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	h.mu.RLock()
	metrics := h.metrics
	h.mu.RUnlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if metrics == nil {
		// Fake mode runs no projector. Report an empty body rather than 404 so a
		// scrape target stays valid across modes.
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, metrics.Render())
}

func (h *Health) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "ok")
}

func (h *Health) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if blocking := h.blockingDependencies(); len(blocking) != 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		// Name what is blocking. "not ready" alone gives an operator nothing to
		// act on, and the readiness-only dependencies do not appear in
		// cortexctl diagnostics, which reports the boundaries resolved at
		// startup.
		fmt.Fprintf(w, "not ready: %s\n", strings.Join(blocking, " "))
		return
	}

	w.WriteHeader(http.StatusOK)
	h.mu.RLock()
	warnings := append([]string(nil), h.warnings...)
	h.mu.RUnlock()
	if len(warnings) == 0 {
		fmt.Fprintln(w, "ready")
		return
	}
	fmt.Fprintf(w, "ready %s\n", warnings[0])
}

func (h *Health) ready() bool {
	return len(h.blockingDependencies()) == 0
}

// blockingDependencies lists the required dependencies that are not ready, in
// declaration order.
func (h *Health) blockingDependencies() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var blocking []string
	for _, name := range h.order {
		if h.required[name] && !h.dependencies[name] {
			blocking = append(blocking, name)
		}
	}
	return blocking
}
