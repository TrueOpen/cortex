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

type Health struct {
	mu           sync.RWMutex
	dependencies map[string]bool
	order        []string
	required     map[string]bool
	warnings     []string
	metrics      http.Handler
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
	return newHealth([]string{"chain", "model_service", "store", "keeper", "keeper_identity", "model_support", "builder_descriptor", "tx_broadcaster", DependencyChainSync, DependencyWorkload}, optional)
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

// Readiness reports what /readyz would answer and the state of every
// dependency, for the metrics exporter.
func (h *Health) Readiness() (ready bool, dependencies map[string]bool) {
	ready = len(h.blockingDependencies()) == 0
	h.mu.RLock()
	defer h.mu.RUnlock()
	dependencies = make(map[string]bool, len(h.dependencies))
	for name, healthy := range h.dependencies {
		dependencies[name] = healthy
	}
	return ready, dependencies
}

// AttachMetrics serves metrics, normally NewMetricsHandler, on the health
// server's /metrics route.
func (h *Health) AttachMetrics(metrics http.Handler) {
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

func (h *Health) handleMetrics(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	metrics := h.metrics
	h.mu.RUnlock()
	if metrics == nil {
		// Report an empty body rather than 404 so the scrape target stays valid
		// before metrics are attached.
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		return
	}
	metrics.ServeHTTP(w, r)
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
