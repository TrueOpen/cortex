package observability

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/diagnostics"
)

func TestHealthzIsLive(t *testing.T) {
	health := NewHealth()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	health.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestReadyzIsFalseWhenDependenciesAreUnhealthy(t *testing.T) {
	health := NewHealth()
	health.SetDependency("chain", false)
	health.SetDependency("model", true)
	health.SetDependency("store", true)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	health.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestSetDependencyRejectsUnknownDependency(t *testing.T) {
	health := NewHealth()

	err := health.SetDependency("builder", true)

	if err == nil {
		t.Fatalf("SetDependency() error = nil, want error")
	}
	if !errors.Is(err, ErrUnknownDependency) {
		t.Fatalf("SetDependency() error = %v, want ErrUnknownDependency", err)
	}
}

func TestReadyzIsTrueWhenAllDependenciesAreHealthy(t *testing.T) {
	health := NewHealth()
	if err := health.SetDependency("chain", true); err != nil {
		t.Fatalf("SetDependency(chain): %v", err)
	}
	if err := health.SetDependency("model", true); err != nil {
		t.Fatalf("SetDependency(model): %v", err)
	}
	if err := health.SetDependency("store", true); err != nil {
		t.Fatalf("SetDependency(store): %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	health.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestReadyzDisplaysSecurityWarning(t *testing.T) {
	health := NewHealth()
	for _, name := range []string{"chain", "model", "store"} {
		if err := health.SetDependency(name, true); err != nil {
			t.Fatalf("SetDependency(%s): %v", name, err)
		}
	}
	health.SetWarning("UNSAFE_TRUSTED_TRANSPORT")
	health.SetWarning("UNSAFE_TRUSTED_TRANSPORT")
	rec := httptest.NewRecorder()
	health.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ready UNSAFE_TRUSTED_TRANSPORT") {
		t.Fatalf("/readyz = %d %q", rec.Code, rec.Body.String())
	}
}

func TestIntegrationHealthRequiresKeeperIdentityNexusAndTxBroadcaster(t *testing.T) {
	health := NewIntegrationHealth()
	for _, name := range []string{"chain", "model_service", "store", "keeper", "keeper_identity"} {
		if err := health.SetDependency(name, true); err != nil {
			t.Fatalf("SetDependency(%s): %v", name, err)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	health.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if err := health.SetDependency("nexus", true); err != nil {
		t.Fatalf("SetDependency(nexus): %v", err)
	}
	rec = httptest.NewRecorder()
	health.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want %d until envelope auth is ready", rec.Code, http.StatusServiceUnavailable)
	}
	if err := health.SetDependency("nexus_envelope_auth", true); err != nil {
		t.Fatalf("SetDependency(nexus_envelope_auth): %v", err)
	}
	rec = httptest.NewRecorder()
	health.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want %d until tx broadcaster is ready", rec.Code, http.StatusServiceUnavailable)
	}
	if err := health.SetDependency("tx_broadcaster", true); err != nil {
		t.Fatalf("SetDependency(tx_broadcaster): %v", err)
	}
	if err := health.SetDependency(DependencyChainSync, true); err != nil {
		t.Fatalf("SetDependency(chain_sync): %v", err)
	}
	rec = httptest.NewRecorder()
	health.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want %d until model support is ready", rec.Code, http.StatusServiceUnavailable)
	}
	if err := health.SetDependency("model_support", true); err != nil {
		t.Fatalf("SetDependency(model_support): %v", err)
	}
	rec = httptest.NewRecorder()
	health.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want %d until the Builder descriptor is verified", rec.Code, http.StatusServiceUnavailable)
	}
	if err := health.SetDependency("builder_descriptor", true); err != nil {
		t.Fatalf("SetDependency(builder_descriptor): %v", err)
	}
	rec = httptest.NewRecorder()
	health.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want %d until the workload is running", rec.Code, http.StatusServiceUnavailable)
	}
	if err := health.SetDependency(DependencyWorkload, true); err != nil {
		t.Fatalf("SetDependency(workload): %v", err)
	}
	rec = httptest.NewRecorder()
	health.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// Every other dependency describes a boundary the node talks to. A node whose
// workload has stopped still reaches all of them, so without this /readyz
// answers 200 for a node that cannot take any work.
func TestIntegrationHealthReportsNotReadyWhenWorkloadStops(t *testing.T) {
	health := NewIntegrationHealth()
	for _, name := range []string{"chain", "model_service", "store", "keeper", "keeper_identity", "model_support", "nexus", "nexus_envelope_auth", "builder_descriptor", "tx_broadcaster", DependencyChainSync, DependencyWorkload} {
		if err := health.SetDependency(name, true); err != nil {
			t.Fatalf("SetDependency(%s): %v", name, err)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	health.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz status = %d, want %d while serving", rec.Code, http.StatusOK)
	}

	// The workload exits; every boundary it depended on is still reachable.
	if err := health.SetDependency(DependencyWorkload, false); err != nil {
		t.Fatalf("SetDependency(workload): %v", err)
	}
	rec = httptest.NewRecorder()
	health.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want %d once the workload has stopped", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestIntegrationHealthAllowsOptionalTxBroadcasterToBeUnready(t *testing.T) {
	health := NewIntegrationHealthWithTxRequirement(false)
	for _, name := range []string{"chain", "model_service", "store", "keeper", "keeper_identity", "model_support", "nexus", "nexus_envelope_auth", "builder_descriptor", DependencyChainSync, DependencyWorkload} {
		if err := health.SetDependency(name, true); err != nil {
			t.Fatalf("SetDependency(%s): %v", name, err)
		}
	}
	if err := health.SetDependency("tx_broadcaster", false); err != nil {
		t.Fatalf("SetDependency(tx_broadcaster): %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	health.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz status = %d, want %d with optional tx broadcaster", rec.Code, http.StatusOK)
	}
}

func TestHealthApplyDependencyStatuses(t *testing.T) {
	health := NewIntegrationHealth()
	err := health.Apply([]diagnostics.DependencyStatus{
		{Name: "chain", Ready: true},
		{Name: "model_service", Ready: true},
		{Name: "store", Ready: true},
		{Name: "keeper", Ready: true},
		{Name: "nexus", Ready: false, Error: "nexus publisher is required"},
		{Name: "tx_broadcaster", Ready: true},
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	health.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestHealthApplyRejectsUnknownDependencyStatus(t *testing.T) {
	health := NewIntegrationHealth()

	err := health.Apply([]diagnostics.DependencyStatus{{Name: "builder", Ready: true}})

	if err == nil {
		t.Fatalf("Apply() error = nil, want error")
	}
	if !errors.Is(err, ErrUnknownDependency) {
		t.Fatalf("Apply() error = %v, want ErrUnknownDependency", err)
	}
}

func TestHealthApplyRejectsUnknownDependencyWithoutPartialUpdate(t *testing.T) {
	health := NewIntegrationHealth()

	err := health.Apply([]diagnostics.DependencyStatus{
		{Name: "chain", Ready: true},
		{Name: "builder", Ready: true},
	})

	if err == nil {
		t.Fatalf("Apply() error = nil, want error")
	}
	if !errors.Is(err, ErrUnknownDependency) {
		t.Fatalf("Apply() error = %v, want ErrUnknownDependency", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	health.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if err := health.SetDependency("model_service", true); err != nil {
		t.Fatalf("SetDependency(model_service): %v", err)
	}
	if err := health.SetDependency("store", true); err != nil {
		t.Fatalf("SetDependency(store): %v", err)
	}
	if err := health.SetDependency("keeper", true); err != nil {
		t.Fatalf("SetDependency(keeper): %v", err)
	}
	if err := health.SetDependency("nexus", true); err != nil {
		t.Fatalf("SetDependency(nexus): %v", err)
	}
	rec = httptest.NewRecorder()
	health.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want %d; Apply partially updated chain", rec.Code, http.StatusServiceUnavailable)
	}
}

// "not ready" alone gives an operator nothing to act on, and the
// readiness-only dependencies (workload, chain_sync) do not appear in
// cortexctl diagnostics, which reports the boundaries resolved at startup.
func TestReadyzNamesTheBlockingDependencies(t *testing.T) {
	health := NewIntegrationHealth()
	for _, name := range []string{"chain", "model_service", "store", "keeper", "keeper_identity", "model_support", "nexus", "nexus_envelope_auth", "tx_broadcaster"} {
		if err := health.SetDependency(name, true); err != nil {
			t.Fatalf("SetDependency(%s): %v", name, err)
		}
	}
	// Only the workload is missing.
	rec := httptest.NewRecorder()
	health.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(rec.Body.String(), DependencyWorkload) {
		t.Fatalf("/readyz body = %q, want it to name %q", rec.Body.String(), DependencyWorkload)
	}
	if strings.Contains(rec.Body.String(), "keeper_identity") {
		t.Fatalf("/readyz body = %q, want only the unready dependencies", rec.Body.String())
	}
}

// Operators had no way to read the registry because nothing served it.
func TestMetricsRouteServesAttachedRegistry(t *testing.T) {
	health := NewHealth()
	metrics := NewMetricsRegistry()
	metrics.ObserveSnapshot(MetricsSnapshot{TaskQueueFailed: 2})
	health.AttachMetrics(metrics)

	rec := httptest.NewRecorder()
	health.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics code = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "cortex_task_queue_failed 2") {
		t.Fatalf("/metrics body = %q, want the observed queue failure count", rec.Body.String())
	}
}

// Fake mode runs no projector, so no registry is attached. The route must stay a
// valid scrape target rather than 404 differently per mode.
func TestMetricsRouteIsEmptyWithoutRegistry(t *testing.T) {
	rec := httptest.NewRecorder()
	NewHealth().Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics code = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); body != "" {
		t.Fatalf("/metrics body = %q, want empty", body)
	}
}
