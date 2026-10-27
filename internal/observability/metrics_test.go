package observability

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func scrape(t *testing.T, source NodeStateSource) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	NewMetricsHandler(source).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Code, rec.Body.String()
}

func TestMetricsReportNodeStateReadAtScrape(t *testing.T) {
	state := NodeState{
		Version:           "v1.2.3",
		ChainCursorHeight: 90,
		ChainTipHeight:    100,
		ChainLagBlocks:    10,
		Ready:             false,
		Dependencies:      map[string]bool{"chain": true, DependencyWorkload: false},
		TaskQueue: []TaskQueueRow{
			{Role: "WORKER", Status: "PENDING"},
			{Role: "WORKER", Status: "PENDING"},
			{Role: "VERIFIER", Status: "FAILED", AutoHalted: true},
		},
	}
	code, body := scrape(t, func(context.Context) (NodeState, error) { return state, nil })
	if code != http.StatusOK {
		t.Fatalf("/metrics code = %d, want 200; body:\n%s", code, body)
	}
	for _, want := range []string{
		`cortex_build_info{version="v1.2.3"} 1`,
		"cortex_chain_cursor_height 90",
		"cortex_chain_tip_height 100",
		"cortex_chain_sync_lag_blocks 10",
		"cortex_ready 0",
		`cortex_dependency_ready{dependency="chain"} 1`,
		`cortex_dependency_ready{dependency="workload"} 0`,
		`cortex_task_queue_rows{role="WORKER",status="PENDING"} 2`,
		`cortex_task_queue_rows{role="VERIFIER",status="FAILED"} 1`,
		`cortex_task_queue_auto_halted{role="VERIFIER"} 1`,
		// The standard runtime collectors come with the library.
		"go_goroutines ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q; body:\n%s", want, body)
		}
	}
}

// Every scrape reads the source again: a gauge must never be a value cached
// from an earlier pass.
func TestMetricsReadTheSourceOnEveryScrape(t *testing.T) {
	height := uint64(1)
	source := func(context.Context) (NodeState, error) {
		return NodeState{ChainTipHeight: height}, nil
	}
	handler := NewMetricsHandler(source)
	for _, want := range []string{"cortex_chain_tip_height 1", "cortex_chain_tip_height 2"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("/metrics missing %q; body:\n%s", want, rec.Body.String())
		}
		height++
	}
}

// A state that cannot be read fails the scrape instead of reporting zeros, so a
// broken exporter cannot pass for an idle, caught-up node.
func TestMetricsFailTheScrapeWhenStateIsUnreadable(t *testing.T) {
	code, body := scrape(t, func(context.Context) (NodeState, error) {
		return NodeState{}, errors.New("store closed")
	})
	if code != http.StatusInternalServerError {
		t.Fatalf("/metrics code = %d, want 500; body:\n%s", code, body)
	}
	if strings.Contains(body, "cortex_chain_tip_height 0") {
		t.Fatalf("/metrics reported a zero height for an unreadable state:\n%s", body)
	}
}
