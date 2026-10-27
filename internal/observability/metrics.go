package observability

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NodeState is what /metrics reports about the node. It is read from the
// authoritative local state -- the diagnostics snapshot, the readiness
// dependencies and the task queue in the store -- on every scrape, never cached,
// so a gauge cannot outlive the state it describes.
type NodeState struct {
	Version string
	// Both heights are reported, not just the lag: the lag is 0 whenever the
	// cursor is at or above the tip, so a store left behind by a chain reset
	// would otherwise read exactly like a caught-up node.
	ChainCursorHeight uint64
	ChainTipHeight    uint64
	ChainLagBlocks    uint64
	Ready             bool
	Dependencies      map[string]bool
	TaskQueue         []TaskQueueRow
}

// TaskQueueRow is one active task queue row, as cortexctl task list shows it.
type TaskQueueRow struct {
	Role, Status string
	AutoHalted   bool
}

// NodeStateSource reads the current NodeState.
type NodeStateSource func(context.Context) (NodeState, error)

// scrapeTimeout bounds one read of the node state. The task queue read takes
// the task runner lock, so a slow store must not hold a scrape open.
const scrapeTimeout = 5 * time.Second

var (
	buildInfoDesc       = prometheus.NewDesc("cortex_build_info", "Version of the running cortexd binary; always 1.", []string{"version"}, nil)
	chainCursorDesc     = prometheus.NewDesc("cortex_chain_cursor_height", "Last chain height whose Keeper events this node has consumed.", nil, nil)
	chainTipDesc        = prometheus.NewDesc("cortex_chain_tip_height", "Latest chain height this node has observed.", nil, nil)
	chainLagDesc        = prometheus.NewDesc("cortex_chain_sync_lag_blocks", "Blocks between the chain tip and the event cursor; 0 when the cursor is at or above the tip.", nil, nil)
	readyDesc           = prometheus.NewDesc("cortex_ready", "1 when /readyz answers ready, 0 otherwise.", nil, nil)
	dependencyReadyDesc = prometheus.NewDesc("cortex_dependency_ready", "Readiness of each dependency /readyz gates on.", []string{"dependency"}, nil)
	taskQueueRowsDesc   = prometheus.NewDesc("cortex_task_queue_rows", "Active task queue rows by role and status.", []string{"role", "status"}, nil)
	autoHaltedDesc      = prometheus.NewDesc("cortex_task_queue_auto_halted", "Active task queue rows the scheduler has deliberately halted, by role.", []string{"role"}, nil)
	scrapeErrorDesc     = prometheus.NewDesc("cortex_node_state_scrape_error", "The node state could not be read.", nil, nil)
)

// NewMetricsHandler serves the node state together with the standard Go runtime
// and process collectors in the Prometheus exposition format. When the state
// cannot be read the scrape fails with 500 instead of reporting zeros, so a
// broken exporter cannot pass for an idle, caught-up node.
func NewMetricsHandler(source NodeStateSource) http.Handler {
	registry := prometheus.NewRegistry()
	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		nodeCollector{source: source},
	)
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{ErrorHandling: promhttp.HTTPErrorOnError})
}

type nodeCollector struct {
	source NodeStateSource
}

func (c nodeCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range []*prometheus.Desc{buildInfoDesc, chainCursorDesc, chainTipDesc, chainLagDesc, readyDesc, dependencyReadyDesc, taskQueueRowsDesc, autoHaltedDesc, scrapeErrorDesc} {
		ch <- desc
	}
}

func (c nodeCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), scrapeTimeout)
	defer cancel()
	state, err := c.source(ctx)
	if err != nil {
		ch <- prometheus.NewInvalidMetric(scrapeErrorDesc, err)
		return
	}
	gauge := func(desc *prometheus.Desc, value float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, value, labels...)
	}
	gauge(buildInfoDesc, 1, state.Version)
	gauge(chainCursorDesc, float64(state.ChainCursorHeight))
	gauge(chainTipDesc, float64(state.ChainTipHeight))
	gauge(chainLagDesc, float64(state.ChainLagBlocks))
	gauge(readyDesc, boolGauge(state.Ready))
	for name, ready := range state.Dependencies {
		gauge(dependencyReadyDesc, boolGauge(ready), name)
	}

	rows := map[[2]string]int{}
	halted := map[string]int{}
	for _, row := range state.TaskQueue {
		rows[[2]string{row.Role, row.Status}]++
		if row.AutoHalted {
			halted[row.Role]++
		}
	}
	for key, count := range rows {
		gauge(taskQueueRowsDesc, float64(count), key[0], key[1])
	}
	for role, count := range halted {
		gauge(autoHaltedDesc, float64(count), role)
	}
}

func boolGauge(value bool) float64 {
	if value {
		return 1
	}
	return 0
}
