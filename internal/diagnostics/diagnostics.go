package diagnostics

type DependencyStatus struct {
	Name       string `json:"name"`
	Endpoint   string `json:"endpoint,omitempty"`
	Configured bool   `json:"configured"`
	Ready      bool   `json:"ready"`
	Error      string `json:"error,omitempty"`
	// Optional marks a boundary whose absence does not stop this node from
	// serving, so a reader can tell "broken" from "not used here". The workload
	// gate has always made this distinction for tx_broadcaster; the record did
	// not, which is how a dependency no enabled path needs produced 1186
	// consecutive not-ready log lines that operators had to learn to ignore.
	//
	// It is a property of the deployment, never of the probe result: a
	// dependency does not become optional by failing.
	Optional bool `json:"optional,omitempty"`
}

type Diagnostics struct {
	Mode                 string `json:"mode"`
	ModelTransport       string `json:"model_transport"`
	KeeperEndpoint       string `json:"keeper_endpoint,omitempty"`
	NexusIngress         string `json:"nexus_ingress,omitempty"`
	NexusBuilderOperator string `json:"nexus_builder_operator,omitempty"`
	// ChainCursorHeight and ChainTipHeight make Keeper event consumption
	// legible without opening the compact store. Lag alone is not enough: it is 0 whenever
	// the cursor is at or above the tip, so a store left behind by a chain reset
	// -- cursor far above the tip -- reads exactly like a caught-up node.
	ChainCursorHeight uint64 `json:"chain_cursor_height,omitempty"`
	ChainTipHeight    uint64 `json:"chain_tip_height,omitempty"`
	ChainLagBlocks    uint64 `json:"chain_lag_blocks,omitempty"`
	// ChainCursorRefusal explains why event consumption refused to advance.
	ChainCursorRefusal string             `json:"chain_cursor_refusal,omitempty"`
	SecurityWarnings   []string           `json:"security_warnings,omitempty"`
	Dependencies       []DependencyStatus `json:"dependencies"`
}

func (d Diagnostics) Dependency(name string) (DependencyStatus, bool) {
	for _, status := range d.Dependencies {
		if status.Name == name {
			return status, true
		}
	}
	return DependencyStatus{}, false
}
