package daemon

import (
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

func TestRequiredTaskLiability(t *testing.T) {
	p := func(minimum uint64, coverage, slash uint32) chainclient.WorkerLiabilityParamsSnapshot {
		return chainclient.WorkerLiabilityParamsSnapshot{MinTaskLiability: minimum, OrderCoverageBps: coverage, ObjectiveForgerySlashBps: slash}
	}
	for _, c := range []struct {
		name   string
		tokens uint64
		price  string
		ratio  uint32
		bond   uint64
		params chainclient.WorkerLiabilityParamsSnapshot
		want   uint64
	}{
		// worker_max = 1e6*3/1e6 = 3, verify_max = floor(3*5000/1e4) = 1, order_value = 4
		{"full coverage", 1_000_000, "3", 5_000, 10_000, p(1, 10_000, 0), 4},
		{"coverage rounds up", 1_000_000, "3", 5_000, 10_000, p(1, 3_333, 0), 2},
		{"slash term dominates", 1_000_000, "3", 5_000, 10_000, p(1, 10_000, 500), 500},
		{"floor dominates", 128, "10", 0, 1_000, p(10, 10_000, 0), 10},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := requiredTaskLiability(c.tokens, c.price, c.ratio, c.bond, c.params)
			if err != nil || !got.IsUint64() || got.Uint64() != c.want {
				t.Fatalf("liability = %v, %v; want %d", got, err, c.want)
			}
		})
	}
	if _, err := requiredTaskLiability(1, "x", 0, 0, p(1, 0, 0)); err == nil {
		t.Fatal("a non-decimal price_bid is refused")
	}
}
