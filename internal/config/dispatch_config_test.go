package config

import (
	"math"
	"strings"
	"testing"
)

func TestValidateDispatchHeartbeatMustBeBelowTTL(t *testing.T) {
	cfg := validConfig()
	cfg.Dispatch = DispatchConfig{
		EvidenceRetentionBlocks: 200_000,
		Handraise:               HandraiseConfig{HeartbeatMS: 30_000, TTLMS: 30_000, MinChangeIntervalMS: 500},
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "dispatch.handraise.heartbeat_ms must be less than dispatch.handraise.ttl_ms") {
		t.Fatalf("Validate() error = %v, want heartbeat/ttl error", err)
	}
	cfg.Dispatch.Handraise.TTLMS = 30_001
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if cfg.Dispatch.Handraise.RootHistory != 0 {
		t.Fatal("Validate must not fill defaults; defaults() does")
	}
}

func TestDispatchRootHistoryDefaultsOutsideValidate(t *testing.T) {
	if got := defaults().Dispatch.Handraise.RootHistory; got != DefaultHandraiseRootHistory {
		t.Fatalf("defaults() root_history = %d, want %d", got, DefaultHandraiseRootHistory)
	}
	cfg := validConfig()
	for _, n := range []int{-1, 4097} {
		cfg.Dispatch.Handraise.RootHistory = n
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "dispatch.handraise.root_history must be 0 (default) or 1–4096") {
			t.Fatalf("root_history %d: %v", n, err)
		}
	}
}

func TestValidateDispatchMillisecondsFitADuration(t *testing.T) {
	cfg := validConfig()
	cfg.Dispatch = DispatchConfig{
		EvidenceRetentionBlocks: 1,
		Handraise:               HandraiseConfig{HeartbeatMS: 1, TTLMS: math.MaxUint64, MinChangeIntervalMS: math.MaxUint64 / 2},
	}
	err := cfg.Validate()
	for _, f := range []string{"dispatch.handraise.ttl_ms", "dispatch.handraise.min_change_interval_ms"} {
		if err == nil || !strings.Contains(err.Error(), f+" is too large") {
			t.Fatalf("Validate() error = %v, want %s too large", err, f)
		}
	}
}

func TestValidateDispatchTimingsAreAllOrNothing(t *testing.T) {
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("outside real mode an absent dispatch block is valid: %v", err)
	}
	cfg.Dispatch.Handraise.HeartbeatMS = 10_000
	err := cfg.Validate()
	for _, field := range []string{"dispatch.handraise.ttl_ms", "dispatch.handraise.min_change_interval_ms", "dispatch.evidence_retention_blocks"} {
		if err == nil || !strings.Contains(err.Error(), field+" is required") {
			t.Fatalf("Validate() error = %v, want %s required", err, field)
		}
	}
}

func TestValidateDispatchMinPriceBid(t *testing.T) {
	model := strings.Repeat("ab", 32)
	cfg := validConfig()
	cfg.Dispatch.MinPriceBid = map[string]uint64{
		MinPriceBidKey(model, 1): 10,
		model + "@01":            10,
		"notamodel@1":            10,
		MinPriceBidKey(model, 2): 0,
	}
	err := cfg.Validate()
	for _, want := range []string{
		`dispatch.min_price_bid key "` + model + `@01"`,
		`dispatch.min_price_bid key "notamodel@1"`,
		`dispatch.min_price_bid["` + model + `@2"] must be greater than zero`,
	} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("Validate() error = %v, want %q", err, want)
		}
	}
	if strings.Contains(err.Error(), `key "`+model+`@1"`) {
		t.Fatal("a canonical key must be accepted")
	}
}

func TestLoadFileParsesDispatchSection(t *testing.T) {
	model := strings.Repeat("ab", 32)
	path := writeConfig(t, `
chain_id: trueopen-devnet-1
admin:
  uds_path: /tmp/cortexd.sock
model_management:
  endpoint: 127.0.0.1:9090
node:
  rpc_endpoint: http://127.0.0.1:26657
  rest_endpoint: http://127.0.0.1:1317
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/cortex.kv
signer:
  uri: file:///tmp/cortex/signer.key
dispatch:
  evidence_retention_blocks: 200000
  handraise:
    heartbeat_ms: 10000
    ttl_ms: 30000
    min_change_interval_ms: 500
  min_price_bid:
    "`+model+`@1": 25
`)
	cfg, err := LoadFileWithOverrides(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := cfg.Dispatch
	if d.Handraise.RootHistory != DefaultHandraiseRootHistory {
		t.Fatalf("a loaded config gets the root_history default, got %d", d.Handraise.RootHistory)
	}
	if d.EvidenceRetentionBlocks != 200_000 || d.Handraise.HeartbeatMS != 10_000 || d.Handraise.TTLMS != 30_000 ||
		d.Handraise.MinChangeIntervalMS != 500 || d.MinPriceBid[MinPriceBidKey(model, 1)] != 25 {
		t.Fatalf("Dispatch = %+v", d)
	}
}
