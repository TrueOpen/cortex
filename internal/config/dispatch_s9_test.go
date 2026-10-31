package config

import (
	"strings"
	"testing"
)

const (
	s9BuilderA = "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"
	s9BuilderB = "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man"
	s9Model    = "c2e5065e9dda862ec6970d2c54765ad9414f22fe7ae82cf94dae6825828129c1"
)

// s9Dispatch is a complete dispatch block for validRealConfig's profile.
func s9Dispatch() DispatchConfig {
	return DispatchConfig{
		Builders:                  []string{s9BuilderA},
		EvidenceRetentionBlocks:   201_600,
		Handraise:                 HandraiseConfig{HeartbeatMS: 10_000, TTLMS: 30_000, MinChangeIntervalMS: 500},
		MinPriceBid:               map[string]uint64{MinPriceBidKey(s9Model, 1): 1_000},
		Stream:                    DispatchStreamConfig{KeepaliveMS: 15_000, MaxMissed: 3},
		ReceiptRescueMarginBlocks: 5,
		Omission:                  DispatchOmissionConfig{RosterGraceBlocks: 20, ChallengeMarginBlocks: 5},
	}
}

func requireProblem(t *testing.T, cfg Config, want string) {
	t.Helper()
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Validate() = %v, want a problem containing %q", err, want)
	}
}

func TestDispatchS9RealModeRequiresTheBlock(t *testing.T) {
	cfg := validRealConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the complete real config must validate: %v", err)
	}
	cfg.Dispatch = DispatchConfig{}
	requireProblem(t, cfg, "dispatch.builders must list at least one Builder operator in real mode")
}

func TestDispatchS9EverySettingIsRequired(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*Config)
		want   string
	}{
		"timings":         {func(c *Config) { c.Dispatch.Handraise, c.Dispatch.EvidenceRetentionBlocks = HandraiseConfig{}, 0 }, "dispatch.evidence_retention_blocks and dispatch.handraise"},
		"keepalive":       {func(c *Config) { c.Dispatch.Stream.KeepaliveMS = 0 }, "dispatch.stream.keepalive_ms is required"},
		"max missed":      {func(c *Config) { c.Dispatch.Stream.MaxMissed = 0 }, "dispatch.stream.max_missed must be at least 1"},
		"handler timeout": {func(c *Config) { c.Dispatch.Stream.HandlerTimeoutMS = 15_000 }, "dispatch.stream.handler_timeout_ms must be below dispatch.stream.keepalive_ms"},
		"backoff":         {func(c *Config) { c.Dispatch.Stream.ReconnectMinMS, c.Dispatch.Stream.ReconnectMaxMS = 500, 100 }, "dispatch.stream.reconnect_min_ms must not exceed"},
		"rescue":          {func(c *Config) { c.Dispatch.ReceiptRescueMarginBlocks = 0 }, "dispatch.receipt_rescue_margin_blocks is required with tx.enabled"},
		"omission":        {func(c *Config) { c.Dispatch.Omission.RosterGraceBlocks = 0 }, "dispatch.omission.roster_grace_blocks and dispatch.omission.challenge_margin_blocks are required"},
		"capacity":        {func(c *Config) { c.ModelManagement.MaxConcurrency = 0 }, "model_management.max_concurrency must be greater than zero when dispatch.builders is set"},
		"price":           {func(c *Config) { c.Dispatch.MinPriceBid = nil }, `dispatch.min_price_bid["` + s9Model + `@1"] is required in real mode`},
		"address":         {func(c *Config) { c.Dispatch.Builders = []string{"trueopen1notabech32"} }, `dispatch.builders entry "trueopen1notabech32" is not a bech32 operator address`},
		"duplicate":       {func(c *Config) { c.Dispatch.RetiringBuilders = []string{s9BuilderA} }, "dispatch.retiring_builders lists " + s9BuilderA + ", already in dispatch.builders"},
		"all retiring":    {func(c *Config) { c.Dispatch.Builders, c.Dispatch.RetiringBuilders = nil, []string{s9BuilderB} }, "dispatch.builders must keep at least one Builder that is not being retired"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validRealConfig()
			tc.mutate(&cfg)
			requireProblem(t, cfg, tc.want)
		})
	}
}

func TestDispatchS9IntegrationModeMayOmitTheBlockAndThePrices(t *testing.T) {
	cfg := validRealConfig()
	cfg.Mode = ModeIntegration
	cfg.Dispatch = DispatchConfig{}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("integration without dispatch.builders runs no dispatch plane: %v", err)
	}
	cfg.Dispatch = s9Dispatch()
	cfg.Dispatch.MinPriceBid = nil
	if err := cfg.Validate(); err != nil {
		t.Fatalf("integration may leave profiles unpriced (H4 drops them): %v", err)
	}
}

func TestDispatchS9StreamDurations(t *testing.T) {
	s := DispatchStreamConfig{KeepaliveMS: 15_000, MaxMissed: 3}
	if s.Keepalive().Milliseconds() != 15_000 || s.HandlerTimeout().Milliseconds() != 7_500 {
		t.Fatalf("keepalive %v handler %v", s.Keepalive(), s.HandlerTimeout())
	}
	s.HandlerTimeoutMS = 2_000
	if s.HandlerTimeout().Milliseconds() != 2_000 {
		t.Fatal("an explicit handler timeout wins")
	}
	if got := (DispatchConfig{Builders: []string{s9BuilderB}, RetiringBuilders: []string{s9BuilderA}}).AllBuilders(); len(got) != 2 || got[0] != s9BuilderA {
		t.Fatalf("AllBuilders = %v, want both, sorted", got)
	}
}

func TestDispatchS9BuildersEnvironmentOverride(t *testing.T) {
	path := writeConfig(t, `
mode: fake
chain_id: cortex-local
admin:
  uds_path: /tmp/cortex/admin.sock
node:
  rpc_endpoint: http://127.0.0.1:26657
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/cortex.kv
signer:
  uri: file:///tmp/cortex/key.json
model_management:
  max_concurrency: 1
dispatch:
  evidence_retention_blocks: 201600
  handraise: {heartbeat_ms: 10000, ttl_ms: 30000, min_change_interval_ms: 500}
  stream: {keepalive_ms: 15000, max_missed: 3}
`)
	t.Setenv("CORTEX_DISPATCH_BUILDERS", s9BuilderA+", "+s9BuilderB)
	cfg, err := LoadFileWithOverrides(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Dispatch.Builders) != 2 || cfg.Dispatch.Builders[1] != s9BuilderB {
		t.Fatalf("builders = %v", cfg.Dispatch.Builders)
	}
}
