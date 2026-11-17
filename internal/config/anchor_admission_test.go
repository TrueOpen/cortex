package config

import (
	"strings"
	"testing"
	"time"
)

const anchorAdmissionTestConfig = `
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
`

func TestAnchorAdmissionConfig(t *testing.T) {
	t.Run("unset is no gate", func(t *testing.T) {
		cfg, err := LoadFileWithOverrides(writeConfig(t, anchorAdmissionTestConfig), nil)
		if err != nil {
			t.Fatal(err)
		}
		if a := cfg.Dispatch.AnchorAdmission; a.Enabled() || a.File != "" || a.MaxAgeS != 0 {
			t.Fatalf("anchor admission = %+v, want unset", a)
		}
	})
	t.Run("yaml", func(t *testing.T) {
		cfg, err := LoadFileWithOverrides(writeConfig(t, anchorAdmissionTestConfig+`
dispatch:
  anchor_admission:
    file: /run/anchor/admission.json
    max_age_s: 45
`), nil)
		if err != nil {
			t.Fatal(err)
		}
		a := cfg.Dispatch.AnchorAdmission
		if !a.Enabled() || a.File != "/run/anchor/admission.json" || a.MaxAge() != 45*time.Second {
			t.Fatalf("anchor admission = %+v", a)
		}
	})
	t.Run("environment, then flag", func(t *testing.T) {
		path := writeConfig(t, anchorAdmissionTestConfig)
		t.Setenv("CORTEX_ANCHOR_ADMISSION_FILE", "/env/admission.json")
		cfg, err := LoadFileWithOverrides(path, nil)
		if err != nil {
			t.Fatal(err)
		}
		a := cfg.Dispatch.AnchorAdmission
		if a.File != "/env/admission.json" || a.MaxAge() != DefaultAnchorAdmissionMaxAgeS*time.Second {
			t.Fatalf("anchor admission = %+v, want the environment file and the default max age", a)
		}
		t.Setenv("CORTEX_ANCHOR_ADMISSION_MAX_AGE_S", "30")
		cfg, err = LoadFileWithOverrides(path, map[string]string{"anchor_admission_file": "/flag/admission.json"})
		if err != nil {
			t.Fatal(err)
		}
		if a := cfg.Dispatch.AnchorAdmission; a.File != "/flag/admission.json" || a.MaxAge() != 30*time.Second {
			t.Fatalf("anchor admission = %+v, want the flag file and max_age_s 30", a)
		}
	})
	t.Run("a max age that is not a number of seconds is refused", func(t *testing.T) {
		t.Setenv("CORTEX_ANCHOR_ADMISSION_MAX_AGE_S", "1m")
		if _, err := LoadFileWithOverrides(writeConfig(t, anchorAdmissionTestConfig), nil); err == nil || !strings.Contains(err.Error(), "CORTEX_ANCHOR_ADMISSION_MAX_AGE_S") {
			t.Fatalf("err = %v, want the variable named", err)
		}
	})
	t.Run("the slot TTL", func(t *testing.T) {
		cfg, err := LoadFileWithOverrides(writeConfig(t, anchorAdmissionTestConfig+`
dispatch:
  anchor_admission: {file: /run/a.json, reserve_ttl_s: 900}
`), nil)
		if err != nil || cfg.Dispatch.AnchorAdmission.ReserveTTL() != 15*time.Minute {
			t.Fatalf("reserve_ttl_s 900: %s, %v", cfg.Dispatch.AnchorAdmission.ReserveTTL(), err)
		}
		if got := (AnchorAdmissionConfig{File: "/run/a.json"}).ReserveTTL(); got != DefaultAnchorAdmissionReserveTTLS*time.Second {
			t.Fatalf("default slot TTL %s", got)
		}
		_, err = LoadFileWithOverrides(writeConfig(t, anchorAdmissionTestConfig+`
dispatch:
  anchor_admission: {file: /run/a.json, reserve_ttl_s: 86401}
`), nil)
		if err == nil || !strings.Contains(err.Error(), "dispatch.anchor_admission.reserve_ttl_s") {
			t.Fatalf("err = %v, want the field named", err)
		}
	})
	t.Run("a slot TTL shorter than the max age is refused", func(t *testing.T) {
		for _, block := range []string{
			"{file: /run/a.json, reserve_ttl_s: 1}",                  // against the default max age
			"{file: /run/a.json, max_age_s: 120, reserve_ttl_s: 60}", // against the one set
			"{file: /run/a.json, max_age_s: 3600}",                   // the default TTL against the one set
		} {
			_, err := LoadFileWithOverrides(writeConfig(t, anchorAdmissionTestConfig+`
dispatch:
  anchor_admission: `+block+`
`), nil)
			if err == nil || !strings.Contains(err.Error(), "dispatch.anchor_admission.reserve_ttl_s") || !strings.Contains(err.Error(), "max_age_s") {
				t.Fatalf("%s: err = %v, want reserve_ttl_s refused against max_age_s", block, err)
			}
		}
		if _, err := LoadFileWithOverrides(writeConfig(t, anchorAdmissionTestConfig+`
dispatch:
  anchor_admission: {file: /run/a.json, max_age_s: 60, reserve_ttl_s: 60}
`), nil); err != nil {
			t.Fatalf("reserve_ttl_s equal to max_age_s: %v", err)
		}
	})
	t.Run("a max age beyond a day is refused", func(t *testing.T) {
		_, err := LoadFileWithOverrides(writeConfig(t, anchorAdmissionTestConfig+`
dispatch:
  anchor_admission: {file: /run/a.json, max_age_s: 86401}
`), nil)
		if err == nil || !strings.Contains(err.Error(), "dispatch.anchor_admission.max_age_s") {
			t.Fatalf("err = %v, want the field named", err)
		}
	})
}

func TestAnchorSeedRuleConfig(t *testing.T) {
	load := func(t *testing.T, rule string) (Config, error) {
		t.Helper()
		body := anchorAdmissionTestConfig
		if rule != "" {
			body = strings.Replace(body, "  max_concurrency: 1\n", "  max_concurrency: 1\n  anchor_seed_rule: "+rule+"\n", 1)
		}
		return LoadFileWithOverrides(writeConfig(t, body), nil)
	}
	cfg, err := load(t, "")
	if err != nil || cfg.ModelManagement.AnchorSeedRule != "" {
		t.Fatalf("unset: rule %q, err %v, want the binding off", cfg.ModelManagement.AnchorSeedRule, err)
	}
	cfg, err = load(t, "seed-v2")
	if err != nil || cfg.ModelManagement.AnchorSeedRule != AnchorSeedRuleV2 {
		t.Fatalf("seed-v2: rule %q, err %v", cfg.ModelManagement.AnchorSeedRule, err)
	}
	if _, err = load(t, "seed-v1"); err == nil || !strings.Contains(err.Error(), "model_management.anchor_seed_rule") {
		t.Fatalf("seed-v1: err = %v, want the field named", err)
	}
}
