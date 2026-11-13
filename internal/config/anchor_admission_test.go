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
			t.Fatalf("anchor admission = %+v, want the environment file and the 90 s default", a)
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
