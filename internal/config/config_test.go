package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadFileMinimalConfig(t *testing.T) {
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
`)

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}

	if cfg.ChainID != "trueopen-devnet-1" {
		t.Fatalf("ChainID = %q", cfg.ChainID)
	}
	if cfg.Admin.UDSPath != "/tmp/cortexd.sock" {
		t.Fatalf("Admin.UDSPath = %q", cfg.Admin.UDSPath)
	}
	if cfg.ModelManagement.Endpoint != "127.0.0.1:9090" {
		t.Fatalf("ModelManagement.Endpoint = %q", cfg.ModelManagement.Endpoint)
	}
	if cfg.ChallengeVerifier.Enabled {
		t.Fatalf("ChallengeVerifier.Enabled = true, want false by default")
	}
	if cfg.Tx.FeeDenom != "uusdc" || cfg.Tx.Enabled {
		t.Fatalf("default fee configuration = %+v; want uusdc without enabling transactions", cfg.Tx)
	}
}

func TestValidateRejectsEmptyChainID(t *testing.T) {
	cfg := validConfig()
	cfg.ChainID = ""

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "chain_id") {
		t.Fatalf("Validate() error = %v, want chain_id error", err)
	}
}

func TestLoadFileRejectsLegacySQLitePath(t *testing.T) {
	path := writeConfig(t, `
store:
  sqlite_path: /tmp/cortex/cortex.kv
`)

	_, err := LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), `unknown store field "sqlite_path"`) {
		t.Fatalf("LoadFile() error = %v, want clean-cutover rejection of store.sqlite_path", err)
	}
}

func TestLoadFileRejectsInterimKVPathAlias(t *testing.T) {
	path := writeConfig(t, `
store:
  kv_path: /tmp/cortex/legacy.kv
`)
	_, err := LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), `unknown store field "kv_path"`) {
		t.Fatalf("LoadFile() error = %v, want clean-cutover rejection of store.kv_path", err)
	}
}

func TestStorePathEnvironmentOverride(t *testing.T) {
	path := writeConfig(t, `
chain_id: trueopen-devnet-1
admin:
  uds_path: /tmp/cortexd.sock
node:
  rpc_endpoint: http://127.0.0.1:26657
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/from-yaml.kv
signer:
  uri: file:///tmp/cortex/signer.key
`)
	t.Setenv("CORTEX_STORE_PATH", "/tmp/cortex/from-env.kv")

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if cfg.Store.Path != "/tmp/cortex/from-env.kv" {
		t.Fatalf("Store.Path = %q, want environment override", cfg.Store.Path)
	}
}

func TestLegacyStoreKVPathEnvironmentVariableIsNotAnAlias(t *testing.T) {
	path := writeConfig(t, `
chain_id: trueopen-devnet-1
admin:
  uds_path: /tmp/cortexd.sock
node:
  rpc_endpoint: http://127.0.0.1:26657
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/configured-store
signer:
  uri: file:///tmp/cortex/signer.key
`)
	t.Setenv("CORTEX_STORE_KV_PATH", "/tmp/cortex/legacy-alias")
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Store.Path != "/tmp/cortex/configured-store" {
		t.Fatalf("legacy env alias changed Store.Path to %q", cfg.Store.Path)
	}
}

func TestValidateAllowsFakeModelManagementWithoutEndpoint(t *testing.T) {
	cfg := validConfig()
	cfg.ModelManagement.Endpoint = ""

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateAllowsLocalModelManagementWithoutEndpoint(t *testing.T) {
	cfg := validConfig()
	cfg.ModelManagement.Transport = " LOCAL "
	cfg.ModelManagement.Endpoint = ""
	cfg.ModelManagement.MaxConcurrency = 4

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

// Handraise capacity comes from max_concurrency, and vLLM publishes no
// equivalent to probe, so an unset value has to be rejected at startup rather
// than surface later as "model service capacity is invalid for handraise".
func TestValidateLocalModelManagementRequiresMaxConcurrency(t *testing.T) {
	cfg := validConfig()
	cfg.ModelManagement.Transport = "local"
	cfg.ModelManagement.Endpoint = ""

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "model_management.max_concurrency") {
		t.Fatalf("Validate() error = %v, want model_management.max_concurrency error", err)
	}
}

func TestValidateGRPCModelManagementRequiresEndpoint(t *testing.T) {
	cfg := validConfig()
	cfg.ModelManagement.Transport = "grpc"
	cfg.ModelManagement.Endpoint = ""

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "model_management.endpoint") {
		t.Fatalf("Validate() error = %v, want model_management.endpoint error", err)
	}
}

func TestLoadFileDefaultsChallengeVerifierToFalse(t *testing.T) {
	path := writeConfig(t, `
chain_id: trueopen-devnet-1
admin:
  uds_path: /tmp/cortexd.sock
model_management:
  endpoint: 127.0.0.1:9090
node:
  rpc_endpoint: http://127.0.0.1:26657
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/cortex.kv
signer:
  uri: file:///tmp/cortex/signer.key
`)

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if cfg.ChallengeVerifier.Enabled {
		t.Fatalf("ChallengeVerifier.Enabled = true, want false")
	}
}

func TestLoadFileParsesChallengeVerifierEnabledTrue(t *testing.T) {
	path := writeConfig(t, `
chain_id: trueopen-devnet-1
admin:
  uds_path: /tmp/cortexd.sock
model_management:
  endpoint: 127.0.0.1:9090
node:
  rpc_endpoint: http://127.0.0.1:26657
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/cortex.kv
signer:
  uri: file:///tmp/cortex/signer.key
challenge_verifier:
  enabled: true
`)

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if !cfg.ChallengeVerifier.Enabled {
		t.Fatalf("ChallengeVerifier.Enabled = false, want true")
	}
}

func TestLoadFileRejectsInvalidChallengeVerifierBoolean(t *testing.T) {
	path := writeConfig(t, `
chain_id: trueopen-devnet-1
admin:
  uds_path: /tmp/cortexd.sock
model_management:
  endpoint: 127.0.0.1:9090
node:
  rpc_endpoint: http://127.0.0.1:26657
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/cortex.kv
signer:
  uri: file:///tmp/cortex/signer.key
challenge_verifier:
  enabled: ture
`)

	_, err := LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), "challenge_verifier.enabled") {
		t.Fatalf("LoadFile() error = %v, want challenge_verifier.enabled error", err)
	}
}

func TestLoadFilePreservesHashInsideQuotedValue(t *testing.T) {
	path := writeConfig(t, `
chain_id: trueopen-devnet-1
admin:
  uds_path: /tmp/cortexd.sock
model_management:
  endpoint: 127.0.0.1:9090
node:
  rpc_endpoint: http://127.0.0.1:26657
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/cortex.kv
signer:
  uri: "file:///tmp/cortex/signer.key#v1"
`)

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if cfg.Signer.URI != "file:///tmp/cortex/signer.key#v1" {
		t.Fatalf("Signer.URI = %q", cfg.Signer.URI)
	}
}

func TestLoadFileRejectsUnknownField(t *testing.T) {
	path := writeConfig(t, `
chain_id: trueopen-devnet-1
unknown_setting: true
admin:
  uds_path: /tmp/cortexd.sock
model_management:
  transport: fake
node:
  rpc_endpoint: http://127.0.0.1:26657
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/cortex.kv
signer:
  uri: file:///tmp/cortex/signer.key
`)

	_, err := LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), `unknown field "unknown_setting"`) {
		t.Fatalf("LoadFile() error = %v, want strict unknown-field rejection", err)
	}
}

func TestPayloadKeyConfigCutoverRejectsRemovedYAML(t *testing.T) {
	removedKey := "payload_" + "key_store"
	path := writeConfig(t, fmt.Sprintf(`
chain_id: trueopen-devnet-1
%s:
  uri: file:///run/secrets/payload-keys
admin:
  uds_path: /tmp/cortexd.sock
model_management:
  transport: fake
node:
  rpc_endpoint: http://127.0.0.1:26657
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/cortex.kv
signer:
  uri: file:///tmp/cortex/signer.key
`, removedKey))

	_, err := LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), `unknown field "`+removedKey+`"`) {
		t.Fatalf("LoadFile() error = %v, want removed %s to fail strict YAML decoding", err, removedKey)
	}
}

func TestPayloadKeyConfigCutoverOmitsDeploymentEnvironment(t *testing.T) {
	removedEnvironment := "CORTEX_PAYLOAD_" + "KEY_STORE_URI"
	if key, ok := deploymentEnvironment[removedEnvironment]; ok {
		t.Fatalf("%s still maps to %q", removedEnvironment, key)
	}
	removedOverride := "payload_key_" + "store_uri"
	for _, key := range DeploymentOverrideKeys() {
		if key == removedOverride {
			t.Fatalf("%s is still deployment-configurable", removedOverride)
		}
	}
}

// A setDeploymentValue case that no environment key routes to is dead code: the
// setting looks configurable in the source and is unreachable from cortexd. The
// env->flag direction is already guarded in cmd/cortexd; this pins the other one
// for the output bound, whose case shipped unreachable.
func TestMaxOutputBytesIsDeploymentConfigurable(t *testing.T) {
	const key = "task_max_output_bytes"
	if got := deploymentEnvironment["CORTEX_TASK_MAX_OUTPUT_BYTES"]; got != key {
		t.Fatalf("CORTEX_TASK_MAX_OUTPUT_BYTES maps to %q, want %q", got, key)
	}
	cfg := defaults()
	if err := setDeploymentValue(&cfg, key, "1048576"); err != nil {
		t.Fatalf("setDeploymentValue(%s) error = %v", key, err)
	}
	if cfg.TaskExecution.MaxOutputBytes != 1048576 {
		t.Fatalf("MaxOutputBytes = %d, want the override applied", cfg.TaskExecution.MaxOutputBytes)
	}
}

func TestLoadFileParsesYAMLBlockList(t *testing.T) {
	path := writeConfig(t, `
chain_id: trueopen-devnet-1
admin:
  uds_path: /tmp/cortexd.sock
model_management:
  transport: fake
node:
  rpc_endpoint: http://127.0.0.1:26657
nexus:
  subscribe_models:
    - 6d120a31a3858346e04517111eb3e1e03c4a5a9757b12cd3d2acb27c6bc9d6a2
    - embed-small
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/cortex.kv
signer:
  uri: file:///tmp/cortex/signer.key
`)

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if got := strings.Join(cfg.Nexus.SubscribeModels, ","); got != "6d120a31a3858346e04517111eb3e1e03c4a5a9757b12cd3d2acb27c6bc9d6a2,embed-small" {
		t.Fatalf("subscribe models = %q", got)
	}
}

func TestLoadFilePrecedenceDefaultsYAMLEnvFlags(t *testing.T) {
	path := writeConfig(t, `
chain_id: from-yaml
admin:
  uds_path: /tmp/cortexd.sock
model_management:
  transport: fake
node:
  rpc_endpoint: http://127.0.0.1:26657
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/cortex.kv
signer:
  uri: file:///tmp/cortex/signer.key
health: {}
`)
	t.Setenv("CORTEX_CHAIN_ID", "from-env")
	t.Setenv("CORTEX_HEALTH_BIND", "127.0.0.1:9091")

	cfg, err := LoadFileWithOverrides(path, map[string]string{"chain_id": "from-flag"})
	if err != nil {
		t.Fatalf("LoadFileWithOverrides() error = %v", err)
	}
	if cfg.ChainID != "from-flag" {
		t.Fatalf("chain ID = %q, want flag override", cfg.ChainID)
	}
	if cfg.Health.Bind != "127.0.0.1:9091" {
		t.Fatalf("health bind = %q, want environment override", cfg.Health.Bind)
	}
	if cfg.Keeper.PollIntervalMS != 1000 {
		t.Fatalf("keeper poll interval = %d, want default", cfg.Keeper.PollIntervalMS)
	}
}

func TestLoadFileNexusEnvelopeAuthModeEnvAndFlagPrecedence(t *testing.T) {
	path := writeConfig(t, `
chain_id: trueopen-devnet-1
admin:
  uds_path: /tmp/cortexd.sock
model_management:
  transport: fake
node:
  rpc_endpoint: http://127.0.0.1:26657
nexus:
  auth_token_file: /run/secrets/nexus.token
  envelope_auth_mode: strict
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/cortex.kv
signer:
  uri: file:///tmp/cortex/signer.key
`)
	t.Setenv("CORTEX_NEXUS_ENVELOPE_AUTH_MODE", NexusEnvelopeAuthTrustedDev)

	fromEnv, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if !fromEnv.Nexus.TrustedNATSDev() {
		t.Fatalf("environment EnvelopeAuthMode = %q, want trusted_nats_dev", fromEnv.Nexus.EnvelopeAuthMode)
	}

	fromFlag, err := LoadFileWithOverrides(path, map[string]string{"nexus_envelope_auth_mode": NexusEnvelopeAuthStrict})
	if err != nil {
		t.Fatalf("LoadFileWithOverrides() error = %v", err)
	}
	if fromFlag.Nexus.EnvelopeAuthMode != NexusEnvelopeAuthStrict || fromFlag.Nexus.TrustedNATSDev() {
		t.Fatalf("flag EnvelopeAuthMode = %q, want strict", fromFlag.Nexus.EnvelopeAuthMode)
	}
}

// Absent envelope bounds resolve to the deployment constants both sides of the
// bus agree on, so a hand-written config does not have to restate them.
func TestValidateDefaultsNexusEnvelopeBounds(t *testing.T) {
	cfg := validConfig()

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if got := cfg.Nexus.EnvelopeTTL(); got != 30*time.Second {
		t.Fatalf("EnvelopeTTL() = %v, want 30s", got)
	}
	if got := cfg.Nexus.EnvelopeClockSkew(); got != 2*time.Second {
		t.Fatalf("EnvelopeClockSkew() = %v, want 2s", got)
	}
}

// An operator who writes zero is asking for no clock tolerance at all. Reading
// that back as "unset" would widen a freshness window against an explicit
// instruction.
func TestValidateKeepsExplicitZeroNexusEnvelopeClockSkew(t *testing.T) {
	cfg := validConfig()
	cfg.Nexus.EnvelopeClockSkewMS = envelopeBoundMS(0)

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if got := cfg.Nexus.EnvelopeClockSkew(); got != 0 {
		t.Fatalf("EnvelopeClockSkew() = %v, want no tolerance", got)
	}
}

// A short TTL on its own is legal: the unwritten skew derives from the TTL
// instead of failing the config against a key absent from the operator's YAML.
func TestValidateDerivesNexusEnvelopeClockSkewFromShortTTL(t *testing.T) {
	cfg := validConfig()
	cfg.Nexus.EnvelopeClockSkewMS = nil
	cfg.Nexus.EnvelopeTTLMS = envelopeBoundMS(1000)

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	ttl, skew := cfg.Nexus.EnvelopeTTL(), cfg.Nexus.EnvelopeClockSkew()
	if ttl != time.Second {
		t.Fatalf("EnvelopeTTL() = %v, want 1s", ttl)
	}
	if skew <= 0 || skew >= ttl {
		t.Fatalf("EnvelopeClockSkew() = %v, want inside (0, %v)", skew, ttl)
	}
}

// Where the operator did write both, a skew reaching the TTL would accept an
// envelope already expired by its own stamps, so it stays a hard error. An
// explicit skew is judged against the effective TTL, defaulted or not.
func TestValidateRejectsNexusEnvelopeClockSkewAtOrAboveTTL(t *testing.T) {
	tests := map[string]struct {
		ttlMS  *uint64
		skewMS uint64
	}{
		"skew equals ttl":            {ttlMS: envelopeBoundMS(5000), skewMS: 5000},
		"skew above ttl":             {ttlMS: envelopeBoundMS(5000), skewMS: 5001},
		"skew reaches defaulted ttl": {ttlMS: nil, skewMS: defaultEnvelopeTTLMS},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Nexus.EnvelopeTTLMS = test.ttlMS
			cfg.Nexus.EnvelopeClockSkewMS = envelopeBoundMS(test.skewMS)

			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), "nexus.envelope_clock_skew_ms must be less than nexus.envelope_ttl_ms") {
				t.Fatalf("Validate() error = %v, want skew below TTL error", err)
			}
		})
	}
}

// A zero TTL expires every envelope at the instant it is stamped, so nothing
// on the bus would ever be fresh.
func TestValidateRejectsZeroNexusEnvelopeTTL(t *testing.T) {
	cfg := validConfig()
	cfg.Nexus.EnvelopeTTLMS = envelopeBoundMS(0)

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "nexus.envelope_ttl_ms must be greater than zero") {
		t.Fatalf("Validate() error = %v, want zero TTL error", err)
	}
}

// Milliseconds beyond the ceiling are not a freshness window, and a large
// enough count wraps when converted to a time.Duration: it comes back out
// tiny, inverting the skew-below-TTL ordering validation exists to enforce.
func TestValidateRejectsNexusEnvelopeBoundsAboveCeiling(t *testing.T) {
	wrappingMS := uint64(1152921504606846977)
	if wrapped := time.Duration(wrappingMS) * time.Millisecond; wrapped >= time.Minute {
		t.Fatalf("%d ms no longer overflows time.Duration (= %v); pick a value that does", wrappingMS, wrapped)
	}

	for _, boundMS := range []uint64{maxEnvelopeBoundMS + 1, wrappingMS} {
		t.Run(fmt.Sprintf("ttl %d", boundMS), func(t *testing.T) {
			cfg := validConfig()
			cfg.Nexus.EnvelopeTTLMS = envelopeBoundMS(boundMS)

			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), "nexus.envelope_ttl_ms must not exceed") {
				t.Fatalf("Validate() error = %v, want TTL ceiling error", err)
			}
		})
		t.Run(fmt.Sprintf("clock skew %d", boundMS), func(t *testing.T) {
			cfg := validConfig()
			cfg.Nexus.EnvelopeClockSkewMS = envelopeBoundMS(boundMS)

			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), "nexus.envelope_clock_skew_ms must not exceed") {
				t.Fatalf("Validate() error = %v, want clock skew ceiling error", err)
			}
		})
	}
}

// A bound that cannot be parsed must stop startup naming the variable that
// carried it, not fall back to a default the operator did not ask for.
func TestLoadFileRejectsMalformedNexusEnvelopeTTLEnv(t *testing.T) {
	path := writeConfig(t, `
chain_id: trueopen-devnet-1
admin:
  uds_path: /tmp/cortexd.sock
model_management:
  transport: fake
node:
  rpc_endpoint: http://127.0.0.1:26657
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/cortex.kv
signer:
  uri: file:///tmp/cortex/signer.key
`)
	t.Setenv("CORTEX_NEXUS_ENVELOPE_TTL_MS", "not-a-number")

	_, err := LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), "CORTEX_NEXUS_ENVELOPE_TTL_MS") || !strings.Contains(err.Error(), "unsigned integer") {
		t.Fatalf("LoadFile() error = %v, want environment parse error", err)
	}
}

func TestLoadFileNexusEnvelopeBoundsEnvAndFlagPrecedence(t *testing.T) {
	path := writeConfig(t, `
chain_id: trueopen-devnet-1
admin:
  uds_path: /tmp/cortexd.sock
model_management:
  transport: fake
node:
  rpc_endpoint: http://127.0.0.1:26657
nexus:
  envelope_ttl_ms: 30000
  envelope_clock_skew_ms: 2000
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/cortex.kv
signer:
  uri: file:///tmp/cortex/signer.key
`)

	t.Run("yaml", func(t *testing.T) {
		cfg, err := LoadFile(path)
		if err != nil {
			t.Fatalf("LoadFile() error = %v", err)
		}
		assertEnvelopeBounds(t, cfg.Nexus, 30*time.Second, 2*time.Second)
	})

	t.Run("environment beats yaml", func(t *testing.T) {
		t.Setenv("CORTEX_NEXUS_ENVELOPE_TTL_MS", "20000")
		t.Setenv("CORTEX_NEXUS_ENVELOPE_CLOCK_SKEW_MS", "1000")

		cfg, err := LoadFile(path)
		if err != nil {
			t.Fatalf("LoadFile() error = %v", err)
		}
		assertEnvelopeBounds(t, cfg.Nexus, 20*time.Second, time.Second)
	})

	t.Run("flag beats environment", func(t *testing.T) {
		t.Setenv("CORTEX_NEXUS_ENVELOPE_TTL_MS", "20000")
		t.Setenv("CORTEX_NEXUS_ENVELOPE_CLOCK_SKEW_MS", "1000")

		cfg, err := LoadFileWithOverrides(path, map[string]string{
			"nexus_envelope_ttl_ms":        "10000",
			"nexus_envelope_clock_skew_ms": "0",
		})
		if err != nil {
			t.Fatalf("LoadFileWithOverrides() error = %v", err)
		}
		assertEnvelopeBounds(t, cfg.Nexus, 10*time.Second, 0)
	})
}

func assertEnvelopeBounds(t *testing.T, cfg NexusConfig, wantTTL, wantSkew time.Duration) {
	t.Helper()

	if got := cfg.EnvelopeTTL(); got != wantTTL {
		t.Fatalf("EnvelopeTTL() = %v, want %v", got, wantTTL)
	}
	if got := cfg.EnvelopeClockSkew(); got != wantSkew {
		t.Fatalf("EnvelopeClockSkew() = %v, want %v", got, wantSkew)
	}
}

func envelopeBoundMS(value uint64) *uint64 {
	return &value
}

func TestLoadFileEmptyYAMLUsesDefaultsThenValidates(t *testing.T) {
	path := writeConfig(t, "")

	_, err := LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), "chain_id") {
		t.Fatalf("LoadFile(empty) error = %v, want validation error", err)
	}
	if strings.Contains(err.Error(), "EOF") {
		t.Fatalf("LoadFile(empty) returned decoder EOF instead of validation: %v", err)
	}
}

func TestLoadFileExplicitModelSubscriptionEnvWinsAlias(t *testing.T) {
	path := writeConfig(t, `
chain_id: trueopen-devnet-1
admin:
  uds_path: /tmp/cortexd.sock
model_management:
  transport: fake
node:
  rpc_endpoint: http://127.0.0.1:26657
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/cortex.kv
signer:
  uri: file:///tmp/cortex/signer.key
`)
	t.Setenv("CORTEX_MODEL_ID", "alias-model")
	t.Setenv("CORTEX_NEXUS_SUBSCRIBE_MODELS", "explicit-a,explicit-b")

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if got := strings.Join(cfg.Nexus.SubscribeModels, ","); got != "explicit-a,explicit-b" {
		t.Fatalf("Nexus.SubscribeModels = %q, want explicit environment value", got)
	}
}

func TestLoadFileIgnoresEmptyEnvironmentValues(t *testing.T) {
	path := writeConfig(t, `
chain_id: from-yaml
admin:
  uds_path: /tmp/cortexd.sock
model_management:
  transport: fake
node:
  rpc_endpoint: http://127.0.0.1:26657
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/cortex.kv
signer:
  uri: file:///tmp/cortex/signer.key
`)
	t.Setenv("CORTEX_CHAIN_ID", "")

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if cfg.ChainID != "from-yaml" {
		t.Fatalf("ChainID = %q, want YAML value", cfg.ChainID)
	}
}

func TestLoadFileRejectsInvalidEnvironmentWithoutEchoingValue(t *testing.T) {
	path := writeConfig(t, `
chain_id: trueopen-devnet-1
admin:
  uds_path: /tmp/cortexd.sock
model_management:
  transport: fake
node:
  rpc_endpoint: http://127.0.0.1:26657
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/cortex.kv
signer:
  uri: file:///tmp/cortex/signer.key
`)
	secret := "not-a-bool-secret-value"
	t.Setenv("CORTEX_SIGNER_PASSWORD_STDIN", secret)

	_, err := LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), "CORTEX_SIGNER_PASSWORD_STDIN") {
		t.Fatalf("LoadFile() error = %v, want invalid environment error", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("LoadFile() leaked environment value: %v", err)
	}
}

func TestLoadFileDefaultsModeToFake(t *testing.T) {
	path := writeConfig(t, `
chain_id: trueopen-devnet-1
admin:
  uds_path: /tmp/cortexd.sock
model_management:
  endpoint: 127.0.0.1:9090
node:
  rpc_endpoint: http://127.0.0.1:26657
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/cortex.kv
signer:
  uri: file:///tmp/cortex/signer.key
`)

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if cfg.Mode != ModeFake {
		t.Fatalf("Mode = %q, want %q", cfg.Mode, ModeFake)
	}
}

func TestValidateDefaultsEmptyModeToFake(t *testing.T) {
	cfg := validConfig()
	cfg.Mode = ""

	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if cfg.Mode != ModeFake {
		t.Fatalf("Mode = %q, want %q", cfg.Mode, ModeFake)
	}
}

func TestValidateDefaultsNexusEnvelopeAuthToStrict(t *testing.T) {
	cfg := validConfig()
	cfg.Nexus.EnvelopeAuthMode = ""

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if cfg.Nexus.EnvelopeAuthMode != NexusEnvelopeAuthStrict || cfg.Nexus.TrustedNATSDev() {
		t.Fatalf("EnvelopeAuthMode = %q, want strict", cfg.Nexus.EnvelopeAuthMode)
	}
}

func TestValidateNexusEnvelopeAuthMode(t *testing.T) {
	t.Run("explicit trusted transport", func(t *testing.T) {
		cfg := validConfig()
		cfg.Nexus.EnvelopeAuthMode = NexusEnvelopeAuthTrustedDev
		cfg.Nexus.AuthTokenFile = "/run/secrets/nexus.token"
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
		if !cfg.Nexus.TrustedNATSDev() {
			t.Fatal("TrustedNATSDev() = false")
		}
	})

	// Cortex only implements nats.Token, so a broker configured for
	// user/password carries them in the URL. That transport is authenticated
	// even though no token file exists.
	t.Run("trusted transport accepts nats url credentials", func(t *testing.T) {
		cfg := validConfig()
		cfg.Nexus.EnvelopeAuthMode = NexusEnvelopeAuthTrustedDev
		cfg.Nexus.AuthTokenFile = ""
		cfg.Nexus.NATSURL = "nats://bus-user:bus-password@nexus.devnet.trueopen.xyz:4222"
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want URL credentials to satisfy trusted transport", err)
		}
		if !cfg.Nexus.NATSURLCredentials() {
			t.Fatal("NATSURLCredentials() = false")
		}
	})

	t.Run("trusted transport requires some credential", func(t *testing.T) {
		cfg := validConfig()
		cfg.Nexus.EnvelopeAuthMode = NexusEnvelopeAuthTrustedDev
		cfg.Nexus.AuthTokenFile = ""
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "authenticated NATS transport") {
			t.Fatalf("Validate() error = %v, want transport credential error", err)
		}
		if cfg.Nexus.NATSURLCredentials() {
			t.Fatal("NATSURLCredentials() = true for a URL without userinfo")
		}
	})

	t.Run("invalid mode", func(t *testing.T) {
		cfg := validConfig()
		cfg.Nexus.EnvelopeAuthMode = "disabled"
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "strict or trusted_nats_dev") {
			t.Fatalf("Validate() error = %v, want mode error", err)
		}
	})
}

// A real-mode node creates and binds its own JetStream durable consumer, which
// is impossible without the stream name. There is no implicit fallback any
// more, so the missing key has to stop the daemon at load rather than surface
// as a subscribe failure on the first task subject.
func TestValidateNexusJetStreamStream(t *testing.T) {
	t.Run("real mode requires it", func(t *testing.T) {
		for name, value := range map[string]string{"missing": "", "blank": "   "} {
			t.Run(name, func(t *testing.T) {
				cfg := validRealConfig()
				cfg.Nexus.JetStreamStream = value
				err := cfg.Validate()
				if err == nil || !strings.Contains(err.Error(), "nexus.jetstream_stream is required") {
					t.Fatalf("Validate() error = %v, want nexus.jetstream_stream to be required", err)
				}
			})
		}
	})

	// Fake mode runs no NATS transport at all, so the key is not its business.
	t.Run("fake mode does not need it", func(t *testing.T) {
		cfg := validConfig()
		cfg.Nexus.JetStreamStream = ""
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want a fake-bus config to be unaffected", err)
		}
	})
}

// TestValidateAcceptsARealModeNodeWithoutADirectTransactionPath replaces a test
// that asserted the opposite -- that every real-mode node must configure
// tx.enabled, because a selected Verifier's commit has no relay and must be
// self-submitted.
//
// The commit exit is unchanged. What the old rule got wrong is that it made a
// per-round exit a precondition for the whole node: nexus relays worker
// handraise, infer receipt, verifier handraise and the Verifier result receipt
// as its own transaction, so a node with no direct transaction path -- a
// file:// keystore signer cannot produce one at all -- still serves a full
// Worker round. Refusing the configuration bought nothing and cost every duty.
func TestValidateAcceptsARealModeNodeWithoutADirectTransactionPath(t *testing.T) {
	cfg := validRealConfig()
	cfg.Tx.Enabled = false

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want a real-mode node without a direct transaction path accepted", err)
	}
	if cfg.RequiresWorkloadTx() {
		t.Fatal("RequiresWorkloadTx() = true for a real-mode node with both direct paths disabled")
	}
}

func TestValidateRequiresTransactionsForDirectWorkloadPath(t *testing.T) {
	cfg := validRealConfig()
	cfg.Tx.Enabled = false
	cfg.SelfRescue.Enabled = true

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "tx.enabled must be true when a direct workload transaction path is enabled") {
		t.Fatalf("Validate() error = %v, want direct-workload tx.enabled error", err)
	}
}

// TestCommitExitFeeCapOnlyNarrows pins the FR6 guardrail: self_rescue's
// per-transaction bound applies to the commit exit, and it can only reduce what
// the exit is allowed to spend.
func TestCommitExitFeeCapOnlyNarrows(t *testing.T) {
	cfg := validRealConfig()
	cfg.Tx.MaxFeeAmount = 1000
	for name, tc := range map[string]struct {
		selfRescue uint64
		want       uint64
	}{
		"unset falls back to the tx ceiling": {selfRescue: 0, want: 1000},
		"a narrower bound wins":              {selfRescue: 250, want: 250},
		"a wider bound is ignored":           {selfRescue: 5000, want: 1000},
	} {
		t.Run(name, func(t *testing.T) {
			cfg.SelfRescue.MaxFeeAmount = tc.selfRescue
			if got := cfg.CommitExitFeeCap(); got != tc.want {
				t.Fatalf("CommitExitFeeCap() = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestRealModeStillRejectsDeadlineRiskSelfRescue is the other half of the
// narrowing: the flag now gates only the deadline-risk trigger, that trigger is
// still frozen on issue #108, and the refusal must keep naming the issue an
// operator would go read.
func TestRealModeStillRejectsDeadlineRiskSelfRescue(t *testing.T) {
	cfg := validRealConfig()
	cfg.SelfRescue.Enabled = true

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "self_rescue.enabled must be false in real mode") {
		t.Fatalf("Validate() error = %v, want the deadline-risk trigger refused", err)
	}
	if !strings.Contains(err.Error(), "issue #108") {
		t.Fatalf("Validate() error = %v, want the refusal to still cite issue #108", err)
	}
	if !strings.Contains(err.Error(), "deadline-risk") {
		t.Fatalf("Validate() error = %v, want the refusal scoped to the deadline-risk trigger", err)
	}

	// And with the flag off -- the shipped posture -- nothing about the commit
	// exit is blocked: the config validates and still demands the tx path the
	// exit needs.
	cfg.SelfRescue.Enabled = false
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want self_rescue.enabled=false to leave the commit exit available", err)
	}
}

func TestValidateRejectsChallengeVerifierInRealMode(t *testing.T) {
	cfg := validRealConfig()
	cfg.ChallengeVerifier.Enabled = true

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "challenge_verifier.enabled must be false in real mode") {
		t.Fatalf("Validate() error = %v, want real-mode challenge verifier rejection", err)
	}
}

func TestValidateRejectsUnwiredSelfRescueInRealMode(t *testing.T) {
	cfg := validRealConfig()
	cfg.SelfRescue = SelfRescueConfig{Enabled: true, MarginBlocks: 12, MaxFeeAmount: 1000, FeeDenom: "utrueopen", AllowedTxTypes: []string{"MsgInferReceiptCommitOnlyTx"}}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "issue #108") {
		t.Fatalf("Validate() error = %v, want unwired self-rescue rejection", err)
	}
}

func TestValidateBoundsHTTPSignerProofInterval(t *testing.T) {
	for _, interval := range []uint64{0, 999, 3600001} {
		cfg := validRealConfig()
		cfg.Signer.ReadinessProofIntervalMS = interval

		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "signer.readiness_proof_interval_ms") {
			t.Fatalf("Validate() interval %d error = %v, want signer proof interval bounds", interval, err)
		}
	}
}

func TestLoadFileParsesIntegrationEndpoints(t *testing.T) {
	path := writeConfig(t, `
mode: real
chain_id: trueopen-devnet-1
admin:
  uds_path: /tmp/cortexd.sock
model_management:
  endpoint: 127.0.0.1:9090
  transport: grpc
node:
  rpc_endpoint: http://127.0.0.1:26657
  rest_endpoint: http://127.0.0.1:1317
keeper:
  api_url: https://keeper.devnet.trueopen.xyz
  poll_interval_ms: 250
  max_lag_blocks: 15
task_execution:
  retry_delay_ms: 5000
  input_resolver: nexus
nexus:
  ingress_url: https://nexus.devnet.trueopen.xyz
  nats_url: tls://nexus.devnet.trueopen.xyz:4222
  nats_ca_file: /tmp/cortex/nats-ca.pem
  nats_user_key_file: /tmp/cortex/nats-user.nk
  auth_token_file: /tmp/cortex/nexus.token
  jetstream_stream: TRUEOPEN_TASK
tx:
  enabled: true
  max_fee_amount: 1000
  fee_denom: utrueopen
  max_attempts: 4
  poll_attempts: 20
  gas_limit: 250000
local_identity:
  operator_address: trueopen1operator
  service_key_ref: kms://cortex/service-key
  supported_model_profiles: [c2e5065e9dda862ec6970d2c54765ad9414f22fe7ae82cf94dae6825828129c1@1=llm_text_v1]
  model_service_id: model-svc-1
self_rescue:
  enabled: false
  margin_blocks: 12
  max_fee_amount: 2000
  fee_denom: utrueopen
  allowed_tx_types: [MsgInferReceiptCommitOnlyTx, MsgCommitTx, MsgResultTx, MsgWorkerRevealTx, MsgSettleTx]
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/cortex.kv
signer:
  uri: http://127.0.0.1:9080
  readiness_proof_interval_ms: 45000
`)

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if cfg.Mode != ModeReal {
		t.Fatalf("Mode = %q, want %q", cfg.Mode, ModeReal)
	}
	if cfg.Keeper.APIURL != "https://keeper.devnet.trueopen.xyz" {
		t.Fatalf("Keeper.APIURL = %q", cfg.Keeper.APIURL)
	}
	if cfg.Keeper.PollIntervalMS != 250 || cfg.Keeper.MaxLagBlocks != 15 {
		t.Fatalf("Keeper polling config = %#v", cfg.Keeper)
	}
	if cfg.TaskExecution.RetryDelayMS != 5000 {
		t.Fatalf("TaskExecution = %#v", cfg.TaskExecution)
	}
	if cfg.Node.RESTEndpoint != "http://127.0.0.1:1317" || cfg.Tx.GasLimit != 250000 {
		t.Fatalf("Cosmos tx runtime config not parsed: node=%#v tx=%#v signer=%#v", cfg.Node, cfg.Tx, cfg.Signer)
	}
	if cfg.Nexus.NATSURL != "tls://nexus.devnet.trueopen.xyz:4222" {
		t.Fatalf("Nexus.NATSURL = %q", cfg.Nexus.NATSURL)
	}
	if cfg.ModelManagement.Transport != "grpc" {
		t.Fatalf("ModelManagement.Transport = %q", cfg.ModelManagement.Transport)
	}
	if !cfg.Tx.Enabled || cfg.Tx.MaxFeeAmount != 1000 || cfg.Tx.FeeDenom != "utrueopen" || cfg.Tx.MaxAttempts != 4 {
		t.Fatalf("Tx config = %#v", cfg.Tx)
	}
	if cfg.LocalIdentity.OperatorAddress != "trueopen1operator" || cfg.LocalIdentity.ServiceKeyRef != "kms://cortex/service-key" || len(cfg.LocalIdentity.SupportedModelProfiles) != 1 || cfg.LocalIdentity.ModelServiceID != "model-svc-1" {
		t.Fatalf("LocalIdentity = %#v", cfg.LocalIdentity)
	}
	if cfg.Signer.ReadinessProofIntervalMS != 45000 {
		t.Fatalf("Signer = %#v", cfg.Signer)
	}
	if cfg.SelfRescue.Enabled || cfg.SelfRescue.MarginBlocks != 12 || cfg.SelfRescue.MaxFeeAmount != 2000 || len(cfg.SelfRescue.AllowedTxTypes) != 5 {
		t.Fatalf("SelfRescue = %#v", cfg.SelfRescue)
	}
}

func TestRealExampleConfigLoadsProductionBoundaries(t *testing.T) {
	cfg, err := LoadFile(filepath.Join("..", "..", "configs", "real.example.yaml"))
	if err != nil {
		t.Fatalf("LoadFile(real.example.yaml) error = %v", err)
	}

	if cfg.Mode != ModeReal {
		t.Fatalf("Mode = %q, want %q", cfg.Mode, ModeReal)
	}
	if cfg.ModelManagement.Transport != "grpc" || cfg.ModelManagement.Endpoint == "" {
		t.Fatalf("model management config = %#v", cfg.ModelManagement)
	}
	if cfg.Node.RPCEndpoint == "" || cfg.Nexus.IngressURL == "" || cfg.Nexus.NATSURL == "" {
		t.Fatalf("keeper/nexus config missing: keeper=%#v nexus=%#v", cfg.Keeper, cfg.Nexus)
	}
	if cfg.Keeper.PollIntervalMS == 0 || cfg.Keeper.MaxLagBlocks == 0 {
		t.Fatalf("keeper polling config missing: %#v", cfg.Keeper)
	}
	if cfg.TaskExecution.RetryDelayMS == 0 {
		t.Fatalf("task execution config missing: %#v", cfg.TaskExecution)
	}
	// The production example runs a grpc model transport, so its Worker input
	// must come from Nexus. A fixture root would be a local-only shortcut.
	if cfg.TaskExecution.InputResolver != InputResolverNexus || cfg.TaskExecution.FixtureRoot != "" {
		t.Fatalf("task input resolver = %#v, want nexus without a fixture root", cfg.TaskExecution)
	}
	if len(cfg.Nexus.SubscribeModels) != 1 || cfg.Nexus.SubscribeModels[0] != "6d120a31a3858346e04517111eb3e1e03c4a5a9757b12cd3d2acb27c6bc9d6a2" {
		t.Fatalf("nexus model subscriptions = %#v, want model IDs rather than NATS subjects", cfg.Nexus.SubscribeModels)
	}
	if !cfg.Tx.Enabled || cfg.Tx.MaxFeeAmount == 0 || cfg.Tx.FeeDenom == "" || cfg.Tx.MaxAttempts == 0 {
		t.Fatalf("tx submit config incomplete: %#v", cfg.Tx)
	}
	if cfg.LocalIdentity.ModelServiceID == "" || cfg.LocalIdentity.OperatorAddress == "" || cfg.LocalIdentity.ServiceKeyRef == "" {
		t.Fatalf("local identity incomplete: %#v", cfg.LocalIdentity)
	}
	if cfg.Artifacts.RetentionPolicyVersion != "retention-v1" {
		t.Fatalf("artifacts retention policy = %q", cfg.Artifacts.RetentionPolicyVersion)
	}
	if cfg.SelfRescue.Enabled {
		t.Fatalf("self-rescue must remain disabled until issue #108: %#v", cfg.SelfRescue)
	}
	if cfg.Signer.URI == "" || cfg.Artifacts.Root == "" || cfg.Store.Path == "" || cfg.Admin.UDSPath == "" {
		t.Fatalf("local operator paths incomplete: signer=%#v artifacts=%#v store=%#v admin=%#v", cfg.Signer, cfg.Artifacts, cfg.Store, cfg.Admin)
	}
}

func TestIntegrationRoleExamplesUseSharedFakeFixtureBoundary(t *testing.T) {
	for _, name := range []string{"integration.worker.example.yaml", "integration.verifier.example.yaml"} {
		t.Run(name, func(t *testing.T) {
			cfg, err := LoadFile(filepath.Join("..", "..", "configs", name))
			if err != nil {
				t.Fatalf("LoadFile(%s) error = %v", name, err)
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate(%s) error = %v", name, err)
			}
			if cfg.Mode != ModeReal || cfg.ModelManagement.Transport != "fake" || cfg.TaskExecution.InputResolver != "fixture" || cfg.TaskExecution.FixtureRoot != "/tmp/cortex-integration-fixtures" || len(cfg.LocalIdentity.Duties) != 0 {
				t.Fatalf("integration config = %#v", cfg)
			}
		})
	}
}

func TestValidateRealModeRequiresIntegrationEndpoints(t *testing.T) {
	cfg := validConfig()
	cfg.Mode = ModeReal

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("Validate() error = nil, want missing integration endpoint error")
	}
	// nexus.ingress_url is not here: it is optional now that the dial address
	// comes from the Builder's on-chain descriptor. TestRealModeAcceptsAnAbsent
	// NexusIngressURL covers that from the other side.
	for _, want := range []string{"nexus.nats_url", "local_identity.model_service_id", "local_identity.operator_address", "local_identity.service_key_ref", "local_identity.supported_model_profiles"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Validate() error = %q, want field %q", err.Error(), want)
		}
	}
}

// TestRealModeAcceptsAnAbsentNexusIngressURL pins the half of the contract the
// removal from the required list creates. No Nexus call takes the configured
// value as a target -- the dial address comes from the Builder's on-chain
// descriptor -- so an operator who has not been handed one can still start.
//
// Written from both ends, because "optional" must not mean "ignored". A
// configured value is still a real assertion: it is cross-checked against the
// descriptor at startup, and it still has to name a secure transport.
func TestRealModeAcceptsAnAbsentNexusIngressURL(t *testing.T) {
	t.Run("absent is accepted", func(t *testing.T) {
		cfg := validRealConfig()
		cfg.Nexus.IngressURL = ""
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want an absent ingress_url accepted", err)
		}
	})

	t.Run("absent does not read as insecure", func(t *testing.T) {
		// The scheme check must not fire on the empty string: having no value is
		// not the same as having a plaintext one.
		cfg := validRealConfig()
		cfg.Nexus.IngressURL = ""
		cfg.Nexus.BuilderOperatorAddress = "trueopen1builderoperator"
		cfg.Nexus.AllowInsecureDescriptor = false
		if err := cfg.Validate(); err != nil && strings.Contains(err.Error(), "nexus.ingress_url must use https") {
			t.Fatalf("Validate() error = %v, want no scheme complaint for an absent value", err)
		}
	})

	t.Run("a configured value is still checked", func(t *testing.T) {
		cfg := validRealConfig()
		cfg.Nexus.IngressURL = "http://nexus.example.org"
		cfg.Nexus.BuilderOperatorAddress = "trueopen1builderoperator"
		cfg.Nexus.AllowInsecureDescriptor = false
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "nexus.ingress_url must use https") {
			t.Fatalf("Validate() error = %v, want a plaintext configured ingress refused", err)
		}
	})
}

func TestLoadFileDefaultsTaskExecutionRetryPolicy(t *testing.T) {
	path := writeConfig(t, `
chain_id: trueopen-devnet-1
admin:
  uds_path: /tmp/cortexd.sock
model_management:
  endpoint: 127.0.0.1:9090
node:
  rpc_endpoint: http://127.0.0.1:26657
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/cortex.kv
signer:
  uri: file:///tmp/cortex/signer.key
`)

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if cfg.TaskExecution.RetryDelayMS != 30000 {
		t.Fatalf("TaskExecution defaults = %#v", cfg.TaskExecution)
	}
}

func TestValidateDefaultsSafeArtifactsRetentionPeriod(t *testing.T) {
	cfg := validConfig()
	cfg.Artifacts.MinimumRetentionBlocks = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if cfg.Artifacts.MinimumRetentionBlocks != 100800 {
		t.Fatalf("minimum retention blocks = %d, want 100800", cfg.Artifacts.MinimumRetentionBlocks)
	}
}

func TestLoadFileRejectsObsoleteDeadlineDelta(t *testing.T) {
	path := writeConfig(t, `
chain_id: trueopen-devnet-1
admin:
  uds_path: /tmp/cortexd.sock
model_management:
  endpoint: 127.0.0.1:9090
node:
  rpc_endpoint: http://127.0.0.1:26657
task_execution:
  infer_deadline_delta_heights: 120
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/cortex.kv
signer:
  uri: file:///tmp/cortex/signer.key
`)

	_, err := LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), "unknown task_execution field") {
		t.Fatalf("LoadFile() error = %v, want obsolete deadline field rejection", err)
	}
}

func TestValidateRealModeRequiresTaskExecutionRetryPolicy(t *testing.T) {
	cfg := validRealConfig()
	cfg.TaskExecution.RetryDelayMS = 0

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("Validate() error = nil, want task execution errors")
	}
	for _, want := range []string{"task_execution.retry_delay_ms"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Validate() error = %q, want field %q", err.Error(), want)
		}
	}
}

func TestValidateRealModeRequiresLocalIdentityModelService(t *testing.T) {
	cfg := validRealConfig()
	cfg.LocalIdentity.ModelServiceID = ""

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "local_identity.model_service_id") {
		t.Fatalf("Validate() error = %v, want local identity model service error", err)
	}
}

func TestValidateRealModeRequiresStableLocalIdentity(t *testing.T) {
	cfg := validRealConfig()
	cfg.LocalIdentity.OperatorAddress = ""
	cfg.LocalIdentity.ServiceKeyRef = ""
	cfg.LocalIdentity.SupportedModelProfiles = nil

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("Validate() error = nil, want stable identity errors")
	}
	for _, want := range []string{"local_identity.operator_address", "local_identity.service_key_ref", "local_identity.supported_model_profiles"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Validate() error = %q, want field %q", err.Error(), want)
		}
	}
}

// Duty selection is retired. A config that still carries the key describes a
// node topology that no longer exists, and silently ignoring it would be worse
// than either outcome: an operator reading `duties: [WORKER]` would believe the
// node does not verify while it subscribes to the Verifier subjects regardless.
// The refusal covers fake mode too, so this asserts every mode.
func TestValidateRejectsRetiredDutiesKeyInEveryMode(t *testing.T) {
	for _, mode := range []string{ModeFake, ModeReal, ModeIntegration} {
		cfg := validRealConfig()
		cfg.Mode = mode
		cfg.LocalIdentity.Duties = []string{"WORKER", "VERIFIER"}

		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "local_identity.duties has been removed") {
			t.Fatalf("Validate() error for mode %q = %v, want the duties retirement refusal", mode, err)
		}
	}
}

// The deployment-override surface loses the key with the config field: an
// operator's exported CORTEX_DUTIES is no longer read, and there is no
// --duties flag to pass either.
func TestDeploymentOverridesNoLongerCarryDuties(t *testing.T) {
	for _, key := range DeploymentOverrideKeys() {
		if key == "duties" {
			t.Fatalf("DeploymentOverrideKeys() still contains %q", key)
		}
	}
}

func TestValidateRealModeRejectsMalformedSupportedModelProfile(t *testing.T) {
	for _, binding := range []string{"c2e5065e9dda862ec6970d2c54765ad9414f22fe7ae82cf94dae6825828129c1", "c2e5065e9dda862ec6970d2c54765ad9414f22fe7ae82cf94dae6825828129c1@llm_text_v1", "c2e5065e9dda862ec6970d2c54765ad9414f22fe7ae82cf94dae6825828129c1@0=llm_text_v1", "c2e5065e9dda862ec6970d2c54765ad9414f22fe7ae82cf94dae6825828129c1@01=llm_text_v1", "c2e5065e9dda862ec6970d2c54765ad9414f22fe7ae82cf94dae6825828129c1@1="} {
		cfg := validRealConfig()
		cfg.LocalIdentity.SupportedModelProfiles = []string{binding}

		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "local_identity.supported_model_profiles") {
			t.Fatalf("Validate() binding %q error = %v, want supported model profiles error", binding, err)
		}
	}
}

func TestLocalIdentityResolvesCapabilityByNumericProfileVersion(t *testing.T) {
	identity := validRealConfig().LocalIdentity
	profiles, err := identity.ModelProfiles()
	if err != nil {
		t.Fatalf("ModelProfiles() error = %v", err)
	}
	if len(profiles) != 1 || profiles[0] != (ModelProfileRef{ModelID: "c2e5065e9dda862ec6970d2c54765ad9414f22fe7ae82cf94dae6825828129c1", ProfileVersion: 1, Capability: "llm_text_v1"}) {
		t.Fatalf("ModelProfiles() = %#v", profiles)
	}
	capability, err := identity.CapabilityFor("c2e5065e9dda862ec6970d2c54765ad9414f22fe7ae82cf94dae6825828129c1", 1)
	if err != nil || capability != "llm_text_v1" {
		t.Fatalf("CapabilityFor() = %q, %v", capability, err)
	}
	if _, err := identity.CapabilityFor("c2e5065e9dda862ec6970d2c54765ad9414f22fe7ae82cf94dae6825828129c1", 2); err == nil {
		t.Fatalf("CapabilityFor() missing binding error = nil")
	}
}

func TestValidateRealModeAcceptsConfiguredFeeDenom(t *testing.T) {
	for _, denom := range []string{"uusdc", "utrueopen", "hyperlane/0x4444444444444444444444444444444444444444"} {
		t.Run(denom, func(t *testing.T) {
			cfg := validRealConfig()
			cfg.Tx.FeeDenom = denom
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() configured denom %q: %v", denom, err)
			}
		})
	}
}

func TestValidateRealModeRejectsInvalidFeeDenom(t *testing.T) {
	for _, denom := range []string{"", " uusdc", "uusdc ", "u usdc", "12coin", "us", strings.Repeat("u", 129)} {
		t.Run(denom, func(t *testing.T) {
			cfg := validRealConfig()
			cfg.Tx.FeeDenom = denom
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "tx.fee_denom") {
				t.Fatalf("Validate() invalid denom %q: %v", denom, err)
			}
		})
	}
}

func TestValidateFakeModeAllowsEmptyLocalIdentity(t *testing.T) {
	cfg := validConfig()
	cfg.LocalIdentity = LocalIdentityConfig{}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRealModeRequiresStrictCosmosTransactionRuntime(t *testing.T) {
	base := validRealConfig()
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{name: "REST endpoint", mutate: func(c *Config) { c.Node.RESTEndpoint = "" }, want: "node.rest_endpoint"},
		{name: "gas limit", mutate: func(c *Config) { c.Tx.GasLimit = 0 }, want: "tx.gas_limit"},
		{name: "unsupported signer scheme", mutate: func(c *Config) { c.Signer.URI = "kms://cortex/operator" }, want: "signer.uri must be an HTTP(S) URL"},
		{name: "signer credentials in url", mutate: func(c *Config) { c.Signer.URI = "http://user:pw@signer:9080" }, want: "signer.uri must be an HTTP(S) URL"},
		{name: "both password sources", mutate: func(c *Config) { c.Signer.PasswordEnv, c.Signer.PasswordFile = "A", "/b" }, want: "mutually exclusive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.mutate(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestLoadFileRejectsUnknownMode(t *testing.T) {
	cfg := validConfig()
	cfg.Mode = "prod"

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("Validate() error = %v, want mode error", err)
	}
}

func TestLoadFileRejectsLegacyIdentityAndOperatorKeyFields(t *testing.T) {
	for _, legacy := range []string{
		"signer:\n  operator_key_ref: operator.json\n",
		"signer:\n  operator_key_version: 1\n",
		"local_identity:\n  cortex_node_id: trueopen1node\n",
		"local_identity:\n  expected_service_key_version: 1\n",
	} {
		if _, err := LoadFile(writeConfig(t, legacy)); err == nil {
			t.Fatalf("LoadFile accepted removed identity/key field in %q", legacy)
		}
	}
}

func TestValidateRequiresModelManagementTransport(t *testing.T) {
	cfg := validConfig()
	cfg.ModelManagement.Transport = ""

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "model_management.transport") {
		t.Fatalf("Validate() error = %v, want model_management.transport error", err)
	}
}

func TestValidateRealModeAllowsFakeModelWithFixtureInput(t *testing.T) {
	cfg := validRealConfig()
	cfg.ModelManagement.Transport = "fake"
	cfg.ModelManagement.Endpoint = ""
	cfg.TaskExecution.InputResolver = "fixture"
	cfg.TaskExecution.FixtureRoot = t.TempDir()

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRealModeFakeModelRequiresFixtureInput(t *testing.T) {
	tests := map[string]func(*Config){
		"resolver": func(cfg *Config) { cfg.TaskExecution.InputResolver = "" },
		"root":     func(cfg *Config) { cfg.TaskExecution.FixtureRoot = "" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := validRealConfig()
			cfg.ModelManagement.Transport = "fake"
			cfg.ModelManagement.Endpoint = ""
			cfg.TaskExecution.InputResolver = "fixture"
			cfg.TaskExecution.FixtureRoot = t.TempDir()
			mutate(&cfg)

			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), "task_execution") {
				t.Fatalf("Validate() error = %v, want task_execution error", err)
			}
		})
	}
}

func TestValidateRejectsFixtureInputForRealModelTransport(t *testing.T) {
	cfg := validRealConfig()
	cfg.TaskExecution.InputResolver = "fixture"
	cfg.TaskExecution.FixtureRoot = t.TempDir()

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "fixture") {
		t.Fatalf("Validate() error = %v, want fixture compatibility error", err)
	}
}

// task_execution.input_resolver: nexus is the real-mode Worker input path. It
// reaches the receiving Builder's Nexus, so it needs a real model transport
// and no local fixture root.
func TestValidateRealModeAcceptsNexusInputResolver(t *testing.T) {
	for _, transport := range []string{"grpc", "local"} {
		t.Run(transport, func(t *testing.T) {
			cfg := validRealConfig()
			cfg.ModelManagement.Transport = transport
			cfg.TaskExecution.InputResolver = InputResolverNexus
			if transport == "local" {
				// The local transport carries its own concurrency bound.
				cfg.ModelManagement.MaxConcurrency = 1
			}

			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() error = %v, want nexus input over %s transport to be accepted", err, transport)
			}
			// Nexus input needs no fixture root and no extra required key
			// beyond the real-mode boundaries already asserted elsewhere.
			if cfg.TaskExecution.FixtureRoot != "" {
				t.Fatalf("FixtureRoot = %q, want nexus input to need none", cfg.TaskExecution.FixtureRoot)
			}
		})
	}
}

// The resolver value is compared case-insensitively on a trimmed string, the
// same as model_management.transport.
func TestValidateNormalizesInputResolverValue(t *testing.T) {
	cfg := validRealConfig()
	cfg.TaskExecution.InputResolver = "  Nexus "

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want a padded mixed-case resolver to be accepted", err)
	}
	// Callers must branch on the normalized value, never the raw YAML string.
	if mode := cfg.TaskExecution.InputResolverMode(); mode != InputResolverNexus {
		t.Fatalf("InputResolverMode() = %q, want %q", mode, InputResolverNexus)
	}
}

// Fake inference does not constrain the input source: input resolution goes through
// the task-data client and service-key authentication and never touches the model
// service. "Real input + fake inference" is the integration combination with a fully
// real data plane and only the GPU left out, so it has to be legal.
func TestValidateAcceptsNexusInputResolverWithFakeTransport(t *testing.T) {
	cfg := validRealConfig()
	cfg.ModelManagement.Transport = "fake"
	cfg.ModelManagement.Endpoint = ""
	cfg.TaskExecution.InputResolver = InputResolverNexus

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nexus input with fake transport to be accepted", err)
	}
}

// But the source has to be chosen explicitly: left empty, the Worker never gets an
// input and retries until it times out.
func TestValidateRequiresInputResolverForFakeTransport(t *testing.T) {
	cfg := validRealConfig()
	cfg.ModelManagement.Transport = "fake"
	cfg.ModelManagement.Endpoint = ""
	cfg.TaskExecution.InputResolver = ""

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "task_execution.input_resolver") {
		t.Fatalf("Validate() error = %v, want a missing input_resolver error", err)
	}
}

func TestValidateRejectsUnknownInputResolver(t *testing.T) {
	for _, resolver := range []string{"http", "builder", "fixtures"} {
		t.Run(resolver, func(t *testing.T) {
			cfg := validRealConfig()
			cfg.TaskExecution.InputResolver = resolver

			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), "task_execution.input_resolver") {
				t.Fatalf("Validate() error = %v, want unknown resolver %q to be rejected", err, resolver)
			}
		})
	}
}

// An empty resolver leaves a real-mode Worker with no way to read task input,
// which used to strand it in an endless retry loop (issue #113). Duty selection
// is retired, so every real-mode node can be drawn as a Worker and the
// requirement is unconditional -- there is no longer a verifier-only node that
// legally lacks a resolver.
func TestValidateRealModeRequiresInputResolver(t *testing.T) {
	cfg := validRealConfig()
	cfg.TaskExecution.InputResolver = ""

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "task_execution.input_resolver") {
		t.Fatalf("Validate() error = %v, want a missing input resolver to be rejected", err)
	}
}

func validConfig() Config {
	return Config{
		Mode:    ModeFake,
		ChainID: "trueopen-devnet-1",
		Admin: AdminConfig{
			UDSPath: "/tmp/cortexd.sock",
		},
		ModelManagement: ModelManagementConfig{
			Endpoint:  "127.0.0.1:9090",
			Transport: "fake",
		},
		Node: NodeConfig{
			RPCEndpoint:  "http://127.0.0.1:26657",
			RESTEndpoint: "http://127.0.0.1:1317",
		},
		Artifacts: ArtifactsConfig{
			Root: "/tmp/cortex/evidence",
		},
		Store: StoreConfig{
			Path: "/tmp/cortex/cortex.kv",
		},
		Signer: SignerConfig{
			URI: "file:///tmp/cortex/signer.key",
		},
		TaskExecution: TaskExecutionConfig{
			RetryDelayMS: 30000,
		},
	}
}

func validRealConfig() Config {
	cfg := validConfig()
	cfg.Mode = ModeReal
	cfg.ModelManagement.Transport = "grpc"
	// grpc transport plus a WORKER duty: Nexus is the only legal input source.
	cfg.TaskExecution.InputResolver = InputResolverNexus
	cfg.Keeper.APIURL = "https://keeper.devnet.trueopen.xyz"
	cfg.Nexus.IngressURL = "https://nexus.devnet.trueopen.xyz"
	cfg.Nexus.NATSURL = "tls://nexus.devnet.trueopen.xyz:4222"
	cfg.Nexus.NATSUserKeyFile = "/etc/cortex/nats-user.nk"
	cfg.Nexus.NATSCAFile = "/etc/cortex/nats-ca.pem"
	cfg.Nexus.JetStreamStream = "TRUEOPEN_TASK"
	cfg.LocalIdentity = LocalIdentityConfig{
		OperatorAddress:        "trueopen1operator",
		ServiceKeyRef:          "kms://cortex/service-key",
		SupportedModelProfiles: []string{"c2e5065e9dda862ec6970d2c54765ad9414f22fe7ae82cf94dae6825828129c1@1=llm_text_v1"},
		ModelServiceID:         "model-svc-1",
	}
	cfg.Tx = TxConfig{Enabled: true, MaxFeeAmount: 1000, FeeDenom: "utrueopen", MaxAttempts: 3, PollAttempts: 20, GasLimit: 250000}
	cfg.Signer = SignerConfig{URI: "http://127.0.0.1:9080", ReadinessProofIntervalMS: 30000}
	cfg.SelfRescue = SelfRescueConfig{Enabled: false, MarginBlocks: 12, MaxFeeAmount: 1000, FeeDenom: "utrueopen", AllowedTxTypes: []string{"MsgInferReceiptCommitOnlyTx"}}
	return cfg
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(contents)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// A file signer URI keeps keys inside cortexd. That is weaker than an external
// signing service but is supported for integration environments, so validation
// must accept it.
func TestValidateRealModeAcceptsLocalKeyFileSigner(t *testing.T) {
	for _, uri := range []string{"file:///etc/cortex/keys.json", "file:keys.json"} {
		t.Run(uri, func(t *testing.T) {
			cfg := validRealConfig()
			cfg.Signer.URI = uri
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() error = %v, want a file signer to be accepted", err)
			}
			if !cfg.Signer.LocalKeys() {
				t.Fatalf("LocalKeys() = false, want true for %q", uri)
			}
		})
	}
	cfg := validRealConfig()
	if cfg.Signer.LocalKeys() {
		t.Fatalf("LocalKeys() = true for an HTTP signer %q", cfg.Signer.URI)
	}
	// file://host/path names a remote machine and must not be mistaken for a
	// local file.
	cfg.Signer.URI = "file://remote-host/keys.json"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("Validate() accepted a file URI with a host")
	}
}

// The fake model service and the fixture input resolver are the supported
// real-mode integration pairing, and both are deployment-specific paths and
// modes rather than anything the shipped template should carry.
func TestLoadFileFixtureIntegrationSettingsComeFromEnvironment(t *testing.T) {
	path := writeConfig(t, `
chain_id: trueopen-devnet-1
admin:
  uds_path: /tmp/cortexd.sock
node:
  rpc_endpoint: http://127.0.0.1:26657
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/cortex.kv
signer:
  uri: file:///tmp/cortex/keystore
health: {}
`)
	t.Setenv("CORTEX_MODEL_TRANSPORT", "fake")
	t.Setenv("CORTEX_TASK_INPUT_RESOLVER", "fixture")
	t.Setenv("CORTEX_TASK_FIXTURE_ROOT", "/opt/cortex/fixtures")

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if cfg.ModelManagement.Transport != "fake" || cfg.TaskExecution.InputResolver != "fixture" ||
		cfg.TaskExecution.FixtureRoot != "/opt/cortex/fixtures" {
		t.Fatalf("task execution = %#v, want the fixture integration pairing from the environment", cfg.TaskExecution)
	}
}

func TestNexusBuilderDescriptorVerificationRequiresTLSUnlessOptedOut(t *testing.T) {
	cfg := validRealConfig()
	cfg.Nexus.BuilderOperatorAddress = "trueopen1builderoperator"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want an https ingress with descriptor verification to be accepted", err)
	}
	if !cfg.Nexus.VerifiesBuilderDescriptor() {
		t.Fatalf("VerifiesBuilderDescriptor() = false, want descriptor verification enabled")
	}

	// grpcs:// is the same TLS transport spelled for a gRPC endpoint, so gating
	// on the https prefix alone refused a secure configuration outright.
	cfg.Nexus.IngressURL = "grpcs://nexus.devnet.trueopen.xyz:8443"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want a grpcs ingress accepted with descriptor verification on", err)
	}

	// grpc:// is the plaintext spelling and stays behind the opt-in, exactly
	// like http://.
	cfg.Nexus.IngressURL = "grpc://nexus.devnet.trueopen.xyz:8080"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "nexus.ingress_url must use https or grpcs") {
		t.Fatalf("Validate() error = %v, want plaintext grpc ingress to be rejected", err)
	}

	cfg.Nexus.IngressURL = "http://nexus.devnet.trueopen.xyz:8080"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "nexus.ingress_url must use https") {
		t.Fatalf("Validate() error = %v, want plaintext ingress to be rejected", err)
	}

	cfg.Nexus.AllowInsecureDescriptor = true
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "nexus.allow_insecure_descriptor must be false in real mode") {
		t.Fatalf("Validate() error = %v, want real mode refusal of allow_insecure_descriptor", err)
	}
	cfg.Mode = ModeFake
	cfg.Nexus.AllowInsecureDescriptor = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want the explicit insecure opt-in to be accepted in fake mode", err)
	}
}

func TestNexusBuilderOperatorMustBeCanonical(t *testing.T) {
	cfg := validRealConfig()
	cfg.Nexus.BuilderOperatorAddress = " trueopen1builderoperator "
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "nexus.builder_operator_address must be canonical") {
		t.Fatalf("Validate() error = %v, want a canonical operator address requirement", err)
	}
}

func TestNexusDescriptorOverridesLoadFromDeploymentEnvironment(t *testing.T) {
	t.Setenv("CORTEX_NEXUS_BUILDER_OPERATOR", "trueopen1builderoperator")
	t.Setenv("CORTEX_NEXUS_ALLOW_INSECURE_DESCRIPTOR", "true")
	cfg := Config{}
	if err := applyEnv(&cfg); err != nil {
		t.Fatalf("applyEnv() error = %v", err)
	}
	if cfg.Nexus.BuilderOperatorAddress != "trueopen1builderoperator" || !cfg.Nexus.AllowInsecureDescriptor {
		t.Fatalf("Nexus = %#v", cfg.Nexus)
	}
}

func TestValidateCopiesDeprecatedEvidenceRootToArtifacts(t *testing.T) {
	cfg := validConfig()
	cfg.Artifacts = ArtifactsConfig{}
	cfg.Evidence = ArtifactsConfig{Root: "/tmp/cortex/evidence"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if cfg.Artifacts.Root != "/tmp/cortex/evidence" {
		t.Fatalf("Artifacts.Root = %q, want copied from deprecated Evidence.Root", cfg.Artifacts.Root)
	}
}

func TestValidatePrefersArtifactsRootOverDeprecatedEvidenceRoot(t *testing.T) {
	cfg := validConfig()
	cfg.Evidence = ArtifactsConfig{Root: "/tmp/cortex/evidence"}
	cfg.Artifacts = ArtifactsConfig{Root: "/tmp/cortex/artifacts"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if cfg.Artifacts.Root != "/tmp/cortex/artifacts" {
		t.Fatalf("Artifacts.Root = %q, want /tmp/cortex/artifacts", cfg.Artifacts.Root)
	}
}

func TestDeprecatedEvidenceRootEnvVarLosesToArtifactsRoot(t *testing.T) {
	t.Setenv("CORTEX_ARTIFACTS_ROOT", "/canonical")
	t.Setenv("CORTEX_EVIDENCE_ROOT", "/deprecated")
	cfg, err := LoadFileWithOverrides("testdata/valid.yaml", nil)
	if err != nil {
		t.Fatalf("LoadFileWithOverrides() error = %v", err)
	}
	if cfg.Artifacts.Root != "/canonical" {
		t.Fatalf("Artifacts.Root = %q, want /canonical", cfg.Artifacts.Root)
	}
}

func TestFlagArtifactsRootWinsOverEvidenceRoot(t *testing.T) {
	cfg, err := LoadFileWithOverrides("testdata/valid.yaml", map[string]string{
		"evidence_root":  "/deprecated",
		"artifacts_root": "/canonical",
	})
	if err != nil {
		t.Fatalf("LoadFileWithOverrides() error = %v", err)
	}
	if cfg.Artifacts.Root != "/canonical" {
		t.Fatalf("Artifacts.Root = %q, want /canonical", cfg.Artifacts.Root)
	}
}

func TestDeprecatedEvidenceYAMLBlockLoadedEndToEnd(t *testing.T) {
	cfg, err := LoadFileWithOverrides("testdata/deprecated_artifacts.yaml", nil)
	if err != nil {
		t.Fatalf("LoadFileWithOverrides() error = %v", err)
	}
	if cfg.Artifacts.Root != "/tmp/cortex/deprecated-evidence" {
		t.Fatalf("Artifacts.Root = %q", cfg.Artifacts.Root)
	}
	if cfg.Artifacts.RetentionPolicyVersion != "retention-v9" {
		t.Fatalf("Artifacts.RetentionPolicyVersion = %q", cfg.Artifacts.RetentionPolicyVersion)
	}
	if cfg.Artifacts.MinimumRetentionBlocks != 999999 {
		t.Fatalf("Artifacts.MinimumRetentionBlocks = %d", cfg.Artifacts.MinimumRetentionBlocks)
	}
}

func TestArtifactsTakesPrecedenceOverDeprecatedEvidenceYAML(t *testing.T) {
	cfg, err := LoadFileWithOverrides("testdata/deprecated_artifacts.yaml", map[string]string{
		"artifacts_root": "/yaml-wins",
	})
	if err != nil {
		t.Fatalf("LoadFileWithOverrides() error = %v", err)
	}
	if cfg.Artifacts.Root != "/yaml-wins" {
		t.Fatalf("Artifacts.Root = %q, want /yaml-wins", cfg.Artifacts.Root)
	}
	if cfg.Artifacts.RetentionPolicyVersion != "retention-v9" {
		t.Fatalf("Artifacts.RetentionPolicyVersion = %q", cfg.Artifacts.RetentionPolicyVersion)
	}
}

// TestRealModeRefusesTrustedNATSDevAndAllowInsecureDescriptor verifies that the
// two development-only Nexus flags are rejected when mode is real.
func TestRealModeRefusesTrustedNATSDevAndAllowInsecureDescriptor(t *testing.T) {
	cfg := validRealConfig()
	cfg.Nexus.EnvelopeAuthMode = NexusEnvelopeAuthTrustedDev
	cfg.Nexus.AuthTokenFile = "/run/secrets/nexus.token"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "nexus.envelope_auth_mode must not be trusted_nats_dev in real mode") {
		t.Fatalf("Validate() error = %v, want real mode refusal of trusted_nats_dev", err)
	}

	cfg = validRealConfig()
	cfg.Nexus.IngressURL = "http://nexus.devnet.trueopen.xyz:8080"
	cfg.Nexus.BuilderOperatorAddress = "trueopen1builderoperator"
	cfg.Nexus.AllowInsecureDescriptor = true
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "nexus.allow_insecure_descriptor must be false in real mode") {
		t.Fatalf("Validate() error = %v, want real mode refusal of allow_insecure_descriptor", err)
	}
}

// TestFrozenFeatureProducesOneProblem asserts a frozen feature yields exactly
// one problem, not a cascade.
func TestFrozenFeatureProducesOneProblem(t *testing.T) {
	cfg := validConfig()
	cfg.Mode = ModeReal
	cfg.SelfRescue.Enabled = true
	errs := cfg.Validate()
	if errs == nil {
		t.Fatal("expected validation errors")
	}
	problems := strings.Split(errs.Error(), "; ")
	var selfRescueCount int
	for _, p := range problems {
		if strings.Contains(p, "self_rescue") {
			selfRescueCount++
		}
	}
	if selfRescueCount != 1 {
		t.Fatalf("self_rescue problems = %d, want 1; problems: %v", selfRescueCount, problems)
	}
}

// TestRequiredFieldsHaveConsumers asserts every required config field names the
// subsystem that consumes it. If a required entry is added without a consumer,
// this test fails.
func TestRequiredFieldsHaveConsumers(t *testing.T) {
	cfg := validRealConfig()
	cfg.Tx.Enabled = true
	cfg.TaskExecution.InputResolver = "fixture"
	cfg.TaskExecution.FixtureRoot = "/tmp/fixtures"
	for _, f := range cfg.collectRequiredFields("fake", InputResolverFixture) {
		if strings.TrimSpace(f.consumer) == "" {
			t.Fatalf("required field %q is missing a consumer", f.field)
		}
	}
}

// Integration mode is real mode everywhere except the envelope trust boundary.
// The point of the third value is that opting into the dev-only Nexus flags is
// a named deployment rather than an override smuggled past a real-mode config,
// so the two axes are asserted separately here: same wiring, different posture.
func TestIntegrationModeWiresRealDependenciesAndPermitsTheDevNexusFlags(t *testing.T) {
	cfg := validRealConfig()
	cfg.Mode = ModeIntegration
	if !cfg.UsesRealDependencies() {
		t.Fatal("UsesRealDependencies() = false, want integration mode to wire real dependencies")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want a real-shaped integration config accepted", err)
	}

	// The relaxations real mode refuses outright are exactly what this mode is
	// for, and it must accept them together rather than one at a time.
	cfg.Nexus.EnvelopeAuthMode = NexusEnvelopeAuthTrustedDev
	cfg.Nexus.AllowInsecureDescriptor = true

	// Trusted transport is not a free pass: with envelope signatures off, the
	// NATS transport IS the authentication boundary, so it must be
	// authenticated. Integration mode keeps that requirement.
	unauthenticated := cfg
	unauthenticated.Nexus.AuthTokenFile = ""
	unauthenticated.Nexus.NATSURL = "nats://nexus.example.org:4222"
	if err := unauthenticated.Validate(); err == nil ||
		!strings.Contains(err.Error(), "requires an authenticated NATS transport") {
		t.Fatalf("Validate() error = %v, want trusted transport to require an authenticated broker", err)
	}

	cfg.Nexus.NATSURL = "nats://app:secret@nexus.example.org:4222"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want integration mode to admit the dev Nexus flags", err)
	}

	// Real mode still refuses both, so the ban was narrowed to the posture and
	// not deleted.
	cfg.Mode = ModeReal
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want real mode to keep refusing the dev Nexus flags")
	}
	for _, want := range []string{
		"nexus.envelope_auth_mode must not be trusted_nats_dev in real mode",
		"nexus.allow_insecure_descriptor must be false in real mode",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Validate() error = %v, want it to contain %q", err, want)
		}
	}
}

// Every rule that is about dialling real dependencies has to fire in
// integration mode too. A rule that only fired in real mode would be a
// requirement integration deployments silently skip, which is how the mode
// would rot into a second, weaker contract.
func TestIntegrationModeEnforcesTheSameDependencyRulesAsRealMode(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{name: "nats url required without the on-chain identity", mutate: func(c *Config) { c.Nexus.NATSURL, c.Nexus.NATSUserKeyFile = "", "" }, want: "nexus.nats_url"},
		{name: "operator address required", mutate: func(c *Config) { c.LocalIdentity.OperatorAddress = "" }, want: "local_identity.operator_address"},
		{name: "signer uri validated", mutate: func(c *Config) { c.Signer.URI = "ftp://signer" }, want: "signer.uri"},
		{name: "retry delay required", mutate: func(c *Config) { c.TaskExecution.RetryDelayMS = 0 }, want: "task_execution.retry_delay_ms"},
		{name: "challenge verifier frozen", mutate: func(c *Config) { c.ChallengeVerifier.Enabled = true }, want: "challenge_verifier.enabled"},
		{name: "self rescue frozen", mutate: func(c *Config) { c.SelfRescue.Enabled = true }, want: "self_rescue.enabled"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			real := validRealConfig()
			testCase.mutate(&real)
			realErr := real.Validate()
			if realErr == nil || !strings.Contains(realErr.Error(), testCase.want) {
				t.Fatalf("real mode Validate() = %v, want %q", realErr, testCase.want)
			}

			integration := validRealConfig()
			integration.Mode = ModeIntegration
			testCase.mutate(&integration)
			integrationErr := integration.Validate()
			if integrationErr == nil || !strings.Contains(integrationErr.Error(), testCase.want) {
				t.Fatalf("integration mode Validate() = %v, want the same %q refusal as real mode", integrationErr, testCase.want)
			}
		})
	}
}

func TestModeMustBeOneOfTheThreeKnownValues(t *testing.T) {
	cfg := validRealConfig()
	cfg.Mode = "production"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "mode must be fake, real or integration") {
		t.Fatalf("Validate() error = %v, want the mode allowlist to name all three values", err)
	}
}

// TestDowngradeDescriptorTLSIsAnIntegrationOnlySwitchCoupledToThePlaintextOptIn
// pins the compatibility path for a devnet BuilderSet that publishes https://
// in front of an ingress terminating no TLS: integration mode may dial it in
// the clear, real mode may not, and neither may do so without also stating the
// plaintext opt-in, because a downgraded endpoint IS a plaintext one.
func TestDowngradeDescriptorTLSIsAnIntegrationOnlySwitchCoupledToThePlaintextOptIn(t *testing.T) {
	cfg := validRealConfig()
	cfg.Nexus.DowngradeDescriptorTLS = true
	cfg.Nexus.AllowInsecureDescriptor = true
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "nexus.downgrade_descriptor_tls must be false in real mode") {
		t.Fatalf("Validate() error = %v, want real mode refusal of downgrade_descriptor_tls", err)
	}

	cfg = validRealConfig()
	cfg.Mode = ModeIntegration
	cfg.Nexus.DowngradeDescriptorTLS = true
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "nexus.downgrade_descriptor_tls requires nexus.allow_insecure_descriptor") {
		t.Fatalf("Validate() error = %v, want the downgrade to require the plaintext opt-in", err)
	}

	cfg.Nexus.AllowInsecureDescriptor = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want integration mode to accept both switches together", err)
	}

	// The default is off: honouring the published scheme must not depend on an
	// operator remembering to say so.
	if validRealConfig().Nexus.DowngradeDescriptorTLS {
		t.Fatal("DowngradeDescriptorTLS = true by default, want the published scheme honoured")
	}
}

// The switch is reachable from the environment like the other Nexus dev flags,
// so a containerised devnet node can set it without a bespoke config file.
func TestDowngradeDescriptorTLSCanBeSetFromTheEnvironment(t *testing.T) {
	path := writeConfig(t, `
chain_id: trueopen-devnet-1
admin:
  uds_path: /tmp/cortexd.sock
model_management:
  transport: fake
node:
  rpc_endpoint: http://127.0.0.1:26657
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/cortex.kv
signer:
  uri: file:///tmp/cortex/signer.key
nexus:
  allow_insecure_descriptor: true
`)
	cfg, err := LoadFileWithOverrides(path, map[string]string{
		"nexus_downgrade_descriptor_tls": "true",
	})
	if err != nil {
		t.Fatalf("LoadFileWithOverrides() error = %v", err)
	}
	if !cfg.Nexus.DowngradeDescriptorTLS {
		t.Fatal("Nexus.DowngradeDescriptorTLS = false, want the override applied")
	}
	if _, err := LoadFileWithOverrides(path, map[string]string{
		"nexus_downgrade_descriptor_tls": "maybe",
	}); err == nil || !strings.Contains(err.Error(), "invalid nexus_downgrade_descriptor_tls") {
		t.Fatalf("LoadFileWithOverrides() error = %v, want a refusal naming the key", err)
	}
}
