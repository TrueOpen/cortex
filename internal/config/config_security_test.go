package config

import (
	"strings"
	"testing"
)

// The deployment security baseline (monorepo 20-service-design/deployment-security-baseline) and the ADR-0016
// transition state, as checked in real mode: NATS over tls:// with a creds file, https
// on the node ports, and TLS required for a model service on another host. The
// integration / fake modes are unchanged.

func hardenedRealConfig() Config {
	cfg := validRealConfig()
	cfg.Nexus.NATSURL = "tls://nats.example:4222"
	cfg.Nexus.NATSUserKeyFile = "/etc/cortex/nats-user.nk"
	cfg.Nexus.NATSCAFile = "/etc/cortex/nats-ca.pem"
	cfg.Node.RPCEndpoint = "https://node.example:26657"
	cfg.Node.RESTEndpoint = "https://node.example:1317"
	cfg.ModelManagement.Endpoint = "model.example:9090"
	cfg.ModelManagement.TLS = ModelServiceTLSConfig{PubkeyHash: strings.Repeat("ab", 32)}
	return cfg
}

func TestRealModeAcceptsAHardenedConfig(t *testing.T) {
	cfg := hardenedRealConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("hardened real config rejected: %v", err)
	}
}

func TestRealModeAllowsLoopbackNodeAndModelServiceInPlaintext(t *testing.T) {
	cfg := hardenedRealConfig()
	cfg.Nexus.NATSURL = "nats://127.0.0.1:4222" // same-host NATS in plaintext + token is allowed
	cfg.Nexus.NATSCredsFile = ""
	cfg.Nexus.AuthTokenFile = "/tmp/token"
	cfg.Node.RPCEndpoint = "http://127.0.0.1:26657"
	cfg.Node.RESTEndpoint = "http://localhost:1317"
	cfg.ModelManagement.Endpoint = "127.0.0.1:9090"
	cfg.ModelManagement.TLS = ModelServiceTLSConfig{}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("loopback plaintext endpoints rejected: %v", err)
	}
}

func TestRealModeRefusesWeakTransportSettings(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"plaintext nats", func(c *Config) { c.Nexus.NATSURL = "nats://nats.example:4222" }, "nexus.nats_url must use tls://"},
		{"plaintext remote rpc", func(c *Config) { c.Node.RPCEndpoint = "http://node.example:26657" }, "node.rpc_endpoint"},
		{"plaintext remote rest", func(c *Config) { c.Node.RESTEndpoint = "http://node.example:1317" }, "node.rest_endpoint"},
		{"remote model service without tls", func(c *Config) { c.ModelManagement.TLS = ModelServiceTLSConfig{} }, "model_management.tls"},
		{"model service tls with both ca and hash", func(c *Config) {
			c.ModelManagement.TLS = ModelServiceTLSConfig{CAFile: "/etc/cortex/model-ca.pem", PubkeyHash: strings.Repeat("ab", 32)}
		}, "model_management.tls"},
		{"model service malformed hash", func(c *Config) { c.ModelManagement.TLS = ModelServiceTLSConfig{PubkeyHash: "zz"} }, "pubkey_hash"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := hardenedRealConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want an error naming %s", err, tc.want)
			}
		})
	}
}

// With the on-chain identity the NATS address and certificate may come from a
// Builder's sentinel (interface-and-topic-list §4.12): leaving both unset is a valid
// real-mode config. Whether the Builder then serves a certificate is checked when
// connecting, and a remote server with none is refused there.
func TestRealModeTakesNATSAddressAndCertificateFromSentinel(t *testing.T) {
	cfg := hardenedRealConfig()
	cfg.Nexus.NATSURL, cfg.Nexus.NATSCAFile = "", ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("real mode without nats_url and nats_ca_file rejected: %v", err)
	}
	cfg.Nexus.NATSUserKeyFile = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "nexus.nats_url is required unless nexus.nats_user_key_file") {
		t.Fatalf("Validate = %v, want nats_url required without the on-chain identity", err)
	}
}

// Baseline items 4 and 5: a model service on another host must use TLS, with no
// "a controlled internal network may be plaintext" exemption; the old allow_plaintext
// field is refused outright by strict YAML validation.
func TestRealModeHasNoPlaintextExemptionForRemoteModelService(t *testing.T) {
	cfg := hardenedRealConfig()
	cfg.ModelManagement.TLS = ModelServiceTLSConfig{}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "model_management.tls") {
		t.Fatalf("remote plaintext model service accepted: %v", err)
	}
	if strings.Contains(err.Error(), "allow_plaintext") {
		t.Fatalf("error still advertises the removed allow_plaintext switch: %v", err)
	}
}

func TestIntegrationModeKeepsPlaintextTransports(t *testing.T) {
	cfg := validRealConfig()
	cfg.Mode = ModeIntegration
	cfg.Nexus.NATSURL = "nats://127.0.0.1:4222"
	cfg.Nexus.AuthTokenFile = "/tmp/token"
	cfg.Nexus.AllowInsecureDescriptor = true
	cfg.Node.RPCEndpoint = "http://node.example:26657"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("integration mode must keep today's plaintext configs: %v", err)
	}
}

func TestTransportSecurityEnvironment(t *testing.T) {
	path := writeConfig(t, `
chain_id: trueopen-devnet-1
admin:
  uds_path: /tmp/cortexd.sock
node:
  rpc_endpoint: http://127.0.0.1:26657
artifacts:
  root: /tmp/cortex/evidence
store:
  path: /tmp/cortex/store.kv
signer:
  uri: file:///tmp/cortex/signer.key
`)
	t.Setenv("CORTEX_NEXUS_NATS_CA_FILE", "/etc/cortex/nats-ca.pem")
	t.Setenv("CORTEX_NEXUS_NATS_CREDS_FILE", "/etc/cortex/nats.creds")
	t.Setenv("CORTEX_MODEL_SERVICE_TLS_PUBKEY_HASH", strings.Repeat("cd", 32))
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if cfg.Nexus.NATSCAFile != "/etc/cortex/nats-ca.pem" || cfg.Nexus.NATSCredsFile != "/etc/cortex/nats.creds" ||
		cfg.ModelManagement.TLS.PubkeyHash != strings.Repeat("cd", 32) {
		t.Fatalf("environment not applied: nexus=%+v model=%+v", cfg.Nexus, cfg.ModelManagement.TLS)
	}
}
