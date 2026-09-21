package config

import (
	"strings"
	"testing"
)

func chainIdentityRealConfig() Config {
	cfg := hardenedRealConfig()
	cfg.Nexus.NATSCredsFile = ""
	cfg.Nexus.NATSUserKeyFile = "/var/lib/cortex/nats-user.nk"
	return cfg
}

func TestRealModeAcceptsChainIdentityNATSAuth(t *testing.T) {
	cfg := chainIdentityRealConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("hardened chain-identity config rejected: %v", err)
	}
}

func TestRealModeRequiresNATSUserKeyFileForRemoteNATS(t *testing.T) {
	cfg := chainIdentityRealConfig()
	cfg.Nexus.NATSUserKeyFile = ""
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "nexus.nats_user_key_file is required in real mode") {
		t.Fatalf("want nats_user_key_file requirement, got %v", err)
	}
}

func TestRealModeRejectsRetiredCredsFile(t *testing.T) {
	cfg := chainIdentityRealConfig()
	cfg.Nexus.NATSCredsFile = "/etc/cortex/nats.creds"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "nexus.nats_creds_file is retired in real mode") {
		t.Fatalf("want creds refusal, got %v", err)
	}
}

func TestRealModeLoopbackNATSStillNeedsNoUserKey(t *testing.T) {
	cfg := chainIdentityRealConfig()
	cfg.Nexus.NATSURL = "tls://127.0.0.1:4222"
	cfg.Nexus.NATSUserKeyFile = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("loopback NATS is a deployment choice and stays admitted: %v", err)
	}
}

func TestIntegrationModeStillAcceptsCredsFile(t *testing.T) {
	cfg := chainIdentityRealConfig()
	cfg.Mode = ModeIntegration
	cfg.Nexus.NATSUserKeyFile = ""
	cfg.Nexus.NATSCredsFile = "/etc/cortex/nats.creds"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("creds stay legal outside real mode until ADR-0016 P5: %v", err)
	}
}

func TestNATSUserKeyFileEnvOverride(t *testing.T) {
	cfg := validConfig()
	if err := setDeploymentValue(&cfg, "nexus_nats_user_key_file", "/tmp/k.nk"); err != nil {
		t.Fatalf("setDeploymentValue(nexus_nats_user_key_file) error = %v", err)
	}
	if cfg.Nexus.NATSUserKeyFile != "/tmp/k.nk" {
		t.Fatalf("env override not applied: %q", cfg.Nexus.NATSUserKeyFile)
	}
}
