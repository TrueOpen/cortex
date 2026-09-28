package natsidentity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nats-io/nkeys"
)

func TestLoadOrCreateUserKeyCreatesThenReuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nats-user.nk")
	first, created, err := LoadOrCreateUserKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("first call must create the key")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("seed file mode = %o, want 0600", info.Mode().Perm())
	}
	second, created, err := LoadOrCreateUserKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("second call must load, not recreate")
	}
	firstPub, _ := first.PublicKey()
	secondPub, _ := second.PublicKey()
	if firstPub != secondPub || !strings.HasPrefix(firstPub, "U") {
		t.Fatalf("keys differ or not a user key: %s / %s", firstPub, secondPub)
	}
}

func TestLoadOrCreateUserKeyRejectsNonUserSeed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nats-user.nk")
	acct, _ := nkeys.CreateAccount()
	seed, _ := acct.Seed()
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateUserKey(path); err == nil || !strings.Contains(err.Error(), "user") {
		t.Fatalf("account seed must be refused, got %v", err)
	}
}

func TestLoadOrCreateUserKeyRejectsWorldReadableSeed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nats-user.nk")
	user, _ := nkeys.CreateUser()
	seed, _ := user.Seed()
	if err := os.WriteFile(path, seed, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateUserKey(path); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("world-readable seed must be refused, got %v", err)
	}
}

func TestLoadOrCreateUserKeyRefusesEmptyPath(t *testing.T) {
	if _, _, err := LoadOrCreateUserKey("  "); err == nil {
		t.Fatal("empty path must be refused")
	}
}

func TestLoadOrCreateUserKeyFromWireVectorSeed(t *testing.T) {
	// The wire vector's test-only seed: an all-zero raw seed. Once loaded, the
	// public key must equal the vector's nats_user_pubkey.
	path := filepath.Join(t.TempDir(), "nats-user.nk")
	if err := os.WriteFile(path, []byte("SUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEQ\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kp, _, err := LoadOrCreateUserKey(path)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := kp.PublicKey()
	if pub != "UA5WUJ54Z23KILLCUOUNAKTPBVZWKMQVO4O6EQ5GHLAERIMLLHNCTYM5" {
		t.Fatalf("pubkey = %s", pub)
	}
}

func TestLoadOrCreateUserKeyRejectsGarbageSeed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nats-user.nk")
	if err := os.WriteFile(path, []byte("not-an-nkey-seed"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadOrCreateUserKey(path)
	if err == nil {
		t.Fatal("garbage seed must be refused")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error must name the path %s, got %v", path, err)
	}
}
