// Package natsidentity lets cortex join NATS with its on-chain identity (ADR-0016
// decision three; interface-and-topic-list §5.14): the node holds one NATS user key locally
// and signs a binding declaration for it with the Keeper-confirmed service key,
// which the NATS-side auth callback checks against the chain. cortex holds no
// secret issued by the NATS operator.
package natsidentity

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/nats-io/nkeys"
)

// LoadOrCreateUserKey reads the NATS user key seed (SU…) at path, generating one
// and writing it with 0600 when it does not exist. The returned created reports
// whether this call generated it. A non-user-class seed and a file that is not
// 0600 are both refused: the seed is the private key.
func LoadOrCreateUserKey(path string) (nkeys.KeyPair, bool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, false, fmt.Errorf("nats user key file path is required")
	}
	f, err := os.Open(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return createUserKey(path)
	case err != nil:
		return nil, false, fmt.Errorf("read nats user key %s: %w", path, err)
	}
	defer f.Close()
	// The permission check and the read share one fd, so no file can be swapped
	// between a stat-by-path and the read (TOCTOU). Stat follows symlinks here, and
	// that is deliberate: the mode bits must be checked on the file really pointed at.
	info, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, false, fmt.Errorf("nats user key %s has mode %o; it is a private key and must be 0600", path, perm)
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, false, fmt.Errorf("read nats user key %s: %w", path, err)
	}
	kp, err := nkeys.FromSeed(bytes.TrimSpace(raw))
	if err != nil {
		return nil, false, fmt.Errorf("nats user key %s is not an nkey seed: %w", path, err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return nil, false, err
	}
	if !nkeys.IsValidPublicUserKey(pub) {
		return nil, false, fmt.Errorf("nats user key %s is not a user key (want SU… seed, public key U…), got %s…", path, pub[:2])
	}
	return kp, false, nil
}

// createUserKey generates a fresh NATS user key and writes it to path with O_EXCL
// exclusive creation, so two concurrent processes cannot overwrite each other.
func createUserKey(path string) (nkeys.KeyPair, bool, error) {
	kp, err := nkeys.CreateUser()
	if err != nil {
		return nil, false, fmt.Errorf("generate nats user key: %w", err)
	}
	seed, err := kp.Seed()
	if err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("create nats user key directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, false, fmt.Errorf("create nats user key %s: %w", path, err)
	}
	if _, err := f.Write(append(seed, '\n')); err != nil {
		f.Close()
		return nil, false, fmt.Errorf("write nats user key %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return nil, false, fmt.Errorf("close nats user key %s: %w", path, err)
	}
	return kp, true, nil
}
