package signer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/TrueOpen/cortex/internal/codec"
)

// ErrCosmosTxUnsupported is returned by the in-process signer for chain
// transaction signing. Producing a valid TxRaw needs the chain's protobuf Msg
// definitions and an agreed SIGN_MODE; emitting a guess would create
// transactions the chain rejects, so this fails closed instead.
var ErrCosmosTxUnsupported = fmt.Errorf("%w: in-process signer cannot build Cosmos transactions", ErrRejected)

// KeyRef names one configured key. The ref is a keystore file name relative to
// the signer directory, or an absolute path.
type KeyRef struct {
	Ref string
}

// LocalSigner signs with key material held in this process. It reads standard
// Web3 Secret Storage (keystore v3) files, so keys can be created and rotated
// with geth, ethers, web3.py or any other keystore tooling.
//
// Holding keys in the daemon means a compromise of cortexd is a compromise of
// the keys. Prefer an external signing service for anything beyond
// integration environments.
type LocalSigner struct {
	hrp  string
	keys map[string]*Key
}

// NewLocalSigner decrypts the keystore file for each requested ref. A ref whose
// file is absent is simply not loaded, so a node can start with only the keys
// it needs right now and the caller decides which absences are fatal.
func NewLocalSigner(dir string, password []byte, hrp string, refs []KeyRef) (*LocalSigner, error) {
	if strings.TrimSpace(hrp) == "" {
		return nil, fmt.Errorf("bech32 hrp is required to derive signer addresses")
	}
	local := &LocalSigner{hrp: hrp, keys: make(map[string]*Key, len(refs))}
	for _, ref := range refs {
		if strings.TrimSpace(ref.Ref) == "" {
			continue
		}
		path := ref.Ref
		if !filepath.IsAbs(path) {
			path = filepath.Join(dir, path)
		}
		raw, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read keystore for %s: %w", ref.Ref, err)
		}
		if len(password) == 0 {
			return nil, fmt.Errorf("keystore %s requires a password", ref.Ref)
		}
		privateHex, err := decryptKeystoreV3(raw, password)
		if err != nil {
			return nil, fmt.Errorf("keystore %s: %w", ref.Ref, err)
		}
		private, err := parsePrivateKeyHex(privateHex)
		if err != nil {
			return nil, fmt.Errorf("keystore %s: %w", ref.Ref, err)
		}
		if _, exists := local.keys[ref.Ref]; exists {
			return nil, fmt.Errorf("duplicate signer key reference %s", ref.Ref)
		}
		local.keys[ref.Ref] = &Key{Ref: ref.Ref, private: private}
	}
	if len(local.keys) == 0 {
		return nil, fmt.Errorf("no keystore file resolved under %s", dir)
	}
	return local, nil
}

// Has reports whether a key ref was loaded, so startup can check
// what is available before anything tries to sign with it.
func (s *LocalSigner) Has(keyRef string) bool {
	if s == nil {
		return false
	}
	_, ok := s.keys[keyRef]
	return ok
}

// AddressFor returns the bech32 address a loaded key signs as. Callers use it
// to confirm a key matches the identity the chain expects before relying on it.
func (s *LocalSigner) AddressFor(keyRef string) (string, bool) {
	if s == nil {
		return "", false
	}
	key, ok := s.keys[keyRef]
	if !ok {
		return "", false
	}
	id, err := identityFor(key.private.PubKey(), s.hrp)
	if err != nil {
		return "", false
	}
	return id.Address, true
}

// Keys returns the public identity of every loaded key, safe to log.
func (s *LocalSigner) Keys() []KeyDescriptor {
	if s == nil {
		return nil
	}
	out := make([]KeyDescriptor, 0, len(s.keys))
	for _, key := range s.keys {
		identity, err := identityFor(key.private.PubKey(), s.hrp)
		if err != nil {
			continue
		}
		out = append(out, KeyDescriptor{
			Ref:              key.Ref,
			CompressedPubkey: identity.CompressedPubkeyHex, Address: identity.Address,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Ref < out[j].Ref
	})
	return out
}

func (s *LocalSigner) SignDigest(_ context.Context, req DigestRequest) ([]byte, error) {
	if err := validateKey(req.KeyRef, req.ExpectedSignerAddress); err != nil {
		return nil, err
	}
	if req.Digest == (codec.Hash{}) {
		return nil, fmt.Errorf("digest is required")
	}
	key, ok := s.keys[req.KeyRef]
	if !ok {
		return nil, fmt.Errorf("%w: no key for %s", ErrRejected, req.KeyRef)
	}
	identity, err := identityFor(key.private.PubKey(), s.hrp)
	if err != nil {
		return nil, err
	}
	// The caller states which identity it believes it signs as. A mismatch has
	// to fail rather than produce a valid signature by the wrong key.
	if identity.Address != req.ExpectedSignerAddress {
		return nil, fmt.Errorf("%w: signer address mismatch", ErrRejected)
	}
	return signCompact(key.private, req.Digest)
}

// CanSignCosmosTx is false until SignDoc assembly is implemented. Reporting
// this honestly is what stops the daemon from activating a workload that
// cannot submit commit or result transactions.
func (s *LocalSigner) CanSignCosmosTx() bool { return false }

func (s *LocalSigner) SignCosmosTx(context.Context, CosmosTxRequest) ([]byte, error) {
	return nil, ErrCosmosTxUnsupported
}

// zero wipes secret bytes once they are no longer needed. Go's GC can still
// have copied them, but clearing the caller's slice is the part we control.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
