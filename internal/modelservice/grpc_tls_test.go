package modelservice

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Deployment security baseline: cortex must reach a model service on another host
// over TLS. The model service uses a self-signed certificate, and the cortex config
// names either the certificate file (ca_file) or the public key fingerprint
// (pubkey_hash = sha256(SubjectPublicKeyInfo)), checked at dial time.

func selfSignedCert(t *testing.T) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "model-service"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, der
}

func TestGRPCTLSPubkeyHashVerifierAcceptsOnlyTheCommittedKey(t *testing.T) {
	leaf, der := selfSignedCert(t)
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	want := hex.EncodeToString(sum[:])

	cfg, err := grpcTLSConfig(GRPCTLS{PubkeyHash: want})
	if err != nil {
		t.Fatalf("grpcTLSConfig: %v", err)
	}
	if cfg == nil || cfg.VerifyPeerCertificate == nil || !cfg.InsecureSkipVerify {
		t.Fatal("pubkey_hash must install a peer-certificate verifier instead of the CA chain")
	}
	if err := cfg.VerifyPeerCertificate([][]byte{der}, nil); err != nil {
		t.Fatalf("matching certificate rejected: %v", err)
	}
	other, otherDER := selfSignedCert(t)
	_ = other
	if err := cfg.VerifyPeerCertificate([][]byte{otherDER}, nil); err == nil || !strings.Contains(err.Error(), "pubkey_hash") {
		t.Fatalf("mismatched certificate accepted or wrong error: %v", err)
	}
}

func TestGRPCTLSCAFileTrustsTheGivenCertificate(t *testing.T) {
	_, der := selfSignedCert(t)
	path := filepath.Join(t.TempDir(), "model-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := grpcTLSConfig(GRPCTLS{CAFile: path})
	if err != nil {
		t.Fatalf("grpcTLSConfig: %v", err)
	}
	if cfg == nil || cfg.RootCAs == nil || cfg.InsecureSkipVerify {
		t.Fatal("ca_file must produce a root pool with normal chain verification")
	}
}

func TestGRPCTLSDisabledMeansPlaintext(t *testing.T) {
	cfg, err := grpcTLSConfig(GRPCTLS{})
	if err != nil || cfg != nil {
		t.Fatalf("no tls settings must mean plaintext dial, got cfg=%v err=%v", cfg, err)
	}
	if _, err := grpcTLSConfig(GRPCTLS{PubkeyHash: "not-hex"}); err == nil || !strings.Contains(err.Error(), "pubkey_hash") {
		t.Fatalf("malformed pubkey_hash = %v, want an error naming pubkey_hash", err)
	}
	if _, err := grpcTLSConfig(GRPCTLS{CAFile: "/nonexistent/ca.pem"}); err == nil || !strings.Contains(err.Error(), "ca_file") {
		t.Fatalf("missing ca_file = %v, want an error naming ca_file", err)
	}
}
