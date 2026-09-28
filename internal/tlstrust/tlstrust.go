// Package tlstrust builds the client TLS configuration for a peer that serves a
// self-signed certificate: the model service and the chain node. The operator
// names the trust anchor in one of two ways:
//
//   - ca_file: the peer certificate (or the CA that issued it) in PEM. The peer
//     is verified as a normal certificate chain, hostname included, against this
//     pool only.
//   - pubkey_hash: hex(sha256(SubjectPublicKeyInfo DER)) of the peer's leaf
//     certificate, 64 lowercase hex characters. The peer is accepted when its
//     leaf carries exactly that public key; issuer, validity dates and hostname
//     are not checked, so the pin alone is the binding.
//
// The fingerprint is the same one nexus publishes as tls_pubkey_hash, so an
// operator computes every pin with one command:
//
//	openssl x509 -in cert.pem -noout -pubkey | openssl pkey -pubin -outform DER | sha256sum | cut -d" " -f1
package tlstrust

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
)

var pubkeyHashHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// PubkeyHash is hex(sha256(SubjectPublicKeyInfo DER)) of a certificate.
func PubkeyHash(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// ValidPubkeyHash reports whether value is 64 lowercase hex characters.
func ValidPubkeyHash(value string) bool {
	return pubkeyHashHex.MatchString(value)
}

// ClientConfig turns a ca_file / pubkey_hash pair into a client tls.Config.
// label prefixes every error (for example "model service tls"). It returns
// nil, nil when neither is set, meaning the caller keeps its default: plaintext
// for the model service, the system root CAs for an https node endpoint.
func ClientConfig(label, caFile, pubkeyHash string) (*tls.Config, error) {
	ca, hash := strings.TrimSpace(caFile), strings.TrimSpace(strings.ToLower(pubkeyHash))
	switch {
	case ca == "" && hash == "":
		return nil, nil
	case ca != "" && hash != "":
		return nil, fmt.Errorf("%s: set ca_file or pubkey_hash, not both", label)
	case hash != "":
		if !ValidPubkeyHash(hash) {
			return nil, fmt.Errorf("%s: pubkey_hash must be 64 lowercase hex", label)
		}
		return &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec // verification moves to VerifyPeerCertificate, against the public key fingerprint
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return fmt.Errorf("%s: peer presented no certificate (pubkey_hash check)", label)
				}
				leaf, err := x509.ParseCertificate(rawCerts[0])
				if err != nil {
					return fmt.Errorf("%s: parse peer certificate: %w", label, err)
				}
				if got := PubkeyHash(leaf); got != hash {
					return fmt.Errorf("%s: certificate pubkey_hash %s does not match configured %s", label, got, hash)
				}
				return nil
			},
		}, nil
	default:
		pemBytes, err := os.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("%s: read ca_file: %w", label, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("%s: ca_file %s contains no certificate", label, ca)
		}
		return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, nil
	}
}

// HTTPTransport returns an http.RoundTripper that trusts the peer named by
// caFile or pubkeyHash, built on a clone of http.DefaultTransport so proxy,
// keep-alive and timeout defaults stay the same. It returns a nil RoundTripper
// when neither is set, so an http.Client using it falls back to
// http.DefaultTransport and the system root CAs, exactly as before.
//
// One transport carries one trust anchor, so its connection pool never mixes
// connections verified under different pins.
func HTTPTransport(label, caFile, pubkeyHash string) (http.RoundTripper, error) {
	tlsConfig, err := ClientConfig(label, caFile, pubkeyHash)
	if err != nil {
		return nil, err
	}
	if tlsConfig == nil {
		return nil, nil
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	return transport, nil
}
