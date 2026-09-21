package signer

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/SingaXYZ/cortex/internal/codec"
)

// Canonical Web3 Secret Storage test vectors. Using them as fixtures proves
// Cortex reads what geth, ethers and web3.py write, rather than only reading
// back something it produced itself.
const (
	web3Password   = "testpassword"
	web3PrivateKey = "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"

	web3PBKDF2Keystore = `{
	  "crypto": {
	    "cipher": "aes-128-ctr",
	    "cipherparams": {"iv": "6087dab2f9fdbbfaddc31a909735c1e6"},
	    "ciphertext": "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
	    "kdf": "pbkdf2",
	    "kdfparams": {"c": 262144, "dklen": 32, "prf": "hmac-sha256", "salt": "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"},
	    "mac": "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
	  },
	  "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
	  "version": 3
	}`

	web3ScryptKeystore = `{
	  "crypto": {
	    "cipher": "aes-128-ctr",
	    "cipherparams": {"iv": "83dbcc02d8ccb40e466191a123791e0e"},
	    "ciphertext": "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
	    "kdf": "scrypt",
	    "kdfparams": {"dklen": 32, "n": 262144, "p": 8, "r": 1, "salt": "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"},
	    "mac": "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
	  },
	  "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
	  "version": 3
	}`
)

func TestDecryptKeystoreV3MatchesWeb3SecretStorageVectors(t *testing.T) {
	for name, vector := range map[string]string{"pbkdf2": web3PBKDF2Keystore, "scrypt": web3ScryptKeystore} {
		t.Run(name, func(t *testing.T) {
			got, err := decryptKeystoreV3([]byte(vector), []byte(web3Password))
			if err != nil {
				t.Fatalf("decryptKeystoreV3: %v", err)
			}
			if got != web3PrivateKey {
				t.Fatalf("private key = %s, want %s", got, web3PrivateKey)
			}
		})
	}
}

func TestDecryptKeystoreV3RejectsWrongPassword(t *testing.T) {
	_, err := decryptKeystoreV3([]byte(web3PBKDF2Keystore), []byte("nope"))
	if err == nil || !strings.Contains(err.Error(), "mac mismatch") {
		t.Fatalf("error = %v, want a mac mismatch", err)
	}
}

// keystoreDir writes the canonical keystore under the given file names.
func keystoreDir(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(web3ScryptKeystore), 0o600); err != nil {
			t.Fatalf("write keystore: %v", err)
		}
	}
	return dir
}

func TestLocalSignerSignsAndVerifies(t *testing.T) {
	dir := keystoreDir(t, "operator.json")
	local, err := NewLocalSigner(dir, []byte(web3Password), "trueopen", []KeyRef{{Ref: "operator.json"}})
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	keys := local.Keys()
	if len(keys) != 1 || keys[0].Ref != "operator.json" {
		t.Fatalf("Keys() = %#v", keys)
	}
	// The chain rejects anything that is not a 33-byte compressed point.
	if len(keys[0].CompressedPubkey) != 66 ||
		(!strings.HasPrefix(keys[0].CompressedPubkey, "02") && !strings.HasPrefix(keys[0].CompressedPubkey, "03")) {
		t.Fatalf("compressed pubkey %q is not the on-chain form", keys[0].CompressedPubkey)
	}
	if !strings.HasPrefix(keys[0].Address, "trueopen1") {
		t.Fatalf("address = %q, want a trueopen1 prefix", keys[0].Address)
	}

	digest := codec.HashWithDomain("TRUEOPEN_WORKER_HANDRAISE_V1", []byte("payload"))
	signature, err := local.SignDigest(context.Background(), DigestRequest{
		KeyRef: "operator.json", ExpectedSignerAddress: keys[0].Address, Digest: digest,
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	if len(signature) != 64 {
		t.Fatalf("signature length = %d, want 64", len(signature))
	}
	if !verifyCompact(t, keys[0].CompressedPubkey, digest, signature) {
		t.Fatalf("signature does not verify against the advertised public key")
	}
}

func TestVerifyDigestSignatureUsesCurrentServicePublicKey(t *testing.T) {
	dir := keystoreDir(t, "service.json")
	local, err := NewLocalSigner(dir, []byte(web3Password), "trueopen", []KeyRef{{Ref: "service.json"}})
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	key := local.Keys()[0]
	digest := codec.HashWithDomain("TRUEOPEN_SERVICE_KEY_READINESS_V1", []byte("binding"))
	signature, err := local.SignDigest(context.Background(), DigestRequest{
		KeyRef: "service.json", ExpectedSignerAddress: key.Address, Digest: digest,
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	if err := VerifyDigestSignature(key.CompressedPubkey, digest, signature); err != nil {
		t.Fatalf("VerifyDigestSignature: %v", err)
	}
	wrongDigest := codec.HashWithDomain("TRUEOPEN_SERVICE_KEY_READINESS_V1", []byte("other"))
	if err := VerifyDigestSignature(key.CompressedPubkey, wrongDigest, signature); err == nil {
		t.Fatal("VerifyDigestSignature accepted a signature for another binding")
	}
	if err := VerifyDigestSignature(key.CompressedPubkey, digest, signature[:63]); err == nil {
		t.Fatal("VerifyDigestSignature accepted a short signature")
	}
}

// verifyCompact checks the 64-byte [R||S] signature independently rather than
// re-running the production signing path.
func verifyCompact(t *testing.T, compressedPubkeyHex string, digest codec.Hash, signature []byte) bool {
	t.Helper()
	pubBytes, err := hex.DecodeString(compressedPubkeyHex)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	public, err := secp256k1.ParsePubKey(pubBytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	var r, s secp256k1.ModNScalar
	r.SetByteSlice(signature[:32])
	s.SetByteSlice(signature[32:])
	if s.IsOverHalfOrder() {
		t.Fatalf("signature is not low-S")
	}
	return ecdsa.NewSignature(&r, &s).Verify(digest[:], public)
}

func TestLocalSignerRejectsAddressMismatch(t *testing.T) {
	dir := keystoreDir(t, "operator.json")
	local, err := NewLocalSigner(dir, []byte(web3Password), "trueopen", []KeyRef{{Ref: "operator.json"}})
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	_, err = local.SignDigest(context.Background(), DigestRequest{
		KeyRef: "operator.json", ExpectedSignerAddress: "trueopen1someoneelse",
		Digest: codec.HashWithDomain("D", []byte("x")),
	})
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("SignDigest error = %v, want rejection", err)
	}
}

// A node may start with only its operator key: the service key is not used
// until Keeper reports the node ready and the workload activates.
func TestLocalSignerLoadsOnlyTheKeystoresThatExist(t *testing.T) {
	dir := keystoreDir(t, "operator.json")
	local, err := NewLocalSigner(dir, []byte(web3Password), "trueopen", []KeyRef{
		{Ref: "operator.json"},
		{Ref: "service.json"},
	})
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	if !local.Has("operator.json") {
		t.Fatalf("Has(operator) = false for a keystore that exists")
	}
	if local.Has("service.json") {
		t.Fatalf("Has(service) = true for a keystore that does not exist")
	}
}

func TestNewLocalSignerFailsClosed(t *testing.T) {
	dir := keystoreDir(t, "operator.json")
	refs := []KeyRef{{Ref: "operator.json"}}

	if _, err := NewLocalSigner(dir, []byte("wrong"), "trueopen", refs); err == nil {
		t.Fatalf("NewLocalSigner accepted a wrong password")
	}
	if _, err := NewLocalSigner(dir, nil, "trueopen", refs); err == nil {
		t.Fatalf("NewLocalSigner loaded a keystore without a password")
	}
	if _, err := NewLocalSigner(dir, []byte(web3Password), "", refs); err == nil {
		t.Fatalf("NewLocalSigner accepted an empty hrp")
	}
	if _, err := NewLocalSigner(dir, []byte(web3Password), "trueopen", []KeyRef{{Ref: "absent.json"}}); err == nil {
		t.Fatalf("NewLocalSigner accepted a directory with no resolvable keystore")
	}
}

// Chain writes must fail loudly rather than emit a transaction the chain will
// reject.
func TestLocalSignerRefusesCosmosTx(t *testing.T) {
	dir := keystoreDir(t, "operator.json")
	local, err := NewLocalSigner(dir, []byte(web3Password), "trueopen", []KeyRef{{Ref: "operator.json"}})
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	if _, err := local.SignCosmosTx(context.Background(), CosmosTxRequest{}); !errors.Is(err, ErrCosmosTxUnsupported) {
		t.Fatalf("SignCosmosTx error = %v, want ErrCosmosTxUnsupported", err)
	}
}

func TestOpenDispatchesOnScheme(t *testing.T) {
	dir := keystoreDir(t, "operator.json")
	opts := OpenOptions{HRP: "trueopen", KeyRefs: []KeyRef{{Ref: "operator.json"}}}

	remote, err := Open("http://127.0.0.1:9080", opts)
	if err != nil {
		t.Fatalf("Open(http): %v", err)
	}
	if _, ok := remote.(*Client); !ok {
		t.Fatalf("Open(http) = %T, want *Client", remote)
	}

	t.Setenv("CORTEX_SIGNER_TEST_PW", web3Password)
	local, err := Open("file://"+dir, OpenOptions{HRP: opts.HRP, KeyRefs: opts.KeyRefs, PasswordEnv: "CORTEX_SIGNER_TEST_PW"})
	if err != nil {
		t.Fatalf("Open(file): %v", err)
	}
	if _, ok := local.(*LocalSigner); !ok {
		t.Fatalf("Open(file) = %T, want *LocalSigner", local)
	}

	for _, uri := range []string{"", "kms://cortex/key", "memory://operator", "file://remote-host/keys"} {
		if _, err := Open(uri, opts); err == nil {
			t.Fatalf("Open(%q) accepted an unsupported signer uri", uri)
		}
	}
}

func TestOpenResolvesPasswordSources(t *testing.T) {
	dir := keystoreDir(t, "operator.json")
	base := OpenOptions{HRP: "trueopen", KeyRefs: []KeyRef{{Ref: "operator.json"}}}

	t.Run("env", func(t *testing.T) {
		t.Setenv("CORTEX_SIGNER_TEST_PW", web3Password)
		opts := base
		opts.PasswordEnv = "CORTEX_SIGNER_TEST_PW"
		if _, err := Open("file://"+dir, opts); err != nil {
			t.Fatalf("Open: %v", err)
		}
	})
	t.Run("file", func(t *testing.T) {
		pwPath := filepath.Join(t.TempDir(), "pw")
		if err := os.WriteFile(pwPath, []byte(web3Password+"\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		opts := base
		opts.PasswordFile = pwPath
		if _, err := Open("file://"+dir, opts); err != nil {
			t.Fatalf("Open: %v", err)
		}
	})
	t.Run("stdin", func(t *testing.T) {
		opts := base
		opts.PasswordStdin = true
		opts.Stdin = strings.NewReader(web3Password + "\n")
		if _, err := Open("file://"+dir, opts); err != nil {
			t.Fatalf("Open: %v", err)
		}
	})
	t.Run("two sources rejected", func(t *testing.T) {
		opts := base
		opts.PasswordEnv, opts.PasswordFile = "A", "/b"
		if _, err := Open("file://"+dir, opts); err == nil {
			t.Fatalf("Open accepted two password sources")
		}
	})
	t.Run("missing env", func(t *testing.T) {
		opts := base
		opts.PasswordEnv = "CORTEX_SIGNER_ABSENT"
		if _, err := Open("file://"+dir, opts); err == nil {
			t.Fatalf("Open accepted an unset password variable")
		}
	})
}

// A file:// URI with a host names a remote machine. Treating it as a local
// path would silently open a different directory than the operator wrote.
func TestOpenRejectsFileURIWithHost(t *testing.T) {
	dir := keystoreDir(t, "operator.json")
	t.Setenv("CORTEX_SIGNER_TEST_PW", web3Password)
	opts := OpenOptions{
		HRP:         "trueopen",
		KeyRefs:     []KeyRef{{Ref: "operator.json"}},
		PasswordEnv: "CORTEX_SIGNER_TEST_PW",
	}
	// The directory really exists, so a rejection here cannot be a false pass
	// caused by a missing path.
	if _, err := Open("file://"+dir, opts); err != nil {
		t.Fatalf("Open(file://%s) error = %v, want success", dir, err)
	}
	_, err := Open("file://remote-host"+dir, opts)
	if err == nil {
		t.Fatalf("Open accepted a file URI with a host")
	}
	if !strings.Contains(err.Error(), "must not have a host") {
		t.Fatalf("error = %v, want a host rejection", err)
	}
}

// The in-process signer must say plainly that it cannot build chain
// transactions, so the daemon does not advertise a ready tx broadcaster.
func TestLocalSignerReportsNoCosmosTxCapability(t *testing.T) {
	dir := keystoreDir(t, "operator.json")
	local, err := NewLocalSigner(dir, []byte(web3Password), "trueopen", []KeyRef{{Ref: "operator.json"}})
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	if local.CanSignCosmosTx() {
		t.Fatalf("CanSignCosmosTx() = true for a signer whose SignCosmosTx always fails")
	}
	if !NewClient(ClientConfig{Endpoint: "http://127.0.0.1:9080"}).CanSignCosmosTx() {
		t.Fatalf("CanSignCosmosTx() = false for the remote signing client")
	}
}

func TestLocalSignerAddressForReportsLoadedIdentity(t *testing.T) {
	dir := keystoreDir(t, "operator.json")
	local, err := NewLocalSigner(dir, []byte(web3Password), "trueopen", []KeyRef{{Ref: "operator.json"}})
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	address, ok := local.AddressFor("operator.json")
	if !ok || address != local.Keys()[0].Address {
		t.Fatalf("AddressFor = %q/%v, want %q", address, ok, local.Keys()[0].Address)
	}
	if _, ok := local.AddressFor("absent.json"); ok {
		t.Fatalf("AddressFor reported an absent key as loaded")
	}
}
