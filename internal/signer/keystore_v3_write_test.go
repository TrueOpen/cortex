package signer

import (
	"encoding/json"
	"strings"
	"testing"
)

// keystoreTestKey is a throwaway 32-byte key. It never touches a network.
const keystoreTestKey = "4c0883a69102937d6231471b5dbb6204fe512961708279a3b0a1d0b1b9c82a1f"

// TestEncryptKeystoreV3RoundTripsThroughTheReader is the property that matters:
// this writer exists so a node can be onboarded without geth, and a keystore
// only the writer understands would be worth nothing. The reader under test is
// the same one that opens a geth file.
func TestEncryptKeystoreV3RoundTripsThroughTheReader(t *testing.T) {
	password := []byte("correct horse battery staple")

	document, err := EncryptKeystoreV3(keystoreTestKey, password)
	if err != nil {
		t.Fatalf("EncryptKeystoreV3: %v", err)
	}
	recovered, err := decryptKeystoreV3(document, password)
	if err != nil {
		t.Fatalf("decryptKeystoreV3: %v", err)
	}
	if recovered != keystoreTestKey {
		t.Fatalf("recovered = %s, want the original key", recovered)
	}
}

// TestEncryptKeystoreV3RefusesTheWrongPassword confirms the MAC is doing its
// job in files this writer produced, not only in imported ones.
func TestEncryptKeystoreV3RefusesTheWrongPassword(t *testing.T) {
	document, err := EncryptKeystoreV3(keystoreTestKey, []byte("right"))
	if err != nil {
		t.Fatalf("EncryptKeystoreV3: %v", err)
	}
	if _, err := decryptKeystoreV3(document, []byte("wrong")); err == nil ||
		!strings.Contains(err.Error(), "mac mismatch") {
		t.Fatalf("decrypt with the wrong password = %v, want a mac mismatch", err)
	}
}

// TestEncryptKeystoreV3ProducesDistinctCiphertext pins that salt and IV are
// random per file. Reusing either across two files encrypted with the same
// password is the classic way a keystore writer leaks.
func TestEncryptKeystoreV3ProducesDistinctCiphertext(t *testing.T) {
	password := []byte("same password both times")

	first, err := EncryptKeystoreV3(keystoreTestKey, password)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EncryptKeystoreV3(keystoreTestKey, password)
	if err != nil {
		t.Fatal(err)
	}

	var a, b keystoreV3
	if err := json.Unmarshal(first, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(second, &b); err != nil {
		t.Fatal(err)
	}
	if a.Crypto.CipherText == b.Crypto.CipherText {
		t.Fatal("two encryptions of the same key produced identical ciphertext")
	}
	if a.Crypto.CipherParams.IV == b.Crypto.CipherParams.IV {
		t.Fatal("two encryptions reused the same IV")
	}
	if string(a.Crypto.KDFParams) == string(b.Crypto.KDFParams) {
		t.Fatal("two encryptions reused the same scrypt salt")
	}
}

// TestEncryptKeystoreV3WritesTheParametersTheReaderAccepts guards the pairing
// the writer depends on. It derives through deriveKeystoreKey, so a KDF or
// cipher the reader refuses could not be written -- but the version and the
// cipher name are written literally, and those are worth pinning.
func TestEncryptKeystoreV3WritesTheParametersTheReaderAccepts(t *testing.T) {
	document, err := EncryptKeystoreV3(keystoreTestKey, []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	var file keystoreV3
	if err := json.Unmarshal(document, &file); err != nil {
		t.Fatal(err)
	}
	if file.Version != keystoreVersion3 {
		t.Fatalf("version = %d, want %d", file.Version, keystoreVersion3)
	}
	if file.Crypto.Cipher != "aes-128-ctr" || file.Crypto.KDF != "scrypt" {
		t.Fatalf("cipher = %q kdf = %q, want aes-128-ctr and scrypt", file.Crypto.Cipher, file.Crypto.KDF)
	}
	var params scryptKDFParams
	if err := json.Unmarshal(file.Crypto.KDFParams, &params); err != nil {
		t.Fatal(err)
	}
	if params.N != keystoreScryptN || params.DKLen != keystoreDKLen {
		t.Fatalf("scrypt params = %+v, want N=%d dklen=%d", params, keystoreScryptN, keystoreDKLen)
	}
	// The file must not carry the key in any other form. An `address` field is
	// legal in v3 and geth writes one, but Cortex derives its bech32 address
	// from the decrypted key and ignores it, so writing one would only be a
	// second place for an identity to disagree with itself.
	if strings.Contains(string(document), keystoreTestKey) {
		t.Fatal("keystore document contains the plaintext private key")
	}
}

func TestEncryptKeystoreV3RefusesMalformedInput(t *testing.T) {
	for _, test := range []struct {
		name     string
		key      string
		password []byte
		want     string
	}{
		{name: "short key", key: "abcd", password: []byte("p"), want: "64 hex characters"},
		{name: "non hex key", key: strings.Repeat("z", 64), password: []byte("p"), want: "64 hex characters"},
		{name: "empty password", key: keystoreTestKey, password: nil, want: "must not be empty"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := EncryptKeystoreV3(test.key, test.password); err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want one mentioning %q", err, test.want)
			}
		})
	}
}
