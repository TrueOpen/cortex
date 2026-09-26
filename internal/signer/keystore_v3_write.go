package signer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Cortex reads keystore v3 files that geth, ethers or web3.py produced, and
// that stayed true right up until someone had to onboard a node with none of
// those installed. EncryptKeystoreV3 closes that gap without widening the read
// path: it is the exact mirror of decryptKeystoreV3, so anything written here
// is read back by the same code that reads a geth file, and anything the
// reader refuses this writer cannot emit.
//
// scrypt is the only KDF offered. The reader also accepts pbkdf2 because files
// in the wild use it; there is no reason to create new ones.
const (
	// keystoreScryptN is the work factor geth calls StandardScryptN. It is the
	// slow one on purpose: this key signs on behalf of an on-chain identity,
	// and the file it lands in is the thing an attacker takes a copy of.
	keystoreScryptN = 1 << 18
	keystoreScryptR = 8
	keystoreScryptP = 1
	keystoreDKLen   = 32
)

// EncryptKeystoreV3 encrypts a 32-byte secp256k1 private key into a Web3 Secret
// Storage (keystore v3) document.
//
// privateKeyHex is the key as 64 hex characters, matching what decryptKeystoreV3
// returns, so a caller can round-trip without converting representations.
//
// The result is verified by decrypting it again before it is returned. Writing
// a keystore nobody can open is a silent loss of the only copy of a key, and it
// is exactly the failure that shows up later, on a different machine, when the
// file is needed.
func EncryptKeystoreV3(privateKeyHex string, password []byte) ([]byte, error) {
	key, err := hex.DecodeString(privateKeyHex)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("private key must be 64 hex characters")
	}
	defer zero(key)
	if len(password) == 0 {
		return nil, fmt.Errorf("keystore password must not be empty")
	}

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("read keystore salt: %w", err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("read keystore iv: %w", err)
	}

	kdfParams, err := json.Marshal(scryptKDFParams{
		DKLen: keystoreDKLen, N: keystoreScryptN, P: keystoreScryptP, R: keystoreScryptR,
		Salt: hex.EncodeToString(salt),
	})
	if err != nil {
		return nil, fmt.Errorf("encode scrypt params: %w", err)
	}
	crypto := keystoreCrypto{
		Cipher:       "aes-128-ctr",
		CipherParams: keystoreCipherPar{IV: hex.EncodeToString(iv)},
		KDF:          "scrypt",
		KDFParams:    kdfParams,
	}
	// Derived through the same function the reader uses, so a parameter the
	// reader would reject cannot be written here.
	derived, err := deriveKeystoreKey(crypto, password)
	if err != nil {
		return nil, err
	}
	defer zero(derived)

	block, err := aes.NewCipher(derived[:16])
	if err != nil {
		return nil, fmt.Errorf("create keystore cipher: %w", err)
	}
	ciphertext := make([]byte, len(key))
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, key)
	crypto.CipherText = hex.EncodeToString(ciphertext)
	crypto.MAC = hex.EncodeToString(keccak256(append(append([]byte{}, derived[16:32]...), ciphertext...)))

	document, err := json.MarshalIndent(keystoreV3{Version: keystoreVersion3, Crypto: crypto}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode keystore: %w", err)
	}
	// The round-trip check. It costs one more scrypt derivation, which at this
	// work factor is the slowest thing in the function -- and it is the only
	// thing that makes "the file was written" mean "the key can be recovered".
	recovered, err := decryptKeystoreV3(document, password)
	if err != nil {
		return nil, fmt.Errorf("verify written keystore: %w", err)
	}
	if recovered != privateKeyHex {
		return nil, fmt.Errorf("verify written keystore: decrypted key differs from the input")
	}
	return document, nil
}
