package signer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

// Web3 Secret Storage (keystore v3) is the established format for encrypting
// secp256k1 private keys. Cortex only reads them: keys are created and rotated
// with geth, ethers, web3.py or any other keystore tooling.
//
// Note that a v3 file's own `address` field is an Ethereum address. Cortex
// derives its bech32 address from the decrypted key instead, so that field is
// ignored.
const keystoreVersion3 = 3

type keystoreV3 struct {
	Version int            `json:"version"`
	ID      string         `json:"id,omitempty"`
	Address string         `json:"address,omitempty"`
	Crypto  keystoreCrypto `json:"crypto"`
}

type keystoreCrypto struct {
	Cipher       string            `json:"cipher"`
	CipherText   string            `json:"ciphertext"`
	CipherParams keystoreCipherPar `json:"cipherparams"`
	KDF          string            `json:"kdf"`
	KDFParams    json.RawMessage   `json:"kdfparams"`
	MAC          string            `json:"mac"`
}

type keystoreCipherPar struct {
	IV string `json:"iv"`
}

type scryptKDFParams struct {
	DKLen int    `json:"dklen"`
	N     int    `json:"n"`
	P     int    `json:"p"`
	R     int    `json:"r"`
	Salt  string `json:"salt"`
}

type pbkdf2KDFParams struct {
	DKLen int    `json:"dklen"`
	C     int    `json:"c"`
	PRF   string `json:"prf"`
	Salt  string `json:"salt"`
}

// decryptKeystoreV3 returns the private key hex held in a keystore v3 file.
func decryptKeystoreV3(raw []byte, password []byte) (string, error) {
	var file keystoreV3
	if err := json.Unmarshal(raw, &file); err != nil {
		return "", fmt.Errorf("decode keystore: %w", err)
	}
	if file.Version != keystoreVersion3 {
		return "", fmt.Errorf("unsupported keystore version %d, want %d", file.Version, keystoreVersion3)
	}
	if !strings.EqualFold(file.Crypto.Cipher, "aes-128-ctr") {
		return "", fmt.Errorf("unsupported keystore cipher %q", file.Crypto.Cipher)
	}
	derived, err := deriveKeystoreKey(file.Crypto, password)
	if err != nil {
		return "", err
	}
	defer zero(derived)

	ciphertext, err := hex.DecodeString(file.Crypto.CipherText)
	if err != nil || len(ciphertext) == 0 {
		return "", fmt.Errorf("keystore ciphertext must be non-empty hex")
	}
	// Verify before decrypting: the MAC is over the second half of the derived
	// key concatenated with the ciphertext.
	mac := keccak256(append(append([]byte{}, derived[16:32]...), ciphertext...))
	expected, err := hex.DecodeString(file.Crypto.MAC)
	if err != nil || subtle.ConstantTimeCompare(mac, expected) != 1 {
		return "", fmt.Errorf("keystore mac mismatch: wrong password or corrupt file")
	}

	iv, err := hex.DecodeString(file.Crypto.CipherParams.IV)
	if err != nil || len(iv) != aes.BlockSize {
		return "", fmt.Errorf("keystore iv must be %d-byte hex", aes.BlockSize)
	}
	block, err := aes.NewCipher(derived[:16])
	if err != nil {
		return "", fmt.Errorf("create keystore cipher: %w", err)
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCTR(block, iv).XORKeyStream(plaintext, ciphertext)
	defer zero(plaintext)
	if len(plaintext) != 32 {
		return "", fmt.Errorf("keystore holds a %d-byte key, want 32", len(plaintext))
	}
	return hex.EncodeToString(plaintext), nil
}

func deriveKeystoreKey(crypto keystoreCrypto, password []byte) ([]byte, error) {
	switch strings.ToLower(crypto.KDF) {
	case "scrypt":
		var params scryptKDFParams
		if err := json.Unmarshal(crypto.KDFParams, &params); err != nil {
			return nil, fmt.Errorf("decode scrypt params: %w", err)
		}
		salt, err := hex.DecodeString(params.Salt)
		if err != nil || len(salt) == 0 {
			return nil, fmt.Errorf("keystore scrypt salt must be non-empty hex")
		}
		if params.DKLen < 32 {
			return nil, fmt.Errorf("keystore scrypt dklen must be at least 32")
		}
		return scrypt.Key(password, salt, params.N, params.R, params.P, params.DKLen)
	case "pbkdf2":
		var params pbkdf2KDFParams
		if err := json.Unmarshal(crypto.KDFParams, &params); err != nil {
			return nil, fmt.Errorf("decode pbkdf2 params: %w", err)
		}
		if !strings.EqualFold(params.PRF, "hmac-sha256") {
			return nil, fmt.Errorf("unsupported keystore pbkdf2 prf %q", params.PRF)
		}
		salt, err := hex.DecodeString(params.Salt)
		if err != nil || len(salt) == 0 {
			return nil, fmt.Errorf("keystore pbkdf2 salt must be non-empty hex")
		}
		if params.DKLen < 32 {
			return nil, fmt.Errorf("keystore pbkdf2 dklen must be at least 32")
		}
		return pbkdf2.Key(password, salt, params.C, params.DKLen, sha256.New), nil
	default:
		return nil, fmt.Errorf("unsupported keystore kdf %q", crypto.KDF)
	}
}

// keccak256 is the legacy Keccak the keystore v3 MAC is defined over, which is
// not the same as standardised SHA3-256.
func keccak256(data []byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(data)
	return hasher.Sum(nil)
}
