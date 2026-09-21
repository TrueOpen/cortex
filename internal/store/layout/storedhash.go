package layout

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/SingaXYZ/cortex/internal/codec"
)

// StoredHash is a 32-byte digest stored in Pebble and represented in JSON as
// exactly 64 lowercase hexadecimal characters. It is used by the task storage
// layout instead of codec.Hash so that store JSON contracts are stable and
// compact (32 raw bytes are not expanded into a 32-element JSON number array).
type StoredHash [32]byte

// String returns the canonical 64-character lowercase hex form.
func (h StoredHash) String() string {
	return hex.EncodeToString(h[:])
}

// IsZero reports whether every byte is zero.
func (h StoredHash) IsZero() bool {
	for _, b := range h {
		if b != 0 {
			return false
		}
	}
	return true
}

// StoredHashFromCodec returns a StoredHash backed by the bytes of a codec.Hash.
func StoredHashFromCodec(h codec.Hash) StoredHash {
	var out StoredHash
	copy(out[:], h[:])
	return out
}

// MarshalJSON encodes the hash as a JSON string of exactly 64 lowercase hex
// characters.
func (h StoredHash) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(h[:]))
}

// UnmarshalJSON decodes a StoredHash from JSON. It accepts:
//   - the target form: a JSON string of exactly 64 lowercase hex characters;
//   - the legacy form: a JSON array of exactly 32 byte-valued numbers.
//
// Any other shape, including uppercase hex, prefixes, odd length, short/long
// input, null, and trailing content, is rejected. The receiver is left unchanged
// when validation fails, so callers can safely attempt to unmarshal into a
// StoredHash that already holds a value.
func (h *StoredHash) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err == nil {
		dec, err := decodeStoredHashString(raw)
		if err != nil {
			return err
		}
		*h = dec
		return nil
	}

	// Legacy form: an exact 32-element JSON array of byte-valued numbers.
	var legacy []byte
	lerr := json.Unmarshal(data, &legacy)
	if lerr == nil {
		if len(legacy) != 32 {
			return fmt.Errorf("stored hash legacy array must be exactly 32 bytes, got %d", len(legacy))
		}
		copy(h[:], legacy)
		return nil
	}

	return fmt.Errorf("stored hash must be 64 lowercase hex characters or a legacy 32-byte array: %w", lerr)
}

func decodeStoredHashString(raw string) (StoredHash, error) {
	// Reject null, booleans, numbers, and any non-string JSON token. json.Unmarshal
	// already guarantees we have a JSON string here, but guard against the empty
	// string and embedded whitespace as well.
	if len(raw) == 0 {
		return StoredHash{}, fmt.Errorf("stored hash must not be empty")
	}
	if len(raw) >= 2 && (raw[0:2] == "0x" || raw[0:2] == "0X") {
		return StoredHash{}, fmt.Errorf("stored hash must not have a 0x prefix")
	}
	if len(raw) != 64 {
		return StoredHash{}, fmt.Errorf("stored hash must be 64 hex characters, got %d", len(raw))
	}
	if strings.ToLower(raw) != raw {
		return StoredHash{}, fmt.Errorf("stored hash must be lowercase hex")
	}
	var out StoredHash
	if _, err := hex.Decode(out[:], []byte(raw)); err != nil {
		return StoredHash{}, fmt.Errorf("stored hash must be valid hex: %w", err)
	}
	return out, nil
}
