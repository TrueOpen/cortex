package chainclient

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Uint64String implements the protobuf JSON representation for uint64 fields.
type Uint64String uint64

// ProfileVersion implements Node's ProtoJSON representation for uint32
// profile_version fields. Unlike protobuf uint64 values, uint32 values are JSON
// numbers rather than quoted decimal strings.
type ProfileVersion string

// ProtoBytes32 decodes a fixed protobuf bytes field from its ProtoJSON base64
// representation and retains the raw bytes for exact digest comparisons.
type ProtoBytes32 []byte

func (v ProtoBytes32) MarshalJSON() ([]byte, error) {
	if len(v) != 32 {
		return nil, fmt.Errorf("protobuf bytes32 must contain exactly 32 bytes")
	}
	return json.Marshal(base64.StdEncoding.EncodeToString(v))
}

func (v *ProtoBytes32) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("decode ProtoJSON bytes32 into nil destination")
	}
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return fmt.Errorf("protobuf bytes32 must be a base64 JSON string")
	}
	// A Hash32 field wire annotates as REST_BYTES_ENCODING_HASH32_LOWER_HEX
	// arrives as 64 lowercase hex characters (see restProtoJSON). Base64 of 32
	// bytes is always 44 characters, so the two forms cannot be confused.
	if len(encoded) == 64 && strings.ToLower(encoded) == encoded {
		raw, err := hex.DecodeString(encoded)
		if err != nil {
			return fmt.Errorf("protobuf bytes32 hex must decode to exactly 32 bytes")
		}
		*v = append((*v)[:0], raw...)
		return nil
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("protobuf bytes32 must decode to exactly 32 bytes")
	}
	*v = append((*v)[:0], raw...)
	return nil
}

func (v ProtoBytes32) Hex() string { return hex.EncodeToString(v) }

func (v ProtoBytes32) IsSet() bool { return len(v) == 32 }

func NewProfileVersion(value uint32) ProfileVersion {
	return ProfileVersion(strconv.FormatUint(uint64(value), 10))
}

func (v ProfileVersion) String() string {
	return string(v)
}

func (v ProfileVersion) Uint32() uint32 {
	parsed, _ := strconv.ParseUint(string(v), 10, 32)
	return uint32(parsed)
}

func (v ProfileVersion) MarshalJSON() ([]byte, error) {
	parsed, err := parseProfileVersion(string(v), true)
	if err != nil {
		return nil, err
	}
	return []byte(strconv.FormatUint(uint64(parsed), 10)), nil
}

func (v *ProfileVersion) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("decode profile version into nil destination")
	}
	if len(data) == 0 || data[0] == '"' {
		return fmt.Errorf("protobuf uint32 profile_version must be a JSON number")
	}
	raw := string(data)
	parsed, err := parseProfileVersion(raw, true)
	if err != nil {
		return err
	}
	*v = NewProfileVersion(parsed)
	return nil
}

func parseProfileVersion(raw string, allowZero bool) (uint32, error) {
	parsed, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || strconv.FormatUint(parsed, 10) != raw {
		return 0, fmt.Errorf("profile_version must be a canonical uint32")
	}
	if !allowZero && parsed == 0 {
		return 0, fmt.Errorf("profile_version must be non-zero")
	}
	return uint32(parsed), nil
}

func NewUint64String(value uint64) Uint64String {
	return Uint64String(value)
}

func (v Uint64String) Uint64() uint64 {
	return uint64(v)
}

func (v Uint64String) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatUint(uint64(v), 10))
}

func (v *Uint64String) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("decode protobuf uint64 into nil destination")
	}
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return fmt.Errorf("protobuf uint64 must be a decimal JSON string")
	}
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("decode protobuf uint64 string: %w", err)
	}
	parsed, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != raw {
		return fmt.Errorf("invalid protobuf uint64 %q", raw)
	}
	*v = Uint64String(parsed)
	return nil
}

// HexHash is a SHA-256 digest encoded as canonical lowercase hex in Keeper JSON.
type HexHash [32]byte

// CSVStrings decodes Keeper string fields that carry canonical comma-separated
// participant lists.
type CSVStrings []string

func (v *CSVStrings) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("Keeper participant list must be a JSON string")
	}
	if raw == "" {
		*v = nil
		return nil
	}
	parts := strings.Split(raw, ",")
	for _, part := range parts {
		if part == "" || strings.TrimSpace(part) != part {
			return fmt.Errorf("Keeper participant list must be canonical CSV")
		}
	}
	*v = CSVStrings(parts)
	return nil
}

func (v CSVStrings) MarshalJSON() ([]byte, error) {
	return json.Marshal(strings.Join(v, ","))
}

func (h HexHash) String() string {
	return hex.EncodeToString(h[:])
}

func (h HexHash) IsZero() bool {
	return bytes.Equal(h[:], make([]byte, len(h)))
}

func (h HexHash) MarshalJSON() ([]byte, error) {
	return json.Marshal(h.String())
}

func (h *HexHash) UnmarshalJSON(data []byte) error {
	if h == nil {
		return fmt.Errorf("decode Keeper hash into nil destination")
	}
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("decode Keeper hash string: %w", err)
	}
	if len(raw) != hex.EncodedLen(len(h)) {
		return fmt.Errorf("Keeper hash must be 64 lowercase hex characters")
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || hex.EncodeToString(decoded) != raw {
		return fmt.Errorf("Keeper hash must be 64 lowercase hex characters")
	}
	copy(h[:], decoded)
	return nil
}
