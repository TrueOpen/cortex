package nodewire

import (
	"fmt"
	"strings"
)

// Cosmos address codecs accept bounded non-empty account bytes. The Node
// canonical preimage helpers apply the same 1..255 bound; 20 bytes is the
// current deployment convention, not a consensus wire restriction.
const (
	minOperatorAddressCodecBytes = 1
	maxOperatorAddressCodecBytes = 255
)

// bech32DecodeLimit is the string-length limit cosmos-sdk's DecodeAndConvert
// passes to its decoder. It is deliberately the cosmos value (1023) and not the
// BIP-173 default (90): an address Node accepts must not be refused here.
const bech32DecodeLimit = 1023

// bech32Charset is the ordered BIP-173 data charset; a character's index is its
// 5-bit value.
const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// CanonicalOperatorAddressBytes converts a Bech32 operator address into the
// address codec bytes every frozen preimage frames. The Bech32 text is NEVER
// framed: the human-readable prefix is presentation, so two chains that share a
// prefix are separated by the chain_id field instead.
//
// The re-encode comparison is load-bearing, not defensive. Bech32 decoding
// accepts an all-uppercase string and any non-canonical trailing bit padding, so
// without it two different strings would frame the same bytes and a caller could
// sign a digest under an address spelling the chain does not use.
//
// A Keeper additionally checks the address against its own configured codec and
// against the authoritative assignment. This is the pure, prefix-agnostic decode
// a non-Go consumer has to reproduce.
func CanonicalOperatorAddressBytes(field, value string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("%s must be a non-empty canonical Bech32 address", field)
	}
	if strings.TrimSpace(value) != value {
		return nil, fmt.Errorf("%s must not carry leading or trailing whitespace", field)
	}
	hrp, raw, err := bech32DecodeAndConvert(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not a decodable Bech32 address: %w", field, err)
	}
	if len(raw) < minOperatorAddressCodecBytes || len(raw) > maxOperatorAddressCodecBytes {
		return nil, fmt.Errorf("%s decodes to %d address bytes, want %d..%d", field, len(raw), minOperatorAddressCodecBytes, maxOperatorAddressCodecBytes)
	}
	reencoded, err := bech32ConvertAndEncode(hrp, raw)
	if err != nil {
		return nil, fmt.Errorf("%s could not be re-encoded: %w", field, err)
	}
	if reencoded != value {
		return nil, fmt.Errorf("%s must be the canonical Bech32 encoding of its address bytes", field)
	}
	return raw, nil
}

// CanonicalOperatorAddressString encodes a 20-byte account with a canonical
// lowercase Bech32 prefix, including Ethereum-derived EIP-712 user accounts.
func CanonicalOperatorAddressString(hrp string, raw []byte) (string, error) {
	if len(raw) != 20 || hrp == "" || strings.TrimSpace(hrp) != hrp || strings.ToLower(hrp) != hrp {
		return "", fmt.Errorf("20 account bytes and a canonical lowercase Bech32 prefix are required")
	}
	address, err := bech32ConvertAndEncode(hrp, raw)
	if err != nil {
		return "", err
	}
	if _, err := CanonicalOperatorAddressBytes("account", address); err != nil {
		return "", err
	}
	return address, nil
}

// bech32DecodeAndConvert reproduces cosmos-sdk types/bech32.DecodeAndConvert:
// decode the Bech32 string, then regroup the 5-bit data to 8-bit bytes without
// padding. The returned human-readable part is lowercase.
//
// Cortex has no cosmos-sdk dependency, so the BIP-173 decoder is spelled out
// here. internal/signer carries an encode-only copy for deriving its own
// addresses; the two are separate because that one is unexported and cannot
// decode, and because a consensus decoder must not move when a key-management
// helper changes.
func bech32DecodeAndConvert(bech string) (string, []byte, error) {
	if len(bech) > bech32DecodeLimit {
		return "", nil, fmt.Errorf("bech32 string is %d characters, over the %d limit", len(bech), bech32DecodeLimit)
	}
	// A non-empty HRP, the separator and a 6-character checksum is 8 characters.
	if len(bech) < 8 {
		return "", nil, fmt.Errorf("bech32 string is %d characters, under the 8 minimum", len(bech))
	}
	normalized, err := bech32Normalize(bech)
	if err != nil {
		return "", nil, err
	}
	separator := strings.LastIndexByte(normalized, '1')
	if separator < 1 || separator+7 > len(normalized) {
		return "", nil, fmt.Errorf("bech32 separator at index %d is invalid", separator)
	}
	hrp := normalized[:separator]
	decoded, err := bech32DataToBytes(normalized[separator+1:])
	if err != nil {
		return "", nil, err
	}
	values, checksum := decoded[:len(decoded)-6], decoded[len(decoded)-6:]
	if !bech32VerifyChecksum(hrp, values, checksum) {
		return "", nil, fmt.Errorf("bech32 checksum is invalid")
	}
	converted, err := bech32ConvertBits(values, 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, converted, nil
}

// bech32ConvertAndEncode reproduces cosmos-sdk types/bech32.ConvertAndEncode:
// regroup 8-bit bytes to padded 5-bit values and encode them under a lowercased
// human-readable part.
func bech32ConvertAndEncode(hrp string, payload []byte) (string, error) {
	converted, err := bech32ConvertBits(payload, 8, 5, true)
	if err != nil {
		return "", err
	}
	hrp = strings.ToLower(hrp)
	var out strings.Builder
	out.Grow(len(hrp) + 1 + len(converted) + 6)
	out.WriteString(hrp)
	out.WriteByte('1')
	for _, value := range append(converted, bech32Checksum(hrp, converted)...) {
		if int(value) >= len(bech32Charset) {
			return "", fmt.Errorf("bech32 data value %d is out of range", value)
		}
		out.WriteByte(bech32Charset[value])
	}
	return out.String(), nil
}

// bech32Normalize rejects out-of-range and mixed-case strings and lowercases an
// all-uppercase one, because Bech32 checksums are defined over lowercase.
func bech32Normalize(bech string) (string, error) {
	var hasLower, hasUpper bool
	for i := range len(bech) {
		c := bech[i]
		if c < 33 || c > 126 {
			return "", fmt.Errorf("bech32 character %d at index %d is out of range", c, i)
		}
		hasLower = hasLower || (c >= 'a' && c <= 'z')
		hasUpper = hasUpper || (c >= 'A' && c <= 'Z')
		if hasLower && hasUpper {
			return "", fmt.Errorf("bech32 string must not be mixed case")
		}
	}
	if hasUpper {
		return strings.ToLower(bech), nil
	}
	return bech, nil
}

// bech32DataToBytes maps each data character to its 5-bit charset index.
func bech32DataToBytes(data string) ([]byte, error) {
	decoded := make([]byte, 0, len(data))
	for i := range len(data) {
		index := strings.IndexByte(bech32Charset, data[i])
		if index < 0 {
			return nil, fmt.Errorf("bech32 character %q at data index %d is not in the charset", data[i], i)
		}
		decoded = append(decoded, byte(index))
	}
	return decoded, nil
}

// bech32ConvertBits regroups fromBits-wide values into toBits-wide values. With
// pad it appends a zero-filled final group; without it an incomplete group must
// be under fromBits wide and all zero, which is what rejects a non-canonical
// address whose trailing padding carries data.
func bech32ConvertBits(data []byte, fromBits, toBits uint8, pad bool) ([]byte, error) {
	var acc uint32
	var bits uint8
	maxValue := uint32(1)<<toBits - 1
	out := make([]byte, 0, len(data)*int(fromBits)/int(toBits)+1)
	for _, value := range data {
		acc = acc<<fromBits | uint32(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			out = append(out, byte(acc>>bits&maxValue))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte(acc<<(toBits-bits)&maxValue))
		}
		return out, nil
	}
	if bits >= fromBits || byte(acc<<(toBits-bits)&maxValue) != 0 {
		return nil, fmt.Errorf("bech32 data has a non-canonical incomplete group")
	}
	return out, nil
}

func bech32VerifyChecksum(hrp string, values, checksum []byte) bool {
	combined := append(bech32HRPExpand(hrp), values...)
	combined = append(combined, checksum...)
	return bech32Polymod(combined) == 1
}

func bech32Checksum(hrp string, values []byte) []byte {
	combined := append(bech32HRPExpand(hrp), values...)
	combined = append(combined, 0, 0, 0, 0, 0, 0)
	polymod := bech32Polymod(combined) ^ 1
	out := make([]byte, 6)
	for i := range 6 {
		out[i] = byte(polymod >> uint(5*(5-i)) & 31)
	}
	return out
}

func bech32HRPExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := range len(hrp) {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := range len(hrp) {
		out = append(out, hrp[i]&31)
	}
	return out
}

func bech32Polymod(values []byte) uint32 {
	generator := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	checksum := uint32(1)
	for _, value := range values {
		top := checksum >> 25
		checksum = (checksum&0x1ffffff)<<5 ^ uint32(value)
		for i := range 5 {
			if top>>uint(i)&1 == 1 {
				checksum ^= generator[i]
			}
		}
	}
	return checksum
}
