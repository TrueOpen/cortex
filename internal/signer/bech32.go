package signer

import (
	"fmt"
	"strings"
)

// Minimal BIP-173 bech32 encoder for the 20-byte Ethereum account payload.
const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Encode(hrp string, payload []byte) (string, error) {
	hrp = strings.TrimSpace(hrp)
	if hrp == "" || hrp != strings.ToLower(hrp) {
		return "", fmt.Errorf("bech32 hrp must be lowercase and non-empty")
	}
	if len(payload) == 0 {
		return "", fmt.Errorf("bech32 payload is required")
	}
	converted, err := convertBits(payload, 8, 5, true)
	if err != nil {
		return "", err
	}
	combined := append(converted, bech32Checksum(hrp, converted)...)
	var out strings.Builder
	out.WriteString(hrp)
	out.WriteByte('1')
	for _, value := range combined {
		if int(value) >= len(bech32Charset) {
			return "", fmt.Errorf("bech32 value out of range")
		}
		out.WriteByte(bech32Charset[value])
	}
	return out.String(), nil
}

func convertBits(data []byte, fromBits, toBits uint8, pad bool) ([]byte, error) {
	var acc uint32
	var bits uint8
	maxValue := uint32(1)<<toBits - 1
	out := make([]byte, 0, len(data)*int(fromBits)/int(toBits)+1)
	for _, value := range data {
		if fromBits == 8 && value > 255 {
			return nil, fmt.Errorf("invalid data range")
		}
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
	} else if bits >= fromBits || byte(acc<<(toBits-bits)&maxValue) != 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	return out, nil
}

func bech32Checksum(hrp string, payload []byte) []byte {
	values := append(bech32HRPExpand(hrp), payload...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	polymod := bech32Polymod(values) ^ 1
	out := make([]byte, 6)
	for i := 0; i < 6; i++ {
		out[i] = byte(polymod >> uint(5*(5-i)) & 31)
	}
	return out
}

func bech32HRPExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

func bech32Polymod(values []byte) uint32 {
	generator := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	checksum := uint32(1)
	for _, value := range values {
		top := checksum >> 25
		checksum = (checksum&0x1ffffff)<<5 ^ uint32(value)
		for i := 0; i < 5; i++ {
			if top>>uint(i)&1 == 1 {
				checksum ^= generator[i]
			}
		}
	}
	return checksum
}
