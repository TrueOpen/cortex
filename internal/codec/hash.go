package codec

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
)

type Hash [32]byte

// String renders a hash the way the chain, the bus and every operator log
// spell one: lowercase hex, no prefix.
//
// It exists because Hash is a byte array, and `%s`/`%v` on a byte array print
// the 32 raw bytes -- so an error message built with `%s` emitted control
// characters where the digest an operator has to compare against Keeper was
// supposed to be. Nothing about the value changed; it is now readable.
func (h Hash) String() string { return hex.EncodeToString(h[:]) }

// IsZero reports the unset digest. A zero hash is not a hash this repository
// ever derives -- it means a field arrived empty -- and the distinction is worth
// naming at the call sites that have to report which commitment is missing.
func (h Hash) IsZero() bool { return h == Hash{} }

func HashBytes(value []byte) Hash {
	return sha256.Sum256(value)
}

// HashWithDomain implements H_FIELDS_V1: the domain and every typed field use
// independent uint64 length frames. It is not the single-payload H_V1 scheme.
func HashWithDomain(domain string, fields ...[]byte) Hash {
	if strings.TrimSpace(domain) == "" {
		panic("protocol hash domain is required")
	}
	var material bytes.Buffer
	writeLengthPrefixed(&material, []byte(domain))
	for _, field := range fields {
		writeLengthPrefixed(&material, field)
	}
	return HashBytes(material.Bytes())
}

// HashV1 implements H_V1 for one canonical opaque payload.
func HashV1(domain string, payload []byte) Hash {
	if strings.TrimSpace(domain) == "" {
		panic("protocol hash domain is required")
	}
	var material bytes.Buffer
	material.WriteString("TRUEOPEN_FRAME_V1")
	var domainLen [4]byte
	binary.BigEndian.PutUint32(domainLen[:], uint32(len(domain)))
	material.Write(domainLen[:])
	material.WriteString(domain)
	writeLengthPrefixed(&material, payload)
	return HashBytes(material.Bytes())
}

func ProtocolHash(domain string, input any) (Hash, error) {
	if strings.TrimSpace(domain) == "" {
		return Hash{}, fmt.Errorf("protocol hash domain is required")
	}
	if isMap(input) {
		return Hash{}, fmt.Errorf("protocol hash input must not be map/JSON material")
	}
	field, ok := input.([]byte)
	if !ok {
		return Hash{}, fmt.Errorf("protocol hash input must be canonical []byte, got %T", input)
	}
	return HashWithDomain(domain, field), nil
}

func Uint64Bytes(value uint64) []byte {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], value)
	return out[:]
}

func writeLengthPrefixed(buf *bytes.Buffer, value []byte) {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(value)))
	buf.Write(lenBuf[:])
	buf.Write(value)
}

func isMap(input any) bool {
	if input == nil {
		return false
	}
	return reflect.TypeOf(input).Kind() == reflect.Map
}
