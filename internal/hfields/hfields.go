// Package hfields implements the frozen H_FIELDS_V1 hashing framing that every
// wire signing preimage is expressed in.
//
// Framing (checked against wire's shared/framing_v1.json vectors):
//
//	preimage = u64_be(len(domain)) || domain ||
//	           for each field: u64_be(len(field)) || field
//	digest   = SHA-256(preimage)
//
// Field encoding is typed, not stringified: uint32/uint64 are fixed-width big
// endian, bool is one byte, an enum is its uint32 big-endian number, and a
// nested frame is the inner field frame with no domain prefix. That typing is
// why this package exists. The older helper in internal/builderclient frames
// string fields only and renders uint64 as decimal text, which matches the
// previous Node vector and cannot express the frozen framing.
//
// One thing is deliberately absent: there is no address field constructor.
// An operator address is framed as its address-codec bytes, not its Bech32
// text, and this package carries no Bech32 decoder. Callers that must frame an
// address resolve the bytes themselves and pass Bytes - see
// internal/nodewire/address.go CanonicalOperatorAddressBytes.
//
// Concrete message preimages live in the packages that own their field order,
// not here: internal/identity derives the task id, internal/keepercontract the
// Hub support digests, and internal/nodewire every Task-domain preimage. This
// package supplies only the primitive.
package hfields

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/TrueOpen/cortex/internal/codec"
)

const (
	// lengthPrefixBytes is the frozen per-field u64 big-endian length prefix.
	lengthPrefixBytes = 8
	// maxInlineField is the widest field the frame can hold without a heap
	// allocation. It is sized to codec.Hash, the widest fixed-width field.
	maxInlineField = len(codec.Hash{})
)

// fieldKind selects which member of Field carries the encoded payload.
type fieldKind uint8

const (
	// kindBytes reads ref, and is also the zero value: the zero Field is an
	// empty field, which is how the frozen encoding frames an absent optional.
	kindBytes fieldKind = iota
	// kindString reads str, so string fields never copy to frame.
	kindString
	// kindInline reads inline[:inlineLen].
	kindInline
)

// Field is one ordered field of an H_FIELDS_V1 preimage. Build fields with the
// typed constructors below and pass them to Preimage or Digest; a constructor
// that cannot express its value carries the error until then, so the framing
// call is the single place that has to be checked.
//
// Fields hold variable-length payloads by reference. A caller must not mutate
// the backing array of a value passed to Bytes before framing completes.
type Field struct {
	ref       []byte
	str       string
	inline    [maxInlineField]byte
	inlineLen uint8
	kind      fieldKind
	err       error
}

// String frames a string field as its strict UTF-8 bytes. Go strings may hold
// arbitrary bytes, so invalid UTF-8 is rejected rather than framed.
func String(value string) Field {
	if !utf8.ValidString(value) {
		return Field{err: errors.New("string field is not valid UTF-8")}
	}
	return Field{str: value, kind: kindString}
}

// Bytes frames a bytes field as its raw bytes. A nil or empty value frames as
// an empty field.
func Bytes(value []byte) Field {
	return Field{ref: value, kind: kindBytes}
}

// Hash frames a 32-byte digest field as its raw bytes.
func Hash(value codec.Hash) Field {
	field := Field{inlineLen: uint8(len(value)), kind: kindInline}
	copy(field.inline[:], value[:])
	return field
}

// Uint32 frames a uint32 field as 4 bytes big endian.
func Uint32(value uint32) Field {
	field := Field{inlineLen: 4, kind: kindInline}
	binary.BigEndian.PutUint32(field.inline[:4], value)
	return field
}

// Uint64 frames a uint64 field as 8 bytes big endian.
func Uint64(value uint64) Field {
	field := Field{inlineLen: 8, kind: kindInline}
	binary.BigEndian.PutUint64(field.inline[:8], value)
	return field
}

// Int32 frames an int32 as its two's-complement 4-byte big-endian encoding.
func Int32(value int32) Field {
	return Uint32(uint32(value))
}

// Int64 frames an int64 as its two's-complement 8-byte big-endian encoding.
//
// It exists for the fixed-point metric fields, which are signed: a logprob is
// negative, so encoding one through Uint64 would be a conversion the reader has
// to know about rather than a typed field.
func Int64(value int64) Field {
	return Uint64(uint64(value))
}

// Optional frames one proto3-optional field with explicit presence, per
// canonical-encoding-and-domain-hashing §4.4:
//
//	absent  -> 0x00
//	present -> 0x01 || u64_be(len(value)) || value
//
// The presence byte is what keeps an absent field distinct from a field that
// carries zero, and it is deliberately NOT itself length-prefixed: the framed
// value is appended to it raw, and the concatenation is the one field the outer
// frame then length-prefixes. Encoding absent as a present zero, or dropping the
// inner frame, silently merges two distinct messages into one digest.
//
// Absent is Optional(false, Field{}); the value passed with false is ignored.
func Optional(present bool, value Field) Field {
	if !present {
		return Field{ref: []byte{0}, kind: kindBytes}
	}
	if value.err != nil {
		return Field{err: fmt.Errorf("optional field: %w", value.err)}
	}
	encoded := make([]byte, 0, 1+lengthPrefixBytes+value.size())
	encoded = append(encoded, 1)
	encoded = appendLength(encoded, value.size())
	encoded = value.appendValue(encoded)
	return Field{ref: encoded, kind: kindBytes}
}

// Bool frames a bool field as one byte, 0x00 or 0x01.
func Bool(value bool) Field {
	field := Field{inlineLen: 1, kind: kindInline}
	if value {
		field.inline[0] = 1
	}
	return field
}

// Enum frames a protobuf enum field as its uint32 big-endian number. Generated
// Go enums are ~int32; a negative number has no uint32 encoding and is
// rejected instead of wrapping.
func Enum[E ~int32](value E) Field {
	if value < 0 {
		return Field{err: fmt.Errorf("enum value %d is negative and has no uint32 encoding", int32(value))}
	}
	return Uint32(uint32(value))
}

// Frame frames a nested field group as a single field: the inner fields are
// length-prefixed the same way, with no domain prefix, and the whole inner
// frame then takes its own length prefix in the outer frame. An empty group
// frames as an empty field.
func Frame(fields ...Field) Field {
	if err := firstFieldError(fields); err != nil {
		return Field{err: fmt.Errorf("nested frame: %w", err)}
	}
	return Field{ref: appendFields(make([]byte, 0, framedSize(fields)), fields), kind: kindBytes}
}

// FrameBytes returns bare FRAME_V1 bytes for the ordered fields, with NO domain
// and no magic:
//
//	FRAME_V1(v1, ..., vn) = u64_be(len(v1)) || v1 || ... || u64_be(len(vn)) || vn
//
// canonical-encoding-and-domain-hashing §3.2 defines this frame independently of any hash scheme,
// and it is the right primitive for an opaque blob that is committed to by a
// bare SHA-256 rather than by a domain-separated digest. Using Preimage for such
// a blob would put a string in the domain slot that §4.2 governs - it must match
// ^TRUEOPEN_[A-Z0-9_]+_V[1-9][0-9]*$ and be registered - and a blob's version token
// is neither.
//
// Callers that are producing a signing digest want Digest, not this.
func FrameBytes(fields ...Field) ([]byte, error) {
	if err := firstFieldError(fields); err != nil {
		return nil, err
	}
	return appendFields(make([]byte, 0, framedSize(fields)), fields), nil
}

// Preimage returns the exact H_FIELDS_V1 preimage bytes for domain and the
// ordered fields. Use it when the bytes themselves are needed, for example to
// pin a golden vector; use Digest to sign or compare.
func Preimage(domain string, fields ...Field) ([]byte, error) {
	if err := validateDomain(domain); err != nil {
		return nil, err
	}
	if err := firstFieldError(fields); err != nil {
		return nil, err
	}
	out := make([]byte, 0, lengthPrefixBytes+len(domain)+framedSize(fields))
	out = appendLength(out, len(domain))
	out = append(out, domain...)
	return appendFields(out, fields), nil
}

// Digest returns SHA-256 over the H_FIELDS_V1 preimage for domain and fields.
func Digest(domain string, fields ...Field) (codec.Hash, error) {
	preimage, err := Preimage(domain, fields...)
	if err != nil {
		return codec.Hash{}, err
	}
	return codec.HashBytes(preimage), nil
}

// validateDomain rejects the domains the framing cannot carry. A domain is the
// only unprefixed-by-name part of the preimage, so an empty or blank one would
// silently collapse two different messages into one digest.
func validateDomain(domain string) error {
	if strings.TrimSpace(domain) == "" {
		return errors.New("hfields: domain is required")
	}
	if !utf8.ValidString(domain) {
		return errors.New("hfields: domain is not valid UTF-8")
	}
	return nil
}

func firstFieldError(fields []Field) error {
	for i := range fields {
		if fields[i].err != nil {
			return fmt.Errorf("field %d: %w", i, fields[i].err)
		}
	}
	return nil
}

func framedSize(fields []Field) int {
	size := lengthPrefixBytes * len(fields)
	for i := range fields {
		size += fields[i].size()
	}
	return size
}

func appendFields(dst []byte, fields []Field) []byte {
	for i := range fields {
		dst = appendLength(dst, fields[i].size())
		dst = fields[i].appendValue(dst)
	}
	return dst
}

func appendLength(dst []byte, length int) []byte {
	var prefix [lengthPrefixBytes]byte
	binary.BigEndian.PutUint64(prefix[:], uint64(length))
	return append(dst, prefix[:]...)
}

func (f *Field) size() int {
	switch f.kind {
	case kindString:
		return len(f.str)
	case kindInline:
		return int(f.inlineLen)
	default:
		return len(f.ref)
	}
}

func (f *Field) appendValue(dst []byte) []byte {
	switch f.kind {
	case kindString:
		return append(dst, f.str...)
	case kindInline:
		return append(dst, f.inline[:f.inlineLen]...)
	default:
		return append(dst, f.ref...)
	}
}
