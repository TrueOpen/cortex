package hfields

import "fmt"

// Declarations only tests use, kept out of the production binary.

// Enum frames a protobuf enum field as its uint32 big-endian number. Generated
// Go enums are ~int32; a negative number has no uint32 encoding and is
// rejected instead of wrapping.
func Enum[E ~int32](value E) Field {
	if value < 0 {
		return Field{err: fmt.Errorf("enum value %d is negative and has no uint32 encoding", int32(value))}
	}
	return Uint32(uint32(value))
}
