// Package dispatchwire converts generated Phase 1 protobuf messages to the
// (full name, wire bytes) form github.com/TrueOpen/wire/dispatch hashes and
// verifies. It owns no domain, field table or tree algorithm: wire's
// PHASE1_CONTRACT requires consumers to reuse that package rather than copy it.
package dispatchwire

import (
	"fmt"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"
)

// Name is the fully qualified protobuf name wire/dispatch registers tables by.
func Name(msg proto.Message) string {
	return string(msg.ProtoReflect().Descriptor().FullName())
}

// Raw is the native protobuf encoding wire/dispatch decodes strictly.
// Deterministic marshaling keeps field order canonical.
func Raw(msg proto.Message) ([]byte, error) {
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", Name(msg), err)
	}
	return raw, nil
}

// Digest is the message's signing digest. The signature field is excluded by
// the projection, so the digest of a signed message equals the digest that was
// signed -- which is why dispatch_ticket_hash, dispatch_accept_digest and
// handraise_root_digest are all Digest of the signed message.
func Digest(msg proto.Message) ([32]byte, error) {
	raw, err := Raw(msg)
	if err != nil {
		return [32]byte{}, err
	}
	d, err := dispatch.SigningDigest(Name(msg), raw)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%s signing digest: %w", Name(msg), err)
	}
	return d, nil
}
