package dispatchwire

import (
	"errors"
	"fmt"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// builderSignatureField is the proto field every Builder-signed Phase 1
// message carries its current-service-key signature in. Which messages are
// Builder-signed is read from the generated descriptor, not from a list kept
// here, so a new wire message cannot be missed or misclassified by this
// package.
const builderSignatureField = "builder_service_signature"

var (
	// ErrNotBuilderSigned: the message type carries no Builder signature.
	ErrNotBuilderSigned = errors.New("dispatchwire: not a Builder-signed message")
	// ErrBuilderSignature: the Builder signature does not verify. The wire
	// error is wrapped alongside it.
	ErrBuilderSignature = errors.New("dispatchwire: Builder signature rejected")
)

// builderSignatureNumber returns the field number of builder_service_signature
// for a registered message type, or ErrNotBuilderSigned.
func builderSignatureNumber(desc protoreflect.MessageDescriptor) (protowire.Number, error) {
	f := desc.Fields().ByName(builderSignatureField)
	if f == nil || f.Kind() != protoreflect.BytesKind || f.IsList() {
		return 0, fmt.Errorf("%w: %s", ErrNotBuilderSigned, desc.FullName())
	}
	return f.Number(), nil
}

// VerifyBuilderSignedRaw verifies builder_service_signature over received wire
// bytes. Call it on bytes taken off the stream BEFORE proto.Unmarshal: wire's
// strict decoder rejects duplicated singular fields, unknown fields and
// non-minimal encodings that proto.Unmarshal would silently accept or
// collapse, so only the raw bytes are what the Builder actually signed.
// builderPubKey is the Builder's current service key (33-byte compressed),
// resolved from chain authority for the stream's authenticated Builder.
func VerifyBuilderSignedRaw(fullName string, raw, builderPubKey []byte) error {
	mt, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(fullName))
	if err != nil {
		return fmt.Errorf("%w: %s is not a registered message", ErrNotBuilderSigned, fullName)
	}
	sigNumber, err := builderSignatureNumber(mt.Descriptor())
	if err != nil {
		return err
	}
	d, err := dispatch.SigningDigest(fullName, raw)
	if err != nil {
		return fmt.Errorf("%s signing digest: %w", fullName, err)
	}
	// The strict decode above guarantees at most one occurrence of each
	// singular field, so the first match is the only one.
	var sig []byte
	for b := raw; len(b) > 0; {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return fmt.Errorf("%s: %w", fullName, protowire.ParseError(n))
		}
		b = b[n:]
		if num == sigNumber && typ == protowire.BytesType {
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return fmt.Errorf("%s: %w", fullName, protowire.ParseError(m))
			}
			sig = v
			break
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			return fmt.Errorf("%s: %w", fullName, protowire.ParseError(m))
		}
		b = b[m:]
	}
	if err := dispatch.VerifyDigestSignature(builderPubKey, d[:], sig); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrBuilderSignature, fullName, err)
	}
	return nil
}

// VerifyBuilderSigned is VerifyBuilderSignedRaw over a message's deterministic
// encoding. Use it for locally built or already strictly validated messages;
// for bytes received from a peer use VerifyBuilderSignedRaw before unmarshaling.
func VerifyBuilderSigned(msg proto.Message, builderPubKey []byte) error {
	if msg == nil {
		return fmt.Errorf("%w: nil message", ErrNotBuilderSigned)
	}
	if _, err := builderSignatureNumber(msg.ProtoReflect().Descriptor()); err != nil {
		return err
	}
	raw, err := Raw(msg)
	if err != nil {
		return err
	}
	return VerifyBuilderSignedRaw(Name(msg), raw, builderPubKey)
}
