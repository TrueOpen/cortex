package dispatchwire

import (
	"fmt"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"
)

// builderSignatureField is the proto field every Builder-signed Phase 1
// message carries its current-service-key signature in. Which messages are
// Builder-signed is read from the generated descriptor, not from a list kept
// here, so a new wire message cannot be missed or misclassified by this
// package.
const builderSignatureField = "builder_service_signature"

// VerifyBuilderSigned checks builder_service_signature against the Builder's
// current service public key (33-byte compressed). The caller resolves that
// key from the chain (QueryCurrentServiceKey); a self-reported, cached-past
// or static key must never be passed here.
func VerifyBuilderSigned(msg proto.Message, builderPubKey []byte) error {
	name := Name(msg)
	field := msg.ProtoReflect().Descriptor().Fields().ByName(builderSignatureField)
	if field == nil {
		return fmt.Errorf("%s is not a Builder-signed message", name)
	}
	sig := msg.ProtoReflect().Get(field).Bytes()
	raw, err := Raw(msg)
	if err != nil {
		return err
	}
	if err := dispatch.ValidateMessage(name, raw); err != nil {
		return fmt.Errorf("%s strict decode: %w", name, err)
	}
	d, err := dispatch.SigningDigest(name, raw)
	if err != nil {
		return fmt.Errorf("%s signing digest: %w", name, err)
	}
	if err := dispatch.VerifyDigestSignature(builderPubKey, d[:], sig); err != nil {
		return fmt.Errorf("%s builder signature: %w", name, err)
	}
	return nil
}
