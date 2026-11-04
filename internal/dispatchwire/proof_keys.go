package dispatchwire

import (
	"errors"
	"fmt"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// builderNonceField is the signed service key generation every retained
// Builder dispatch message carries since wire b30fba8 (ticket, root, record,
// input response, revoke, record notice, result header).
const builderNonceField = "service_authorization_nonce"

// ErrBuilderKeyGeneration: the message names a service key generation this
// node cannot resolve, or one that may not sign it (zero, unknown, older than
// its ticket, or past its key's cutoff). The wire error is wrapped alongside.
var ErrBuilderKeyGeneration = errors.New("dispatchwire: Builder key generation rejected")

// BuilderKeys is one Builder's service-key binding as chain authority reports
// it (hub.v1.CurrentServiceKeyViewV1): the current generation and the one
// previous generation the last rotation retired. It resolves the key of the
// generation a message names by its own signed nonce (wire PHASE1_CONTRACT
// "Retained message generations"); it grants no live permission by itself.
type BuilderKeys struct {
	Operator      string
	Current       []byte // 33-byte compressed
	CurrentNonce  uint64
	CurrentActive bool // false: the current key is REVOKED
	// RevokedHeight is the explicit emergency-revoke cutoff of a REVOKED
	// current key; zero for a terminal revocation without one.
	RevokedHeight uint64
	// Previous is nil when the binding retains no previous generation.
	Previous              []byte
	PreviousNonce         uint64
	PreviousRetiredHeight uint64
}

// Key returns the key of generation nonce; zero names the current key, for
// Builder messages that carry no nonce. It checks no proof cutoff: use the
// Verify*Proof functions for that.
func (k BuilderKeys) Key(nonce uint64) ([]byte, error) {
	switch {
	case nonce == 0 || nonce == k.CurrentNonce:
		if len(k.Current) == 0 {
			return nil, fmt.Errorf("%w: Builder %s has no current key", ErrBuilderKeyGeneration, k.Operator)
		}
		return k.Current, nil
	case k.Previous != nil && nonce == k.PreviousNonce:
		return k.Previous, nil
	}
	return nil, fmt.Errorf("%w: Builder %s has no generation %d (current %d)", ErrBuilderKeyGeneration, k.Operator, nonce, k.CurrentNonce)
}

// lookup is wire's ProofKeyOptions.LookupProofKey over this binding.
func (k BuilderKeys) lookup(s dispatch.ServiceProofSigner) (dispatch.ProofKeyBinding, error) {
	if s.ParticipantType != dispatch.ProofParticipantBuilder || s.OperatorAddress != k.Operator {
		return dispatch.ProofKeyBinding{}, fmt.Errorf("no binding for %s", s.OperatorAddress)
	}
	switch {
	case s.ServiceAuthorizationNonce == 0 || s.ServiceAuthorizationNonce == k.CurrentNonce:
		b := dispatch.ProofKeyBinding{PublicKey: k.Current, ServiceAuthorizationNonce: k.CurrentNonce, Status: dispatch.ProofKeyActive}
		if !k.CurrentActive {
			b.Status, b.RevokedHeight = dispatch.ProofKeyRevoked, k.RevokedHeight
		}
		return b, nil
	case k.Previous != nil && s.ServiceAuthorizationNonce == k.PreviousNonce:
		return dispatch.ProofKeyBinding{PublicKey: k.Previous, ServiceAuthorizationNonce: k.PreviousNonce,
			Status: dispatch.ProofKeyPrevious, PreviousRetiredHeight: k.PreviousRetiredHeight}, nil
	}
	return dispatch.ProofKeyBinding{}, fmt.Errorf("unknown generation %d", s.ServiceAuthorizationNonce)
}

// options passes the order height on only when it is known: a signed order's
// earliest_submit_height is positive, and a missing one must fail closed for a
// key with a cutoff rather than read as height zero.
func (k BuilderKeys) options(orderEarliestSubmitHeight uint64) dispatch.ProofKeyOptions {
	opts := dispatch.ProofKeyOptions{LookupProofKey: k.lookup}
	if orderEarliestSubmitHeight != 0 {
		esh := orderEarliestSubmitHeight
		opts.OrderEarliestSubmitHeight = &esh
	}
	return opts
}

func proofErr(name string, err error) error {
	if errors.Is(err, dispatch.ErrProofKeyUnavailable) {
		return fmt.Errorf("%w: %s: %w", ErrBuilderKeyGeneration, name, err)
	}
	return fmt.Errorf("%w: %s: %w", ErrBuilderSignature, name, err)
}

// VerifyTicketProof verifies a raw DispatchTicketV1 with wire's
// VerifyDispatchProof: the key is the generation the ticket's own nonce
// names, and a previous or revoked key only proves a ticket whose
// max(order earliest_submit_height, bound_change_height) precedes its cutoff.
// orderEarliestSubmitHeight comes from the order this ticket was offered with.
func VerifyTicketProof(chainID string, ticket []byte, keys BuilderKeys, orderEarliestSubmitHeight uint64) error {
	const name = "task.v1.DispatchTicketV1"
	if err := dispatch.VerifyDispatchProof(chainID, name, ticket, keys.options(orderEarliestSubmitHeight)); err != nil {
		return proofErr(name, err)
	}
	return nil
}

// VerifyRootProof verifies a raw SignedHandraiseRootV1 the same way; a root's
// cutoff is compared with its own root_height, never an order's.
func VerifyRootProof(chainID string, root []byte, keys BuilderKeys) error {
	const name = "task.v1.SignedHandraiseRootV1"
	opts := dispatch.ProofKeyOptions{LookupProofKey: keys.lookup}
	if err := dispatch.VerifyDispatchProof(chainID, name, root, opts); err != nil {
		return proofErr(name, err)
	}
	return nil
}

// VerifyTicketBoundProof verifies a retained DispatchInputResponseV1,
// DispatchRevokeV1 or RecordResultNoticeV1 against the raw ticket its
// dispatch_ticket_hash names, with wire's VerifyTicketBoundDispatchProof: its
// signed nonce must be positive and not older than the ticket's, and selects
// the current or previous key under the ticket's cutoff. The original signed
// bytes are what is verified; nothing is re-signed after a cutover.
func VerifyTicketBoundProof(chainID, name string, raw, ticket []byte, keys BuilderKeys, orderEarliestSubmitHeight uint64) error {
	if err := dispatch.VerifyTicketBoundDispatchProof(chainID, name, raw, ticket, keys.options(orderEarliestSubmitHeight)); err != nil {
		return proofErr(name, err)
	}
	return nil
}

// builderBindingField is the BuilderMessageBindingV1 that OpenVerifyV1 and
// VerifierAssignmentNotifyV1 sign their generation in.
const builderBindingField = "binding"

// SignedBuilderNonce returns the service key generation a Builder-signed
// message names: its own top-level service_authorization_nonce, or that of
// its signed BuilderMessageBindingV1 (OpenVerifyV1, VerifierAssignmentNotifyV1;
// since wire b30fba8 those nonces also select current or previous). has is
// false for a type that names no generation. Call it on bytes wire's strict
// decoder accepted: a duplicated field is not resolved here.
func SignedBuilderNonce(fullName string, raw []byte) (nonce uint64, has bool, err error) {
	mt, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(fullName))
	if err != nil {
		return 0, false, fmt.Errorf("%w: %s is not a registered message", ErrNotBuilderSigned, fullName)
	}
	desc := mt.Descriptor()
	if f := desc.Fields().ByName(builderNonceField); f != nil && f.Kind() == protoreflect.Uint64Kind && !f.IsList() {
		v, _, err := scalarField(fullName, raw, f.Number())
		return v, true, err
	}
	b := desc.Fields().ByName(builderBindingField)
	if b == nil || b.Kind() != protoreflect.MessageKind || b.IsList() {
		return 0, false, nil
	}
	f := b.Message().Fields().ByName(builderNonceField)
	if f == nil || f.Kind() != protoreflect.Uint64Kind || f.IsList() {
		return 0, false, nil
	}
	_, binding, err := scalarField(fullName, raw, b.Number())
	if err != nil {
		return 0, true, err
	}
	v, _, err := scalarField(fullName, binding, f.Number())
	return v, true, err
}

// scalarField returns the first occurrence of field num in raw: a varint's
// value or a length-delimited field's bytes. An absent field is zero/nil.
func scalarField(fullName string, raw []byte, num protowire.Number) (uint64, []byte, error) {
	for b := raw; len(b) > 0; {
		n, typ, l := protowire.ConsumeTag(b)
		if l < 0 {
			return 0, nil, fmt.Errorf("%s: %w", fullName, protowire.ParseError(l))
		}
		b = b[l:]
		switch {
		case n == num && typ == protowire.VarintType:
			v, m := protowire.ConsumeVarint(b)
			if m < 0 {
				return 0, nil, fmt.Errorf("%s: %w", fullName, protowire.ParseError(m))
			}
			return v, nil, nil
		case n == num && typ == protowire.BytesType:
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return 0, nil, fmt.Errorf("%s: %w", fullName, protowire.ParseError(m))
			}
			return 0, v, nil
		}
		m := protowire.ConsumeFieldValue(n, typ, b)
		if m < 0 {
			return 0, nil, fmt.Errorf("%s: %w", fullName, protowire.ParseError(m))
		}
		b = b[m:]
	}
	return 0, nil, nil
}
