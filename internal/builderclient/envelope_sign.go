package builderclient

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/TrueOpen/wire/bus"

	"github.com/TrueOpen/cortex/internal/codec"
)

// BusEnvelopeSignDomain is the domain separator of the TRUEOPEN_BUS_ENVELOPE_V2
// signing projection. The projection - which fields are signed, their order,
// their byte encodings and the digest rule - is owned by
// github.com/TrueOpen/wire/bus, the canonical implementation both nexus
// and cortex link. This repository never re-implements the byte layout.
//
// The domain moved from V1 to V2 with the protobuf migration: V1 named the
// retired 20-field trueopen-cjson-v1 projection, and one domain must never cover
// two different signed field sets.
const BusEnvelopeSignDomain = bus.Domain

// BusEnvelopeSignDigest returns the digest a signer signs: the typed
// H_FIELDS_V1 digest of the 13-field TRUEOPEN_BUS_ENVELOPE_V2 projection, as
// computed by wire's bus package.
func BusEnvelopeSignDigest(envelope BusEnvelope) (codec.Hash, error) {
	fields, err := envelope.signingFields()
	if err != nil {
		return codec.Hash{}, err
	}
	digest, err := bus.SigningDigest(fields)
	if err != nil {
		return codec.Hash{}, fmt.Errorf("Nexus BusEnvelope signing digest: %w", err)
	}
	return codec.Hash(digest), nil
}

// VerifyBusEnvelopeSignature checks an envelope signature against the sender's
// compressed secp256k1 public key hex. The key must be the one the chain
// currently binds to (sender_participant_type, sender_operator_address): this
// function deliberately takes the resolved key rather than reading one from
// the envelope, because an envelope-carried key authenticates nothing and no
// historical-key fallback is allowed.
//
// The signature rule - 64-byte compact low-S R||S over the direct digest,
// rejecting DER, 65-byte recoverable and high-S encodings - is enforced by
// wire's bus.VerifyDigestSignature.
func VerifyBusEnvelopeSignature(envelope BusEnvelope, compressedPubkeyHex string) error {
	if len(envelope.Signature) == 0 {
		return fmt.Errorf("Nexus envelope carries no signature")
	}
	publicKey, err := hex.DecodeString(strings.TrimSpace(compressedPubkeyHex))
	if err != nil {
		return fmt.Errorf("decode current service public key: %w", err)
	}
	digest, err := BusEnvelopeSignDigest(envelope)
	if err != nil {
		return err
	}
	if err := bus.VerifyDigestSignature(publicKey, digest[:], envelope.Signature); err != nil {
		return fmt.Errorf("verify Nexus envelope signature: %w", err)
	}
	return nil
}

// BusEnvelopeReplayKeys returns the durable StoreOnce keys for an envelope:
// wire's dual replay keys, one over message_id and one over nonce, both scoped
// to (chain_id, sender_operator, authorization_nonce) so one sender's
// identifiers cannot evict another's.
func BusEnvelopeReplayKeys(envelope BusEnvelope, authorizationNonce uint64) ([]string, error) {
	record := bus.ReplayRecord{
		ChainID:            strings.TrimSpace(envelope.ChainID),
		SenderOperator:     strings.TrimSpace(envelope.SenderOperatorAddress),
		AuthorizationNonce: authorizationNonce,
		MessageID:          strings.TrimSpace(envelope.MessageID),
		Nonce:              envelope.Nonce,
	}
	messageKey, err := record.MessageKey()
	if err != nil {
		return nil, err
	}
	nonceKey, err := record.NonceKey()
	if err != nil {
		return nil, err
	}
	return []string{messageKey, nonceKey}, nil
}
