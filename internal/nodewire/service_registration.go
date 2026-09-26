package nodewire

import (
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
)

const DomainServiceRegistrationV1 = "TRUEOPEN_SERVICE_REGISTRATION_V1"

// ParticipantType values, as the frozen shared.v1.ParticipantType enum numbers
// them. The domain binds this immediately after chain_id so a Cortex proof and
// a Builder proof over otherwise identical material are different digests, which
// is what makes cross-participant replay fail rather than succeed.
const (
	ParticipantTypeCortexV1  uint32 = 1
	ParticipantTypeBuilderV1 uint32 = 2
)

// InitialServiceAuthorizationNonce is the nonce a first registration binds.
// Later key rotations carry a higher one; registration is always 1, so it is a
// constant here rather than a parameter a caller can get wrong.
const InitialServiceAuthorizationNonce uint64 = 1

// ServiceRegistrationPreimage returns the H_FIELDS_V1 projection the registry
// freezes for TRUEOPEN_SERVICE_REGISTRATION_V1 (§10.0c step 1).
//
// The signature over its digest is the proof-of-possession MsgStakeService
// carries as service_key_proof: it shows the holder of service_pubkey agreed to
// be bound to this operator, on this chain, in this role. The Hub Keeper
// recomputes the same digest and rejects a mismatch, so every field here is
// consensus-visible and none of them is a local convention.
//
// operatorAddress is the address's 20 raw bytes, NOT its bech32 text. The
// distinction matters and is easy to get wrong in the direction that still
// compiles: framing the bech32 string produces a well-formed digest that the
// chain will simply refuse, with nothing pointing at the cause.
func ServiceRegistrationPreimage(chainID string, participantType uint32, operatorAddress []byte, servicePubkey []byte, nonce uint64) ([]byte, error) {
	if _, err := canonicalUTF8Field("chain_id", chainID); err != nil {
		return nil, err
	}
	// canonicalUTF8Field accepts the empty string, which is right for digests
	// whose chain_id was already established upstream. Here it is not: this
	// proof's whole content is "I agree to be bound to this operator on this
	// chain", and an empty chain_id binds it to none. It would still frame,
	// still hash and still sign -- and then be refused on chain with nothing
	// pointing at the cause.
	if chainID == "" {
		return nil, fmt.Errorf("chain_id is required: a registration proof binds a service key to one chain")
	}
	switch participantType {
	case ParticipantTypeCortexV1, ParticipantTypeBuilderV1:
	default:
		return nil, fmt.Errorf("participant_type %d is not a registerable identity domain", participantType)
	}
	if len(operatorAddress) != 20 {
		return nil, fmt.Errorf("operator_address must be the 20 raw address bytes, got %d", len(operatorAddress))
	}
	if len(servicePubkey) != 33 {
		return nil, fmt.Errorf("service_pubkey must be the 33-byte compressed secp256k1 key, got %d", len(servicePubkey))
	}
	if nonce == 0 {
		return nil, fmt.Errorf("initial_service_authorization_nonce must not be zero")
	}
	return hfields.Preimage(
		DomainServiceRegistrationV1,
		hfields.String(chainID),
		hfields.Uint32(participantType),
		hfields.Bytes(operatorAddress),
		hfields.Bytes(servicePubkey),
		hfields.Uint64(nonce),
	)
}

// ServiceRegistrationDigest is what a registering node signs to produce
// service_key_proof.
func ServiceRegistrationDigest(chainID string, participantType uint32, operatorAddress []byte, servicePubkey []byte, nonce uint64) (codec.Hash, error) {
	return digestOf(ServiceRegistrationPreimage(chainID, participantType, operatorAddress, servicePubkey, nonce))
}

// CortexServiceRegistrationDigest is the same digest for a caller holding the
// bech32 operator address, which is the form it takes in config, in logs and in
// every command line. It decodes through the same helper the other digests use,
// so an address this repository would refuse anywhere else is refused here too
// rather than being framed as opaque bytes.
func CortexServiceRegistrationDigest(chainID, operatorAddress string, servicePubkey []byte) (codec.Hash, error) {
	raw, err := CanonicalOperatorAddressBytes("operator_address", operatorAddress)
	if err != nil {
		return codec.Hash{}, err
	}
	return ServiceRegistrationDigest(chainID, ParticipantTypeCortexV1, raw, servicePubkey, InitialServiceAuthorizationNonce)
}
