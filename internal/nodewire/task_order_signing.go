package nodewire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"unicode/utf8"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/codec"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// TaskOrderSigningDigest derives the EIP-712 order domain version 3, which binds
// the raw bytes32 model id. EVM chain ID and fee denomination are authoritative
// chain configuration; the order does not carry either, so callers must provide
// both explicitly.
func TaskOrderSigningDigest(order *taskv1.TaskOrderV3, evmChainID uint64, feeDenom string) (codec.Hash, error) {
	if order == nil {
		return codec.Hash{}, fmt.Errorf("TaskOrderV3 is required")
	}
	raw, err := proto.Marshal(order)
	if err != nil {
		return codec.Hash{}, err
	}
	decoded, err := decodeTaskOrderV3(raw)
	if err != nil {
		return codec.Hash{}, err
	}
	return taskOrderSigningDigest(decoded, evmChainID, feeDenom)
}

func taskOrderSigningDigest(order taskOrderV3, evmChainID uint64, feeDenom string) (codec.Hash, error) {
	if evmChainID == 0 || feeDenom == "" || !utf8.ValidString(feeDenom) {
		return codec.Hash{}, fmt.Errorf("authoritative EVM chain ID and fee denomination are required")
	}
	taskHash, err := taskOrderHash(order)
	if err != nil {
		return codec.Hash{}, err
	}
	return taskOrderTypedDigest(order, taskHash, evmChainID, feeDenom), nil
}

func taskOrderTypedDigest(order taskOrderV3, taskHash codec.Hash, evmChainID uint64, feeDenom string) codec.Hash {
	domain := orderKeccak(
		orderKeccak([]byte("EIP712Domain(string name,string version,uint256 chainId)")),
		orderKeccak([]byte("TrueOpen Task Order")), orderKeccak([]byte("3")), orderUint256(evmChainID))
	message := orderKeccak(
		orderKeccak([]byte("TaskOrder(string chainId,string user,bytes32 sessionId,uint64 orderSequence,bytes32 modelId,uint32 profileVersion,string maxFee,string feeDenom,uint64 earliestSubmitHeight,uint64 orderExpireHeight,bytes32 taskHash)")),
		orderKeccak([]byte(order.ChainID)), orderKeccak([]byte(order.UserAddress)), order.SessionID,
		orderUint256(uint64(order.OrderSequence)), []byte(order.ModelID), orderUint256(uint64(order.ProfileVersion)),
		orderKeccak([]byte(order.MaxFee.AtomicUnits)), orderKeccak([]byte(feeDenom)),
		orderUint256(uint64(order.EarliestSubmitHeight)), orderUint256(uint64(order.OrderExpireHeight)), taskHash[:])
	var digest codec.Hash
	copy(digest[:], orderKeccak([]byte{0x19, 0x01}, domain, message))
	return digest
}

// ErrNoSignatureChainID: the carrier states no signature_chain_id and the
// caller supplied no fallback EVM chain id, so its EIP-712 domain is unknown.
var ErrNoSignatureChainID = errors.New("SignedOrderV2 states no signature_chain_id and no fallback EVM chain id was given")

// SignedOrderView is one decode of a SignedOrderV2 carrier: the canonical
// task_hash, the order facts and the recovered signing account.
type SignedOrderView struct {
	TaskHash codec.Hash
	Facts    TaskOrderFacts
	// Signer is the 20-byte account that produced user_signature. Whether it
	// may sign for the session is the caller's decision: the wallet branch is
	// Signer == user_address, the delegated branch (wire v0.5.1) is Signer ==
	// StreamState.session_key, and only the caller holds StreamState.
	Signer []byte
}

// ParseSignedOrder decodes the carrier once and returns its task hash, facts
// and signer. The EIP-712 domain chain id is the one the carrier states: the
// signing wallet chose it and the signature covers it, so it is read from the
// carrier rather than configured. evmChainID is the fallback for a carrier
// that states none, which is every carrier signed before the field existed,
// when the chain's own EVM chain id was the authoritative domain; with
// evmChainID 0 such a carrier is refused with ErrNoSignatureChainID.
func ParseSignedOrder(value string, evmChainID uint64, feeDenom string) (SignedOrderView, error) {
	carrier, err := parseSignedOrderHex(value)
	if err != nil {
		return SignedOrderView{}, err
	}
	taskHash, err := taskOrderHash(carrier.order)
	if err != nil {
		return SignedOrderView{}, err
	}
	domain := carrier.domainChainID(evmChainID)
	if domain == 0 {
		return SignedOrderView{}, ErrNoSignatureChainID
	}
	if feeDenom == "" || !utf8.ValidString(feeDenom) {
		return SignedOrderView{}, fmt.Errorf("authoritative EVM chain ID and fee denomination are required")
	}
	digest := taskOrderTypedDigest(carrier.order, taskHash, domain, feeDenom)
	compact := append([]byte{carrier.userSignature[64]}, carrier.userSignature[:64]...)
	pub, _, err := ecdsa.RecoverCompact(compact, digest[:])
	if err != nil {
		return SignedOrderView{}, fmt.Errorf("recover order signer: %w", err)
	}
	return SignedOrderView{TaskHash: taskHash, Facts: carrier.facts(), Signer: orderKeccak(pub.SerializeUncompressed()[1:])[12:]}, nil
}

// SignedOrderSigner is ParseSignedOrder's Signer.
func SignedOrderSigner(value string, evmChainID uint64, feeDenom string) ([]byte, error) {
	view, err := ParseSignedOrder(value, evmChainID, feeDenom)
	if err != nil {
		return nil, err
	}
	return view.Signer, nil
}

// VerifySignedOrderEnvelope checks the exact signed carrier against its
// user_address. It accepts only the current SignedOrderV2 eip712 signature
// format.
//
// Since wire v0.5.1 the Keeper also admits an order signed by the session's
// registered key. That branch needs StreamState, so it is not checked here: this
// verifies the wallet branch only, and admission must not rely on it (the
// Dispatcher uses SignedOrderSigner and checks both branches).
func VerifySignedOrderEnvelope(value string, evmChainID uint64, feeDenom string) error {
	signer, err := SignedOrderSigner(value, evmChainID, feeDenom)
	if err != nil {
		return err
	}
	raw, _ := hex.DecodeString(value)
	carrier, err := decodeSignedOrderV2(raw)
	if err != nil {
		return err
	}
	address, err := CanonicalOperatorAddressBytes("user_address", carrier.order.UserAddress)
	if err != nil {
		return err
	}
	if !bytes.Equal(address, signer) {
		return fmt.Errorf("SignedOrderV2 signature does not match user_address on EVM chain %s", strconv.FormatUint(carrier.domainChainID(evmChainID), 10))
	}
	return nil
}

// domainChainID is the EIP-712 domain chain id the carrier was signed under.
func (s signedOrderV2) domainChainID(fallback uint64) uint64 {
	if s.signatureChainID != 0 {
		return s.signatureChainID
	}
	return fallback
}

func orderKeccak(parts ...[]byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	for _, part := range parts {
		_, _ = hash.Write(part)
	}
	return hash.Sum(nil)
}

func orderUint256(value uint64) []byte {
	word := make([]byte, 32)
	binary.BigEndian.PutUint64(word[24:], value)
	return word
}
