package nodewire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"unicode/utf8"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/codec"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// TaskOrderSigningDigest derives the released EIP-712 order domain version 2.
// EVM chain ID and fee denomination are authoritative chain configuration; the
// order does not carry either, so callers must provide both explicitly.
func TaskOrderSigningDigest(order *taskv1.TaskOrderV2, evmChainID uint64, feeDenom string) (codec.Hash, error) {
	if order == nil {
		return codec.Hash{}, fmt.Errorf("TaskOrderV2 is required")
	}
	raw, err := proto.Marshal(order)
	if err != nil {
		return codec.Hash{}, err
	}
	decoded, err := decodeTaskOrderV2(raw)
	if err != nil {
		return codec.Hash{}, err
	}
	return taskOrderSigningDigest(decoded, evmChainID, feeDenom)
}

func taskOrderSigningDigest(order taskOrderV2, evmChainID uint64, feeDenom string) (codec.Hash, error) {
	if evmChainID == 0 || feeDenom == "" || !utf8.ValidString(feeDenom) {
		return codec.Hash{}, fmt.Errorf("authoritative EVM chain ID and fee denomination are required")
	}
	taskHash, err := taskOrderHash(order)
	if err != nil {
		return codec.Hash{}, err
	}
	return taskOrderTypedDigest(order, taskHash, evmChainID, feeDenom), nil
}

func taskOrderTypedDigest(order taskOrderV2, taskHash codec.Hash, evmChainID uint64, feeDenom string) codec.Hash {
	domain := orderKeccak(
		orderKeccak([]byte("EIP712Domain(string name,string version,uint256 chainId)")),
		orderKeccak([]byte("TrueOpen Task Order")), orderKeccak([]byte("2")), orderUint256(evmChainID))
	message := orderKeccak(
		orderKeccak([]byte("TaskOrder(string chainId,string user,bytes32 sessionId,uint64 orderSequence,string modelId,uint32 profileVersion,string maxFee,string feeDenom,uint64 earliestSubmitHeight,uint64 orderExpireHeight,bytes32 taskHash)")),
		orderKeccak([]byte(order.ChainID)), orderKeccak([]byte(order.UserAddress)), order.SessionID,
		orderUint256(uint64(order.OrderSequence)), orderKeccak([]byte(order.ModelID)), orderUint256(uint64(order.ProfileVersion)),
		orderKeccak([]byte(order.MaxFee.AtomicUnits)), orderKeccak([]byte(feeDenom)),
		orderUint256(uint64(order.EarliestSubmitHeight)), orderUint256(uint64(order.OrderExpireHeight)), taskHash[:])
	var digest codec.Hash
	copy(digest[:], orderKeccak([]byte{0x19, 0x01}, domain, message))
	return digest
}

// VerifySignedOrderEnvelope checks the exact signed carrier and recovered user
// address. It accepts only the current SignedOrderV2 eip712 signature format.
func VerifySignedOrderEnvelope(value string, evmChainID uint64, feeDenom string) error {
	if _, _, err := TaskOrderHashAndFactsSignedOrderHex(value); err != nil {
		return err
	}
	raw, _ := hex.DecodeString(value)
	order, _, signature, err := decodeSignedOrderV2(raw)
	if err != nil {
		return err
	}
	digest, err := taskOrderSigningDigest(order, evmChainID, feeDenom)
	if err != nil {
		return err
	}
	compact := append([]byte{signature[64]}, signature[:64]...)
	pub, _, err := ecdsa.RecoverCompact(compact, digest[:])
	if err != nil {
		return fmt.Errorf("recover order signer: %w", err)
	}
	address, err := CanonicalOperatorAddressBytes("user_address", order.UserAddress)
	if err != nil {
		return err
	}
	recovered := orderKeccak(pub.SerializeUncompressed()[1:])[12:]
	if !bytes.Equal(address, recovered) {
		return fmt.Errorf("SignedOrderV2 signature does not match user_address on EVM chain %s", strconv.FormatUint(evmChainID, 10))
	}
	return nil
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
