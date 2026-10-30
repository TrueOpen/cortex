package nodewire

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

func TestSignedOrderSignerRecoversTheSigningAccount(t *testing.T) {
	var order taskv1.TaskOrderV3
	if err := protojson.Unmarshal(goldenTaskOrderJSON(t), &order); err != nil {
		t.Fatal(err)
	}
	wallet := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{1}, 32))
	delegate := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{2}, 32))
	var err error
	if order.UserAddress, err = EVMAccountAddress("trueopen", wallet.PubKey().SerializeUncompressed()); err != nil {
		t.Fatal(err)
	}
	walletRaw, err := CanonicalOperatorAddressBytes("user_address", order.UserAddress)
	if err != nil {
		t.Fatal(err)
	}
	carrier := func(key *secp256k1.PrivateKey) string {
		digest, err := TaskOrderSigningDigest(&order, 4242, "uusdc")
		if err != nil {
			t.Fatal(err)
		}
		compact := ecdsa.SignCompact(key, digest[:], false)
		raw, err := proto.Marshal(&taskv1.SignedOrderV2{Order: &order, SignatureScheme: "eip712",
			UserSignature: append(append([]byte(nil), compact[1:]...), compact[0]), SignatureChainId: 4242})
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(raw)
	}
	got, err := SignedOrderSigner(carrier(wallet), 0, "uusdc")
	if err != nil || !bytes.Equal(got, walletRaw) {
		t.Fatalf("wallet signer = %x, %v; want %x", got, err, walletRaw)
	}
	if err := VerifySignedOrderEnvelope(carrier(wallet), 0, "uusdc"); err != nil {
		t.Fatalf("the wallet branch must still verify: %v", err)
	}
	delegateAddr, err := EVMAccountAddress("trueopen", delegate.PubKey().SerializeUncompressed())
	if err != nil {
		t.Fatal(err)
	}
	delegateRaw, err := CanonicalOperatorAddressBytes("delegate", delegateAddr)
	if err != nil {
		t.Fatal(err)
	}
	got, err = SignedOrderSigner(carrier(delegate), 0, "uusdc")
	if err != nil || !bytes.Equal(got, delegateRaw) {
		t.Fatalf("delegate signer = %x, %v; want %x", got, err, delegateRaw)
	}
	if err := VerifySignedOrderEnvelope(carrier(delegate), 0, "uusdc"); err == nil {
		t.Fatal("a delegate's signature is not the wallet branch")
	}
	if _, err := SignedOrderSigner(carrier(wallet), 0, ""); err == nil {
		t.Fatal("the fee denomination is part of the signed domain and is required")
	}
	if _, err := EVMAccountAddress("trueopen", wallet.PubKey().SerializeCompressed()); err == nil {
		t.Fatal("only the 65-byte uncompressed point derives an EVM account")
	}
}

// ParseSignedOrder decodes the carrier once and answers task hash, facts and
// signer together; a carrier that states no signature_chain_id needs a
// fallback chain id, and without one it is refused by name.
func TestParseSignedOrderAnswersOnce(t *testing.T) {
	var order taskv1.TaskOrderV3
	if err := protojson.Unmarshal(goldenTaskOrderJSON(t), &order); err != nil {
		t.Fatal(err)
	}
	wallet := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{1}, 32))
	var err error
	if order.UserAddress, err = EVMAccountAddress("trueopen", wallet.PubKey().SerializeUncompressed()); err != nil {
		t.Fatal(err)
	}
	walletRaw, err := CanonicalOperatorAddressBytes("user_address", order.UserAddress)
	if err != nil {
		t.Fatal(err)
	}
	carrier := func(chainID uint64) string {
		digest, err := TaskOrderSigningDigest(&order, 4242, "uusdc")
		if err != nil {
			t.Fatal(err)
		}
		compact := ecdsa.SignCompact(wallet, digest[:], false)
		raw, err := proto.Marshal(&taskv1.SignedOrderV2{Order: &order, SignatureScheme: "eip712",
			UserSignature: append(append([]byte(nil), compact[1:]...), compact[0]), SignatureChainId: chainID})
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(raw)
	}
	stated := carrier(4242)
	view, err := ParseSignedOrder(stated, 0, "uusdc")
	if err != nil {
		t.Fatal(err)
	}
	hash, facts, err := TaskOrderHashAndFactsSignedOrderHex(stated)
	if err != nil || view.TaskHash != hash || view.Facts.SessionID != facts.SessionID || view.Facts.SignatureChainID != 4242 || !bytes.Equal(view.Signer, walletRaw) {
		t.Fatalf("view = %+v, %v", view, err)
	}
	legacy := carrier(0)
	if _, err := ParseSignedOrder(legacy, 0, "uusdc"); !errors.Is(err, ErrNoSignatureChainID) {
		t.Fatalf("legacy carrier without a fallback: err = %v, want ErrNoSignatureChainID", err)
	}
	if view, err := ParseSignedOrder(legacy, 4242, "uusdc"); err != nil || !bytes.Equal(view.Signer, walletRaw) {
		t.Fatalf("legacy carrier with the fallback: %+v, %v", view, err)
	}
}
