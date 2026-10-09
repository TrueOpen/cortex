package nodewire

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/wirevectors"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

func TestTaskOrderEIP712PublishedDigest(t *testing.T) {
	raw, err := wirevectors.File("shared/account_signing_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		TaskOrder struct {
			Domain struct {
				ChainID string `json:"chain_id"`
			}
			Message       map[string]string
			SigningDigest string `json:"signing_digest"`
		} `json:"task_order"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	m := fixture.TaskOrder.Message
	u := func(k string) uint64 {
		v, err := strconv.ParseUint(m[k], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	b := func(k string) []byte {
		v, err := hex.DecodeString(m[k])
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	order := taskOrderV3{ChainID: m["chainId"], UserAddress: m["user"], SessionID: b("sessionId"), OrderSequence: taskOrderUint64(u("orderSequence")),
		ModelID: b("modelId"), ProfileVersion: uint32(u("profileVersion")), MaxFee: taskOrderAmount{AtomicUnits: m["maxFee"]},
		EarliestSubmitHeight: taskOrderUint64(u("earliestSubmitHeight")), OrderExpireHeight: taskOrderUint64(u("orderExpireHeight"))}
	chainID, err := strconv.ParseUint(fixture.TaskOrder.Domain.ChainID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	var taskHash codec.Hash
	copy(taskHash[:], b("taskHash"))
	digest := taskOrderTypedDigest(order, taskHash, chainID, m["feeDenom"])
	if hex.EncodeToString(digest[:]) != fixture.TaskOrder.SigningDigest {
		t.Fatalf("EIP-712 digest %x, want %s", digest, fixture.TaskOrder.SigningDigest)
	}
}

// wire v0.4.0 links each accepted task_order_v3.json order to its EIP-712
// signing digest. The account_signing_v1.json vector above signs an opaque
// taskHash; these rows are the ones whose taskHash is a real
// TRUEOPEN_TASK_ORDER_V3 digest, so they bind the whole chain the user signs.
func TestTaskOrderEIP712VectorsMatchEveryPublishedDigest(t *testing.T) {
	raw, err := wirevectors.File("task/task_order_eip712_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Domain struct {
			ChainID string `json:"chain_id"`
		} `json:"domain"`
		FeeDenom string `json:"fee_denom"`
		Vectors  []struct {
			Name          string            `json:"name"`
			TaskHash      string            `json:"task_hash"`
			Message       map[string]string `json:"message"`
			SigningDigest string            `json:"signing_digest"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Vectors) == 0 {
		t.Fatal("wire publishes no task-order EIP-712 vectors")
	}
	chainID, err := strconv.ParseUint(fixture.Domain.ChainID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	for _, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			m := vector.Message
			u := func(k string) uint64 {
				v, err := strconv.ParseUint(m[k], 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				return v
			}
			b := func(k string) []byte {
				v, err := hex.DecodeString(m[k])
				if err != nil {
					t.Fatal(err)
				}
				return v
			}
			if m["feeDenom"] != fixture.FeeDenom {
				t.Fatalf("message feeDenom %q, want the file's %q", m["feeDenom"], fixture.FeeDenom)
			}
			if m["taskHash"] != vector.TaskHash {
				t.Fatalf("message taskHash %s, want the row's %s", m["taskHash"], vector.TaskHash)
			}
			order := taskOrderV3{ChainID: m["chainId"], UserAddress: m["user"], SessionID: b("sessionId"), OrderSequence: taskOrderUint64(u("orderSequence")),
				ModelID: b("modelId"), ProfileVersion: uint32(u("profileVersion")), MaxFee: taskOrderAmount{AtomicUnits: m["maxFee"]},
				EarliestSubmitHeight: taskOrderUint64(u("earliestSubmitHeight")), OrderExpireHeight: taskOrderUint64(u("orderExpireHeight"))}
			var taskHash codec.Hash
			copy(taskHash[:], b("taskHash"))
			digest := taskOrderTypedDigest(order, taskHash, chainID, fixture.FeeDenom)
			if hex.EncodeToString(digest[:]) != vector.SigningDigest {
				t.Fatalf("EIP-712 digest %x, want %s", digest, vector.SigningDigest)
			}
		})
	}
}

func TestSignedOrderVerifiesAddressAndEverySignedScope(t *testing.T) {
	var order taskv1.TaskOrderV3
	if err := protojson.Unmarshal(goldenTaskOrderJSON(t), &order); err != nil {
		t.Fatal(err)
	}
	key := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{1}, 32))
	address := orderKeccak(key.PubKey().SerializeUncompressed()[1:])[12:]
	var err error
	order.UserAddress, err = bech32ConvertAndEncode("trueopen", address)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := TaskOrderSigningDigest(&order, 424242, "uusdc")
	if err != nil {
		t.Fatal(err)
	}
	compact := ecdsa.SignCompact(key, digest[:], false)
	signature := append(append([]byte(nil), compact[1:]...), compact[0])
	encode := func(o *taskv1.TaskOrderV3, sig []byte) string {
		raw, err := proto.Marshal(&taskv1.SignedOrderV2{Order: o, SignatureScheme: "eip712", UserSignature: sig})
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(raw)
	}
	carrier := encode(&order, signature)
	if err := VerifySignedOrderEnvelope(carrier, 424242, "uusdc"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*taskv1.TaskOrderV3)
	}{
		{"chain", func(o *taskv1.TaskOrderV3) { o.ChainId += "-changed" }},
		{"price", func(o *taskv1.TaskOrderV3) { o.PriceBid.AtomicUnits = "4" }},
		{"generation", func(o *taskv1.TaskOrderV3) { o.GenerationParams.DecodingParams.Seed++ }},
		{"user", func(o *taskv1.TaskOrderV3) { o.UserAddress = "trueopen1kxet8d94k6mm3wd6hw7tm04lcrqu9s7yxckkka" }},
		{"legacy schema", func(o *taskv1.TaskOrderV3) { o.SchemaVersion = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := proto.Clone(&order).(*taskv1.TaskOrderV3)
			tc.mutate(changed)
			if err := VerifySignedOrderEnvelope(encode(changed, signature), 424242, "uusdc"); err == nil {
				t.Fatal("mutated scope accepted")
			}
		})
	}
	if err := VerifySignedOrderEnvelope(carrier, 424243, "uusdc"); err == nil {
		t.Fatal("wrong EVM chain accepted")
	}
	if err := VerifySignedOrderEnvelope(carrier, 424242, "utrueopen"); err == nil {
		t.Fatal("wrong fee denomination accepted")
	}
	if _, err := TaskOrderSigningDigest(&order, 0, "uusdc"); err == nil {
		t.Fatal("missing EVM chain accepted")
	}
	if _, err := TaskOrderSigningDigest(&order, 424242, ""); err == nil {
		t.Fatal("missing denomination accepted")
	}
	highS := append([]byte(nil), signature...)
	for i := 32; i < 64; i++ {
		highS[i] = 0xff
	}
	if err := VerifySignedOrderEnvelope(encode(&order, highS), 424242, "uusdc"); err == nil {
		t.Fatal("high-S accepted")
	}
}

// TestSignedOrderVerifiesUnderTheCarriedChainID checks where the EIP-712 domain
// chain id comes from once the carrier states one. A browser wallet signs under
// whatever network it is on, so the carried value is authoritative and the
// configured one is only the fallback for a carrier that states none.
func TestSignedOrderVerifiesUnderTheCarriedChainID(t *testing.T) {
	var order taskv1.TaskOrderV3
	if err := protojson.Unmarshal(goldenTaskOrderJSON(t), &order); err != nil {
		t.Fatal(err)
	}
	key := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{2}, 32))
	address := orderKeccak(key.PubKey().SerializeUncompressed()[1:])[12:]
	var err error
	if order.UserAddress, err = bech32ConvertAndEncode("trueopen", address); err != nil {
		t.Fatal(err)
	}
	// The wallet's network, which is not the chain id the node would configure.
	const walletChainID = 11155111
	digest, err := TaskOrderSigningDigest(&order, walletChainID, "uusdc")
	if err != nil {
		t.Fatal(err)
	}
	compact := ecdsa.SignCompact(key, digest[:], false)
	signature := append(append([]byte(nil), compact[1:]...), compact[0])
	// wire v0.4.0's generated type has no signature_chain_id, so the field is
	// appended as the v0.5.0 signer writes it.
	carrier := func(id uint64) string {
		raw, err := proto.Marshal(&taskv1.SignedOrderV2{Order: &order, SignatureScheme: "eip712", UserSignature: signature})
		if err != nil {
			t.Fatal(err)
		}
		if id == 0 {
			return hex.EncodeToString(raw)
		}
		return hex.EncodeToString(protowire.AppendVarint(protowire.AppendTag(raw, 4, protowire.VarintType), id))
	}

	if err := VerifySignedOrderEnvelope(carrier(walletChainID), 424242, "uusdc"); err != nil {
		t.Fatalf("carried chain id was not used to rebuild the domain: %v", err)
	}
	// The carrier claiming the configured chain id does not make the signature
	// verify under it: the claim is covered by the signature, not trusted beside it.
	if err := VerifySignedOrderEnvelope(carrier(424242), 424242, "uusdc"); err == nil {
		t.Fatal("a carrier claiming a chain id it was not signed under was accepted")
	}
	// Stating none falls back to the configured chain id, which is how every
	// carrier signed before the field existed still verifies.
	if err := VerifySignedOrderEnvelope(carrier(0), walletChainID, "uusdc"); err != nil {
		t.Fatalf("a carrier stating no chain id did not fall back: %v", err)
	}
	if err := VerifySignedOrderEnvelope(carrier(0), 424242, "uusdc"); err == nil {
		t.Fatal("the fallback accepted a chain id the order was not signed under")
	}
}
