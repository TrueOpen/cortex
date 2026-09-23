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
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/wirevectors"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

func TestTaskOrderEIP712V2PublishedDigest(t *testing.T) {
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
	order := taskOrderV2{ChainID: m["chainId"], UserAddress: m["user"], SessionID: b("sessionId"), OrderSequence: taskOrderUint64(u("orderSequence")),
		ModelID: m["modelId"], ProfileVersion: uint32(u("profileVersion")), MaxFee: taskOrderAmount{AtomicUnits: m["maxFee"]},
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

func TestSignedOrderV2VerifiesAddressAndEverySignedScope(t *testing.T) {
	var order taskv1.TaskOrderV2
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
	encode := func(o *taskv1.TaskOrderV2, sig []byte) string {
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
		mutate func(*taskv1.TaskOrderV2)
	}{
		{"chain", func(o *taskv1.TaskOrderV2) { o.ChainId += "-changed" }},
		{"price", func(o *taskv1.TaskOrderV2) { o.PriceBid.AtomicUnits = "4" }},
		{"generation", func(o *taskv1.TaskOrderV2) { o.GenerationParams.DecodingParams.Seed++ }},
		{"user", func(o *taskv1.TaskOrderV2) { o.UserAddress = "trueopen1kxet8d94k6mm3wd6hw7tm04lcrqu9s7yxckkka" }},
		{"legacy schema", func(o *taskv1.TaskOrderV2) { o.SchemaVersion = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := proto.Clone(&order).(*taskv1.TaskOrderV2)
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
