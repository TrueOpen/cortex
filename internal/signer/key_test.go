package signer

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
)

func TestServiceAddressesMatchNodeEthereumSeed(t *testing.T) {
	// Public vectors from TrueOpen/node 6779581, config/localnet_genesis_seed.json.
	for _, tc := range []struct{ public, address string }{
		{"0298c2da175fd3063bd2e8156303b98a0f77df43c5ca078eaa08dc2533e829f507", "trueopen1j5me037hs26kmqz7xy6s5f0y224trsphlqjfd2"},
		{"039832910fde7c4012d0b00e0305a2b55073e7fa6bf7670908fbf9467bbfe01849", "trueopen1q8fazf4duvmw5as74kgyyezdxdewahzydav3vl"},
		{"03ce74fda5a57435f8e7796323d65ac00a239e2b33996e45cdd72899870b387271", "trueopen1zz29gdunukh0dsckd5kmete0hmnu6d0ta55vgj"},
		{"028ed93ad13ccc93e453844503fbad48e8ec02e7df22e082697dfd517c4edccada", "trueopen13f2wj4cc90la25k5dljj4ktukp7chremmddxqv"},
	} {
		t.Run(tc.address, func(t *testing.T) {
			public, err := hex.DecodeString(tc.public)
			if err != nil {
				t.Fatal(err)
			}
			got, err := AddressFromCompressedPublicKey("trueopen", public)
			if err != nil || got != tc.address {
				t.Fatalf("service address = %q, %v; want %q", got, err, tc.address)
			}
		})
	}
}

func TestLocalSignerUsesEthereumAccountForDigestSigning(t *testing.T) {
	private, err := parsePrivateKeyHex(strings.Repeat("0", 63) + "1")
	if err != nil {
		t.Fatal(err)
	}
	// Ethereum account for the public test key with private scalar 1.
	raw, err := hex.DecodeString("7e5f4552091a69125d5dfcb7b8c2659029395bdf")
	if err != nil {
		t.Fatal(err)
	}
	address, err := bech32Encode("trueopen", raw)
	if err != nil {
		t.Fatal(err)
	}
	local := &LocalSigner{hrp: "trueopen", keys: map[string]*Key{"service": {Ref: "service", private: private}}}
	if got, ok := local.AddressFor("service"); !ok || got != address {
		t.Fatalf("AddressFor = %q, %v; want %q", got, ok, address)
	}
	keys := local.Keys()
	if len(keys) != 1 || keys[0].Address != address {
		t.Fatalf("Keys = %+v; want Ethereum account %q", keys, address)
	}
	digest := codec.HashWithDomain("TRUEOPEN_SERVICE_KEY_READINESS_V1", []byte("binding"))
	signature, err := local.SignDigest(context.Background(), DigestRequest{KeyRef: "service", ExpectedSignerAddress: address, Digest: digest})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDigestSignature(keys[0].CompressedPubkey, digest, signature); err != nil {
		t.Fatalf("protocol digest signature changed: %v", err)
	}
}
