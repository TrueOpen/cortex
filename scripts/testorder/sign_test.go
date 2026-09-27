package main

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/daemon"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/signer"
	busv1 "github.com/TrueOpen/cortex/proto/bus/v1"
	"google.golang.org/protobuf/proto"
)

const (
	testKeystorePassword = "testpassword"
	// The canonical Web3 Secret Storage (keystore v3) test vector, so the test
	// keystore is one geth, ethers or web3.py would also read. It is written into
	// a temp dir per test: nothing here depends on a file outside the repo.
	testKeystoreJSON = `{
	  "crypto": {
	    "cipher": "aes-128-ctr",
	    "cipherparams": {"iv": "6087dab2f9fdbbfaddc31a909735c1e6"},
	    "ciphertext": "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
	    "kdf": "pbkdf2",
	    "kdfparams": {"c": 262144, "dklen": 32, "prf": "hmac-sha256", "salt": "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"},
	    "mac": "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
	  },
	  "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
	  "version": 3
	}`

	testKeyRef = "service.json"
	// A canonical 20-byte trueopen Bech32 address: the TaskOrderV1 hash decodes
	// user_address, so a placeholder string would fail before anything about
	// signing was exercised. It is deliberately NOT the signing key's own
	// address: the sender is an operator identity and the signing key is its
	// service key, and the two are separate rows on chain.
	testBuilderAddr = "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc"
	testChainID     = "trueopen-devnet-1"
	testModelID     = "099066ebc1498400466fabe744606f360622d8eb24447a109b7a22f89cf4403f"
	// testEnvelopeTTL is both the envelope lifetime and the TTL the test
	// authenticator admits. The authenticator's bound is strict, so the two are
	// one constant rather than two that could drift apart.
	testEnvelopeTTL = 30 * time.Second
)

// testSignerSpec writes the keystore and its password file, then returns the
// spec the tool would build from its flags plus the loaded key's public
// identity. serviceAddress is left for the caller to set, because what belongs
// there is the address the chain binds - and the mismatch case needs a
// different one.
func testSignerSpec(t *testing.T) (signerSpec, signer.KeyDescriptor) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, testKeyRef), []byte(testKeystoreJSON), 0o600); err != nil {
		t.Fatalf("write keystore: %v", err)
	}
	passwordPath := filepath.Join(dir, "password")
	if err := os.WriteFile(passwordPath, []byte(testKeystorePassword+"\n"), 0o600); err != nil {
		t.Fatalf("write password: %v", err)
	}
	spec := signerSpec{
		uri:          "file://" + dir,
		keyRef:       testKeyRef,
		passwordFile: passwordPath,
		hrp:          bech32HRP(testBuilderAddr),
	}
	// The key's address and compressed pubkey come from the signer itself, so
	// the test asserts against what the keystore actually holds rather than a
	// hardcoded identity that could silently stop matching.
	signingClient, err := signer.Open(spec.uri, signer.OpenOptions{
		PasswordFile: spec.passwordFile,
		HRP:          spec.hrp,
		KeyRefs:      []signer.KeyRef{{Ref: spec.keyRef}},
	})
	if err != nil {
		t.Fatalf("signer.Open returned error: %v", err)
	}
	local, ok := signingClient.(*signer.LocalSigner)
	if !ok {
		t.Fatalf("signer.Open(file://) returned %T, want a local signer", signingClient)
	}
	keys := local.Keys()
	if len(keys) != 1 {
		t.Fatalf("keystore loaded %d keys, want 1", len(keys))
	}
	return spec, keys[0]
}

func testOrderSpec(seed string, nonce uint64, now time.Time) orderSpec {
	return orderSpec{
		chainID: testChainID, modelID: testModelID, builderAddr: testBuilderAddr,
		evmChainID: 424242, feeDenom: "uusdc",
		builderSetID: "7", builderSetHash: []byte(strings.Repeat("h", 32)),
		sessionAnchorBlockHash: []byte(strings.Repeat("a", 32)),
		profileVersion:         1, deadlineHeight: 122800, snapshotHeight: 122681,
		authorizationNonce: nonce, ttl: testEnvelopeTTL, now: now, sessionSeed: seed,
	}
}

func TestOrderUsesEIP712WithExplicitChainAndDenomination(t *testing.T) {
	spec := testOrderSpec("eip712", 4, time.Now().UTC())
	built, err := buildOrderFrame(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := builderclient.DecodeBusEnvelope(built.frame)
	if err != nil {
		t.Fatal(err)
	}
	var broadcast busv1.OrderBroadcastV1
	if err := envelope.DecodePayload(&broadcast); err != nil {
		t.Fatal(err)
	}
	encoded, err := proto.Marshal(broadcast.SignedOrder)
	if err != nil {
		t.Fatal(err)
	}
	carrier := hex.EncodeToString(encoded)
	if err := nodewire.VerifySignedOrderEnvelope(carrier, spec.evmChainID, spec.feeDenom); err != nil {
		t.Fatal(err)
	}
	if err := nodewire.VerifySignedOrderEnvelope(carrier, spec.evmChainID+1, spec.feeDenom); err == nil {
		t.Fatal("accepted another EVM chain domain")
	}
	if err := nodewire.VerifySignedOrderEnvelope(carrier, spec.evmChainID, "other"); err == nil {
		t.Fatal("accepted another fee denomination")
	}
	if broadcast.SignedOrder.Order.UserAddress == spec.builderAddr {
		t.Fatal("synthetic user was attributed to the Builder service identity")
	}
	for _, missing := range []string{"chain", "denomination"} {
		invalid := spec
		if missing == "chain" {
			invalid.evmChainID = 0
		} else {
			invalid.feeDenom = ""
		}
		if _, err := buildOrderFrame(invalid, nil); err == nil {
			t.Fatalf("accepted missing %s", missing)
		}
	}
}

// The whole point of the signing flag: the frame the tool publishes must pass
// the production verifier against the compressed pubkey of the signing key. The
// tool signs through internal/daemon's own signer and internal/builderclient's
// own sign bytes, so a frame that failed here would mean the tool minted
// something no node could ever accept.
func TestSignedFramePassesTheProductionVerifier(t *testing.T) {
	spec, key := testSignerSpec(t)
	spec.serviceAddress = key.Address

	envelopeSigner, signedAs, err := openEnvelopeSigner(spec)
	if err != nil {
		t.Fatalf("openEnvelopeSigner returned error: %v", err)
	}
	if signedAs != key.Address {
		t.Fatalf("openEnvelopeSigner reported %q, want the key's own address %q", signedAs, key.Address)
	}

	built, err := buildOrderFrame(testOrderSpec("signed", 4, time.Now().UTC()), envelopeSigner)
	if err != nil {
		t.Fatalf("buildOrderFrame returned error: %v", err)
	}
	if !built.signed {
		t.Fatal("buildOrderFrame reported an unsigned frame while given a signer")
	}
	envelope, err := builderclient.DecodeBusEnvelope(built.frame)
	if err != nil {
		t.Fatalf("DecodeBusEnvelope returned error: %v", err)
	}
	if err := builderclient.VerifyBusEnvelopeSignature(envelope, key.CompressedPubkey); err != nil {
		t.Fatalf("the production verifier refused the tool's own frame: %v", err)
	}

	// A signature that survives a rewrite of a signed field would authenticate
	// a frame the sender never minted. Each of these is one of the 20 signed
	// fields (interface-and-topic-list.md §5.2).
	for name, mutate := range map[string]func(*builderclient.BusEnvelope){
		"subject":                     func(e *builderclient.BusEnvelope) { e.Subject += ".elsewhere" },
		"expires_at_unix_ms":          func(e *builderclient.BusEnvelope) { e.ExpiresAtUnixMs += 60_000 },
		"service_authorization_nonce": func(e *builderclient.BusEnvelope) { e.ServiceAuthorizationNonce++ },
	} {
		t.Run(name, func(t *testing.T) {
			tampered := envelope
			mutate(&tampered)
			if err := builderclient.VerifyBusEnvelopeSignature(tampered, key.CompressedPubkey); err == nil {
				t.Fatalf("the verifier accepted a frame whose %s was rewritten after signing", name)
			}
		})
	}
}

// Without -signer-uri the tool must behave exactly as it always has: an
// unsigned envelope, which only a trusted_nats_dev node accepts.
func TestUnsignedFrameStaysUnsigned(t *testing.T) {
	built, err := buildOrderFrame(testOrderSpec("unsigned", 4, time.Now().UTC()), nil)
	if err != nil {
		t.Fatalf("buildOrderFrame returned error: %v", err)
	}
	if built.signed {
		t.Fatal("buildOrderFrame reported a signed frame while given no signer")
	}
	envelope, err := builderclient.DecodeBusEnvelope(built.frame)
	if err != nil {
		t.Fatalf("DecodeBusEnvelope returned error: %v", err)
	}
	if len(envelope.Signature) != 0 {
		t.Fatalf("the unsigned frame carries a %d-byte signature", len(envelope.Signature))
	}
}

// A key that is not the sender's current service key produces a frame the
// receiving node refuses at the signature step, so the tool must refuse it here
// instead of publishing something guaranteed to be rejected. Both addresses have
// to be named or the operator cannot tell which end is wrong.
func TestOpenEnvelopeSignerRefusesAKeyTheChainDoesNotBind(t *testing.T) {
	spec, key := testSignerSpec(t)
	spec.serviceAddress = "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"

	_, _, err := openEnvelopeSigner(spec)
	if err == nil {
		t.Fatal("openEnvelopeSigner accepted a key that is not the sender's current service key")
	}
	if !strings.Contains(err.Error(), key.Address) || !strings.Contains(err.Error(), spec.serviceAddress) {
		t.Fatalf("error = %v, want it to name both the key address %s and the bound service address %s",
			err, key.Address, spec.serviceAddress)
	}
}

// testMembership is the chain BuilderSet view the authenticator consults.
type testMembership struct{ member string }

func (m testMembership) HasBuilder(_ context.Context, operatorAddress string) (bool, error) {
	return operatorAddress == m.member, nil
}

// testKeeper reports one service-key binding, the way the Keeper would for a
// Builder whose key is ACTIVE.
type testKeeper struct {
	binding chainclient.ServiceKeySnapshot
}

func (k testKeeper) CurrentServiceKey(_ context.Context, _, _ string, _ uint64) (chainclient.ServiceKeySnapshot, error) {
	return k.binding, nil
}

// The end-to-end claim: a frame from this tool, signed with a Builder service
// key, authenticates against the real strict-mode authenticator when the chain
// reports that key as the sender's ACTIVE binding at the envelope's nonce.
//
// This runs the production busEnvelopeAuthenticator, not a reimplementation, so
// it covers every layer a strict node applies: membership, the current binding,
// the nonce, the signature and the replay claim.
func TestSignedFrameAuthenticatesAgainstAStrictModeNode(t *testing.T) {
	spec, key := testSignerSpec(t)
	spec.serviceAddress = key.Address
	envelopeSigner, _, err := openEnvelopeSigner(spec)
	if err != nil {
		t.Fatalf("openEnvelopeSigner returned error: %v", err)
	}

	const nonce = uint64(4)
	// A real clock: the authenticator's freshness window is compared against the
	// envelope's own stamps, and a historical test clock would make the frame
	// arrive already expired.
	now := time.Now().UTC()
	built, err := buildOrderFrame(testOrderSpec("strict-mode", nonce, now), envelopeSigner)
	if err != nil {
		t.Fatalf("buildOrderFrame returned error: %v", err)
	}
	envelope, err := builderclient.DecodeBusEnvelope(built.frame)
	if err != nil {
		t.Fatalf("DecodeBusEnvelope returned error: %v", err)
	}

	binding := chainclient.ServiceKeySnapshot{
		ParticipantType:    chainclient.ParticipantTypeBuilder,
		OperatorAddress:    testBuilderAddr,
		ServiceAddress:     key.Address,
		ServicePubkey:      key.CompressedPubkey,
		AuthorizationNonce: chainclient.NewUint64String(nonce),
		Status:             "ACTIVE",
	}
	authenticator, err := daemon.NewBusEnvelopeAuthenticator(daemon.BusEnvelopeAuthenticatorConfig{
		ChainID:             testChainID,
		Keeper:              testKeeper{binding: binding},
		Members:             testMembership{member: testBuilderAddr},
		PeerOperatorAddress: testBuilderAddr,
		TTL:                 testEnvelopeTTL,
		ClockSkew:           2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewBusEnvelopeAuthenticator returned error: %v", err)
	}
	if err := authenticator.Authenticate(context.Background(), built.subject, envelope); err != nil {
		t.Fatalf("a strict-mode node refused the tool's signed frame: %v", err)
	}
}
