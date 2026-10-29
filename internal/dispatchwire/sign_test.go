package dispatchwire

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/signer"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// fixtureKeyHex is wire's public test key for dispatch_v1.json (bytes 0x01 x32,
// compressed public key 031b84c5...). It is a published fixture, not a credential.
const fixtureKeyHex = "0101010101010101010101010101010101010101010101010101010101010101"

func localSigner(keyHex string) DigestSigner {
	return func(_ context.Context, d [32]byte) ([]byte, error) {
		return signer.SignDigestWithPrivateKeyHex(keyHex, codec.Hash(d))
	}
}

func pubKey(t *testing.T, keyHex string) []byte {
	t.Helper()
	return secp256k1.PrivKeyFromBytes(mustHex(t, keyHex)).PubKey().SerializeCompressed()
}

func TestSignBindingVerifiesUnderWire(t *testing.T) {
	const keyHex = "1111111111111111111111111111111111111111111111111111111111111111"
	b := &nexusv1.DispatchStreamBindingV1{
		SchemaVersion: 1, ChainId: "trueopen-phase1-vector-1",
		BuilderOperator:           "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz",
		CortexOperator:            "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz",
		ServiceAuthorizationNonce: 1, StreamNonce: bytes.Repeat([]byte{7}, 32),
	}
	if err := SignBinding(context.Background(), b, localSigner(keyHex)); err != nil {
		t.Fatal(err)
	}
	d, err := Digest(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := dispatch.VerifyDigestSignature(pubKey(t, keyHex), d[:], b.ServiceSignature); err != nil {
		t.Fatalf("wire rejects the cortex signature: %v", err)
	}
}

// Every Cortex-signed vector, re-signed by the cortex signer with wire's
// fixture key, verifies under wire against the published public key and
// reproduces the published (RFC 6979 deterministic) signature.
func TestResignCortexVectorsWithFixtureKey(t *testing.T) {
	ctx := context.Background()
	s := localSigner(fixtureKeyHex)
	cases := map[string]func(proto.Message) error{
		"nexus_v1_dispatchstreambindingv1": func(m proto.Message) error {
			x := m.(*nexusv1.DispatchStreamBindingV1)
			return SignBinding(ctx, x, s)
		},
		"task_v1_standinghandraisev1": func(m proto.Message) error {
			x := m.(*taskv1.StandingHandraiseV1)
			return SignStandingHandraise(ctx, x, s)
		},
		"task_v1_dispatchacceptv1": func(m proto.Message) error {
			x := m.(*taskv1.DispatchAcceptV1)
			return SignAccept(ctx, x, s)
		},
		"task_v1_dispatchrejectv1": func(m proto.Message) error {
			x := m.(*taskv1.DispatchRejectV1)
			return SignReject(ctx, x, s)
		},
		"nexus_v1_dispatchinputrequestv1": func(m proto.Message) error {
			x := m.(*nexusv1.DispatchInputRequestV1)
			return SignInputRequest(ctx, x, s)
		},
		"task_v1_verifierhandraisev1": func(m proto.Message) error {
			x := m.(*taskv1.VerifierHandraiseV1)
			return SignVerifierHandraise(ctx, x, s)
		},
		"nexus_v1_verifyresultsubmittednoticev1": func(m proto.Message) error {
			x := m.(*nexusv1.VerifyResultSubmittedNoticeV1)
			return SignVerifyResultSubmitted(ctx, x, s)
		},
	}
	for name, resign := range cases {
		row := vectorByName(t, name)
		msg := vectorMessage(t, row)
		// Swap the published signature for garbage first so the test proves
		// the signer overwrites it rather than leaving it in place.
		published := mustHex(t, row.SignatureHex)
		msg.ProtoReflect().Set(msg.ProtoReflect().Descriptor().Fields().ByName("service_signature"),
			protoBytes(bytes.Repeat([]byte{0xee}, 64)))
		if err := resign(msg); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := msg.ProtoReflect().Get(msg.ProtoReflect().Descriptor().Fields().ByName("service_signature")).Bytes()
		d, err := Digest(msg)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(d[:]) != row.DigestHex {
			t.Fatalf("%s: signing changed the digest", name)
		}
		if err := dispatch.VerifyDigestSignature(mustHex(t, row.PublicKeyHex), d[:], got); err != nil {
			t.Fatalf("%s: wire rejects the re-signed message: %v", name, err)
		}
		if !bytes.Equal(got, published) {
			t.Fatalf("%s: re-signed %x, published %s", name, got, row.SignatureHex)
		}
	}
}

func TestSignRejectsMissingOrMisshapedSigner(t *testing.T) {
	ctx := context.Background()
	b := &nexusv1.DispatchStreamBindingV1{SchemaVersion: 1, ChainId: "c",
		BuilderOperator:           "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz",
		CortexOperator:            "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz",
		ServiceAuthorizationNonce: 1, StreamNonce: bytes.Repeat([]byte{7}, 32)}
	stale := bytes.Repeat([]byte{0xee}, 64)
	b.ServiceSignature = stale
	if err := SignBinding(ctx, b, nil); err == nil || b.ServiceSignature != nil {
		t.Fatalf("nil signer: err=%v sig=%x", err, b.ServiceSignature)
	}
	b.ServiceSignature = stale
	der := DigestSigner(func(context.Context, [32]byte) ([]byte, error) { return make([]byte, 71), nil })
	if err := SignBinding(ctx, b, der); err == nil || b.ServiceSignature != nil {
		t.Fatalf("non-raw64 signature accepted: err=%v sig=%x", err, b.ServiceSignature)
	}
	b.ServiceSignature = stale
	failing := DigestSigner(func(context.Context, [32]byte) ([]byte, error) { return nil, errors.New("hsm down") })
	if err := SignBinding(ctx, b, failing); err == nil || b.ServiceSignature != nil {
		t.Fatalf("failing signer: err=%v sig=%x", err, b.ServiceSignature)
	}
}
