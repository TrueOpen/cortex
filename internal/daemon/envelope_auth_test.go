package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	wirebus "github.com/TrueOpen/wire/bus"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/config"
	"github.com/SingaXYZ/cortex/internal/diagnostics"
	"github.com/SingaXYZ/cortex/internal/signer"
	"github.com/SingaXYZ/cortex/internal/store"
	"github.com/SingaXYZ/cortex/internal/store/once"
	busv1 "github.com/SingaXYZ/cortex/proto/bus/v1"
	"google.golang.org/protobuf/proto"
)

// The non-captured TRUEOPEN_BUS_ENVELOPE_V1 field values this package's tests put on
// a hand-built frame. They live here because the authenticator tests are the ones
// that have to agree with a binding; the rest of the package reuses them so there
// is one set of test envelope values rather than several.
const (
	envelopeTestBuilder = "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc"
	// envelopeTestAuthorizationNonce is the authorization nonce
	// envelopeTestBinding publishes. TRUEOPEN_BUS_ENVELOPE_V1 field 7 must equal the
	// nonce carried by the binding the authenticator resolves at verification
	// time (interface-and-topic-list.md §5.2 field 7), so the envelope and the binding deliberately
	// share one constant: a test that drifted them apart would be exercising the
	// stale-nonce refusal by accident. Frames built for the FakeBus paths, which
	// never reach an authenticator, reuse it simply as a non-zero field 7.
	envelopeTestAuthorizationNonce = uint64(4)
	// envelopeTestBuilderSetID is envelope field 11; field 12 is its hash.
	envelopeTestBuilderSetID = "7"
	// envelopeTestSourceSnapshotHeight is field 14, the sender's own chain view.
	envelopeTestSourceSnapshotHeight = uint64(122681)
)

// envelopeTestBuilderSetHash is envelope field 12. It is a bytes32, so a short
// or absent value is a refusal rather than a zero fill; a fresh slice per call
// keeps a mutating test from reaching into another envelope's hash.
func envelopeTestBuilderSetHash() []byte { return bytes.Repeat([]byte{0x5a}, 32) }

// envelopeTestTaskIDHex is the canonical task id every auth-test frame binds:
// payload task_id bytes, subject placeholder and store records all agree.
const envelopeTestTaskIDHex = "0101010101010101010101010101010101010101010101010101010101010101"

type envelopeTestKey struct {
	private   *secp256k1.PrivateKey
	pubkeyHex string
}

type cancelAfterAuthenticate struct {
	builderclient.BusEnvelopeAuthenticator
	cancel context.CancelFunc
}

func (a *cancelAfterAuthenticate) Authenticate(ctx context.Context, subject string, envelope builderclient.BusEnvelope) error {
	if err := a.BusEnvelopeAuthenticator.Authenticate(ctx, subject, envelope); err != nil {
		return err
	}
	if a.cancel != nil {
		a.cancel()
		a.cancel = nil
	}
	return nil
}

func (a *cancelAfterAuthenticate) Release(subject string, envelope builderclient.BusEnvelope) {
	if releaser, ok := a.BusEnvelopeAuthenticator.(interface {
		Release(string, builderclient.BusEnvelope)
	}); ok {
		releaser.Release(subject, envelope)
	}
}

func newEnvelopeTestKey(t *testing.T) envelopeTestKey {
	t.Helper()
	private, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	return envelopeTestKey{private: private, pubkeyHex: hex.EncodeToString(private.PubKey().SerializeCompressed())}
}

func (k envelopeTestKey) signDigest(digest codec.Hash) []byte {
	signature := ecdsa.Sign(k.private, digest[:])
	r, s := signature.R(), signature.S()
	if s.IsOverHalfOrder() {
		s.Negate()
	}
	rBytes, sBytes := r.Bytes(), s.Bytes()
	out := make([]byte, 64)
	copy(out[:32], rBytes[:])
	copy(out[32:], sBytes[:])
	return out
}

// envelopeKeeperStub serves one service-key binding and counts reads, so a test
// can prove the key is resolved per verification rather than cached.
type envelopeKeeperStub struct {
	binding chainclient.ServiceKeySnapshot
	err     error
	reads   int
	heights []uint64
	// queried records exactly what the authenticator asked for, so a defect that
	// resolves the wrong participant type or the wrong operator cannot pass by
	// having the stub echo its own arguments back.
	queriedParticipantTypes []string
	queriedOperators        []string
}

func (k *envelopeKeeperStub) CurrentServiceKey(_ context.Context, participantType, operatorAddress string, height uint64) (chainclient.ServiceKeySnapshot, error) {
	k.reads++
	k.heights = append(k.heights, height)
	k.queriedParticipantTypes = append(k.queriedParticipantTypes, participantType)
	k.queriedOperators = append(k.queriedOperators, operatorAddress)
	if k.err != nil {
		return chainclient.ServiceKeySnapshot{}, k.err
	}
	return k.binding, nil
}

func envelopeTestBinding(key envelopeTestKey) chainclient.ServiceKeySnapshot {
	return chainclient.ServiceKeySnapshot{
		ParticipantType:    chainclient.ParticipantTypeBuilder,
		OperatorAddress:    envelopeTestBuilder,
		ServiceAddress:     "trueopen1builderservice",
		ServicePubkey:      key.pubkeyHex,
		AuthorizationNonce: chainclient.NewUint64String(envelopeTestAuthorizationNonce),
		Status:             "ACTIVE",
	}
}

func envelopeTestAuthenticator(t *testing.T, keeper envelopeServiceKeyReader, now time.Time) builderclient.BusEnvelopeAuthenticator {
	t.Helper()
	authenticator, err := NewBusEnvelopeAuthenticator(BusEnvelopeAuthenticatorConfig{
		ChainID: "trueopen-devnet-1",
		Keeper:  keeper,
		// The chain recognises the test Builder; these tests are about everything
		// that happens after that, so membership is satisfied and the configured
		// operator keeps narrowing to the one sender they all use.
		Members:             &membershipStub{members: map[string]bool{envelopeTestBuilder: true}},
		PeerOperatorAddress: envelopeTestBuilder,
		TTL:                 30 * time.Second,
		ClockSkew:           2 * time.Second,
		Now:                 func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewBusEnvelopeAuthenticator returned error: %v", err)
	}
	return authenticator
}

// Claims are written one key at a time, so a frame refused on its nonce key has
// already written its message-id key. Leaving that behind does two things: it adds
// a permanent row for traffic that was rejected, and it consumes a message id, so
// a later legitimate frame carrying it is refused as a replay it never was.
func TestEnvelopeAuthenticatorReleasesClaimsWhenALaterKeyIsReplayed(t *testing.T) {
	ctx := context.Background()
	key := newEnvelopeTestKey(t)
	// A real-clock now, because the durable claim's lifetime is the envelope's own
	// ExpiresAtUnixMs and once.Claim compares it against the wall clock. A
	// historical test clock would make every claim arrive already expired, and the
	// test would pass while exercising nothing.
	now := time.Now().UTC()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "once.kv"))
	if err != nil {
		t.Fatalf("store.Open returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	onceStore := once.New(db)

	authenticator, err := NewBusEnvelopeAuthenticator(BusEnvelopeAuthenticatorConfig{
		ChainID:             "trueopen-devnet-1",
		Keeper:              &envelopeKeeperStub{binding: envelopeTestBinding(key)},
		Members:             &membershipStub{members: map[string]bool{envelopeTestBuilder: true}},
		PeerOperatorAddress: envelopeTestBuilder,
		TTL:                 30 * time.Second,
		ClockSkew:           2 * time.Second,
		Now:                 func() time.Time { return now },
		StoreOnce:           onceStore,
	})
	if err != nil {
		t.Fatalf("NewBusEnvelopeAuthenticator returned error: %v", err)
	}

	first := envelopeTestMessage(t, key, now, nil)
	if err := authenticator.Authenticate(ctx, first.Subject, first); err != nil {
		t.Fatalf("first Authenticate returned error: %v", err)
	}

	// Same nonce, different message id: the nonce key collides, the message-id
	// key does not.
	second := envelopeTestMessage(t, key, now, func(e *builderclient.BusEnvelope) {
		e.MessageID = first.MessageID + "-other"
		e.Nonce = append([]byte(nil), first.Nonce...)
	})
	if err := authenticator.Authenticate(ctx, second.Subject, second); !errors.Is(err, ErrBusEnvelopeReplay) {
		t.Fatalf("second Authenticate error = %v, want %v", err, ErrBusEnvelopeReplay)
	}

	keys, keyErr := builderclient.BusEnvelopeReplayKeys(second, envelopeTestAuthorizationNonce)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	messageKey := keys[0]
	claimed, err := onceStore.Claim(ctx, messageKey, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Claim returned error: %v", err)
	}
	if !claimed {
		t.Fatal("the refused frame left its message-id key claimed, so a legitimate frame carrying it would be refused as a replay")
	}
}

// The commonest reason a later claim fails is that the request context was
// cancelled, and the store checks the context before deleting - so rolling back
// with the caller's context fails every delete exactly when rollback matters. The
// orphaned key would then refuse the legitimate redelivery until it expired,
// because nothing else knows it exists: a.claims is populated only on success.
func TestReleaseClaimsSurvivesACancelledContext(t *testing.T) {
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "once.kv"))
	if err != nil {
		t.Fatalf("store.Open returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	onceStore := once.New(db)
	a := &busEnvelopeAuthenticator{cfg: BusEnvelopeAuthenticatorConfig{StoreOnce: onceStore}}

	ctx, cancel := context.WithCancel(context.Background())
	expiry := time.Now().UTC().Add(time.Hour)
	if claimed, err := onceStore.Claim(ctx, "message-key", expiry); err != nil || !claimed {
		t.Fatalf("Claim = %v, %v; want the first claim to succeed", claimed, err)
	}
	cancel()

	a.releaseClaims(ctx, []string{"message-key"})

	if claimed, err := onceStore.Claim(context.Background(), "message-key", expiry); err != nil || !claimed {
		t.Fatalf("Claim after rollback = %v, %v; the cancelled rollback orphaned the key", claimed, err)
	}
}

func envelopeTestMessage(t *testing.T, key envelopeTestKey, issuedAt time.Time, mutate func(*builderclient.BusEnvelope)) builderclient.BusEnvelope {
	t.Helper()
	payload, err := proto.Marshal(&busv1.WorkerAssignmentNotifyV1{
		TaskId:                bytes.Repeat([]byte{0x01}, 32),
		TaskHash:              bytes.Repeat([]byte{0x02}, 32),
		WinnerOperatorAddress: "trueopen1worker",
		FinalizedHeight:       12,
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope := builderclient.BusEnvelope{
		SchemaVersion:             builderclient.BusEnvelopeSchemaVersion,
		ChainID:                   "trueopen-devnet-1",
		Subject:                   "trueopen.worker-assignment." + envelopeTestTaskIDHex,
		Kind:                      builderclient.KindWorkerAssignmentNotify,
		SenderParticipantType:     builderclient.ParticipantBuilder,
		SenderOperatorAddress:     envelopeTestBuilder,
		ServiceAuthorizationNonce: envelopeTestAuthorizationNonce,
		MessageID:                 "01a01a8e-6a23-76d7-a839-0a1b6c7d4e5f",
		Nonce:                     []byte(strings.Repeat("n", 32)),
		IssuedAtUnixMs:            issuedAt.UnixMilli(),
		ExpiresAtUnixMs:           issuedAt.Add(30 * time.Second).UnixMilli(),
		Payload:                   payload,
	}
	if mutate != nil {
		mutate(&envelope)
	}
	// The transmitted payload and payload_digest are one claim, not two: field
	// 14 commits SHA-256 of the exact transmitted bytes. Derived here, after
	// the mutation, so a test that rewrites the body stays a test about the body.
	payloadDigest := wirebus.PayloadDigest(envelope.Payload)
	envelope.PayloadDigest = payloadDigest[:]
	return envelopeTestSign(t, key, envelope)
}

// envelopeTestMessageExact signs whatever the mutation left behind, without
// repairing the payload or recomputing payload_digest.
//
// envelopeTestMessage deliberately derives both, which makes it useless for the
// two cases that matter most on the receive path: a body that is NOT its own
// canonical form (§5.2 requires the receiver to refuse it rather than repair it)
// and a payload_digest that does not commit the body (BusEnvelopeSignBytes signs
// a recomputed digest, so a signature attests nothing about the transmitted
// field). Repairing the input before signing would turn both into tests that
// pass for the wrong reason.
func envelopeTestMessageExact(t *testing.T, key envelopeTestKey, issuedAt time.Time, mutate func(*builderclient.BusEnvelope)) builderclient.BusEnvelope {
	t.Helper()
	envelope := envelopeTestMessage(t, key, issuedAt, nil)
	if mutate != nil {
		mutate(&envelope)
	}
	// Our own signer refuses to sign a body that is not its own canonical form, so
	// a frame carrying one cannot be signed here at all - which is the point: only
	// a peer whose implementation disagrees with §5.2 PAYLOAD_BYTES/:397 emits
	// one, and it signs whatever its own rules produced. Such a frame must be
	// refused BEFORE the signature is considered, so a syntactically valid
	// placeholder is enough and a real signature would prove nothing extra. Frames
	// we CAN sign get a real signature, so the refusal cannot be blamed on the
	// signature instead.
	digest, err := builderclient.BusEnvelopeSignDigest(envelope)
	if err != nil {
		envelope.Signature = bytes.Repeat([]byte{0x7f}, 64)
		return envelope
	}
	envelope.Signature = key.signDigest(digest)
	return envelope
}

// envelopeTestOutputAvailableFromWorker builds a frame that is internally
// consistent yet comes from the WRONG configured domain: §5.3 admits both
// CORTEX/WORKER and BUILDER/BUILDER for OUTPUT_AVAILABLE, so the §5.3 table
// accepts this pair and only the authenticator's configured-domain comparison
// can refuse it. Stage and participant type are derived, never hand-picked.
func envelopeTestOutputAvailableFromWorker(t *testing.T, key envelopeTestKey, issuedAt time.Time) builderclient.BusEnvelope {
	t.Helper()
	payload, err := proto.Marshal(&busv1.OutputAvailableV1{
		TaskId:                bytes.Repeat([]byte{0x01}, 32),
		TaskHash:              bytes.Repeat([]byte{0x02}, 32),
		OutputHash:            bytes.Repeat([]byte{0x03}, 32),
		WorkerOperatorAddress: "trueopen1worker",
		PublishedAtUnixMs:     uint64(issuedAt.UnixMilli()),
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope := envelopeTestMessage(t, key, issuedAt, nil)
	envelope.Kind = builderclient.KindOutputAvailable
	envelope.Subject = builderclient.NATSOutputAvailableSubject(envelopeTestTaskIDHex)
	envelope.SenderParticipantType = builderclient.ParticipantCortex
	envelope.Payload = payload
	digest := wirebus.PayloadDigest(payload)
	envelope.PayloadDigest = digest[:]
	return envelopeTestSign(t, key, envelope)
}

func envelopeTestSign(t *testing.T, key envelopeTestKey, envelope builderclient.BusEnvelope) builderclient.BusEnvelope {
	t.Helper()
	digest, err := builderclient.BusEnvelopeSignDigest(envelope)
	if err != nil {
		// A frame the projection itself refuses (bad schema, non-bech32 sender)
		// cannot be signed at all; the authenticator must refuse it before the
		// signature is considered, so a placeholder is enough.
		envelope.Signature = bytes.Repeat([]byte{0x7f}, 64)
		return envelope
	}
	envelope.Signature = key.signDigest(digest)
	return envelope
}

// The happy path proves the authenticator accepts a Builder message signed by
// the key the chain currently binds, and that the key is read at verification
// time rather than trusted from the message.
func TestBusEnvelopeAuthenticatorAcceptsTheCurrentBuilderServiceKey(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	keeper := &envelopeKeeperStub{binding: envelopeTestBinding(key)}
	authenticator := envelopeTestAuthenticator(t, keeper, now)

	if err := authenticator.Authenticate(context.Background(), "trueopen.worker-assignment."+envelopeTestTaskIDHex, envelopeTestMessage(t, key, now, nil)); err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if keeper.reads != 1 {
		t.Fatalf("service key reads = %d, want the binding resolved once per verification", keeper.reads)
	}
	// Height 0 asks for the current binding. A pinned historical height would
	// let a rotated-out key keep authenticating.
	if len(keeper.heights) != 1 || keeper.heights[0] != 0 {
		t.Fatalf("service key read heights = %v, want the current binding", keeper.heights)
	}
	// Resolving the wrong participant type or the wrong operator would
	// authenticate a key the chain never bound to this Builder.
	if got := keeper.queriedParticipantTypes; len(got) != 1 || got[0] != chainclient.ParticipantTypeBuilder {
		t.Fatalf("queried participant types = %v, want %s", got, chainclient.ParticipantTypeBuilder)
	}
	if got := keeper.queriedOperators; len(got) != 1 || got[0] != envelopeTestBuilder {
		t.Fatalf("queried operators = %v, want %s", got, envelopeTestBuilder)
	}
}

// Every rejection below is a case where accepting the message would let an
// unauthenticated party drive this node's task state.
func TestBusEnvelopeAuthenticatorFailsClosed(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()

	for name, testCase := range map[string]struct {
		binding chainclient.ServiceKeySnapshot
		keyErr  error
		mutate  func(*builderclient.BusEnvelope)
		unsign  bool
		want    string
	}{
		"unsigned envelope": {
			binding: envelopeTestBinding(key), unsign: true, want: "no signature",
		},
		"unknown sender": {
			binding: envelopeTestBinding(key),
			mutate: func(e *builderclient.BusEnvelope) {
				e.SenderOperatorAddress = "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"
			},
			want: "not the configured Builder operator",
		},
		"foreign chain": {
			binding: envelopeTestBinding(key),
			mutate:  func(e *builderclient.BusEnvelope) { e.ChainID = "trueopen-devnet-2" },
			want:    "chain id",
		},
		"unsupported schema": {
			binding: envelopeTestBinding(key),
			mutate:  func(e *builderclient.BusEnvelope) { e.SchemaVersion = 2 },
			want:    "schema_version",
		},
		"revoked key": {
			binding: func() chainclient.ServiceKeySnapshot {
				binding := envelopeTestBinding(key)
				binding.Status = "REVOKED"
				return binding
			}(),
			want: "status REVOKED",
		},
		"revoked height recorded": {
			binding: func() chainclient.ServiceKeySnapshot {
				binding := envelopeTestBinding(key)
				binding.RevokedHeight = chainclient.NewUint64String(900)
				return binding
			}(),
			want: "revoked at height 900",
		},
		"binding for another operator": {
			binding: func() chainclient.ServiceKeySnapshot {
				binding := envelopeTestBinding(key)
				binding.OperatorAddress = "trueopen1other"
				return binding
			}(),
			want: "belongs to trueopen1other",
		},
		"key rotated to another key": {
			binding: func() chainclient.ServiceKeySnapshot {
				binding := envelopeTestBinding(key)
				binding.ServicePubkey = newEnvelopeTestKey(t).pubkeyHex
				return binding
			}(),
			want: "does not verify",
		},
		"chain view unavailable": {
			binding: envelopeTestBinding(key), keyErr: errors.New("keeper unreachable"),
			want: "read current service key",
		},
		"expired": {
			binding: envelopeTestBinding(key),
			mutate: func(e *builderclient.BusEnvelope) {
				e.IssuedAtUnixMs = now.Add(-time.Hour).UnixMilli()
				e.ExpiresAtUnixMs = now.Add(-time.Hour).Add(30 * time.Second).UnixMilli()
			},
			want: "expired",
		},
		"issued in the future": {
			binding: envelopeTestBinding(key),
			mutate: func(e *builderclient.BusEnvelope) {
				e.IssuedAtUnixMs = now.Add(time.Minute).UnixMilli()
				e.ExpiresAtUnixMs = now.Add(time.Minute).Add(30 * time.Second).UnixMilli()
			},
			want: "issued in the future",
		},
		"lifetime beyond the accepted TTL": {
			binding: envelopeTestBinding(key),
			mutate: func(e *builderclient.BusEnvelope) {
				e.ExpiresAtUnixMs = now.Add(time.Hour).UnixMilli()
			},
			want: "exceeds the accepted TTL",
		},
		// ValidateEnvelopeIntrinsics owns the presence and ordering of the two
		// stamps now, so the refusal names the field rather than the pair. The
		// clock- and config-dependent freshness rules below still live in
		// checkFreshness and have their own cases.
		"missing stamps": {
			binding: envelopeTestBinding(key),
			mutate:  func(e *builderclient.BusEnvelope) { e.ExpiresAtUnixMs = 0 },
			want:    "expires_at_unix_ms",
		},
	} {
		t.Run(name, func(t *testing.T) {
			keeper := &envelopeKeeperStub{binding: testCase.binding, err: testCase.keyErr}
			authenticator := envelopeTestAuthenticator(t, keeper, now)
			envelope := envelopeTestMessage(t, key, now, testCase.mutate)
			if testCase.unsign {
				envelope.Signature = nil
			}
			err := authenticator.Authenticate(context.Background(), envelope.Subject, envelope)
			if err == nil {
				t.Fatalf("Authenticate() error = nil, want a rejection mentioning %q", testCase.want)
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("Authenticate() error = %v, want it to mention %q", err, testCase.want)
			}
		})
	}
}

// The sender_participant_type selects the key-domain namespace the current-key
// query runs in (interface-and-topic-list.md §5.2 field 5), so a frame must not be able to
// steer that lookup into a keyspace of its own choosing.
//
// This used to be asserted as "the frame's domain must equal the one configured
// domain", with the frame below - a §5.3-legal CORTEX/OUTPUT_AVAILABLE - as the
// case it refused. That was the wrong invariant: §5.3 admits both CORTEX and
// BUILDER for OUTPUT_AVAILABLE, Cortex publishes the CORTEX row from its own
// Worker, and refusing it made the kind unauthenticable on every node. What
// actually bounds the domain is the frozen table, and the surviving assertions
// live in envelope_auth_sender_domain_test.go:
//
//   - a domain the kind's row does not admit is refused before the Keeper read
//     (TestBusEnvelopeAuthenticatorRefusesADomainTheKindDoesNotAdmit),
//   - the keyspace follows the frame's admitted domain rather than a
//     configured constant, and
//   - each domain keeps its own chain authority
//     (TestCortexSenderStillRequiresItsOwnCurrentActiveBinding).
func TestBusEnvelopeAuthenticatorResolvesTheKeyspaceOfAnAdmittedSenderDomain(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	keeper := &envelopeKeeperStub{binding: envelopeTestCortexBinding(key)}
	envelope := envelopeTestOutputAvailableFromCortexWorker(t, key, now)

	if err := envelopeTestAuthenticator(t, keeper, now).Authenticate(context.Background(), envelope.Subject, envelope); err != nil {
		t.Fatalf("Authenticate() error = %v, want the CORTEX row of §5.3 accepted", err)
	}
	if got := keeper.queriedParticipantTypes; len(got) != 1 || got[0] != chainclient.ParticipantTypeCortexNode {
		t.Fatalf("queried participant types = %v, want the keyspace to follow the frame's admitted domain", got)
	}
}

// payload_digest (field 20) is inside the signed set, but BusEnvelopeSignBytes
// signs a RECOMPUTED digest rather than the transmitted one - so a valid
// signature says nothing about the 32 bytes that actually arrived in field 20.
// Without a recompute-and-compare on the receive path the field is unconstrained.
//
// The frame below is signed by the currently bound key and is valid in every
// other respect; only field 20 lies.
func TestBusEnvelopeAuthenticatorRefusesAPayloadDigestThatDoesNotCommitTheBody(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	keeper := &envelopeKeeperStub{binding: envelopeTestBinding(key)}
	envelope := envelopeTestMessageExact(t, key, now, func(e *builderclient.BusEnvelope) {
		e.PayloadDigest = bytes.Repeat([]byte{0x5a}, 32)
	})
	if len(envelope.Signature) != 64 {
		t.Fatalf("signature length = %d, want the frame genuinely signed so the refusal is not the signature", len(envelope.Signature))
	}

	err := envelopeTestAuthenticator(t, keeper, now).Authenticate(context.Background(), envelope.Subject, envelope)
	if err == nil || !strings.Contains(err.Error(), "payload_digest does not commit the transmitted payload") {
		t.Fatalf("Authenticate() error = %v, want the transmitted payload_digest refused", err)
	}
}

// §5.2 requires the receiver to re-canonicalise after typed decode and reject on
// any difference - not to repair the body and carry on. A peer whose encoder
// disagrees with trueopen-cjson-v1 emits a body that is not its own canonical form,
// and this node must refuse it rather than silently agreeing on a third encoding.
func TestBusEnvelopeAuthenticatorRefusesANonCanonicalTransmittedPayload(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	keeper := &envelopeKeeperStub{binding: envelopeTestBinding(key)}
	envelope := envelopeTestMessageExact(t, key, now, func(e *builderclient.BusEnvelope) {
		// Same object, keys out of ascending order: valid JSON, not canonical.
		e.Payload = []byte(`{"winner_worker":"trueopen1worker","session_id":"session-1"}`)
	})

	err := envelopeTestAuthenticator(t, keeper, now).Authenticate(context.Background(), envelope.Subject, envelope)
	if err == nil {
		t.Fatal("Authenticate() error = nil, want a non-canonical transmitted payload refused")
	}
	if keeper.reads != 0 {
		t.Fatalf("service key reads = %d, want the body refused before the Keeper is consulted", keeper.reads)
	}
}

// service_authorization_nonce (field 7) must equal the nonce on the binding resolved
// at verification time (§5.2 field 7). §5.2 allows no historical-key fallback, so a
// frame minted under a superseded binding has nothing to fall back to and must be
// refused - while the same sender under the current binding still passes, because
// this is a rotation check and not a block on the peer.
func TestBusEnvelopeAuthenticatorRefusesAStaleServiceAuthorizationNonce(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	rotated := envelopeTestBinding(key)
	rotated.AuthorizationNonce = chainclient.NewUint64String(envelopeTestAuthorizationNonce + 1)
	keeper := &envelopeKeeperStub{binding: rotated}
	authenticator := envelopeTestAuthenticator(t, keeper, now)

	// The default envelope carries the pre-rotation nonce.
	stale := envelopeTestMessage(t, key, now, nil)
	err := authenticator.Authenticate(context.Background(), stale.Subject, stale)
	if err == nil || !strings.Contains(err.Error(), "service_authorization_nonce") {
		t.Fatalf("Authenticate() error = %v, want the superseded binding nonce refused", err)
	}
	// A stale nonce is a verdict against the sender, not a failure of this node's
	// inputs, so it must not be retried forever.
	if builderclient.IsRetryable(err) {
		t.Fatalf("Authenticate() error = %v, want a permanent refusal", err)
	}

	fresh := envelopeTestMessage(t, key, now, func(e *builderclient.BusEnvelope) {
		e.ServiceAuthorizationNonce = envelopeTestAuthorizationNonce + 1
		e.MessageID = "abcdefabcdefabcdefabcdefabcdefab"
		e.Nonce = []byte(strings.Repeat("m", 32))
	})
	if err := authenticator.Authenticate(context.Background(), fresh.Subject, fresh); err != nil {
		t.Fatalf("Authenticate() error = %v, want the current binding nonce accepted", err)
	}
}

// Replay suppression is durable and claimed before the caller can act, so the
// same envelope can never be processed twice, and a resent nonce is refused even
// under a fresh message id.
func TestBusEnvelopeAuthenticatorSuppressesReplays(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	keeper := &envelopeKeeperStub{binding: envelopeTestBinding(key)}
	authenticator := envelopeTestAuthenticator(t, keeper, now)
	envelope := envelopeTestMessage(t, key, now, nil)

	if err := authenticator.Authenticate(context.Background(), envelope.Subject, envelope); err != nil {
		t.Fatalf("first Authenticate returned error: %v", err)
	}
	err := authenticator.Authenticate(context.Background(), envelope.Subject, envelope)
	if !errors.Is(err, ErrBusEnvelopeReplay) {
		t.Fatalf("second Authenticate() error = %v, want ErrBusEnvelopeReplay", err)
	}

	// A new message id over the same nonce is still a replay: the nonce is the
	// sender's freshness claim, and reusing it is exactly what an attacker
	// replaying a captured frame would do.
	reusedNonce := envelopeTestMessage(t, key, now, func(e *builderclient.BusEnvelope) {
		e.MessageID = "ffffffffffffffffffffffffffffffff"
	})
	if err := authenticator.Authenticate(context.Background(), reusedNonce.Subject, reusedNonce); !errors.Is(err, ErrBusEnvelopeReplay) {
		t.Fatalf("Authenticate() error = %v, want a reused nonce to be a replay", err)
	}

	// A genuinely fresh envelope still passes, so suppression is not a blanket
	// block on the sender.
	fresh := envelopeTestMessage(t, key, now, func(e *builderclient.BusEnvelope) {
		e.MessageID = "abcdefabcdefabcdefabcdefabcdefab"
		e.Nonce = []byte(strings.Repeat("m", 32))
	})
	if err := authenticator.Authenticate(context.Background(), fresh.Subject, fresh); err != nil {
		t.Fatalf("fresh Authenticate returned error: %v", err)
	}
}

func TestBusEnvelopeAuthenticatorReleasesClaimForSourceRedelivery(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	authenticator := envelopeTestAuthenticator(t, &envelopeKeeperStub{binding: envelopeTestBinding(key)}, now)
	envelope := envelopeTestMessage(t, key, now, nil)
	if err := authenticator.Authenticate(context.Background(), envelope.Subject, envelope); err != nil {
		t.Fatal(err)
	}
	releaser, ok := authenticator.(interface {
		Release(string, builderclient.BusEnvelope)
	})
	if !ok {
		t.Fatal("production authenticator cannot release a retryable delivery claim")
	}
	releaser.Release(envelope.Subject, envelope)
	if err := authenticator.Authenticate(context.Background(), envelope.Subject, envelope); err != nil {
		t.Fatalf("byte-identical source redelivery was rejected after release: %v", err)
	}
}

func TestTaskRunnerCancellationReleasesAuthenticatedClaimForRedelivery(t *testing.T) {
	key := newEnvelopeTestKey(t)
	// Wall-clock fresh, because this test is about cancellation releasing the
	// claim and the runner now bounds every inbound envelope against now. The
	// authenticator is still driven at this same instant, so nothing about what
	// it verifies changes.
	now := time.Now().UTC()
	base := envelopeTestAuthenticator(t, &envelopeKeeperStub{binding: envelopeTestBinding(key)}, now)
	ctx, cancel := context.WithCancel(context.Background())
	authenticator := &cancelAfterAuthenticate{BusEnvelopeAuthenticator: base, cancel: cancel}
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// The frame's task_hash is the §5.2 authorization object, i.e. the Keeper's
	// accepted_task_hash - which is exactly the key this store is written under.
	// OrderDigest is the OTHER chain field (accepted_input_hash) and is seeded to
	// a different value on purpose, so this test cannot pass by having the two
	// coincide.
	taskHash := codec.Hash(bytes.Repeat([]byte{0x02}, 32))
	seedInferTask(context.Background(), t, db, taskHash, store.InferTask{TaskID: envelopeTestTaskIDHex, SessionID: "session-1", WorkerAddress: "trueopen1worker", WinnerConfirmHeight: 12, OrderDigest: codec.HashBytes([]byte("cancel-redelivery-order")), ModelID: "model", ProfileVersion: 1, Capability: "capability"})
	envelope := envelopeTestMessage(t, key, now, nil)
	frame, err := builderclient.EncodeBusEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	runner := NewTaskRunner(TaskRunnerConfig{Store: db, LocalWorkerAddress: "trueopen1worker", NexusEnvelopeAuthenticator: authenticator})
	message := builderclient.NATSMessage{Subject: envelope.Subject, Data: frame, JetStream: true}
	if err := runner.HandleNexusMessage(ctx, message); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled delivery error = %v, want context.Canceled", err)
	}
	if err := runner.HandleNexusMessage(context.Background(), message); err != nil {
		t.Fatalf("authenticated redelivery was not admitted: %v", err)
	}
}

func TestBusEnvelopeAuthenticatorExpiresInMemoryClaims(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	authenticator, err := NewBusEnvelopeAuthenticator(BusEnvelopeAuthenticatorConfig{
		ChainID:             "trueopen-devnet-1",
		Keeper:              &envelopeKeeperStub{binding: envelopeTestBinding(key)},
		Members:             &membershipStub{members: map[string]bool{envelopeTestBuilder: true}},
		PeerOperatorAddress: envelopeTestBuilder,
		TTL:                 30 * time.Second,
		ClockSkew:           2 * time.Second,
		Now:                 func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewBusEnvelopeAuthenticator returned error: %v", err)
	}

	message := envelopeTestMessage(t, key, now, nil)
	if err := authenticator.Authenticate(context.Background(), message.Subject, message); err != nil {
		t.Fatal(err)
	}
	if err := authenticator.Authenticate(context.Background(), message.Subject, message); !errors.Is(err, ErrBusEnvelopeReplay) {
		t.Fatalf("replay error=%v", err)
	}
	now = now.Add(33 * time.Second)
	refreshed := envelopeTestMessage(t, key, now, func(e *builderclient.BusEnvelope) {
		e.MessageID = message.MessageID
		e.Nonce = append([]byte(nil), message.Nonce...)
	})
	if err := authenticator.Authenticate(context.Background(), refreshed.Subject, refreshed); err != nil {
		t.Fatalf("expired claim was not released: %v", err)
	}
}

// A missing dependency must be refused at construction, because a nil-tolerant
// authenticator is one that authenticates nothing. Every row must fail for its
// own reason, so the base config is complete: an incomplete base would make the
// whole table pass on whichever guard fires first.
func TestNewBusEnvelopeAuthenticatorRequiresItsDependencies(t *testing.T) {
	base := BusEnvelopeAuthenticatorConfig{
		ChainID:             "trueopen-devnet-1",
		Keeper:              &envelopeKeeperStub{},
		Members:             &membershipStub{},
		PeerOperatorAddress: envelopeTestBuilder,
		TTL:                 30 * time.Second,
	}
	if _, err := NewBusEnvelopeAuthenticator(base); err != nil {
		t.Fatalf("NewBusEnvelopeAuthenticator(base) error = %v, want a complete config to be accepted", err)
	}
	// PeerOperatorAddress is deliberately absent: it is an optional narrowing
	// filter, and an empty one is a node that accepts every current Builder.
	for name, mutate := range map[string]func(*BusEnvelopeAuthenticatorConfig){
		"chain id": func(c *BusEnvelopeAuthenticatorConfig) { c.ChainID = " " },
		"keeper":   func(c *BusEnvelopeAuthenticatorConfig) { c.Keeper = nil },
		"members":  func(c *BusEnvelopeAuthenticatorConfig) { c.Members = nil },
		"ttl":      func(c *BusEnvelopeAuthenticatorConfig) { c.TTL = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			mutate(&cfg)
			if _, err := NewBusEnvelopeAuthenticator(cfg); err == nil {
				t.Fatalf("NewBusEnvelopeAuthenticator() error = nil, want %s to be required", name)
			}
		})
	}

	withoutFilter := base
	withoutFilter.PeerOperatorAddress = ""
	if _, err := NewBusEnvelopeAuthenticator(withoutFilter); err != nil {
		t.Fatalf("NewBusEnvelopeAuthenticator() error = %v, want an empty narrowing filter to be accepted", err)
	}
}

// The outbound signer must produce a signature the peer can verify against this
// node's chain-recorded service key, and must refuse to sign at all before the
// Keeper confirms which identity that is.
func TestBusEnvelopeSignerSignsAsTheConfirmedServiceIdentity(t *testing.T) {
	key := newEnvelopeTestKey(t)
	var signedAs string
	digestSigner := signer.DigestSignerFunc(func(_ context.Context, req signer.DigestRequest) ([]byte, error) {
		if req.KeyRef != "service.json" {
			return nil, fmt.Errorf("unexpected key ref %q", req.KeyRef)
		}
		signedAs = req.ExpectedSignerAddress
		return key.signDigest(req.Digest), nil
	})

	serviceAddress := ""
	envelopeSigner, err := NewBusEnvelopeSigner(BusEnvelopeSignerConfig{
		Signer: digestSigner,
		KeyRef: "service.json",
		ServiceAddress: func() (string, error) {
			if serviceAddress == "" {
				return "", errors.New("workload is not active")
			}
			return serviceAddress, nil
		},
	})
	if err != nil {
		t.Fatalf("NewBusEnvelopeSigner returned error: %v", err)
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	unsigned := envelopeTestMessage(t, key, now, nil)
	unsigned.Signature = nil

	if _, err := envelopeSigner.SignEnvelope(unsigned); err == nil {
		t.Fatal("SignEnvelope() error = nil, want signing refused before the Keeper confirms the identity")
	}

	serviceAddress = "trueopen1cortexservice"
	signature, err := envelopeSigner.SignEnvelope(unsigned)
	if err != nil {
		t.Fatalf("SignEnvelope returned error: %v", err)
	}
	if signedAs != serviceAddress {
		t.Fatalf("signed as %q, want the confirmed service address %q", signedAs, serviceAddress)
	}
	signed := unsigned
	signed.Signature = signature
	if err := builderclient.VerifyBusEnvelopeSignature(signed, key.pubkeyHex); err != nil {
		t.Fatalf("the peer could not verify the produced signature: %v", err)
	}
}

func TestNewBusEnvelopeSignerRequiresItsDependencies(t *testing.T) {
	resolver := func() (string, error) { return "trueopen1cortexservice", nil }
	base := BusEnvelopeSignerConfig{
		Signer:         signer.DigestSignerFunc(func(context.Context, signer.DigestRequest) ([]byte, error) { return nil, nil }),
		KeyRef:         "service.json",
		ServiceAddress: resolver,
	}
	for name, mutate := range map[string]func(*BusEnvelopeSignerConfig){
		"signer":  func(c *BusEnvelopeSignerConfig) { c.Signer = nil },
		"key ref": func(c *BusEnvelopeSignerConfig) { c.KeyRef = " " },
		"address": func(c *BusEnvelopeSignerConfig) { c.ServiceAddress = nil },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			mutate(&cfg)
			if _, err := NewBusEnvelopeSigner(cfg); err == nil {
				t.Fatalf("NewBusEnvelopeSigner() error = nil, want %s to be required", name)
			}
		})
	}
}

// This is the property issue #112 is about: a real-mode node configured only
// through YAML must end up with a usable signer and authenticator, so
// nexus_envelope_auth can become ready without a test double injected through
// RuntimeOptions. Before this, only tests could satisfy the dependency and the
// workload never activated in production.
func TestBuildRuntimeStrictModeConstructsEnvelopeAuthenticationFromConfig(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = t.TempDir() + "/cortex.kv"
	cfg.ModelManagement.Transport = "local"
	cfg.ModelManagement.Endpoint = ""
	cfg.ModelManagement.MaxConcurrency = 1
	cfg.Nexus.EnvelopeAuthMode = config.NexusEnvelopeAuthStrict
	cfg.Nexus.BuilderOperatorAddress = envelopeTestBuilder
	signingClient, _ := readyRuntimeServiceSigner(t)
	cfg.LocalIdentity.ServiceKeyRef = "service.json"

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		Keeper:          &descriptorKeeper{height: 900},
		NexusPublisher:  fakePublisher{},
		NexusSubscriber: fakeSubscriber{},
		SigningClient:   signingClient,
		// No NexusEnvelopeSigner or NexusEnvelopeAuthenticator: the runtime has
		// to build both from configuration.
		TrustInjectedSignerForTests: true,
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() {
		if err := rt.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})

	if rt.Dependencies.NexusEnvelopeSigner == nil || rt.Dependencies.NexusEnvelopeAuthenticator == nil {
		t.Fatalf("signer = %v, authenticator = %v, want both constructed from config",
			rt.Dependencies.NexusEnvelopeSigner, rt.Dependencies.NexusEnvelopeAuthenticator)
	}
	status, ok := rt.DiagnosticsSnapshot().Dependency("nexus_envelope_auth")
	if !ok || !status.Ready {
		t.Fatalf("nexus_envelope_auth = %#v ok=%v, want ready", status, ok)
	}
	// The point of #112 is activation, not a green string: the live status the
	// workload gate consults has to be ready, not just the construction report.
	readiness := rt.CheckWorkloadReadiness(context.Background())
	if !readiness.EnvelopeAuth.Ready {
		t.Fatalf("live envelope auth status = %#v, want ready", readiness.EnvelopeAuth)
	}
}

// Strict mode no longer needs to be told who the peer is: the chain's current
// BuilderSet is the authority, so a node with no configured operator still
// authenticates, and every current Builder is admissible.
func TestBuildRuntimeStrictModeAuthenticatesWithoutAConfiguredBuilderOperator(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = t.TempDir() + "/cortex.kv"
	cfg.ModelManagement.Transport = "local"
	cfg.ModelManagement.Endpoint = ""
	cfg.ModelManagement.MaxConcurrency = 1
	cfg.Nexus.EnvelopeAuthMode = config.NexusEnvelopeAuthStrict
	cfg.Nexus.BuilderOperatorAddress = ""
	signingClient, _ := readyRuntimeServiceSigner(t)
	cfg.LocalIdentity.ServiceKeyRef = "service.json"

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		Keeper:                      &descriptorKeeper{height: 900},
		NexusPublisher:              fakePublisher{},
		NexusSubscriber:             fakeSubscriber{},
		SigningClient:               signingClient,
		TrustInjectedSignerForTests: true,
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	if rt.Dependencies.NexusEnvelopeAuthenticator == nil {
		t.Fatal("authenticator was not constructed; chain membership is enough to authenticate a sender")
	}
	status, ok := rt.DiagnosticsSnapshot().Dependency("nexus_envelope_auth")
	if !ok || !status.Ready {
		t.Fatalf("nexus_envelope_auth = %#v ok=%v, want ready", status, ok)
	}
	if readiness := rt.CheckWorkloadReadiness(context.Background()); !readiness.EnvelopeAuth.Ready {
		t.Fatalf("live envelope auth status = %#v, want ready", readiness.EnvelopeAuth)
	}
}

// The chain authority is not optional. A Keeper client that cannot read the
// current BuilderSet cannot authorize any sender, so the dependency reports that
// rather than silently accepting unauthenticated traffic - and the node still
// starts, so an operator can read the diagnostic.
func TestBuildRuntimeStrictModeWithoutABuilderSetReaderReportsUnready(t *testing.T) {
	cfg := realConfig()
	cfg.Store.Path = t.TempDir() + "/cortex.kv"
	cfg.ModelManagement.Transport = "local"
	cfg.ModelManagement.Endpoint = ""
	cfg.ModelManagement.MaxConcurrency = 1
	cfg.Nexus.EnvelopeAuthMode = config.NexusEnvelopeAuthStrict
	cfg.Nexus.BuilderOperatorAddress = envelopeTestBuilder
	signingClient, _ := readyRuntimeServiceSigner(t)
	cfg.LocalIdentity.ServiceKeyRef = "service.json"

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		Keeper:                      serviceKeyOnlyKeeper{inner: &descriptorKeeper{height: 900}},
		NexusPublisher:              fakePublisher{},
		NexusSubscriber:             fakeSubscriber{},
		SigningClient:               signingClient,
		TrustInjectedSignerForTests: true,
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v, want the node to start and report the gap", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	if rt.Dependencies.NexusEnvelopeAuthenticator != nil {
		t.Fatal("authenticator was constructed without a chain view of the current BuilderSet")
	}
	status, ok := rt.DiagnosticsSnapshot().Dependency("nexus_envelope_auth")
	if !ok || status.Ready || !strings.Contains(status.Error, "BuilderSet") {
		t.Fatalf("nexus_envelope_auth = %#v ok=%v, want an unready status naming the missing BuilderSet read", status, ok)
	}
	if readiness := rt.CheckWorkloadReadiness(context.Background()); readiness.EnvelopeAuth.Ready {
		t.Fatalf("live envelope auth status = %#v, want unready", readiness.EnvelopeAuth)
	}
}

// The gate itself: an unready envelope auth dependency must withhold the
// workload. Without this the status would be decoration.
func TestWorkloadDependenciesRequireEnvelopeAuthentication(t *testing.T) {
	names := []string{"chain", "model_service", "store", "keeper", "nexus", "nexus_envelope_auth", "builder_descriptor"}
	report := diagnostics.Diagnostics{}
	for _, name := range names {
		report.Dependencies = append(report.Dependencies, diagnostics.DependencyStatus{Name: name, Configured: true, Ready: true})
	}
	if !workloadDependenciesReady(report, false) {
		t.Fatal("workloadDependenciesReady() = false with every dependency ready")
	}
	unready := diagnostics.DependencyStatus{Name: "nexus_envelope_auth", Configured: true, Ready: false,
		Error: "read current service key of trueopen1builderoperator: keeper unreachable"}
	if workloadDependenciesReady(report, false, unready) {
		t.Fatal("workloadDependenciesReady() = true while this node cannot authenticate inbound traffic")
	}
}

// trusted_nats_dev keeps the transport as the boundary and publishes unsigned
// envelopes, so it must not construct either object.
func TestBuildRuntimeTrustedNATSDevBuildsNoEnvelopeAuthentication(t *testing.T) {
	cfg := realConfig()
	cfg.Mode = config.ModeFake
	cfg.Store.Path = t.TempDir() + "/cortex.kv"
	cfg.ModelManagement.Transport = "local"
	cfg.ModelManagement.Endpoint = ""
	cfg.ModelManagement.MaxConcurrency = 1
	cfg.Nexus.EnvelopeAuthMode = config.NexusEnvelopeAuthTrustedDev
	cfg.Nexus.AuthTokenFile = writeEnvelopeTokenFile(t)
	cfg.Nexus.BuilderOperatorAddress = envelopeTestBuilder
	signingClient, _ := readyRuntimeServiceSigner(t)
	cfg.LocalIdentity.ServiceKeyRef = "service.json"

	rt, err := BuildRuntimeWithOptions(context.Background(), cfg, RuntimeOptions{
		Keeper:                      &descriptorKeeper{height: 900},
		NexusPublisher:              fakePublisher{},
		NexusSubscriber:             fakeSubscriber{},
		SigningClient:               signingClient,
		TrustInjectedSignerForTests: true,
	})
	if err != nil {
		t.Fatalf("BuildRuntimeWithOptions() error = %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	if rt.Dependencies.NexusEnvelopeSigner != nil || rt.Dependencies.NexusEnvelopeAuthenticator != nil {
		t.Fatal("trusted_nats_dev constructed envelope authentication; the transport is the boundary there")
	}
}

// writeEnvelopeTokenFile satisfies the trusted_nats_dev requirement for an
// authenticated transport without reaching for a path outside the test.
func writeEnvelopeTokenFile(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + "/nexus.token"
	if err := os.WriteFile(path, []byte("devnet-token"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return path
}

// A frame is admitted exactly once. The ingest hook authenticates and claims the
// replay key; the later processing pass over the persisted row must not
// authenticate again, because the claim it would take is its own. Getting this
// wrong made the node drop every legitimate Builder message while reporting the
// dependency ready - the exact failure #112 exists to remove.
func TestNexusFrameIsAuthenticatedOnceFromWireToProcessing(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	keeper := &envelopeKeeperStub{binding: envelopeTestBinding(key)}
	authenticator := envelopeTestAuthenticator(t, keeper, now)
	envelope := envelopeTestMessage(t, key, now, nil)
	frame, err := builderclient.EncodeBusEnvelope(envelope)
	if err != nil {
		t.Fatalf("EncodeBusEnvelope returned error: %v", err)
	}

	// Ingest: this is the wire boundary, so it authenticates and claims.
	if err := authenticator.Authenticate(context.Background(), envelope.Subject, envelope); err != nil {
		t.Fatalf("ingest Authenticate returned error: %v", err)
	}
	// Processing the persisted row must succeed without another claim. Decoding
	// the stored frame is all the processing path is allowed to do.
	decoded, err := builderclient.DecodeBusEnvelope(frame)
	if err != nil {
		t.Fatalf("DecodeBusEnvelope returned error: %v", err)
	}
	if err := decoded.Validate(builderclient.EnvelopeValidation{
		ActualSubject: envelope.Subject,
		ChainID:       envelope.ChainID,
		Kind:          envelope.Kind,
		Now:           now,
	}); err != nil {
		t.Fatalf("persisted frame failed structural validation: %v", err)
	}
	// Proof of the property: a second authentication of the same frame is a
	// replay, which is why the processing path must not perform one.
	if err := authenticator.Authenticate(context.Background(), envelope.Subject, decoded); !errors.Is(err, ErrBusEnvelopeReplay) {
		t.Fatalf("re-authenticating the same frame = %v, want ErrBusEnvelopeReplay", err)
	}
}

// A failure of this node's own inputs must be retryable so the frame is
// redelivered, while a verdict against the sender must be permanent so a bad
// frame is not retried forever.
func TestBusEnvelopeAuthenticatorClassifiesFailuresForRedelivery(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()

	t.Run("unreadable chain view is retryable", func(t *testing.T) {
		keeper := &envelopeKeeperStub{binding: envelopeTestBinding(key), err: errors.New("keeper unreachable")}
		err := envelopeTestAuthenticator(t, keeper, now).
			Authenticate(context.Background(), "trueopen.worker-assignment."+envelopeTestTaskIDHex, envelopeTestMessage(t, key, now, nil))
		if !builderclient.IsRetryable(err) {
			t.Fatalf("error = %v, want it retryable so the frame is redelivered", err)
		}
	})
	t.Run("a rejected signature is permanent", func(t *testing.T) {
		keeper := &envelopeKeeperStub{binding: envelopeTestBinding(newEnvelopeTestKey(t))}
		err := envelopeTestAuthenticator(t, keeper, now).
			Authenticate(context.Background(), "trueopen.worker-assignment."+envelopeTestTaskIDHex, envelopeTestMessage(t, key, now, nil))
		if err == nil || builderclient.IsRetryable(err) {
			t.Fatalf("error = %v, want a permanent rejection", err)
		}
	})
}

// Readiness must follow this node's own ability to authenticate, and must not be
// withdrawable by a peer: otherwise anybody who can publish a bad frame takes
// the node out of service.
func TestBusEnvelopeAuthenticatorReportsOnlyItsOwnDependencyFailures(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	var outcomes []string
	keeper := &envelopeKeeperStub{binding: envelopeTestBinding(key)}
	authenticator, err := NewBusEnvelopeAuthenticator(BusEnvelopeAuthenticatorConfig{
		ChainID: "trueopen-devnet-1",
		Keeper:  keeper,
		// The chain recognises the test Builder; these tests are about everything
		// that happens after that, so membership is satisfied and the configured
		// operator keeps narrowing to the one sender they all use.
		Members:             &membershipStub{members: map[string]bool{envelopeTestBuilder: true}},
		PeerOperatorAddress: envelopeTestBuilder,
		TTL:                 30 * time.Second,
		ClockSkew:           2 * time.Second,
		Now:                 func() time.Time { return now },
		OnDependencyOutcome: func(err error) {
			if err == nil {
				outcomes = append(outcomes, "ok")
				return
			}
			outcomes = append(outcomes, "failed")
		},
	})
	if err != nil {
		t.Fatalf("NewBusEnvelopeAuthenticator returned error: %v", err)
	}

	// A forged frame is the sender's fault and must not be reported.
	forged := envelopeTestMessage(t, newEnvelopeTestKey(t), now, nil)
	if err := authenticator.Authenticate(context.Background(), forged.Subject, forged); err == nil {
		t.Fatal("Authenticate() error = nil for a frame signed by another key")
	}
	if len(outcomes) != 0 {
		t.Fatalf("outcomes = %v, want a peer failure to leave readiness alone", outcomes)
	}

	// This node's own chain view failing is reported, and recovery is reported
	// too, or readiness could never return.
	keeper.err = errors.New("keeper unreachable")
	if err := authenticator.Authenticate(context.Background(), "trueopen.worker-assignment."+envelopeTestTaskIDHex, envelopeTestMessage(t, key, now, nil)); err == nil {
		t.Fatal("Authenticate() error = nil with an unreadable chain view")
	}
	keeper.err = nil
	if err := authenticator.Authenticate(context.Background(), "trueopen.worker-assignment."+envelopeTestTaskIDHex, envelopeTestMessage(t, key, now, nil)); err != nil {
		t.Fatalf("Authenticate returned error after recovery: %v", err)
	}
	if len(outcomes) != 2 || outcomes[0] != "failed" || outcomes[1] != "ok" {
		t.Fatalf("outcomes = %v, want a failure followed by a recovery", outcomes)
	}
}

// The remaining fail-closed rules that the table above does not reach, each one a
// case where accepting the frame would let a signed message be reused somewhere
// it was never minted for.
func TestBusEnvelopeAuthenticatorBindsRoleSubjectAndLifetime(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()

	// A domain the kind does not admit is refused by the §5.3 table inside
	// ValidateEnvelopeIntrinsics, before the Keeper is consulted. The other
	// half - what a domain the table DOES admit then has to prove on chain - is
	// TestCortexSenderStillRequiresItsOwnCurrentActiveBinding. Both checks are
	// needed and neither subsumes the other.
	t.Run("participant the kind does not admit", func(t *testing.T) {
		keeper := &envelopeKeeperStub{binding: envelopeTestBinding(key)}
		envelope := envelopeTestMessage(t, key, now, func(e *builderclient.BusEnvelope) {
			e.SenderParticipantType = builderclient.ParticipantCortex
		})
		err := envelopeTestAuthenticator(t, keeper, now).Authenticate(context.Background(), envelope.Subject, envelope)
		if err == nil || !strings.Contains(err.Error(), "does not admit sender_participant_type") {
			t.Fatalf("error = %v, want the kind/participant table to refuse it", err)
		}
		if keeper.reads != 0 {
			t.Fatalf("service key reads = %d, want the frame refused before the Keeper is consulted", keeper.reads)
		}
	})
	t.Run("delivery subject", func(t *testing.T) {
		keeper := &envelopeKeeperStub{binding: envelopeTestBinding(key)}
		envelope := envelopeTestMessage(t, key, now, nil)
		// A frame signed for one task's subject, replayed onto another's.
		err := envelopeTestAuthenticator(t, keeper, now).Authenticate(context.Background(), "trueopen.worker-assignment."+("02"+envelopeTestTaskIDHex[2:]), envelope)
		if err == nil || !strings.Contains(err.Error(), "was delivered on") {
			t.Fatalf("error = %v, want the delivery subject to be bound", err)
		}
	})
	t.Run("lifetime one millisecond beyond the TTL", func(t *testing.T) {
		keeper := &envelopeKeeperStub{binding: envelopeTestBinding(key)}
		envelope := envelopeTestMessage(t, key, now, func(e *builderclient.BusEnvelope) {
			e.ExpiresAtUnixMs = now.Add(30*time.Second + time.Millisecond).UnixMilli()
		})
		err := envelopeTestAuthenticator(t, keeper, now).Authenticate(context.Background(), envelope.Subject, envelope)
		if err == nil || !strings.Contains(err.Error(), "exceeds the accepted TTL") {
			t.Fatalf("error = %v, want a lifetime past the TTL to be refused with no skew grace", err)
		}
	})
	t.Run("blank participant type in the binding", func(t *testing.T) {
		binding := envelopeTestBinding(key)
		binding.ParticipantType = ""
		keeper := &envelopeKeeperStub{binding: binding}
		envelope := envelopeTestMessage(t, key, now, nil)
		err := envelopeTestAuthenticator(t, keeper, now).Authenticate(context.Background(), envelope.Subject, envelope)
		if err == nil || !strings.Contains(err.Error(), "participant type") {
			t.Fatalf("error = %v, want a partially populated binding to be refused", err)
		}
	})
}

// The late-bound signer identity is the production resolver, so its three real
// states have to hold: no runtime, no confirmed identity yet, and an identity
// withdrawn again.
func TestRuntimeWorkloadServiceAddressFollowsActivation(t *testing.T) {
	var missing *Runtime
	if _, err := missing.workloadServiceAddress(); err == nil {
		t.Fatal("workloadServiceAddress() error = nil on a nil runtime")
	}

	rt := &Runtime{}
	if _, err := rt.workloadServiceAddress(); err == nil ||
		!strings.Contains(err.Error(), "workload is not active") {
		t.Fatalf("error = %v, want signing refused before the Keeper confirms the identity", err)
	}

	rt.ServiceAddress = "trueopen1cortexservice"
	address, err := rt.workloadServiceAddress()
	if err != nil || address != "trueopen1cortexservice" {
		t.Fatalf("address = %q err = %v, want the activated identity", address, err)
	}

	rt.DeactivateWorkload()
	if _, err := rt.workloadServiceAddress(); err == nil {
		t.Fatal("workloadServiceAddress() error = nil after deactivation; a stale identity must not sign")
	}
}
