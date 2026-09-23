package daemon

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
)

// envelopeTestCortexWorker is a real devnet Worker operator address: the
// selected_worker of task fb0197fe… on trueopen-localnet-1. A bech32 address is
// required because the signing projection refuses anything else, so a
// placeholder would make these frames unsignable rather than unauthorized.
const envelopeTestCortexWorker = "trueopen127sthpcvplyvumztjcn036utdwnqx22y8ywtlr"

func envelopeTestCortexBinding(key envelopeTestKey) chainclient.ServiceKeySnapshot {
	return chainclient.ServiceKeySnapshot{
		ParticipantType:    chainclient.ParticipantTypeCortexNode,
		OperatorAddress:    envelopeTestCortexWorker,
		ServiceAddress:     "trueopen1cortexservice",
		ServicePubkey:      key.pubkeyHex,
		AuthorizationNonce: chainclient.NewUint64String(envelopeTestAuthorizationNonce),
		Status:             "ACTIVE",
	}
}

// TestBusEnvelopeAuthenticatorAdmitsEveryDomainTheFrozenSubjectTableAdmits is
// the fix for a structural refusal, not a hardening.
//
// trueopen.output-avail.* has two sender rows in the frozen table
// (builderclient/envelope.go): CORTEX, because a Worker publishes the hint, and
// BUILDER, because Cortex also receives the kind from a Builder. The
// authenticator compared the frame's domain against ONE configured domain,
// hardwired to BUILDER at construction — so the Worker-published half of the
// only kind Cortex both sends and receives could never authenticate on any
// node. Cortex published as CORTEX (worker.go) and refused as
// not-BUILDER, on devnet at roughly one NAK per second until the envelope
// expired, which cost every Verifier its OUTPUT_AVAILABLE wake-up.
//
// The security property the old check aimed at survives: the frame still
// cannot pick its own keyspace. The admissible set comes from the frozen table
// row for its kind, which no frame can influence, rather than from the frame's
// own claim.
func TestBusEnvelopeAuthenticatorAdmitsEveryDomainTheFrozenSubjectTableAdmits(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	keeper := &envelopeKeeperStub{binding: envelopeTestCortexBinding(key)}
	envelope := envelopeTestOutputAvailableFromCortexWorker(t, key, now)

	err := envelopeTestAuthenticator(t, keeper, now).Authenticate(context.Background(), envelope.Subject, envelope)
	if err != nil {
		t.Fatalf("Authenticate() error = %v, want a Worker-published OUTPUT_AVAILABLE accepted", err)
	}
	// The keyspace must follow the frame's domain, or a CORTEX sender would be
	// verified against a Builder binding that cannot exist for it.
	if got := keeper.queriedParticipantTypes; len(got) != 1 || got[0] != chainclient.ParticipantTypeCortexNode {
		t.Fatalf("queried participant types = %v, want the CORTEX_NODE keyspace", got)
	}
	if got := keeper.queriedOperators; len(got) != 1 || got[0] != envelopeTestCortexWorker {
		t.Fatalf("queried operators = %v, want the frame's own sender", got)
	}
}

// The two narrowing rules that exist for Builder senders must not be applied to
// a Cortex sender, because neither can ever be satisfied by one: the configured
// operator names a Builder, and the chain's BuilderSet does not contain Cortex
// nodes. Applying them silently reintroduced the same total refusal.
func TestBuilderNarrowingDoesNotApplyToACortexSender(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	envelope := envelopeTestOutputAvailableFromCortexWorker(t, key, now)

	t.Run("configured Builder operator", func(t *testing.T) {
		keeper := &envelopeKeeperStub{binding: envelopeTestCortexBinding(key)}
		// The PeerOperatorAddress envelopeTestAuthenticator configures is that Builder.
		if err := envelopeTestAuthenticator(t, keeper, now).Authenticate(context.Background(), envelope.Subject, envelope); err != nil {
			t.Fatalf("Authenticate() error = %v, want the Builder-only narrowing skipped for a CORTEX sender", err)
		}
	})

	t.Run("BuilderSet membership", func(t *testing.T) {
		keeper := &envelopeKeeperStub{binding: envelopeTestCortexBinding(key)}
		members := &membershipStub{members: map[string]bool{envelopeTestBuilder: true}}
		authenticator, err := NewBusEnvelopeAuthenticator(BusEnvelopeAuthenticatorConfig{
			ChainID: "trueopen-devnet-1", Keeper: keeper, Members: members,
			TTL: 30 * time.Second, ClockSkew: 2 * time.Second, Now: func() time.Time { return now },
		})
		if err != nil {
			t.Fatalf("NewBusEnvelopeAuthenticator returned error: %v", err)
		}
		if err := authenticator.Authenticate(context.Background(), envelope.Subject, envelope); err != nil {
			t.Fatalf("Authenticate() error = %v, want a CORTEX sender authorized without BuilderSet membership", err)
		}
	})
}

// Widening the admissible domains must not weaken what authorizes a sender
// inside each one. A CORTEX sender's authority is its own current, ACTIVE
// CORTEX_NODE binding: without that, any key at all could publish a hint that
// wakes a Verifier.
func TestCortexSenderStillRequiresItsOwnCurrentActiveBinding(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	envelope := envelopeTestOutputAvailableFromCortexWorker(t, key, now)

	for name, binding := range map[string]chainclient.ServiceKeySnapshot{
		"revoked": func() chainclient.ServiceKeySnapshot {
			b := envelopeTestCortexBinding(key)
			b.Status = "REVOKED"
			return b
		}(),
		"belongs to another operator": func() chainclient.ServiceKeySnapshot {
			b := envelopeTestCortexBinding(key)
			b.OperatorAddress = envelopeTestBuilder
			return b
		}(),
		"resolved in the Builder keyspace": func() chainclient.ServiceKeySnapshot {
			b := envelopeTestCortexBinding(key)
			b.ParticipantType = chainclient.ParticipantTypeBuilder
			return b
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			keeper := &envelopeKeeperStub{binding: binding}
			err := envelopeTestAuthenticator(t, keeper, now).Authenticate(context.Background(), envelope.Subject, envelope)
			if err == nil {
				t.Fatal("Authenticate() error = nil, want the binding refused")
			}
		})
	}
}

// The domain a frame claims must still be one the frozen table admits for its
// kind, and the refusal must land before the Keeper read: that is what stops a
// frame from steering this node's current-key lookup into a keyspace of its own
// choosing. WORKER_ASSIGNMENT_NOTIFY is Builder-only, so a CORTEX claim on it
// has no row.
func TestBusEnvelopeAuthenticatorRefusesADomainTheKindDoesNotAdmit(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	keeper := &envelopeKeeperStub{binding: envelopeTestBinding(key)}
	envelope := envelopeTestMessage(t, key, now, func(e *builderclient.BusEnvelope) {
		e.SenderParticipantType = builderclient.ParticipantCortex
	})

	err := envelopeTestAuthenticator(t, keeper, now).Authenticate(context.Background(), envelope.Subject, envelope)
	if err == nil || !strings.Contains(err.Error(), "does not admit sender_participant_type") {
		t.Fatalf("Authenticate() error = %v, want the frozen table to refuse the domain", err)
	}
	if keeper.reads != 0 {
		t.Fatalf("service key reads = %d, want the frame refused before it can select a keyspace", keeper.reads)
	}
}

func envelopeTestOutputAvailableFromCortexWorker(t *testing.T, key envelopeTestKey, issuedAt time.Time) builderclient.BusEnvelope {
	t.Helper()
	envelope := envelopeTestOutputAvailableFromWorker(t, key, issuedAt)
	envelope.SenderOperatorAddress = envelopeTestCortexWorker
	return envelopeTestSign(t, key, envelope)
}
