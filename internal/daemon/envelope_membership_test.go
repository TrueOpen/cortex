package daemon

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/builderdirectory"
	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/config"
)

// membershipStub is the chain's answer to "is this sender a Builder right now".
type membershipStub struct {
	members map[string]bool
	err     error
	checks  []string
}

func (m *membershipStub) HasBuilder(_ context.Context, operatorAddress string) (bool, error) {
	m.checks = append(m.checks, operatorAddress)
	if m.err != nil {
		return false, m.err
	}
	return m.members[operatorAddress], nil
}

func membershipAuthenticator(t *testing.T, keeper envelopeServiceKeyReader, members *membershipStub, configured string, now time.Time) builderclient.BusEnvelopeAuthenticator {
	t.Helper()
	authenticator, err := NewBusEnvelopeAuthenticator(BusEnvelopeAuthenticatorConfig{
		ChainID:             "trueopen-devnet-1",
		Keeper:              keeper,
		Members:             members,
		PeerOperatorAddress: configured,
		TTL:                 30 * time.Second,
		ClockSkew:           2 * time.Second,
		Now:                 func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewBusEnvelopeAuthenticator returned error: %v", err)
	}
	return authenticator
}

// The chain decides who may send, so a Builder in the current BuilderSet is
// accepted without any local configuration naming it.
func TestEnvelopeAuthenticatorAcceptsAnyCurrentBuilderWithoutConfiguration(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	keeper := &envelopeKeeperStub{binding: envelopeTestBinding(key)}
	members := &membershipStub{members: map[string]bool{envelopeTestBuilder: true}}
	authenticator := membershipAuthenticator(t, keeper, members, "", now)

	message := envelopeTestMessage(t, key, now, nil)
	if err := authenticator.Authenticate(context.Background(), message.Subject, message); err != nil {
		t.Fatalf("Authenticate() error = %v, want a current BuilderSet member to be accepted", err)
	}
	if len(members.checks) != 1 || members.checks[0] != envelopeTestBuilder {
		t.Fatalf("membership checks = %v", members.checks)
	}
}

// A sender the chain does not currently recognise is refused even though the
// frame is otherwise well formed and correctly signed.
func TestEnvelopeAuthenticatorRefusesASenderOutsideTheCurrentBuilderSet(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	keeper := &envelopeKeeperStub{binding: envelopeTestBinding(key)}
	members := &membershipStub{members: map[string]bool{"trueopen1otherbuilder": true}}
	authenticator := membershipAuthenticator(t, keeper, members, "", now)

	message := envelopeTestMessage(t, key, now, nil)
	err := authenticator.Authenticate(context.Background(), message.Subject, message)
	if err == nil || !strings.Contains(err.Error(), "current BuilderSet") {
		t.Fatalf("Authenticate() error = %v, want a non-member sender to be refused", err)
	}
	// Refusing a sender the chain does not recognise is the sender's fault, not
	// this node's, so it must not be resolved as a service-key read either.
	if keeper.reads != 0 {
		t.Fatalf("service key reads = %d, want the sender refused before any key read", keeper.reads)
	}
}

// Configuration may narrow what this node accepts and may never widen it: a
// configured operator that the chain has removed from the set stays refused.
func TestEnvelopeAuthenticatorConfigurationCannotWidenTheChainSet(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	keeper := &envelopeKeeperStub{binding: envelopeTestBinding(key)}
	members := &membershipStub{members: map[string]bool{}}
	authenticator := membershipAuthenticator(t, keeper, members, envelopeTestBuilder, now)

	message := envelopeTestMessage(t, key, now, nil)
	err := authenticator.Authenticate(context.Background(), message.Subject, message)
	if err == nil || !strings.Contains(err.Error(), "current BuilderSet") {
		t.Fatalf("Authenticate() error = %v, want the configured operator to stay refused once removed", err)
	}
}

// The narrowing direction still works: with a configured operator, a different
// member of the same set is refused.
func TestEnvelopeAuthenticatorConfigurationNarrowsToOneBuilder(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	keeper := &envelopeKeeperStub{binding: envelopeTestBinding(key)}
	members := &membershipStub{members: map[string]bool{envelopeTestBuilder: true, "trueopen1otherbuilder": true}}
	authenticator := membershipAuthenticator(t, keeper, members, "trueopen1otherbuilder", now)

	message := envelopeTestMessage(t, key, now, nil)
	err := authenticator.Authenticate(context.Background(), message.Subject, message)
	if err == nil || !strings.Contains(err.Error(), "configured Builder operator") {
		t.Fatalf("Authenticate() error = %v, want the configured filter to refuse another member", err)
	}
}

// An unreadable chain view is this node's failure. Reporting it as "not a
// member" would let a Keeper outage look like an unauthorized sender and would
// discard a frame that is probably fine.
func TestEnvelopeAuthenticatorReportsMembershipReadFailuresAsRetryable(t *testing.T) {
	key := newEnvelopeTestKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	keeper := &envelopeKeeperStub{binding: envelopeTestBinding(key)}
	members := &membershipStub{err: fmt.Errorf("keeper is unavailable")}
	authenticator := membershipAuthenticator(t, keeper, members, "", now)

	message := envelopeTestMessage(t, key, now, nil)
	err := authenticator.Authenticate(context.Background(), message.Subject, message)
	if err == nil || !builderclient.IsRetryable(err) {
		t.Fatalf("Authenticate() error = %v, want a retryable dependency failure", err)
	}
}

// The authenticator cannot be built without the chain authority: a build that
// fell back to the configured operator alone would make configuration the
// authority again.
func TestNewBusEnvelopeAuthenticatorRequiresChainMembership(t *testing.T) {
	_, err := NewBusEnvelopeAuthenticator(BusEnvelopeAuthenticatorConfig{
		ChainID:             "trueopen-devnet-1",
		Keeper:              &envelopeKeeperStub{},
		PeerOperatorAddress: envelopeTestBuilder,
		TTL:                 30 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "membership") {
		t.Fatalf("NewBusEnvelopeAuthenticator() error = %v, want the chain membership requirement", err)
	}
}

// A BuilderSet update must take effect on the next frame, not at the end of a
// cache window, so the reconciler hands the event to whoever holds the cache.
func TestReconcilerReportsBuilderSetUpdates(t *testing.T) {
	var updates int
	reconciler := NewReconciler(ReconcilerOptions{OnBuilderSetUpdated: func() { updates++ }})
	_, err := reconciler.Apply(context.Background(), []chainclient.KeeperEvent{{
		Type:   chainclient.KeeperEventBuilderSetUpdated,
		Height: 120,
	}})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if updates != 1 {
		t.Fatalf("BuilderSet updates observed = %d, want 1", updates)
	}
}

// A configured Builder that the chain has removed from the BuilderSet is a
// conflict between local configuration and consensus. The node can receive
// nothing legitimate from it, so the workload stays down instead of resolving
// the conflict in configuration's favour.
func TestBuilderDescriptorReadinessRefusesAConfiguredBuilderOutsideTheSet(t *testing.T) {
	keeper := &descriptorKeeper{height: 900, descriptor: descriptorRow(t, "https://nexus.example.org")}
	resolver, err := builderdirectory.New(keeper, builderdirectory.Options{})
	if err != nil {
		t.Fatalf("builderdirectory.New: %v", err)
	}
	members, err := builderdirectory.NewMembership(emptyBuilderSetReader{height: keeper.height}, builderdirectory.MembershipOptions{})
	if err != nil {
		t.Fatalf("builderdirectory.NewMembership: %v", err)
	}
	runtime := &Runtime{
		cfg: config.Config{
			Mode: config.ModeReal,
			Nexus: config.NexusConfig{
				IngressURL:             "https://nexus.example.org",
				BuilderOperatorAddress: descriptorTestOperator,
			},
		},
		builderDirectory: resolver,
		builderMembers:   members,
	}

	status := runtime.checkBuilderDescriptorReadiness(context.Background())
	if status.Ready || !strings.Contains(status.Error, "not in the current BuilderSet") {
		t.Fatalf("builder_descriptor = %#v, want the configured Builder refused as a non-member", status)
	}
}

// emptyBuilderSetReader is a live chain whose current BuilderSet contains
// someone else entirely.
type emptyBuilderSetReader struct {
	height uint64
}

func (r emptyBuilderSetReader) CommittedBuilderSet(context.Context) (chainclient.BuilderSetSnapshot, uint64, error) {
	return chainclient.BuilderSetSnapshot{
		BuilderSetVersion: chainclient.Uint64String(8),
		BuilderSetID:      "builder-set-8",
		SetHash:           descriptorTestHashValue(),
		Builders:          []string{"trueopen1otherbuilder"},
		SnapshotHeight:    chainclient.Uint64String(r.height),
	}, r.height, nil
}
