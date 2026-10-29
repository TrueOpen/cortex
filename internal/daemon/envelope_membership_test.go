package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderdirectory"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/config"
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
