package worker

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
)

// countingBuildersProvider answers ResolveReceivingBuilders from a queue of
// results and counts the calls; it never touches the network.
type countingBuildersProvider struct {
	results []func() ([]BuilderEndpoint, error)
	calls   atomic.Int64
}

func (p *countingBuildersProvider) ResolveReceivingBuilder(context.Context, ReceivingBuilderRef) (BuilderEndpoint, error) {
	return BuilderEndpoint{}, errors.New("not used")
}

func (p *countingBuildersProvider) ResolveReceivingBuilders(context.Context, ReceivingBuilderRef) ([]BuilderEndpoint, error) {
	n := int(p.calls.Add(1)) - 1
	if n >= len(p.results) {
		n = len(p.results) - 1
	}
	return p.results[n]()
}

func preresolveEndpoint(operator string) BuilderEndpoint {
	return BuilderEndpoint{
		OperatorAddress: operator, Endpoint: "https://" + operator + ".example",
		ServicePubkey: "02" + strings.Repeat("ab", 32), CurrentHeight: 100, AuthorizationNonce: 1,
	}
}

func listOf(endpoints ...BuilderEndpoint) func() ([]BuilderEndpoint, error) {
	return func() ([]BuilderEndpoint, error) { return endpoints, nil }
}

var preresolveRef = ReceivingBuilderRef{SessionID: "session-1", TaskID: "task-1", AssignedBuilderOperator: "b1"}

func waitPreresolved(p *PreresolvedBuilders) { <-p.done }

// The first open uses the preresolved set, in its order; the next open
// resolves afresh.
func TestPreresolvedBuildersUsedOnceInOrder(t *testing.T) {
	provider := &countingBuildersProvider{results: []func() ([]BuilderEndpoint, error){
		listOf(preresolveEndpoint("b1"), preresolveEndpoint("b2"), preresolveEndpoint("b3")),
	}}
	pre := PreresolveBuilders(context.Background(), provider, preresolveRef)
	waitPreresolved(pre)
	w := New(Config{ReceivingBuilder: provider, PreresolvedBuilders: pre})
	got, err := w.openReceivingBuilders(context.Background(), preresolveRef)
	if err != nil || len(got) != 3 || got[0].OperatorAddress != "b1" || got[2].OperatorAddress != "b3" {
		t.Fatalf("first open = %+v, %v", got, err)
	}
	if calls := provider.calls.Load(); calls != 1 {
		t.Fatalf("provider calls after first open = %d, want the preresolve only", calls)
	}
	if _, err := w.openReceivingBuilders(context.Background(), preresolveRef); err != nil {
		t.Fatal(err)
	}
	if calls := provider.calls.Load(); calls != 2 {
		t.Fatalf("provider calls after second open = %d, want a fresh resolution", calls)
	}
}

// A preresolve that failed, a set that fails the identity check, or a set for
// another task is dropped and the open resolves for itself.
func TestPreresolvedBuildersFallBackToFreshResolution(t *testing.T) {
	incomplete := preresolveEndpoint("b1")
	incomplete.ServicePubkey = ""
	for name, tc := range map[string]struct {
		first func() ([]BuilderEndpoint, error)
		ref   ReceivingBuilderRef
	}{
		"failed":     {first: func() ([]BuilderEndpoint, error) { return nil, errors.New("node unavailable") }, ref: preresolveRef},
		"incomplete": {first: listOf(incomplete), ref: preresolveRef},
		"other task": {first: listOf(preresolveEndpoint("b1")), ref: ReceivingBuilderRef{SessionID: "session-1", TaskID: "task-2", AssignedBuilderOperator: "b1"}},
	} {
		t.Run(name, func(t *testing.T) {
			provider := &countingBuildersProvider{results: []func() ([]BuilderEndpoint, error){
				tc.first, listOf(preresolveEndpoint("b9")),
			}}
			pre := PreresolveBuilders(context.Background(), provider, preresolveRef)
			waitPreresolved(pre)
			w := New(Config{ReceivingBuilder: provider, PreresolvedBuilders: pre})
			got, err := w.openReceivingBuilders(context.Background(), tc.ref)
			if err != nil || len(got) != 1 || got[0].OperatorAddress != "b9" {
				t.Fatalf("open = %+v, %v, want the fresh resolution", got, err)
			}
		})
	}
}
