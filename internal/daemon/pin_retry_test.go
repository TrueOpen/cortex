package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
)

// refreshingEndpoints simulates "descriptor cache + forced re-read": Resolve returns
// the fingerprint in the cache, Refresh returns the latest on-chain fingerprint and
// counts the call.
type refreshingEndpoints struct {
	cached, fresh string
	refreshes     int
	noRefresh     bool // implements BuilderEndpointResolver only, no refresh
}

func (e *refreshingEndpoints) endpoint(pin string) BuilderEndpoint {
	return BuilderEndpoint{
		OperatorAddress: endpointTestBuilder, Endpoint: "https://builder.example",
		TLSPubkeyHash: pin, Source: BuilderEndpointSourceDescriptor,
	}
}

func (e *refreshingEndpoints) ResolveBuilderEndpoint(_ context.Context, operator string) (BuilderEndpoint, error) {
	if operator != endpointTestBuilder {
		return BuilderEndpoint{}, fmt.Errorf("unexpected Builder %q", operator)
	}
	return e.endpoint(e.cached), nil
}

func (e *refreshingEndpoints) RefreshBuilderEndpoint(_ context.Context, operator string) (BuilderEndpoint, error) {
	e.refreshes++
	e.cached = e.fresh
	return e.endpoint(e.fresh), nil
}

// noRefreshEndpoints only resolves, never refreshes (it cannot embed, or the methods
// would be promoted).
type noRefreshEndpoints struct{ inner *refreshingEndpoints }

func (e noRefreshEndpoints) ResolveBuilderEndpoint(ctx context.Context, operator string) (BuilderEndpoint, error) {
	return e.inner.ResolveBuilderEndpoint(ctx, operator)
}

var (
	pinA = strings.Repeat("aa", 32)
	pinB = strings.Repeat("bb", 32)
)

// Fingerprint mismatch -> re-read the descriptor -> the fingerprint changed -> dial
// once more with the new one, retrying exactly once.
func TestDialBuilderRetriesOnceWithTheRefreshedPin(t *testing.T) {
	endpoints := &refreshingEndpoints{cached: pinA, fresh: pinB}
	var pins []string
	err := dialBuilder(context.Background(), endpoints, endpointTestBuilder, func(ctx context.Context, endpoint BuilderEndpoint) error {
		pin, _ := builderclient.TLSPubkeyHashFromContext(ctx)
		pins = append(pins, pin)
		if endpoint.TLSPubkeyHash == pinA {
			return fmt.Errorf("dial: %w", builderclient.ErrTLSPubkeyMismatch)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("dialBuilder: %v", err)
	}
	if endpoints.refreshes != 1 {
		t.Fatalf("refreshes = %d, want 1", endpoints.refreshes)
	}
	if len(pins) != 2 || pins[0] != pinA || pins[1] != pinB {
		t.Fatalf("pins in ctx = %v, want [A B]", pins)
	}
}

// The fingerprint is unchanged after the re-read: this is not a stale cache but a
// wrong peer certificate, so do not retry and return the original error.
func TestDialBuilderDoesNotRetryWhenTheRefreshedPinIsUnchanged(t *testing.T) {
	endpoints := &refreshingEndpoints{cached: pinA, fresh: pinA}
	calls := 0
	err := dialBuilder(context.Background(), endpoints, endpointTestBuilder, func(context.Context, BuilderEndpoint) error {
		calls++
		return fmt.Errorf("dial: %w", builderclient.ErrTLSPubkeyMismatch)
	})
	if !errors.Is(err, builderclient.ErrTLSPubkeyMismatch) {
		t.Fatalf("err = %v, want ErrTLSPubkeyMismatch", err)
	}
	if calls != 1 || endpoints.refreshes != 1 {
		t.Fatalf("calls = %d refreshes = %d, want 1 and 1", calls, endpoints.refreshes)
	}
}

// Other errors trigger no re-read, and a resolver without refresh support is not
// retried either.
func TestDialBuilderOnlyRefreshesForPinMismatch(t *testing.T) {
	endpoints := &refreshingEndpoints{cached: pinA, fresh: pinB}
	other := errors.New("connection refused")
	err := dialBuilder(context.Background(), endpoints, endpointTestBuilder, func(context.Context, BuilderEndpoint) error {
		return other
	})
	if !errors.Is(err, other) || endpoints.refreshes != 0 {
		t.Fatalf("err = %v refreshes = %d, want the original error and no refresh", err, endpoints.refreshes)
	}

	plain := noRefreshEndpoints{inner: &refreshingEndpoints{cached: pinA, fresh: pinB}}
	calls := 0
	err = dialBuilder(context.Background(), plain, endpointTestBuilder, func(context.Context, BuilderEndpoint) error {
		calls++
		return builderclient.ErrTLSPubkeyMismatch
	})
	if !errors.Is(err, builderclient.ErrTLSPubkeyMismatch) || calls != 1 {
		t.Fatalf("resolver without refresh: err = %v calls = %d, want mismatch and 1 call", err, calls)
	}
}
