package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/builderclient"
)

// BuilderEndpointRefresher re-reads the on-chain descriptor once, past the descriptor
// cache. ADR-0015: after a Builder changes certificates the new fingerprint goes on
// chain while the client still holds the old one cached for the Task's lifetime, so
// the handshake check mismatches - at which point the descriptor is re-read and the
// dial retried once, and only a second mismatch refuses.
type BuilderEndpointRefresher interface {
	RefreshBuilderEndpoint(ctx context.Context, operatorAddress string) (BuilderEndpoint, error)
}

// dialBuilder resolves the operator's endpoint and runs op under a ctx that checks the
// certificate against that fingerprint. When op fails on a fingerprint mismatch: re-read
// the descriptor; if the fingerprint changed, run once more with the new one, exactly
// once; if it did not change, the peer certificate is wrong rather than the cache
// stale, so the original error is returned. Other errors trigger no re-read.
func dialBuilder(ctx context.Context, endpoints BuilderEndpointResolver, operator string,
	op func(ctx context.Context, endpoint BuilderEndpoint) error) error {
	endpoint, err := endpoints.ResolveBuilderEndpoint(ctx, operator)
	if err != nil {
		return err
	}
	if err := checkResolvedBuilder(endpoint, operator); err != nil {
		return err
	}
	err = op(endpoint.PinnedContext(ctx), endpoint)
	if !errors.Is(err, builderclient.ErrTLSPubkeyMismatch) {
		return err
	}
	refresher, ok := endpoints.(BuilderEndpointRefresher)
	if !ok {
		return err
	}
	fresh, refreshErr := refresher.RefreshBuilderEndpoint(ctx, operator)
	if refreshErr != nil {
		return fmt.Errorf("%w (re-reading the descriptor also failed: %v)", err, refreshErr)
	}
	if checkResolvedBuilder(fresh, operator) != nil || fresh.TLSPubkeyHash == endpoint.TLSPubkeyHash {
		return err
	}
	return op(fresh.PinnedContext(ctx), fresh)
}

func checkResolvedBuilder(endpoint BuilderEndpoint, operator string) error {
	if endpoint.OperatorAddress != operator || strings.TrimSpace(endpoint.Endpoint) == "" {
		return fmt.Errorf("resolved Builder endpoint does not match receiving Builder %s", operator)
	}
	return nil
}
