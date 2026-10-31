package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"connectrpc.com/connect"

	"github.com/TrueOpen/cortex/internal/builderclient"
)

// dispatchStreamBase is every Session's BaseURL. It names no host: each
// request is re-addressed to the Builder's current on-chain descriptor by
// descriptorClient, so a configured address is never dialled (CD §4.2.2).
const dispatchStreamBase = "https://descriptor.invalid"

type builderMembership interface {
	HasBuilder(ctx context.Context, operator string) (bool, error)
}

type builderEndpointRefresher interface {
	RefreshBuilderEndpoint(ctx context.Context, operator string) (BuilderEndpoint, error)
}

// descriptorClient is a Session's connect.HTTPClient: every dial resolves
// the Builder's NEXUS_GRPC endpoint and tls_pubkey_hash from its current
// descriptor, after checking the Builder is in the current BuilderSet. A
// descriptor rotated by its Builder takes effect on the next reconnect; a
// pin mismatch drops the descriptor cache so that reconnect re-reads it
// (ADR-0015 rule 4, CD §15.1).
type descriptorClient struct {
	builder   string
	endpoints BuilderEndpointResolver
	members   builderMembership // nil: no membership read available
	http      connect.HTTPClient
	downgrade bool // nexus.downgrade_descriptor_tls (devnet only)
}

func (c *descriptorClient) Do(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	if c.members != nil {
		ok, err := c.members.HasBuilder(ctx, c.builder)
		if err != nil {
			return nil, fmt.Errorf("read the current BuilderSet: %w", err)
		}
		if !ok {
			return nil, fmt.Errorf("Builder %s is not in the current BuilderSet", c.builder)
		}
	}
	ep, err := c.endpoints.ResolveBuilderEndpoint(ctx, c.builder)
	if err != nil {
		return nil, err
	}
	if ep.Source != BuilderEndpointSourceDescriptor {
		return nil, fmt.Errorf("Builder %s endpoint came from %s; a DispatchStream dials only the on-chain descriptor", c.builder, ep.Source)
	}
	parsed, err := builderclient.ParseNexusEndpoint(ep.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("Builder %s descriptor endpoint: %w", c.builder, err)
	}
	if c.downgrade {
		parsed = parsed.WithoutTLS()
	}
	origin, err := url.Parse(parsed.DialURI)
	if err != nil {
		return nil, err
	}
	u := *req.URL
	u.Scheme, u.Host = origin.Scheme, origin.Host
	u.Path, u.RawPath = strings.TrimRight(origin.Path, "/")+req.URL.Path, ""
	out := req.Clone(ep.PinnedContext(ctx))
	out.URL, out.Host = &u, ""
	resp, err := c.http.Do(out)
	if err != nil && errors.Is(err, builderclient.ErrTLSPubkeyMismatch) {
		if r, ok := c.endpoints.(builderEndpointRefresher); ok {
			_, _ = r.RefreshBuilderEndpoint(context.WithoutCancel(ctx), c.builder)
		}
	}
	return resp, err
}
