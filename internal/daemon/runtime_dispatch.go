package daemon

import (
	"context"
	"errors"
	"fmt"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/txclient"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
)

// WorkloadSubmitter returns the workload Tx client with the service address
// it signs as, read under one lock: a claim, rescue or challenge names as
// submitter exactly the address that broadcasts it (S6). Inactive: nil, "".
func (r *Runtime) WorkloadSubmitter() (txclient.Client, string) {
	if r == nil {
		return nil, ""
	}
	r.workloadMu.RLock()
	defer r.workloadMu.RUnlock()
	if r.WorkloadTx == nil || r.ServiceAddress == "" {
		return nil, ""
	}
	return r.WorkloadTx, r.ServiceAddress
}

// LastWorkloadReady is the last CheckWorkloadReadiness verdict: chain view,
// identity and signer proof, store write probe (CD §5.1 H1, §4.2.2).
func (r *Runtime) LastWorkloadReady() bool { return r != nil && r.lastReady.Load() }

// ChainTipHeight is the latest chain height the poller observed; 0 before.
func (r *Runtime) ChainTipHeight() uint64 {
	p, ok := r.chainProgressSnapshot()
	if !ok {
		return 0
	}
	return p.ChainHeight
}

// DispatchSigner signs dispatch digests as the current service key.
func (r *Runtime) DispatchSigner() dispatchwire.DigestSigner {
	return func(ctx context.Context, d [32]byte) ([]byte, error) {
		address, _ := r.WorkloadIdentity()
		if address == "" || r.signingClient == nil {
			return nil, builderclient.Retryable(errors.New("workload is not active: no confirmed service key to sign as"))
		}
		return r.signingClient.SignDigest(ctx, signer.DigestRequest{KeyRef: r.cfg.LocalIdentity.ServiceKeyRef, ExpectedSignerAddress: address, Digest: codec.Hash(d)})
	}
}

// runtimeHandraiseLocal is the plane's HandraiseLocal; capacity comes from
// the lease ledger (WithLeaseSlots). No drain controls exist (S9 Q10).
type runtimeHandraiseLocal struct{ rt *Runtime }

func (l runtimeHandraiseLocal) WorkloadReady(context.Context) bool          { return l.rt.LastWorkloadReady() }
func (l runtimeHandraiseLocal) Draining() (bool, map[HandraiseProfile]bool) { return false, nil }
func (l runtimeHandraiseLocal) FreeSlots(context.Context) (uint32, bool)    { return 0, false }
func (r *Runtime) HandraiseLocal() HandraiseLocal                           { return runtimeHandraiseLocal{rt: r} }

type rosterClient interface {
	GetDispatchRoster(ctx context.Context, endpoint string, req *nexusv1.GetDispatchRosterRequest) (*nexusv1.GetDispatchRosterResponse, error)
}

// rosterSource is the S8 DispatchRosterSource: the Builder's descriptor
// endpoint and pin, then IngressAPI.GetDispatchRoster.
type rosterSource struct {
	endpoints BuilderEndpointResolver
	client    rosterClient
}

func (s rosterSource) GetDispatchRoster(ctx context.Context, builder string, req *nexusv1.GetDispatchRosterRequest) (*nexusv1.GetDispatchRosterResponse, error) {
	ep, err := s.endpoints.ResolveBuilderEndpoint(ctx, builder)
	if err != nil {
		if builderclient.IsRetryable(err) || chainclient.IsRetryable(err) {
			// This node could not read the chain: not the Builder's miss.
			return nil, fmt.Errorf("%w: Builder %s descriptor: %w", ErrRosterSourceLocal, builder, err)
		}
		return nil, err // no or an invalid descriptor: the Builder's miss
	}
	if ep.Source != BuilderEndpointSourceDescriptor {
		return nil, fmt.Errorf("Builder %s endpoint came from %s; rosters are read from the on-chain descriptor only", builder, ep.Source)
	}
	return s.client.GetDispatchRoster(ep.PinnedContext(ctx), ep.Endpoint, req)
}

// DispatchRosters is the roster source, or nil when the task-data client
// cannot read rosters.
func (r *Runtime) DispatchRosters() DispatchRosterSource {
	c, ok := r.Dependencies.TaskData.(rosterClient)
	if !ok || r.BuilderEndpoints == nil {
		return nil
	}
	return rosterSource{endpoints: r.BuilderEndpoints, client: c}
}

func newRuntimeDispatchStreams(cfg config.Config, r *Runtime) (*DispatchStreams, error) {
	keys, ok := r.Dependencies.Keeper.(builderServiceKeyReader)
	if !ok {
		return nil, fmt.Errorf("dispatch.builders needs a Keeper client that reads current service keys")
	}
	if r.BuilderEndpoints == nil {
		return nil, fmt.Errorf("dispatch.builders needs the on-chain Builder descriptor resolver")
	}
	var members builderMembership
	if r.builderMembers != nil {
		members = r.builderMembers
	}
	return NewDispatchStreams(DispatchStreamsConfig{
		ChainID: cfg.ChainID, Operator: cfg.LocalIdentity.OperatorAddress,
		Builders: cfg.Dispatch.Builders, Retiring: cfg.Dispatch.RetiringBuilders, Stream: cfg.Dispatch.Stream,
		Endpoints: r.BuilderEndpoints, Members: members, HTTP: builderclient.NewDispatchStreamHTTPClient(),
		Downgrade: cfg.Nexus.DowngradeDescriptorTLS, Keys: keys, Sign: r.DispatchSigner(),
		Height: r.ChainTipHeight, Store: r.Store,
	})
}
