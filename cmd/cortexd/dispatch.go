package main

import (
	"context"
	"fmt"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/daemon"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/observability"
	"github.com/TrueOpen/cortex/internal/txclient"
)

// wireDispatchRunnerConfig points the TaskRunner at the runtime's Builder
// streams: the Verifier FrameSender and NoticeSender are the fan-out over
// the active streams (S7), and the dispatch effects and lease release go
// through a link the plane binds before any runner starts (S5, S6, S8).
func wireDispatchRunnerConfig(cfg *daemon.TaskRunnerConfig, rt *daemon.Runtime) *daemon.DispatchLink {
	if rt == nil || rt.Dispatch == nil {
		return nil
	}
	link := daemon.NewDispatchLink()
	cfg.VerifierSender, cfg.VerifyNotices = rt.Dispatch.Fanout(), rt.Dispatch.Fanout()
	cfg.DispatchRecords, cfg.DispatchEvents, cfg.ReleaseDispatchLease = link, link, link.ReleaseTaskLease
	cfg.TaskBuilders = rt.SelectedTaskBuilders
	if r, ok := rt.Dependencies.Keeper.(chainclient.VerifyCommitReader); ok {
		cfg.VerifyCommitReader = r
	}
	return link
}

func newDispatchPlane(cfg config.Config, rt *daemon.Runtime, runner *daemon.TaskRunner, ev *evidence.Store) (*daemon.DispatchPlane, error) {
	chain, ok := rt.Dependencies.Keeper.(daemon.DispatchPlaneChain)
	if !ok {
		return nil, fmt.Errorf("dispatch.builders needs a Keeper client that serves the Phase 1 dispatch reads")
	}
	profiles, err := cfg.LocalIdentity.ModelProfiles()
	if err != nil {
		return nil, err
	}
	// Without tx.enabled the node has no direct transaction path: claims,
	// receipt rescues and omission challenges are not submitted (config
	// accepts a real-mode node without one).
	var submitter func() (txclient.Client, string)
	if cfg.Tx.Enabled {
		submitter = rt.WorkloadSubmitter
	}
	return daemon.NewDispatchPlane(context.Background(), daemon.DispatchPlaneConfig{
		Streams: rt.Dispatch, Runner: runner, Evidence: ev, Store: rt.Store,
		ChainID: cfg.ChainID, Operator: cfg.LocalIdentity.OperatorAddress, FeeDenom: cfg.Tx.FeeDenom,
		Profiles: profiles, Dispatch: cfg.Dispatch, Capacity: cfg.ModelManagement.MaxConcurrency,
		Local: rt.HandraiseLocal(), Sign: rt.DispatchSigner(), Submitter: submitter,
		HandraiseChain: chain, DispatchChain: chain, VerifierChain: chain, OmissionChain: chain,
		Rosters: rt.DispatchRosters(),
	})
}

// registerDispatchHealth adds the stream rows before any readiness lands:
// per-Builder rows optional, the aggregate row gating /readyz (S9 Q4).
func registerDispatchHealth(health *observability.Health, rt *daemon.Runtime) {
	if health == nil || rt == nil || rt.Dispatch == nil {
		return
	}
	for _, s := range rt.Dispatch.Statuses() {
		health.RegisterDependency(s.Name, s.Name == daemon.DependencyDispatchStreams)
	}
}
