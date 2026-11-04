package main

import (
	"context"

	"github.com/TrueOpen/cortex/internal/adminapi"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/daemon"
)

// modelAvailabilityLister wires `cortexctl model available` to this node's
// Keeper and operator. Nil outside real mode or without a Keeper that can list
// models: the answer is chain state, and a fake Keeper has none worth reporting.
func modelAvailabilityLister(cfg config.Config, rt *daemon.Runtime) func(context.Context, adminapi.ModelAvailableRequest) (adminapi.ModelAvailableResponse, error) {
	if !cfg.UsesRealDependencies() || rt == nil {
		return nil
	}
	reader, ok := rt.Dependencies.Keeper.(adminapi.ChainModelReader)
	if !ok {
		return nil
	}
	operator := cfg.LocalIdentity.OperatorAddress
	return func(ctx context.Context, _ adminapi.ModelAvailableRequest) (adminapi.ModelAvailableResponse, error) {
		return adminapi.ListAvailableModels(ctx, operator, reader)
	}
}
