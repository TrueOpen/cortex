package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/TrueOpen/cortex/internal/adminapi"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/daemon"
)

// chainModelReader is the slice of the Keeper client `cortexctl model
// available` needs: the full model registry and one operator's support rows.
type chainModelReader interface {
	Models(context.Context) ([]chainclient.CurrentModelSnapshot, error)
	ModelSupport(context.Context, string, string) (chainclient.ModelSupportSnapshot, error)
}

// The real Keeper must satisfy it, or the type assertion below quietly turns
// the command off.
var _ chainModelReader = (*chainclient.KeeperABCIClient)(nil)

// modelAvailabilityLister wires `cortexctl model available`. Nil outside real
// mode or without a Keeper that can list models: the answer is chain state,
// and a fake Keeper has none worth reporting.
func modelAvailabilityLister(cfg config.Config, rt *daemon.Runtime) func(context.Context, adminapi.ModelAvailableRequest) (adminapi.ModelAvailableResponse, error) {
	if !cfg.UsesRealDependencies() || rt == nil {
		return nil
	}
	reader, ok := rt.Dependencies.Keeper.(chainModelReader)
	if !ok {
		return nil
	}
	return listAvailableModels(cfg.LocalIdentity.OperatorAddress, reader)
}

// listAvailableModels reads every chain model and joins this operator's support
// row onto each. A model the operator never declared has no row, which reads as
// unsupported; any other read error fails the listing rather than reporting a
// guess.
func listAvailableModels(operator string, reader chainModelReader) func(context.Context, adminapi.ModelAvailableRequest) (adminapi.ModelAvailableResponse, error) {
	return func(ctx context.Context, _ adminapi.ModelAvailableRequest) (adminapi.ModelAvailableResponse, error) {
		models, err := reader.Models(ctx)
		if err != nil {
			return adminapi.ModelAvailableResponse{}, fmt.Errorf("list chain models: %w", err)
		}
		rows := make([]adminapi.ModelAvailableRow, 0, len(models))
		for _, model := range models {
			row := adminapi.ModelAvailableRow{
				ModelID: model.ModelID, Provider: model.Provider, RepoID: model.RepoID, Status: model.Status,
				LatestProfileVersion: model.LatestProfileVersion.Uint32(), ActiveSupporterCount: model.ActiveSupporterCount,
			}
			support, err := reader.ModelSupport(ctx, operator, model.ModelID)
			switch {
			case err == nil:
				row.Supported, row.SupportActive = support.DeclaredSupport, support.SupportActive
			case !errors.Is(err, chainclient.ErrNotFound):
				return adminapi.ModelAvailableResponse{}, fmt.Errorf("read model support %s: %w", model.ModelID, err)
			}
			rows = append(rows, row)
		}
		return adminapi.ModelAvailableResponse{OperatorAddress: operator, Models: rows}, nil
	}
}
