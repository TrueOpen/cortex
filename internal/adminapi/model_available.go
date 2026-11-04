package adminapi

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

// ChainModelReader is the slice of the Keeper client `model available` needs:
// the full model registry and one operator's support rows.
type ChainModelReader interface {
	Models(context.Context) ([]chainclient.CurrentModelSnapshot, error)
	ModelSupport(context.Context, string, string) (chainclient.ModelSupportSnapshot, error)
}

var _ ChainModelReader = (*chainclient.KeeperABCIClient)(nil)

// ListAvailableModels reads every chain model and, when operator is set, joins
// that operator's support row onto each. The daemon calls it with its own
// operator; cortexctl calls it straight against an RPC endpoint.
//
// A model the operator never declared has no row, which reads as unsupported;
// any other read error fails the listing rather than reporting a guess.
func ListAvailableModels(ctx context.Context, operator string, reader ChainModelReader) (ModelAvailableResponse, error) {
	operator = strings.TrimSpace(operator)
	models, err := reader.Models(ctx)
	if err != nil {
		return ModelAvailableResponse{}, fmt.Errorf("list chain models: %w", err)
	}
	rows := make([]ModelAvailableRow, 0, len(models))
	for _, model := range models {
		row := ModelAvailableRow{
			ModelID: model.ModelID, Provider: model.Provider, RepoID: model.RepoID, Status: model.Status,
			LatestProfileVersion: model.LatestProfileVersion.Uint32(), ActiveSupporterCount: model.ActiveSupporterCount,
		}
		if operator != "" {
			var declared, active bool
			support, err := reader.ModelSupport(ctx, operator, model.ModelID)
			switch {
			case err == nil:
				declared, active = support.DeclaredSupport, support.SupportActive
			case !errors.Is(err, chainclient.ErrNotFound):
				return ModelAvailableResponse{}, fmt.Errorf("read model support %s: %w", model.ModelID, err)
			}
			row.Supported, row.SupportActive = &declared, &active
		}
		rows = append(rows, row)
	}
	return ModelAvailableResponse{OperatorAddress: operator, Models: rows}, nil
}

// optionalBool renders a support field that was not asked for as "-".
func optionalBool(value *bool) string {
	if value == nil {
		return "-"
	}
	return fmt.Sprint(*value)
}
