package main

import (
	"context"

	"github.com/TrueOpen/cortex/internal/adminapi"
	"github.com/TrueOpen/cortex/internal/daemon"
)

func taskSettlementSubmitter(runtime *daemon.Runtime) func(context.Context, adminapi.TaskSettlementRequest) (adminapi.TaskSettlementResponse, error) {
	return func(ctx context.Context, req adminapi.TaskSettlementRequest) (adminapi.TaskSettlementResponse, error) {
		obs, err := runtime.SettleTask(ctx, req.TaskID)
		response := adminapi.TaskSettlementResponse{
			TaskID: req.TaskID, Submitted: obs.Submitted, Confirmed: obs.Closed,
			Status: string(obs.Tx.Status), TxHash: obs.Tx.TxHash, IncludedHeight: obs.Tx.IncludedHeight,
			Rejected: obs.Tx.Rejected, RejectReason: obs.Tx.RejectReason,
		}
		if err != nil {
			if obs.Tx.TxHash != "" {
				// Return the known transaction with an explicit operation error;
				// the generic HTTP error response would discard its hash/status.
				response.Error = err.Error()
				return response, nil
			}
			return response, err
		}
		if obs.Closed && !obs.Submitted {
			response.Status = "ALREADY_TERMINAL"
		}
		return response, nil
	}
}
