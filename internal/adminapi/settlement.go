package adminapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
)

type TaskSettlementRequest struct {
	TaskID string `json:"task_id"`
}

type TaskSettlementResponse struct {
	TaskID         string `json:"task_id"`
	Submitted      bool   `json:"submitted"`
	Confirmed      bool   `json:"confirmed"`
	Status         string `json:"status"`
	TxHash         string `json:"tx_hash,omitempty"`
	IncludedHeight uint64 `json:"included_height,omitempty"`
	Rejected       bool   `json:"rejected"`
	RejectReason   string `json:"reject_reason,omitempty"`
	Error          string `json:"error,omitempty"`
}

func (s *Service) TaskSettlement(ctx context.Context, req TaskSettlementRequest) (TaskSettlementResponse, error) {
	if s.taskSettlement == nil {
		return TaskSettlementResponse{}, fmt.Errorf("task settlement is unavailable")
	}
	decoded, err := hex.DecodeString(req.TaskID)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != req.TaskID || bytes.Equal(decoded, make([]byte, 32)) {
		return TaskSettlementResponse{}, fmt.Errorf("task_id must be canonical non-zero Hash32 hex")
	}
	return s.taskSettlement(ctx, req)
}

func (s *Server) handleTaskSettlement(w http.ResponseWriter, r *http.Request) {
	var req TaskSettlementRequest
	s.handle(w, r, &req, func(ctx context.Context) (any, error) {
		return s.service.TaskSettlement(ctx, req)
	})
}

func (c *Client) TaskSettlement(ctx context.Context, req TaskSettlementRequest) (TaskSettlementResponse, error) {
	var out TaskSettlementResponse
	err := c.post(ctx, "/v1/task/settle", req, &out)
	return out, err
}
