package adminapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestTaskSettlementValidatesTaskIDBeforeCallingRuntime(t *testing.T) {
	calls := 0
	service := New(ServiceConfig{TaskSettlement: func(_ context.Context, req TaskSettlementRequest) (TaskSettlementResponse, error) {
		calls++
		return TaskSettlementResponse{TaskID: req.TaskID}, nil
	}})
	for _, taskID := range []string{"", "task-1", strings.Repeat("00", 32), strings.Repeat("AB", 32), " " + strings.Repeat("ab", 32)} {
		if _, err := service.TaskSettlement(context.Background(), TaskSettlementRequest{TaskID: taskID}); err == nil {
			t.Errorf("accepted non-canonical task ID %q", taskID)
		}
	}
	if calls != 0 {
		t.Fatalf("runtime calls=%d for invalid requests", calls)
	}
	if _, err := New(ServiceConfig{}).TaskSettlement(context.Background(), TaskSettlementRequest{TaskID: strings.Repeat("ab", 32)}); err == nil {
		t.Fatal("unavailable settlement handler was accepted")
	}
}

func TestTaskSettlementUnixSocketRoundTrip(t *testing.T) {
	taskID := strings.Repeat("ab", 32)
	socket := filepath.Join(shortTempDir(t), "cortex.sock")
	server := NewServer(socket, New(ServiceConfig{TaskSettlement: func(_ context.Context, req TaskSettlementRequest) (TaskSettlementResponse, error) {
		return TaskSettlementResponse{TaskID: req.TaskID, Submitted: true, Confirmed: true, Status: "KEEPER_CONFIRMED", TxHash: "tx-1", IncludedHeight: 100}, nil
	}}))
	if err := server.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	response, err := NewClient(socket).TaskSettlement(context.Background(), TaskSettlementRequest{TaskID: taskID})
	if err != nil || response.TaskID != taskID || !response.Confirmed || response.TxHash != "tx-1" || response.IncludedHeight != 100 {
		t.Fatalf("response=%#v error=%v", response, err)
	}
	formatted, err := FormatResponse(response, FormatTable)
	if err != nil || !strings.Contains(formatted, "KEEPER_CONFIRMED") || !strings.Contains(formatted, "tx-1") {
		t.Fatalf("table=%q error=%v", formatted, err)
	}
}
