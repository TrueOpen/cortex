package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/adminapi"
)

func TestTaskSettleCommandReportsKeeperConfirmation(t *testing.T) {
	t.Setenv("CORTEX_ADMIN_SOCKET", startTestAdminServer(t))
	var output bytes.Buffer
	taskID := strings.Repeat("ab", 32)
	if err := run([]string{"task", "settle", taskID, "--format", "json"}, &output); err != nil {
		t.Fatal(err)
	}
	var response adminapi.TaskSettlementResponse
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.TaskID != taskID || !response.Confirmed || response.TxHash != "settlement-tx" || response.IncludedHeight != 100 {
		t.Fatalf("response=%#v", response)
	}
}

func TestTaskSettleCommandKeepsUnconfirmedTransactionVisible(t *testing.T) {
	t.Setenv("CORTEX_ADMIN_SOCKET", startTestAdminServer(t))
	var output bytes.Buffer
	err := run([]string{"task", "settle", strings.Repeat("cd", 32), "--format", "json"}, &output)
	if err == nil || !strings.Contains(output.String(), "settlement-pending") || !strings.Contains(output.String(), "Keeper confirmation unavailable") || !strings.Contains(err.Error(), "confirmation") {
		t.Fatalf("output=%q error=%v, want the transaction reference and non-success status", output.String(), err)
	}
}

func TestTaskSettleCommandRejectsFormatBeforeCallingAPI(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "settle-cli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "admin.sock")
	calls := 0
	server := adminapi.NewServer(socket, adminapi.New(adminapi.ServiceConfig{
		TaskSettlement: func(context.Context, adminapi.TaskSettlementRequest) (adminapi.TaskSettlementResponse, error) {
			calls++
			return adminapi.TaskSettlementResponse{Confirmed: true}, nil
		},
	}))
	if err := server.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	t.Setenv("CORTEX_ADMIN_SOCKET", socket)
	var output bytes.Buffer
	err = run([]string{"task", "settle", strings.Repeat("ab", 32), "--format", "yaml"}, &output)
	if err == nil || !strings.Contains(err.Error(), "format") || calls != 0 {
		t.Fatalf("error=%v calls=%d, want format validation before mutation", err, calls)
	}
}
