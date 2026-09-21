package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/adminapi"
	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/daemon"
	"github.com/SingaXYZ/cortex/internal/txclient"
)

type settlementAPITestKeeper struct{ daemon.KeeperClient }

func (settlementAPITestKeeper) SettlementContext(_ context.Context, taskID string) (chainclient.SettlementContext, error) {
	return chainclient.SettlementContext{TaskID: taskID, SessionID: strings.Repeat("12", 32), Phase: 7,
		ObservedHeight: 100, UpdatedHeight: 90, PermissionlessHeight: 100, DeadlineHeight: 200}, nil
}

type settlementAPITestTx struct{}

func (settlementAPITestTx) Submit(_ context.Context, req txclient.Request) (txclient.Observation, error) {
	return txclient.Observation{TaskID: req.TaskID, Kind: req.Kind, TxHash: "known-settlement-tx", Status: txclient.LifecycleIncluded, IncludedHeight: 101}, errors.New("Keeper query unavailable")
}

func TestSettlementAPIKeepsTransactionOnConfirmationError(t *testing.T) {
	runtime := &daemon.Runtime{
		Dependencies:   daemon.Dependencies{Keeper: settlementAPITestKeeper{}},
		ServiceAddress: "trueopen1service",
		ProtocolTx: daemon.NewProtocolTxAdapters(daemon.ProtocolTxAdapterConfig{
			Tx: settlementAPITestTx{}, ServiceAddress: "trueopen1service", GasPayer: "trueopen1service", FeeCap: txclient.Coin{Amount: 25, Denom: "utrueopen"},
		}),
	}
	dir, err := os.MkdirTemp("/tmp", "settle-api-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "admin.sock")
	server := adminapi.NewServer(socket, adminapi.New(adminapi.ServiceConfig{TaskSettlement: taskSettlementSubmitter(runtime)}))
	if err := server.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	response, err := adminapi.NewClient(socket).TaskSettlement(context.Background(), adminapi.TaskSettlementRequest{TaskID: strings.Repeat("ab", 32)})
	encoded, _ := json.Marshal(response)
	if err != nil || response.Confirmed || response.TxHash != "known-settlement-tx" || response.Status != "INCLUDED" || !strings.Contains(string(encoded), "Keeper query unavailable") {
		t.Fatalf("response=%s error=%v, want the known transaction and confirmation failure", encoded, err)
	}
}
