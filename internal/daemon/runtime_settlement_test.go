package daemon

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/txclient"
)

type settlementRuntimeKeeper struct {
	KeeperClient
	state chainclient.SettlementContext
}

func (k settlementRuntimeKeeper) SettlementContext(context.Context, string) (chainclient.SettlementContext, error) {
	return k.state, nil
}

func TestRuntimeSettlementUsesActiveServiceIdentityAndFeeCap(t *testing.T) {
	taskID := strings.Repeat("ab", 32)
	client := txclient.NewFake()
	runtime := &Runtime{
		Dependencies: Dependencies{Keeper: settlementRuntimeKeeper{state: chainclient.SettlementContext{
			TaskID: taskID, SessionID: strings.Repeat("12", 32), Phase: 7,
			ObservedHeight: 100, UpdatedHeight: 90, PermissionlessHeight: 100, DeadlineHeight: 200,
		}}},
		ServiceAddress: "trueopen1service",
		ProtocolTx: NewProtocolTxAdapters(ProtocolTxAdapterConfig{
			Tx: client, ServiceAddress: "trueopen1service", GasPayer: "trueopen1service",
			FeeCap: txclient.Coin{Amount: 25, Denom: "utrueopen"},
		}),
	}
	obs, err := runtime.SettleTask(context.Background(), taskID)
	if err != nil || !obs.Submitted {
		t.Fatalf("observation=%#v error=%v", obs, err)
	}
	requests := client.Requests()
	if len(requests) != 1 {
		t.Fatalf("requests=%d", len(requests))
	}
	var message txclient.SettleTaskMessage
	if err := json.Unmarshal(requests[0].Payload, &message); err != nil {
		t.Fatal(err)
	}
	if message.SubmitterAddress != "trueopen1service" || message.TaskID.Hex() != taskID || requests[0].FeeCap.Amount != 25 {
		t.Fatalf("message=%#v request=%#v", message, requests[0])
	}
	runtime.DeactivateWorkload()
	if _, err := runtime.SettleTask(context.Background(), taskID); err == nil || len(client.Requests()) != 1 {
		t.Fatalf("inactive workload submitted: error=%v requests=%d", err, len(client.Requests()))
	}
}

func TestRuntimeSettlementRefusesUnavailableCosmosSigner(t *testing.T) {
	for _, runtime := range []*Runtime{nil, {}, {ServiceAddress: "trueopen1service"}} {
		if _, err := runtime.SettleTask(context.Background(), strings.Repeat("ab", 32)); err == nil {
			t.Fatal("settlement succeeded without an active Cosmos signer")
		}
	}
}
