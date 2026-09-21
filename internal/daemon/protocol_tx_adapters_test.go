package daemon

import (
	"context"
	"testing"

	"github.com/SingaXYZ/cortex/internal/txclient"
	"github.com/SingaXYZ/cortex/internal/verifier"
)

func TestProtocolTxAdaptersInjectSettlementTxAndFeePolicy(t *testing.T) {
	tx := txclient.NewFake()
	adapters := NewProtocolTxAdapters(ProtocolTxAdapterConfig{
		Tx: tx, ServiceAddress: "trueopen1service", GasPayer: "trueopen1service", FeeCap: txclient.Coin{Amount: 25, Denom: "utrueopen"},
	})
	manager := adapters.Settlement(verifier.SettlementConfig{})

	obs, err := manager.HandleVerifyDeadline(context.Background(), verifier.VerifyDeadlineInput{
		SessionID: "session-1", TaskID: "1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b",
		CurrentHeight: 100, DeadlineHeight: 100, SweepKind: "INFER_DEADLINE",
	})
	if err != nil {
		t.Fatalf("HandleVerifyDeadline() error = %v", err)
	}
	requests := tx.Requests()
	if !obs.Submitted || len(requests) != 1 || requests[0].Kind != txclient.MsgSweepDeadline || requests[0].GasPayer != "trueopen1service" || requests[0].FeeCap.Denom != "utrueopen" {
		t.Fatalf("observation = %#v requests = %#v, want runtime-injected settlement tx policy", obs, requests)
	}
}
