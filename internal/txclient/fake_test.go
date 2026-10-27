package txclient_test

import (
	"context"
	"testing"

	"github.com/TrueOpen/cortex/internal/txclient"
	"github.com/TrueOpen/cortex/internal/txclient/txclienttest"
)

func TestFakeRecordsAcceptedAndRejectedSelfRescueSettlementAndProofTxs(t *testing.T) {
	ctx := context.Background()
	fake := txclienttest.NewFake()
	kinds := []txclient.Kind{
		txclient.MsgSubmitInferReceipt,
		txclient.MsgSubmitVerifyCommit,
		txclient.MsgSubmitVerifyResult,
		txclient.MsgSettleTask,
		txclient.MsgSweepDeadline,
		txclient.MsgDeclareModelSupport,
		txclient.MsgBatchConfirmModelSupport,
	}

	for _, kind := range kinds {
		obs, err := fake.Submit(ctx, txclient.Request{
			TaskID:  "task-1",
			Kind:    kind,
			Payload: txclient.ValidPayload(t, kind),
		})
		if err != nil {
			t.Fatalf("submit %s: %v", kind, err)
		}
		if !obs.Accepted || obs.Kind != kind || obs.TxHash == "" {
			t.Fatalf("accepted observation for %s = %#v", kind, obs)
		}
	}

	fake.RejectNext(txclient.MsgSubmitVerifyCommit, "deadline expired")
	rejected, err := fake.Submit(ctx, txclient.Request{
		TaskID:  "task-1",
		Kind:    txclient.MsgSubmitVerifyCommit,
		Payload: txclient.ValidPayload(t, txclient.MsgSubmitVerifyCommit),
	})
	if err != nil {
		t.Fatalf("submit rejected observation: %v", err)
	}
	if rejected.Accepted || rejected.RejectReason != "deadline expired" {
		t.Fatalf("rejected observation = %#v", rejected)
	}
	if got := fake.Accepted(txclient.MsgSubmitVerifyCommit); len(got) != 1 {
		t.Fatalf("accepted commits = %d, want only first accepted commit", len(got))
	}
	if got := fake.Rejected(txclient.MsgSubmitVerifyCommit); len(got) != 1 {
		t.Fatalf("rejected commits = %d, want 1", len(got))
	}
}

func TestFakeRejectsUnknownTxKind(t *testing.T) {
	fake := txclienttest.NewFake()
	if _, err := fake.Submit(context.Background(), txclient.Request{
		TaskID:  "task-1",
		Kind:    txclient.Kind("MsgUnknownTx"),
		Payload: []byte("payload"),
	}); err == nil {
		t.Fatalf("unknown tx kind accepted")
	}
}
