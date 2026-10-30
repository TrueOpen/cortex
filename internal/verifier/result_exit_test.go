package verifier

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/TrueOpen/cortex/internal/txclient"
)

func testResultSubmitter(tx txclient.Client) ResultSubmitter {
	return NewSettlementManager(SettlementConfig{
		Tx: tx, VerifierAddress: fixtureVerifierAddress, SubmitterAddress: "service-1", GasPayer: "service-1",
		FeeCap: txclient.Coin{Amount: 25, Denom: "utrueopen"},
	})
}

// The signed result used to stop at evidence finalization (S0 removed the bus
// VERIFY_RESULT). It is now self-submitted once, bounded by the reveal deadline.
func TestRevealSelfSubmitsTheResultOnce(t *testing.T) {
	h := newHarness(t)
	h.verifier.cfg.ResultSubmitter = testResultSubmitter(h.tx)
	state := h.validTask()
	state.OpenVerifyAccepted = true
	verifyLocally(t, h, state)
	reveal := revealLocally(t, h, state)
	requests := h.tx.Requests()
	if len(requests) != 2 || requests[1].Kind != txclient.MsgSubmitVerifyResult || requests[1].DeadlineHeight != state.RevealDeadlineHeight {
		t.Fatalf("tx requests = %#v, want the commit then one MsgSubmitVerifyResult bounded by the reveal deadline", requests)
	}
	var submitted txclient.SubmitVerifyResultMessage
	if err := json.Unmarshal(requests[1].Payload, &submitted); err != nil {
		t.Fatal(err)
	}
	receipt := publishedResultReceipt(t, h)
	if uint64(submitted.Receipt.ExpiryHeight) != receipt.ExpiryHeight || submitted.SubmitterAddress != "service-1" ||
		submitted.Receipt.MetricRoot.Hex() != reveal.MetricMaterial.Root.String() {
		t.Fatalf("submitted body = %+v, want the signed receipt from the service address", submitted)
	}
	if !reveal.Delivery.Submitted || !reveal.Delivery.ChainAccepted || reveal.Delivery.Duplicate {
		t.Fatalf("delivery = %+v, want one chain-accepted submission", reveal.Delivery)
	}
	again, err := New(h.verifier.cfg).HandleRevealPhaseStarted(context.Background(), state)
	if err != nil || !again.Delivery.Duplicate || len(h.tx.Requests()) != 2 {
		t.Fatalf("second reveal = %+v, %v; want a durable duplicate with no new tx", again.Delivery, err)
	}
}

// A result the chain rejects is an error, and is not recorded as delivered.
func TestRevealReportsARejectedResult(t *testing.T) {
	h := newHarness(t)
	h.verifier.cfg.ResultSubmitter = testResultSubmitter(h.tx)
	state := h.validTask()
	state.OpenVerifyAccepted = true
	verifyLocally(t, h, state)
	h.tx.RejectNext(txclient.MsgSubmitVerifyResult, "reveal window closed")
	if _, err := h.verifier.HandleRevealPhaseStarted(context.Background(), state); err == nil {
		t.Fatal("a rejected result was reported as delivered")
	}
	again := revealLocally(t, h, state)
	if again.Delivery.Duplicate || !again.Delivery.ChainAccepted {
		t.Fatalf("retry delivery = %+v, want a fresh accepted submission", again.Delivery)
	}
}

func TestRealModeRevealRefusesWithoutAResultExit(t *testing.T) {
	h := newHarness(t)
	state := confirmedTask(t, h)
	if _, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	h.verifier.cfg.ResultSubmitter = nil
	_, err := h.verifier.HandleRevealPhaseStarted(context.Background(), state)
	if !errors.Is(err, ErrResultExitUnavailable) || len(*h.finalized) != 0 {
		t.Fatalf("error = %v, finalized %d; want a refusal before anything is signed", err, len(*h.finalized))
	}
}
