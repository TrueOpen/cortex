package verifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

type recordingResultRelay struct {
	requests []ResultRelayRequest
	err      error
}

func (r *recordingResultRelay) RelayVerifyResult(_ context.Context, req ResultRelayRequest) error {
	r.requests = append(r.requests, req)
	return r.err
}

func countTxKind(requests []txclient.Request, kind txclient.Kind) int {
	n := 0
	for _, request := range requests {
		if request.Kind == kind {
			n++
		}
	}
	return n
}

// A file:// keystore node has no workload tx client, so its only result exit
// is the Builder relay. It used to have none: the reveal refused before
// signing and every selected round ended in a Verifier timeout fault.
func TestRevealRelaysTheResultWithoutADirectSubmitter(t *testing.T) {
	h := newHarness(t)
	relay := &recordingResultRelay{}
	h.verifier.cfg.ResultSubmitter = nil
	h.verifier.cfg.ResultRelay = relay
	state := h.validTask()
	state.OpenVerifyAccepted = true
	verifyLocally(t, h, state)
	reveal := revealLocally(t, h, state)
	if len(relay.requests) != 1 {
		t.Fatalf("relay requests = %d, want the signed result handed to the Builder once", len(relay.requests))
	}
	got := relay.requests[0]
	receipt := publishedResultReceipt(t, h)
	if got.TaskID != state.TaskID || got.SessionID != state.SessionID || got.VerifyRound != state.VerifyRound ||
		len(got.Receipt.ServiceSignature) == 0 || got.Receipt.ExpiryHeight != receipt.ExpiryHeight {
		t.Fatalf("relayed = %+v, want the signed receipt for this round", got)
	}
	if !reveal.Delivery.Relayed || reveal.Delivery.Submitted || reveal.Delivery.ChainAccepted {
		t.Fatalf("delivery = %+v, want a relayed result that claims no chain acceptance", reveal.Delivery)
	}
	if n := countTxKind(h.tx.Requests(), txclient.MsgSubmitVerifyResult); n != 0 {
		t.Fatalf("MsgSubmitVerifyResult self-submissions = %d, want none", n)
	}
}

// A deterministic refusal sends the result to self-submission; a transient
// relay failure is retried without racing the relay; a refusal with no direct
// submitter fails closed.
func TestRevealResultRelayRefusalRouting(t *testing.T) {
	t.Run("refused_self_submits", func(t *testing.T) {
		h := newHarness(t)
		relay := &recordingResultRelay{err: fmt.Errorf("%w: builder said no", ErrResultRelayNotOffered)}
		h.verifier.cfg.ResultSubmitter = testResultSubmitter(h.tx)
		h.verifier.cfg.ResultRelay = relay
		state := h.validTask()
		state.OpenVerifyAccepted = true
		verifyLocally(t, h, state)
		reveal := revealLocally(t, h, state)
		if len(relay.requests) != 1 || !reveal.Delivery.Submitted || reveal.Delivery.Relayed ||
			countTxKind(h.tx.Requests(), txclient.MsgSubmitVerifyResult) != 1 {
			t.Fatalf("relay calls %d, delivery %+v; want one refused relay then one self-submission", len(relay.requests), reveal.Delivery)
		}
	})
	t.Run("transient_does_not_self_submit", func(t *testing.T) {
		h := newHarness(t)
		relay := &recordingResultRelay{err: errors.New("builder unreachable")}
		h.verifier.cfg.ResultSubmitter = testResultSubmitter(h.tx)
		h.verifier.cfg.ResultRelay = relay
		state := h.validTask()
		state.OpenVerifyAccepted = true
		verifyLocally(t, h, state)
		if _, err := h.verifier.HandleRevealPhaseStarted(context.Background(), state); err == nil {
			t.Fatal("a transient relay failure was reported as delivered")
		}
		if n := countTxKind(h.tx.Requests(), txclient.MsgSubmitVerifyResult); n != 0 {
			t.Fatalf("self-submissions = %d, want none while the relay may still carry the result", n)
		}
	})
	t.Run("refused_without_submitter_fails_closed", func(t *testing.T) {
		h := newHarness(t)
		h.verifier.cfg.ResultSubmitter = nil
		h.verifier.cfg.ResultRelay = &recordingResultRelay{err: ErrResultRelayNotOffered}
		state := h.validTask()
		state.OpenVerifyAccepted = true
		verifyLocally(t, h, state)
		if _, err := h.verifier.HandleRevealPhaseStarted(context.Background(), state); !errors.Is(err, ErrResultExitUnavailable) {
			t.Fatalf("error = %v, want ErrResultExitUnavailable", err)
		}
	})
}
