package verifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TrueOpen/cortex/internal/policy"
	"log/slog"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/observability"
	"github.com/TrueOpen/cortex/internal/tasktrace"
	"github.com/TrueOpen/cortex/internal/txclient"
)

// stubCommitRelay stands in for a Task Builder relay that Cortex does not have
// yet. Its whole job is to return one chosen error so the classifier is driven
// by a relay rather than by a hand-built error value.
type stubCommitRelay struct {
	err      error
	requests []CommitRelayRequest
}

func (s *stubCommitRelay) RelayVerifyCommit(_ context.Context, req CommitRelayRequest) error {
	s.requests = append(s.requests, req)
	return s.err
}

// nexusIngressRefusal is the error a connect client produces from nexus's
// SubmitVerifyCommit: FailedPrecondition wrapping the frozen code. It is spelled
// out here rather than wrapping ErrCommitRelayNotOffered on purpose -- the point
// is that an adapter which passes the transport error through unchanged is still
// classified as the deterministic refusal.
func nexusIngressRefusal() error {
	return fmt.Errorf("failed_precondition: NEXUS_INGRESS_RELAY_NOT_OFFERED: this Builder does not " +
		"relay verify submissions in this round; the Verifier must self-submit " +
		"(see docs/nexus-cortex-contract-migration.md §4-B)")
}

// TestRelayNotOfferedSelfSubmitsTheCommit is the first case AC9 names: the relay
// answers with FailedPrecondition + NEXUS_INGRESS_RELAY_NOT_OFFERED and the
// commit goes on chain anyway, without waiting for the commit deadline.
func TestRelayNotOfferedSelfSubmitsTheCommit(t *testing.T) {
	h := newHarness(t)
	relay := &stubCommitRelay{err: nexusIngressRefusal()}
	h.verifier.cfg.CommitRelay = relay
	state := h.validTask()
	state.OpenVerifyAccepted = true

	result := verifyLocally(t, h, state)

	if len(relay.requests) != 1 {
		t.Fatalf("relay attempts = %d, want the relay asked first", len(relay.requests))
	}
	if relay.requests[0].TaskID != state.TaskID || relay.requests[0].VerifyRound != state.VerifyRound {
		t.Fatalf("relay request = %#v, want the task and round under verification", relay.requests[0])
	}
	// The relay is handed the exact signed body, not a re-derivation of it.
	if relay.requests[0].Commit.CommitHash == nil ||
		string(relay.requests[0].Commit.CommitHash) != string(result.CommitHash[:]) {
		t.Fatalf("relay request carried commit_hash %x, want the signed %x", relay.requests[0].Commit.CommitHash, result.CommitHash[:])
	}
	if result.CommitDelivery.Reason != CommitExitRelayNotOffered || !result.CommitDelivery.SelfSubmitted {
		t.Fatalf("delivery = %#v, want a self-submission triggered by the relay refusal", result.CommitDelivery)
	}
	requests := h.tx.Requests()
	if len(requests) != 1 || requests[0].Kind != txclient.MsgSubmitVerifyCommit {
		t.Fatalf("tx requests = %#v, want one MsgSubmitVerifyCommit", requests)
	}
	// Not waiting for the deadline is the whole difference from the deadline-risk
	// trigger, so the state under test is far from it: the current height is
	// nowhere near commit_deadline_height and the commit still went out.
	if state.CurrentHeight+1 >= state.CommitDeadlineHeight {
		t.Fatalf("fixture height %d is already at the commit deadline %d; this test cannot show the exit fires early", state.CurrentHeight, state.CommitDeadlineHeight)
	}
}

// TestRelayNotOfferedClassificationAcceptsBothSpellings pins the classifier
// itself: a wrapped sentinel and a raw connect error both mean "self-submit",
// and nothing else does.
func TestRelayNotOfferedClassificationAcceptsBothSpellings(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want bool
	}{
		"wrapped sentinel":     {err: fmt.Errorf("relay: %w", ErrCommitRelayNotOffered), want: true},
		"raw connect error":    {err: nexusIngressRefusal(), want: true},
		"nil":                  {err: nil, want: false},
		"transport failure":    {err: errors.New("dial tcp 127.0.0.1:8080: connection refused"), want: false},
		"unrelated refusal":    {err: errors.New("permission_denied: NEXUS_INGRESS_ROLE_SIGNATURE_INVALID"), want: false},
		"unimplemented method": {err: errors.New("unimplemented: SubmitVerifyCommit"), want: false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := CommitRelayNotOffered(tc.err); got != tc.want {
				t.Fatalf("CommitRelayNotOffered(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestRestoredRelayIsNotAlsoSelfSubmitted is AC6. A relay that accepts the
// commit ends the exit: submitting the same commit_key directly as well would
// pay gas for a guaranteed duplicate noop and, worse, would make the node look
// like it distrusts a route the contract put first.
func TestRestoredRelayIsNotAlsoSelfSubmitted(t *testing.T) {
	h := newHarness(t)
	relay := &stubCommitRelay{}
	h.verifier.cfg.CommitRelay = relay
	state := h.validTask()
	state.OpenVerifyAccepted = true

	result := verifyLocally(t, h, state)

	if len(relay.requests) != 1 {
		t.Fatalf("relay attempts = %d, want one", len(relay.requests))
	}
	if !result.CommitDelivery.Relayed || result.CommitDelivery.SelfSubmitted {
		t.Fatalf("delivery = %#v, want relayed and not self-submitted", result.CommitDelivery)
	}
	// Relay acceptance is not chain acceptance (nexus contract §7), so the
	// delivery must not claim the Keeper confirmed anything.
	if result.CommitDelivery.ChainAccepted {
		t.Fatalf("delivery = %#v, want a relay ack NOT reported as chain acceptance", result.CommitDelivery)
	}
	if len(h.tx.Requests()) != 0 {
		t.Fatalf("tx requests = %#v, want none once the relay carried the commit", h.tx.Requests())
	}
}

// TestTransientRelayFailureDoesNotSelfSubmit keeps the trigger deterministic. A
// relay that may still accept this commit must not be raced: two routes writing
// the same commit_key is how a duplicate noop and a wasted fee happen, and the
// task runner retries this responsibility anyway.
func TestTransientRelayFailureDoesNotSelfSubmit(t *testing.T) {
	h := newHarness(t)
	h.verifier.cfg.CommitRelay = &stubCommitRelay{err: errors.New("dial tcp: connection refused")}
	state := h.validTask()
	state.OpenVerifyAccepted = true

	_, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("HandleOpenVerifyAccepted error = %v, want the transient relay failure surfaced", err)
	}
	if len(h.tx.Requests()) != 0 {
		t.Fatalf("tx requests = %#v, want none: a transient relay failure is not the deterministic refusal", h.tx.Requests())
	}
}

// TestDeadlineRiskSelfRescueTriggerIsUnchangedByTheCommitExit is the second case
// AC9 names, at the level this package can state it: the B trigger keeps its own
// margin gate and is untouched by the commit exit. Real mode's refusal of that
// trigger is asserted in internal/config
// (TestRealModeStillRejectsDeadlineRiskSelfRescue), which is where the gate now
// lives.
func TestDeadlineRiskSelfRescueTriggerIsUnchangedByTheCommitExit(t *testing.T) {
	client := txclient.NewFake()
	manager := NewSettlementManager(SettlementConfig{
		Tx: client, VerifierAddress: "verifier-1", SubmitterAddress: "trueopen1service",
		GasPayer: "trueopen1service", FeeCap: txclient.Coin{Amount: 25, Denom: "utrueopen"},
	})
	risk := DeadlineRisk{
		TaskID: testTaskID, Type: CommitDeadlineRisk,
		CurrentHeight: 90, DeadlineHeight: 100, Margin: 2, Message: validCommitMessage(),
	}
	obs, err := manager.HandleDeadlineRisk(context.Background(), risk)
	if err != nil || obs.Submitted || len(client.Requests()) != 0 {
		t.Fatalf("HandleDeadlineRisk far from the deadline = %#v err=%v, want no submission", obs, err)
	}
	// The commit exit reaches the same manager by a different method, and that method
	// has no margin gate at all: this is what "gate on the trigger condition, not on a
	// feature flag" means in code.
	direct, err := manager.SubmitVerifyCommitDirect(context.Background(), DirectCommitInput{
		TaskID: testTaskID, Reason: CommitExitRelayChannelAbsent,
		DeadlineHeight: 100, Message: validCommitMessage(),
	})
	if err != nil {
		t.Fatalf("SubmitVerifyCommitDirect() error = %v", err)
	}
	if !direct.Submitted || !direct.Tx.Accepted || direct.Tx.Kind != txclient.MsgSubmitVerifyCommit {
		t.Fatalf("direct submission = %#v, want an accepted MsgSubmitVerifyCommit", direct)
	}
}

// TestCommitSelfSubmissionRefusesAForeignSignerIdentity is AC3. keeper §10.6
// rule 6 admits exactly one outer Cosmos Tx signer for a self-submitted commit:
// the current Cortex service address of the same verifier_operator_address. The
// operator key and any relayer key are illegal, and the refusal has to name the
// mismatch rather than let the chain reject the transaction after gas is spent.
func TestCommitSelfSubmissionRefusesAForeignSignerIdentity(t *testing.T) {
	const (
		operator = "trueopen1operator"
		service  = "trueopen1service"
		relayer  = "trueopen1relayer"
	)
	for name, tc := range map[string]struct {
		submitter string
		operator  string
		want      string
	}{
		"operator key as submitter": {submitter: operator, operator: operator, want: "submitter_address"},
		"relayer key as submitter":  {submitter: relayer, operator: operator, want: "submitter_address"},
		"empty submitter":           {submitter: "", operator: operator, want: "submitter_address"},
		"another operator's commit": {submitter: service, operator: "trueopen1someoneelse", want: "verifier_operator_address"},
	} {
		t.Run(name, func(t *testing.T) {
			client := txclient.NewFake()
			manager := NewSettlementManager(SettlementConfig{
				Tx: client, VerifierAddress: operator, SubmitterAddress: service,
				GasPayer: service, FeeCap: txclient.Coin{Amount: 25, Denom: "utrueopen"},
			})
			message := validCommitMessage()
			message.SubmitterAddress = tc.submitter
			message.Commit.VerifierOperatorAddress = tc.operator
			_, err := manager.SubmitVerifyCommitDirect(context.Background(), DirectCommitInput{
				TaskID: testTaskID, DeadlineHeight: 100, Message: message,
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("SubmitVerifyCommitDirect() error = %v, want the %s mismatch named", err, tc.want)
			}
			if len(client.Requests()) != 0 {
				t.Fatalf("a transaction was broadcast with an illegal signer identity: %#v", client.Requests())
			}
		})
	}
}

// TestCommitSelfSubmissionRequiresTheCommitDeadline keeps a commit from being
// broadcast with no timeout_height. expiry_height is inside the signed body, so
// a zero here means the body was assembled without the Keeper deadline -- and a
// transaction with no timeout can be included after the commit window shut, at
// this node's expense.
func TestCommitSelfSubmissionRequiresTheCommitDeadline(t *testing.T) {
	client := txclient.NewFake()
	manager := NewSettlementManager(SettlementConfig{
		Tx: client, VerifierAddress: "verifier-1", SubmitterAddress: "trueopen1service",
		GasPayer: "trueopen1service", FeeCap: txclient.Coin{Amount: 25, Denom: "utrueopen"},
	})
	_, err := manager.SubmitVerifyCommitDirect(context.Background(), DirectCommitInput{
		TaskID: testTaskID, Message: validCommitMessage(),
	})
	if err == nil || !strings.Contains(err.Error(), "commit deadline height") {
		t.Fatalf("SubmitVerifyCommitDirect() error = %v, want the missing commit deadline refused", err)
	}
	if len(client.Requests()) != 0 {
		t.Fatalf("a commit was broadcast without a timeout height: %#v", client.Requests())
	}
}

// TestRepeatedVerifyConvergesOnOneCommitPerCommitKey is AC4/FR5.
//
// The verify path is retried by design -- it ends in the frozen result-credential
// gap every time -- so the second run re-derives a commit for the same
// commit_key. §10.6 rule 5 makes that a duplicate noop on chain, which costs gas
// and reports nothing useful, so it must converge locally as a success instead.
//
// The retry is handed a changed beacon id, which would move the sample seed,
// yet it re-delivers the persisted commit: same salt, same commit_hash, no
// second prefill, and the durable delivery record makes it a duplicate noop.
func TestRepeatedVerifyConvergesOnOneCommitPerCommitKey(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true

	first := verifyLocally(t, h, state)
	if !first.CommitDelivery.SelfSubmitted || first.CommitDelivery.Duplicate {
		t.Fatalf("first delivery = %#v, want a fresh self-submission", first.CommitDelivery)
	}

	changed := state
	changed.FutureBeaconID = "proposer-vrf-epoch-13"
	second := verifyLocally(t, h, changed)
	if second.CommitHash != first.CommitHash || second.Salt != first.Salt {
		t.Fatal("the retry re-derived its commit instead of re-delivering the persisted one")
	}
	if h.model.VerifyCalls != 1 {
		t.Fatalf("model verify calls = %d, want the persisted commit reused without a second prefill", h.model.VerifyCalls)
	}
	if !second.CommitDelivery.Duplicate {
		t.Fatalf("second delivery = %#v, want a duplicate noop", second.CommitDelivery)
	}
	if !second.CommitDelivery.ChainAccepted || second.CommitDelivery.TxHash != first.CommitDelivery.TxHash {
		t.Fatalf("second delivery = %#v, want it to converge on the accepted first submission", second.CommitDelivery)
	}
	if requests := h.tx.Requests(); len(requests) != 1 {
		t.Fatalf("tx requests = %d, want exactly one per commit_key: %#v", len(requests), requests)
	}
}

// TestRejectedCommitSelfSubmissionIsReportedAsAFailure is the other side of
// convergence: a commit the chain refused must not be recorded as landed, so the
// responsibility retries while its window is open. The refusal carries the tx
// hash, because "rejected" without one cannot be looked up.
func TestRejectedCommitSelfSubmissionIsReportedAsAFailure(t *testing.T) {
	h := newHarness(t)
	h.tx.RejectNext(txclient.MsgSubmitVerifyCommit, "commit window closed")
	state := h.validTask()
	state.OpenVerifyAccepted = true

	result, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if err == nil || !strings.Contains(err.Error(), "rejected on chain") {
		t.Fatalf("HandleOpenVerifyAccepted error = %v, want the on-chain rejection reported", err)
	}
	if !strings.Contains(err.Error(), "commit window closed") {
		t.Fatalf("error = %v, want the chain's own reason included", err)
	}
	if result.CommitDelivery.ChainAccepted {
		t.Fatalf("delivery = %#v, want a rejected commit not marked accepted", result.CommitDelivery)
	}
	if result.CommitDelivery.TxHash == "" {
		t.Fatalf("delivery = %#v, want the tx hash of the rejected submission", result.CommitDelivery)
	}
	// Nothing was memoised, so the retry inside the commit window submits again.
	h.model.VerifyCalls = 0
	if _, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state); err != nil {
		t.Fatalf("retry error = %v, want the retry to land the commit", err)
	}
	if requests := h.tx.Requests(); len(requests) != 2 {
		t.Fatalf("tx requests = %d, want the rejected commit retried", len(requests))
	}
}

// TestSignedCommitWithNoExitFailsClosed pins the wiring failure. A node whose
// verify path can sign a commit but cannot deliver one is the bug this exit
// closes -- the commit used to become a local evidence file and stop there -- so
// the absence of both routes is refused out loud rather than skipped.
func TestSignedCommitWithNoExitFailsClosed(t *testing.T) {
	h := newHarness(t)
	h.verifier.cfg.CommitSubmitter = nil
	state := h.validTask()
	state.OpenVerifyAccepted = true

	_, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if !errors.Is(err, ErrCommitExitUnavailable) {
		t.Fatalf("HandleOpenVerifyAccepted error = %v, want the missing commit exit refused", err)
	}
	if !strings.Contains(err.Error(), CommitExitRelayChannelAbsent) {
		t.Fatalf("error = %v, want the absent relay channel named as the trigger", err)
	}
}

// TestRelayOnlyNodeReachesTheChainThroughTheRelay is the configuration devnet
// actually runs: a file:// keystore signer cannot assemble a Cosmos transaction
// (signer.LocalSigner.CanSignCosmosTx is false), so the node has no direct
// submitter at all, and nexus#70's Builder relay is its only route. Having both
// is the ideal, having only the relay is legal, and the exit must not refuse the
// second case -- refusing it is what left three selected Verifiers retrying
// until the commit deadline with the relay wired and never asked.
func TestRelayOnlyNodeReachesTheChainThroughTheRelay(t *testing.T) {
	h := newHarness(t)
	relay := &stubCommitRelay{}
	h.verifier.cfg.CommitRelay = relay
	h.verifier.cfg.CommitSubmitter = nil
	state := h.validTask()
	state.OpenVerifyAccepted = true

	result := verifyLocally(t, h, state)

	if len(relay.requests) != 1 {
		t.Fatalf("relay attempts = %d, want the relay asked once", len(relay.requests))
	}
	if !result.CommitDelivery.Relayed || result.CommitDelivery.SelfSubmitted {
		t.Fatalf("delivery = %#v, want relayed by a node that cannot self-submit", result.CommitDelivery)
	}
	// Relay acceptance is a Builder ack, not Keeper confirmation (nexus contract
	// §7). A node with no submitter has even less standing to claim otherwise.
	if result.CommitDelivery.ChainAccepted {
		t.Fatalf("delivery = %#v, want a relay ack NOT reported as chain acceptance", result.CommitDelivery)
	}
	if len(h.tx.Requests()) != 0 {
		t.Fatalf("tx requests = %#v, want none: this node has no direct transaction path", h.tx.Requests())
	}
}

// TestRelayOnlyNodeRefusedByTheRelayFailsClosed is the other half. Dropping the
// pre-signature refusal must not turn "no exit at all" into silence: when the
// only route answers with the deterministic NEXUS_INGRESS_RELAY_NOT_OFFERED, the
// commit is signed and undeliverable, and that is reported with the refusal
// named rather than left as a local evidence file.
func TestRelayOnlyNodeRefusedByTheRelayFailsClosed(t *testing.T) {
	h := newHarness(t)
	h.verifier.cfg.CommitRelay = &stubCommitRelay{err: nexusIngressRefusal()}
	h.verifier.cfg.CommitSubmitter = nil
	state := h.validTask()
	state.OpenVerifyAccepted = true

	_, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if !errors.Is(err, ErrCommitExitUnavailable) {
		t.Fatalf("HandleOpenVerifyAccepted error = %v, want the missing commit exit refused", err)
	}
	if !strings.Contains(err.Error(), CommitExitRelayNotOffered) {
		t.Fatalf("error = %v, want the relay's refusal named as the trigger", err)
	}
}

// TestCommitExitTraceSeparatesBroadcastFromChainAcceptance is AC8. The trace line
// an operator reads has to answer four questions -- which exit, why, which
// transaction, and did the CHAIN accept it -- and must never let a local write or
// an ack stand in for the last one (nexus contract §7).
func TestCommitExitTraceSeparatesBroadcastFromChainAcceptance(t *testing.T) {
	h := newHarness(t)
	var records []observability.LogRecord
	h.verifier.cfg.Trace = &tasktrace.Trace{Emit: func(record observability.LogRecord) { records = append(records, record) }}
	state := h.validTask()
	state.OpenVerifyAccepted = true

	verifyLocally(t, h, state)

	var record observability.LogRecord
	for _, candidate := range records {
		if strings.Contains(candidate.Message, "event=verify_commit_exit") {
			record = candidate
		}
	}
	line := record.Message
	if line == "" {
		t.Fatalf("no verify_commit_exit trace line in %#v", records)
	}
	// A commit that landed is an ordinary milestone. The level matters because
	// an operator filtering for ERROR must see the rounds that lost a commit and
	// only those.
	if record.Level != slog.LevelInfo {
		t.Fatalf("trace level = %v, want INFO for a commit the chain confirmed", record.Level)
	}
	for _, want := range []string{
		`exit="self_submit"`,
		`trigger="` + CommitExitRelayChannelAbsent + `"`,
		"keeper_confirmed=true",
		"duplicate_noop=false",
		`verifier_operator_address="` + fixtureVerifierAddress + `"`,
		`submitter_address="service-1"`,
		fmt.Sprintf("commit_deadline_height=%d", state.CommitDeadlineHeight),
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("trace line %q is missing %q", line, want)
		}
	}
	if !strings.Contains(line, "tx=") {
		t.Fatalf("trace line %q carries no tx hash", line)
	}
	// The words a reader must never find: nothing here may describe the local
	// evidence write or the broadcast as the chain accepting the commit.
	for _, forbidden := range []string{"accepted=true", "relay_accepted"} {
		if strings.Contains(line, forbidden) {
			t.Fatalf("trace line %q describes something weaker than Keeper confirmation as acceptance", line)
		}
	}
}

// A signed commit whose delivery failed is re-delivered byte for byte after a
// restart: the persisted salt and verifier_value_root are reused, nothing is
// re-signed and the model is not asked for a second prefill.
func TestFailedCommitDeliveryIsResentUnchangedAfterRestart(t *testing.T) {
	h := newHarness(t)
	h.tx.RejectNext(txclient.MsgSubmitVerifyCommit, "transient keeper refusal")
	state := h.validTask()
	state.OpenVerifyAccepted = true

	first, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if err == nil {
		t.Fatal("the rejected delivery was reported as landed")
	}
	restarted := New(h.verifier.cfg)
	second, err := restarted.HandleOpenVerifyAccepted(context.Background(), state)
	if err != nil {
		t.Fatalf("retry after restart: %v", err)
	}
	if h.model.VerifyCalls != 1 {
		t.Fatalf("model verify calls = %d, want the persisted commit reused", h.model.VerifyCalls)
	}
	if second.Salt != first.Salt || second.CommitHash != first.CommitHash ||
		second.MetricMaterial.VerifierValueRoot != first.MetricMaterial.VerifierValueRoot {
		t.Fatal("the retry changed the salt, the commit hash or the verifier value root")
	}
	requests := h.tx.Requests()
	if len(requests) != 2 || !bytes.Equal(requests[0].Payload, requests[1].Payload) {
		t.Fatalf("tx requests = %d, want the identical signed commit sent twice", len(requests))
	}
	// Once confirmed, a further restart only reports the durable duplicate.
	third, err := New(h.verifier.cfg).HandleOpenVerifyAccepted(context.Background(), state)
	if err != nil || !third.CommitDelivery.Duplicate || len(h.tx.Requests()) != 2 {
		t.Fatalf("third run = %#v, %v, want a duplicate noop without a new tx", third.CommitDelivery, err)
	}
}

// The commit salt is drawn from the CSPRNG, not derived from task data.
func TestCommitSaltIsRandomAndNonZero(t *testing.T) {
	a, err := randomSalt()
	if err != nil {
		t.Fatal(err)
	}
	b, err := randomSalt()
	if err != nil || a.IsZero() || a == b {
		t.Fatalf("salts %s and %s, %v", a, b, err)
	}
}

func submittedCommit(t *testing.T, payload []byte) txclient.SubmitVerifyCommitMessage {
	t.Helper()
	var message txclient.SubmitVerifyCommitMessage
	if err := json.Unmarshal(payload, &message); err != nil {
		t.Fatal(err)
	}
	return message
}

// A key rotation between persisting the commit and retrying it re-signs the
// same commit_hash under the current service_authorization_nonce; an
// unchanged binding reuses the persisted signature.
func TestPersistedCommitIsResignedAfterANonceChange(t *testing.T) {
	h := newHarness(t)
	h.tx.RejectNext(txclient.MsgSubmitVerifyCommit, "transient keeper refusal")
	state := h.validTask()
	state.OpenVerifyAccepted = true
	first, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state)
	if err == nil {
		t.Fatal("the rejected delivery was reported as landed")
	}
	rotated := h.verifier.cfg
	rotated.ServiceAuthorizationNonce++
	second, err := New(rotated).HandleOpenVerifyAccepted(context.Background(), state)
	if err != nil {
		t.Fatalf("retry after the nonce change: %v", err)
	}
	requests := h.tx.Requests()
	before, after := submittedCommit(t, requests[0].Payload), submittedCommit(t, requests[1].Payload)
	if before.Commit.CommitHash != after.Commit.CommitHash || second.CommitHash != first.CommitHash || second.Salt != first.Salt {
		t.Fatal("the re-signed commit does not carry the persisted commit_hash and salt")
	}
	if uint64(after.Commit.ServiceAuthorizationNonce) != rotated.ServiceAuthorizationNonce || before.Commit.ServiceSignature == after.Commit.ServiceSignature {
		t.Fatalf("retry commit = %+v, want the current nonce and a new signature", after.Commit)
	}
	if h.model.VerifyCalls != 1 {
		t.Fatalf("model verify calls = %d, want no second prefill", h.model.VerifyCalls)
	}
}

// A persisted commit is re-delivered before anything about the task's
// evidence is looked at, so it reaches the chain while Builders are down; a
// failure to record the confirmed delivery does not fail the landed commit.
func TestPersistedCommitIsRedeliveredWithoutEvidence(t *testing.T) {
	h := newHarness(t)
	h.tx.RejectNext(txclient.MsgSubmitVerifyCommit, "transient keeper refusal")
	state := h.validTask()
	state.OpenVerifyAccepted = true
	if _, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state); err == nil {
		t.Fatal("the rejected delivery was reported as landed")
	}
	bare := state
	bare.OutputPackage, bare.ConfirmedOutput, bare.ConfirmedOutputChunkLengths = policy.OutputPackageSummary{}, nil, nil
	h.persistence.failKind = verifierCommitDeliveryEvidenceKind
	result, err := New(h.verifier.cfg).HandleOpenVerifyAccepted(context.Background(), bare)
	if err != nil || !result.CommitDelivery.ChainAccepted {
		t.Fatalf("re-delivery without evidence = %+v, %v", result.CommitDelivery, err)
	}
	if h.model.VerifyCalls != 1 {
		t.Fatal("the re-delivery asked the model again")
	}
}

// A record written before the signed commit was persisted is named as such.
func TestPersistedRecordWithoutCommitWireAsksToClearIt(t *testing.T) {
	h := newHarness(t)
	state := h.validTask()
	state.OpenVerifyAccepted = true
	verifyLocally(t, h, state)
	for i := range h.persistence.evidence {
		if h.persistence.evidence[i].Kind != verifierFullResultRevealEvidenceKind {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal(h.persistence.evidence[i].Data, &record); err != nil {
			t.Fatal(err)
		}
		delete(record, "commit_wire")
		h.persistence.evidence[i].Data, _ = json.Marshal(record)
	}
	_, err := New(h.verifier.cfg).HandleOpenVerifyAccepted(context.Background(), state)
	if err == nil || !strings.Contains(err.Error(), "clear this task's local verifier record") {
		t.Fatalf("err = %v, want the explicit clear-the-record refusal", err)
	}
}
