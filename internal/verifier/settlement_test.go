package verifier

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/txclient"
)

func TestDeadlineRisksSubmitCanonicalSelfRescueMessages(t *testing.T) {
	ctx := context.Background()
	client := txclient.NewFake()
	manager := NewSettlementManager(SettlementConfig{Tx: client, VerifierAddress: "verifier-1", WorkerAddress: "worker-1", SubmitterAddress: "trueopen1service", GasPayer: "trueopen1service", FeeCap: txclient.Coin{Amount: 25, Denom: "utrueopen"}})
	tests := []struct {
		name string
		risk DeadlineRisk
		kind txclient.Kind
	}{
		{"commit", DeadlineRisk{TaskID: testTaskID, Type: CommitDeadlineRisk, CurrentHeight: 98, DeadlineHeight: 100, Margin: 2, Message: validCommitMessage()}, txclient.MsgSubmitVerifyCommit},
		{"result", DeadlineRisk{TaskID: testTaskID, Type: ResultRevealDeadlineRisk, CurrentHeight: 298, DeadlineHeight: 300, Margin: 2, Message: validResultMessage()}, txclient.MsgSubmitVerifyResult},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := len(client.Requests())
			obs, err := manager.HandleDeadlineRisk(ctx, tt.risk)
			if err != nil {
				t.Fatalf("HandleDeadlineRisk() error = %v", err)
			}
			if !obs.Submitted || !obs.Tx.Accepted || obs.Tx.Kind != tt.kind {
				t.Fatalf("observation = %#v, want accepted %s", obs, tt.kind)
			}
			req := client.Requests()[before]
			if len(req.Payload) == 0 || req.Payload[0] != '{' {
				t.Fatalf("payload = %q, want typed JSON message", req.Payload)
			}
			if req.DeadlineHeight != tt.risk.DeadlineHeight || req.MaterialDigest == (codec.Hash{}) {
				t.Fatalf("request = %#v, want deadline and material digest", req)
			}
			if req.GasPayer != "trueopen1service" || req.FeeCap.Denom != "utrueopen" {
				t.Fatalf("fee defaults = %#v", req)
			}
		})
	}
}

// TestFullResultAvailabilityRiskHasNoSelfRescueMessage pins the removal of
// MsgSubmitFullResultReveal. Cortex used to map a full-result availability risk onto
// that Msg, but keeper-interface-contract.md §10.9a removed it and reserved msg number 18 as
// "must not be reused", so the mapping described a chain route that no longer
// exists. The risk label is passed as a raw string precisely because the constant is
// gone: an unmapped risk must fail closed with the unsupported-risk reason and must
// not reach the tx client.
func TestFullResultAvailabilityRiskHasNoSelfRescueMessage(t *testing.T) {
	if kind, ok := deadlineRiskTxKind(DeadlineRiskType("full_result_availability")); ok {
		t.Fatalf("deadlineRiskTxKind(full_result_availability) = %s, want no frozen Msg", kind)
	}
	client := txclient.NewFake()
	manager := NewSettlementManager(SettlementConfig{Tx: client, VerifierAddress: "verifier-1", SubmitterAddress: "trueopen1service"})
	obs, err := manager.HandleDeadlineRisk(context.Background(), DeadlineRisk{
		TaskID: testTaskID, Type: DeadlineRiskType("full_result_availability"),
		CurrentHeight: 398, DeadlineHeight: 400, Margin: 2,
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported deadline risk") {
		t.Fatalf("HandleDeadlineRisk() error = %v, want an unsupported deadline risk refusal", err)
	}
	if obs.Submitted || len(client.Requests()) != 0 {
		t.Fatalf("observation = %#v with %d requests, want nothing submitted", obs, len(client.Requests()))
	}
}

// TestWorkerRevealDeadlineRiskFailsClosed pins that the worker reveal self-rescue
// never reaches a transaction: the frozen contract registers no worker reveal Msg
// and its replacement carrier needs the locked Profile's
// evidence_schema.required_infer_evidence, which hub.v1.Query/Profile serves
// and Cortex does not read. Plaintext material must still be refused first, so a
// caller that mistakenly attaches W_i learns that before the contract reason.
func TestWorkerRevealDeadlineRiskFailsClosed(t *testing.T) {
	client := txclient.NewFake()
	manager := NewSettlementManager(SettlementConfig{Tx: client, WorkerAddress: "worker-1", SubmitterAddress: "trueopen1service"})
	reveal := testReceiptOnlyWorkerReveal()
	reveal.FullResultPlaintext = []byte("W_i: plaintext")
	_, err := manager.HandleDeadlineRisk(context.Background(), DeadlineRisk{TaskID: testTaskID, Type: WorkerRevealDeadlineRisk, CurrentHeight: 198, DeadlineHeight: 200, Margin: 2, WorkerReveal: reveal})
	if err == nil || !strings.Contains(err.Error(), "must not include full result plaintext") {
		t.Fatalf("worker reveal self-rescue error = %v, want plaintext rejection", err)
	}
	_, err = manager.HandleDeadlineRisk(context.Background(), DeadlineRisk{TaskID: testTaskID, Type: WorkerRevealDeadlineRisk, CurrentHeight: 198, DeadlineHeight: 200, Margin: 2, WorkerReveal: testReceiptOnlyWorkerReveal()})
	if err == nil || !strings.Contains(err.Error(), "registers no worker reveal Msg") {
		t.Fatalf("worker reveal self-rescue error = %v, want the frozen worker reveal de-registration reason", err)
	}
	if len(client.Requests()) != 0 {
		t.Fatalf("tx submitted for a Msg the frozen contract does not register: %#v", client.Requests())
	}
}

func TestNonUrgentDeadlineRiskDoesNotSubmit(t *testing.T) {
	client := txclient.NewFake()
	manager := NewSettlementManager(SettlementConfig{Tx: client})
	obs, err := manager.HandleDeadlineRisk(context.Background(), DeadlineRisk{TaskID: "task-1", Type: CommitDeadlineRisk, CurrentHeight: 90, DeadlineHeight: 100, Margin: 2})
	if err != nil || obs.Submitted || len(client.Requests()) != 0 {
		t.Fatalf("non-urgent risk = %#v err=%v", obs, err)
	}
}

func TestSettlementEnvelopeUsesExactTypedMessageAndExcludesPlaintext(t *testing.T) {
	message, root := testSettleMessage()
	input := SettlementInput{Message: message, LocalRoot: root, OpeningsValid: true, PlaintextValues: [][]byte{[]byte("V_i"), []byte("W_i")}}
	if _, err := BuildSettlementEnvelope(input); err == nil {
		t.Fatal("BuildSettlementEnvelope accepted plaintext")
	}
	input.PlaintextValues = nil
	first, err := BuildSettlementEnvelope(input)
	if err != nil {
		t.Fatalf("BuildSettlementEnvelope() error = %v", err)
	}
	second, err := BuildSettlementEnvelope(input)
	if err != nil {
		t.Fatalf("BuildSettlementEnvelope() second error = %v", err)
	}
	if first.EvidenceRoot != root || first.EvidenceRoot != second.EvidenceRoot || !bytes.Equal(first.Payload, second.Payload) {
		t.Fatal("settlement envelope is not deterministic")
	}
	// MsgSettleTask asserts nothing the Keeper derives. Every fact the old giant
	// MsgSettle carried must now be impossible to put on the wire.
	for _, derived := range []string{
		"settlement_id", "task_evidence_root", "root_manifest_hash", "settler_signature",
		"task_verdict", "settlement_status", "worker_payout", "refund_amount", "payout_hash",
		"builder_address", "builder_rank", "session_id",
	} {
		if bytes.Contains(first.Payload, []byte(`"`+derived+`"`)) {
			t.Fatalf("payload claims Keeper-derived field %q: %s", derived, first.Payload)
		}
	}
	for _, required := range []string{"task_id", "submitter_address"} {
		if !bytes.Contains(first.Payload, []byte(`"`+required+`"`)) {
			t.Fatalf("payload missing %s: %s", required, first.Payload)
		}
	}
}

func TestStage3BuilderFailureFailsClosedWithoutAuthoritativeKeeperState(t *testing.T) {
	client := txclient.NewFake()
	manager := NewSettlementManager(SettlementConfig{Tx: client, SubmitterAddress: "settler-1", GasPayer: "cortex1operator", FeeCap: txclient.Coin{Amount: 25, Denom: "utrueopen"}})
	message, root := testSettleMessage()
	input := SettlementInput{Message: message, LocalRoot: root, OpeningsValid: true}
	obs, err := manager.HandleStage3BuilderFailure(context.Background(), input)
	if err == nil || !strings.Contains(err.Error(), "authoritative Keeper") {
		t.Fatalf("HandleStage3BuilderFailure() error = %v, want authoritative Keeper state rejection", err)
	}
	if obs.Submitted || len(client.Requests()) != 0 {
		t.Fatalf("observation = %#v requests=%d, want no SettleTx", obs, len(client.Requests()))
	}
}

// TestVerifyDeadlineSweepMapsOntoFrozenDeadlineKind pins the MsgSweepDeadline
// reshape. The frozen TaskDeadlineLocator carries neither a verify round nor a
// deadline height, so the upstream sweep handler routes only WORKER_INFER and
// WORKER_ASSIGNMENT and refuses every verify and finality kind: Cortex must fail
// closed on those instead of paying gas for a guaranteed rejection.
func TestVerifyDeadlineSweepMapsOntoFrozenDeadlineKind(t *testing.T) {
	client := txclient.NewFake()
	manager := NewSettlementManager(SettlementConfig{Tx: client, SubmitterAddress: "settler-1", GasPayer: "cortex1operator", FeeCap: txclient.Coin{Amount: 25, Denom: "utrueopen"}})
	input := VerifyDeadlineInput{SessionID: "session-1", TaskID: testTaskID, CurrentHeight: 500, DeadlineHeight: 500, SweepKind: "INFER_DEADLINE", ChainVerdict: "worker_failed", FailureClass: "missing_settlement"}
	obs, err := manager.HandleVerifyDeadline(context.Background(), input)
	if err != nil {
		t.Fatalf("HandleVerifyDeadline() error = %v", err)
	}
	if !obs.Submitted || !obs.Closed || obs.Tx.Kind != txclient.MsgSweepDeadline {
		t.Fatalf("observation = %#v", obs)
	}
	payload := string(client.Requests()[0].Payload)
	if strings.Contains(payload, "chain_verdict") || strings.Contains(payload, "failure_class") ||
		strings.Contains(payload, "session_id") || strings.Contains(payload, "INFER_DEADLINE") {
		t.Fatalf("sweep payload leaks local state: %s", payload)
	}
	if !strings.Contains(payload, `"deadline_kind":"DEADLINE_KIND_V1_WORKER_INFER"`) {
		t.Fatalf("sweep payload = %s, want the frozen WORKER_INFER deadline kind", payload)
	}

	for kind, want := range map[string]string{
		"VERIFY_DEADLINE":            "cannot be targeted from the frozen V1 TaskDeadlineLocator",
		"COMMIT_DEADLINE":            "cannot be targeted from the frozen V1 TaskDeadlineLocator",
		"REVEAL_DEADLINE":            "cannot be targeted from the frozen V1 TaskDeadlineLocator",
		"VERIFY_OPEN_DEADLINE":       "cannot be targeted from the frozen V1 TaskDeadlineLocator",
		"WORKER_REVEAL_DEADLINE":     "no frozen DeadlineKindV1 value",
		"CHALLENGE_CLOSE":            "K-BLOCK-03/04 gated",
		"CHALLENGE_RESOLVE_DEADLINE": "K-BLOCK-03/04 gated",
		"EVIDENCE_REQUEST_DEADLINE":  "K-BLOCK-03/04 gated",
		"SOMETHING_ELSE":             "unsupported local sweep kind",
	} {
		before := len(client.Requests())
		blocked := input
		blocked.SweepKind = kind
		if _, err := manager.HandleVerifyDeadline(context.Background(), blocked); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("HandleVerifyDeadline(%s) error = %v, want %q", kind, err, want)
		}
		if len(client.Requests()) != before {
			t.Fatalf("HandleVerifyDeadline(%s) submitted a transaction", kind)
		}
	}
}

func TestFirstLegalWorkerRevealSetsReimbursementOnlyOnce(t *testing.T) {
	state := WorkerRevealReimbursementState{TaskID: "task-1", TaskReserve: 1000}
	first := state.Observe(WorkerRevealObservation{TaskID: "task-1", Legal: true, Height: 10, DeadlineHeight: 20, TxHash: "tx-1"})
	if !first.ReimbursementExpected || first.Amount != 1000 {
		t.Fatalf("first = %#v", first)
	}
	if state.Observe(WorkerRevealObservation{TaskID: "task-1", Legal: true, Height: 11, DeadlineHeight: 20, TxHash: "tx-1"}).ReimbursementExpected {
		t.Fatal("duplicate reimbursed")
	}
	if state.Observe(WorkerRevealObservation{TaskID: "task-1", Legal: false, Height: 12, DeadlineHeight: 20, TxHash: "tx-2"}).ReimbursementExpected {
		t.Fatal("invalid reimbursed")
	}
	late := WorkerRevealReimbursementState{TaskID: "task-2", TaskReserve: 500}
	if late.Observe(WorkerRevealObservation{TaskID: "task-2", Legal: true, Height: 21, DeadlineHeight: 20, TxHash: "tx-3"}).ReimbursementExpected {
		t.Fatal("late reveal reimbursed")
	}
}

const testTaskID = "1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b"

func validCommitMessage() txclient.SubmitVerifyCommitMessage {
	hash := txclient.ProtoBytes32(strings.Repeat("ab", 32))
	return txclient.SubmitVerifyCommitMessage{
		Commit: txclient.VerifyCommitMessage{
			SchemaVersion: txclient.TaskWireSchemaVersionV1, ChainID: "trueopen-devnet-1",
			TaskID: txclient.ProtoBytes32(testTaskID), VerifyRound: txclient.VerifyRoundV1,
			VerifierOperatorAddress: "verifier-1", ServiceAuthorizationNonce: 4, CommitHash: hash,
			ExpiryHeight: 100, ServiceSignature: txclient.ProtoBytes(strings.Repeat("cd", 64)),
		},
		SubmitterAddress: "trueopen1service",
	}
}

func validResultMessage() txclient.SubmitVerifyResultMessage {
	hash := txclient.ProtoBytes32(strings.Repeat("ab", 32))
	return txclient.SubmitVerifyResultMessage{
		Receipt: txclient.ResultReceiptMessage{
			SchemaVersion: 2, ChainID: "trueopen-devnet-1",
			TaskID: txclient.ProtoBytes32(testTaskID), VerifyRound: txclient.VerifyRoundV1,
			VerifierOperatorAddress: "verifier-1", ServiceAuthorizationNonce: 4,
			GenerationParamsDigest: hash, MetricRoot: hash, AggregateProofHash: hash, VerifierEvidenceBundleHash: hash,
			VerifierEvidenceManifestSizeBytes: 123, Salt: hash,
			ExpiryHeight: 300, ServiceSignature: txclient.ProtoBytes(strings.Repeat("cd", 64)),
		},
		SubmitterAddress: "trueopen1service",
	}
}

func testReceiptOnlyWorkerReveal() ReceiptOnlyWorkerReveal {
	signature := make([]byte, 64)
	signature[0] = 1
	return ReceiptOnlyWorkerReveal{SessionID: "session-1", VerifyRound: 1, WorkerAddress: "worker-1", SampledValueSetHash: codec.HashWithDomain("VALUES", []byte("values")), EvidenceSchemaVersion: "llm-text-v1", ReceiptSignature: signature}
}

func testSettleMessage() (txclient.SettleTaskMessage, codec.Hash) {
	root := codec.HashWithDomain("TRUEOPEN_TASK_EVIDENCE_ROOT_V1", []byte("root"))
	return txclient.SettleTaskMessage{TaskID: txclient.ProtoBytes32(testTaskID), SubmitterAddress: "settler-1"}, root
}
