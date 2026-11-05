package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/TrueOpen/cortex/internal/codec"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/taskdataauth"
	"github.com/TrueOpen/cortex/internal/txclient/txclienttest"
	"github.com/TrueOpen/cortex/internal/verifier"
)

const relayTestPin = "ab" + "cd" + "ef" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

func testSignedVerifyCommit() nodewire.VerifyCommitV1 {
	return nodewire.VerifyCommitV1{
		SchemaVersion: 1, ChainID: outputTestChainID, TaskID: bytes.Repeat([]byte{0x11}, 32), VerifyRound: 1,
		VerifierOperatorAddress: inputTestOperator, ServiceAuthorizationNonce: 7,
		CommitHash: bytes.Repeat([]byte{0x22}, 32), ExpiryHeight: 900, ServiceSignature: bytes.Repeat([]byte{0x33}, 64),
	}
}

func newVerifyCommitRelay(t *testing.T, client *inputTaskDataClient, trace *collectTrace) *NexusVerifyCommitRelay {
	t.Helper()
	signing, binding := localInputServiceSigner(t)
	auth, err := taskdataauth.New(taskdataauth.Config{
		ServiceKeys: &inputServiceKeys{binding: binding}, Signer: signing,
		ChainID: outputTestChainID, OperatorAddress: inputTestOperator,
		ServiceAddress: binding.ServiceAddress, ServicePubkey: binding.ServicePubkey,
		ServiceKeyRef: inputTestKeyRef, ExpiryBlocks: inputTestExpiry,
	})
	if err != nil {
		t.Fatalf("taskdataauth.New: %v", err)
	}
	relay, err := NewNexusVerifyCommitRelay(NexusVerifyCommitRelayConfig{
		TaskData: client,
		Endpoints: staticEndpoints{endpoint: BuilderEndpoint{
			OperatorAddress: inputTestBuilder, Endpoint: "https://builder.example", Source: BuilderEndpointSourceDescriptor,
			TLSPubkeyHash: relayTestPin,
		}},
		Auth: auth, ChainID: outputTestChainID, Trace: trace.trace(),
	})
	if err != nil {
		t.Fatalf("NewNexusVerifyCommitRelay: %v", err)
	}
	return relay
}

// Phase-one Builder relay: the commit is handed as-is to the receiving Builder the
// on-chain descriptor resolves to, and the request envelope is signed with this
// node's service key, with method name SubmitVerifyCommit and the receiving Builder
// as the Builder address.
func TestNexusVerifyCommitRelayHandsSignedCommitToReceivingBuilder(t *testing.T) {
	client := &inputTaskDataClient{}
	trace := &collectTrace{}
	relay := newVerifyCommitRelay(t, client, trace)
	commit := testSignedVerifyCommit()
	task := store.VerifyTask{SessionID: "session-1", TaskID: hex.EncodeToString(commit.TaskID), BuilderOperatorAddress: inputTestBuilder}

	ack, err := relay.RelayVerifyCommit(context.Background(), task, commit)
	if err != nil {
		t.Fatalf("RelayVerifyCommit: %v", err)
	}
	if ack.CommitKey != codec.HashBytes([]byte("relay-commit")) || ack.Idempotent {
		t.Fatalf("ack = %+v", ack)
	}
	if len(client.commits) != 1 || client.commitEndpoints[0] != "https://builder.example" {
		t.Fatalf("relayed = %d to %v, want one to the descriptor endpoint", len(client.commits), client.commitEndpoints)
	}
	// The same dial path as output confirmation: the fingerprint registered in the
	// descriptor travels with the ctx into the transport and checks the certificate.
	if client.commitPins[0] != relayTestPin {
		t.Fatalf("relay dialled with pin %q, want the descriptor's %q", client.commitPins[0], relayTestPin)
	}
	got := client.commits[0]
	if !bytes.Equal(got.Commit.TaskID, commit.TaskID) || !bytes.Equal(got.Commit.CommitHash, commit.CommitHash) ||
		!bytes.Equal(got.Commit.ServiceSignature, commit.ServiceSignature) || got.Commit.ExpiryHeight != 900 {
		t.Fatalf("commit was not handed over verbatim: %+v", got)
	}
	line := trace.event(t, "verify_commit_relayed")
	if !strings.Contains(line, `builder="`+inputTestBuilder+`"`) || !strings.Contains(line, `commit_key=`) {
		t.Fatalf("trace line = %q", line)
	}
}

func TestNexusVerifyCommitRelayRefusesUnsignedCommitAndMissingBuilder(t *testing.T) {
	client := &inputTaskDataClient{}
	relay := newVerifyCommitRelay(t, client, &collectTrace{})
	commit := testSignedVerifyCommit()
	task := store.VerifyTask{SessionID: "session-1", TaskID: hex.EncodeToString(commit.TaskID), BuilderOperatorAddress: inputTestBuilder}

	unsigned := commit
	unsigned.ServiceSignature = nil
	if _, err := relay.RelayVerifyCommit(context.Background(), task, unsigned); err == nil {
		t.Fatal("an unsigned commit must not be relayed")
	}
	noBuilder := task
	noBuilder.BuilderOperatorAddress = ""
	if _, err := relay.RelayVerifyCommit(context.Background(), noBuilder, commit); err == nil {
		t.Fatal("a task without a receiving Builder must not be relayed")
	}
	if len(client.commits) != 0 {
		t.Fatalf("relayed %d commits, want none", len(client.commits))
	}
}

type stubVerifyCommitRelay struct {
	err   error
	calls int
	tasks []store.VerifyTask
}

func (s *stubVerifyCommitRelay) RelayVerifyCommit(_ context.Context, task store.VerifyTask, _ nodewire.VerifyCommitV1) (builderclient.VerifyRelayAck, error) {
	s.calls++
	s.tasks = append(s.tasks, task)
	return builderclient.VerifyRelayAck{CommitKey: codec.HashBytes([]byte("stub"))}, s.err
}

// Wired onto #345's commit exit: a successful relay means the exit does not
// self-submit; a deterministic refusal from nexus is wrapped as
// ErrCommitRelayNotOffered so the exit self-submits at once; a transient failure is
// returned as-is so the exit retries.
func TestTaskCommitRelayClassifiesNexusAnswersForTheCommitExit(t *testing.T) {
	commit := testSignedVerifyCommit()
	task := store.VerifyTask{SessionID: "session-1", TaskID: hex.EncodeToString(commit.TaskID), BuilderOperatorAddress: inputTestBuilder}
	req := verifier.CommitRelayRequest{SessionID: task.SessionID, TaskID: task.TaskID, VerifyRound: 1, Commit: commit}

	if taskCommitRelayFor(nil, task) != nil {
		t.Fatal("no relay configured must yield a nil CommitRelay (relay channel absent)")
	}
	stub := &stubVerifyCommitRelay{}
	if err := taskCommitRelayFor(stub, task).RelayVerifyCommit(context.Background(), req); err != nil || stub.calls != 1 {
		t.Fatalf("relayed: err = %v, calls = %d", err, stub.calls)
	}
	if got := stub.tasks[0]; got.BuilderOperatorAddress != inputTestBuilder || got.TaskID != task.TaskID {
		t.Fatalf("relay task = %+v", got)
	}
	for name, cause := range map[string]error{
		"invalid argument":    connect.NewError(connect.CodeInvalidArgument, errors.New("commit_hash malformed")),
		"permission denied":   connect.NewError(connect.CodePermissionDenied, errors.New("not a selected verifier")),
		"failed precondition": connect.NewError(connect.CodeFailedPrecondition, errors.New("task is not verifying")),
		"not found":           connect.NewError(connect.CodeNotFound, errors.New("task not found")),
		"permanent transport": builderclient.Permanent(errors.New("scheme mismatch")),
	} {
		t.Run(name, func(t *testing.T) {
			stub := &stubVerifyCommitRelay{err: cause}
			err := taskCommitRelayFor(stub, task).RelayVerifyCommit(context.Background(), req)
			if !verifier.CommitRelayNotOffered(err) {
				t.Fatalf("%s must open the self-submit exit, got %v", name, err)
			}
		})
	}
	for name, cause := range map[string]error{
		"unavailable":    connect.NewError(connect.CodeUnavailable, errors.New("chain unreachable")),
		"retryable dial": builderclient.Retryable(errors.New("connection refused")),
		"plain error":    errors.New("dial tcp: connection refused"),
	} {
		t.Run(name, func(t *testing.T) {
			stub := &stubVerifyCommitRelay{err: cause}
			err := taskCommitRelayFor(stub, task).RelayVerifyCommit(context.Background(), req)
			if err == nil || verifier.CommitRelayNotOffered(err) {
				t.Fatalf("%s must stay transient (retry, no self-submit), got %v", name, err)
			}
		})
	}
}

// resultRelayTaskData records SubmitVerifyResult without the fake client's
// full receipt validation, which the relay itself does not own.
type resultRelayTaskData struct {
	*inputTaskDataClient
	endpoints []string
	receipts  []nodewire.ResultReceiptV3
}

func (c *resultRelayTaskData) SubmitVerifyResult(_ context.Context, endpoint string, req builderclient.SubmitVerifyResultRequest) (builderclient.VerifyRelayAck, error) {
	c.endpoints = append(c.endpoints, endpoint)
	c.receipts = append(c.receipts, req.Receipt)
	return builderclient.VerifyRelayAck{SigningDigest: codec.HashBytes([]byte("relay-result"))}, nil
}

// The signed result goes to the same receiving Builder as the commit, verbatim.
func TestNexusVerifyResultRelayHandsSignedResultToReceivingBuilder(t *testing.T) {
	signing, binding := localInputServiceSigner(t)
	auth, err := taskdataauth.New(taskdataauth.Config{
		ServiceKeys: &inputServiceKeys{binding: binding}, Signer: signing,
		ChainID: outputTestChainID, OperatorAddress: inputTestOperator,
		ServiceAddress: binding.ServiceAddress, ServicePubkey: binding.ServicePubkey,
		ServiceKeyRef: inputTestKeyRef, ExpiryBlocks: inputTestExpiry,
	})
	if err != nil {
		t.Fatalf("taskdataauth.New: %v", err)
	}
	client := &resultRelayTaskData{inputTaskDataClient: &inputTaskDataClient{}}
	trace := &collectTrace{}
	relay, err := NewNexusVerifyResultRelay(NexusVerifyCommitRelayConfig{
		TaskData: client,
		Endpoints: staticEndpoints{endpoint: BuilderEndpoint{
			OperatorAddress: inputTestBuilder, Endpoint: "https://builder.example", Source: BuilderEndpointSourceDescriptor,
			TLSPubkeyHash: relayTestPin,
		}},
		Auth: auth, ChainID: outputTestChainID, Trace: trace.trace(),
	})
	if err != nil {
		t.Fatalf("NewNexusVerifyResultRelay: %v", err)
	}
	receipt := nodewire.ResultReceiptV3{TaskID: bytes.Repeat([]byte{0x11}, 32), VerifyRound: 1, ExpiryHeight: 950, ServiceSignature: bytes.Repeat([]byte{0x44}, 64)}
	task := store.VerifyTask{SessionID: "session-1", TaskID: hex.EncodeToString(receipt.TaskID), BuilderOperatorAddress: inputTestBuilder}

	if _, err := relay.RelayVerifyResult(context.Background(), task, receipt); err != nil {
		t.Fatalf("RelayVerifyResult: %v", err)
	}
	if len(client.receipts) != 1 || client.endpoints[0] != "https://builder.example" ||
		!bytes.Equal(client.receipts[0].ServiceSignature, receipt.ServiceSignature) || client.receipts[0].ExpiryHeight != 950 {
		t.Fatalf("relayed %d to %v, want the signed receipt once to the descriptor endpoint", len(client.receipts), client.endpoints)
	}
	if line := trace.event(t, "verify_result_relayed"); !strings.Contains(line, `builder="`+inputTestBuilder+`"`) {
		t.Fatalf("trace line = %q", line)
	}
	unsigned := receipt
	unsigned.ServiceSignature = nil
	_, err = relay.RelayVerifyResult(context.Background(), task, unsigned)
	if err == nil || len(client.receipts) != 1 {
		t.Fatalf("unsigned receipt: err = %v, relayed %d; want a refusal and nothing sent", err, len(client.receipts))
	}
}

type stubVerifyResultRelay struct {
	err   error
	calls int
}

func (s *stubVerifyResultRelay) RelayVerifyResult(context.Context, store.VerifyTask, nodewire.ResultReceiptV3) (builderclient.VerifyRelayAck, error) {
	s.calls++
	return builderclient.VerifyRelayAck{}, s.err
}

// The reveal's result exit on a node with no workload tx client (a file://
// keystore): it used to refuse with "verifier commit exit requires a workload
// tx client" on every retry until the reveal deadline. With the result relay
// wired it is a complete configuration; without it the refusal names the
// result, not the commit. A deterministic refusal maps onto the self-submit
// exit, and a node that does have a tx client keeps it as the fallback.
func TestResultExitRelaysWithoutAWorkloadTxClient(t *testing.T) {
	task := store.VerifyTask{SessionID: "session-1", TaskID: "task-1", BuilderOperatorAddress: inputTestBuilder}
	stub := &stubVerifyResultRelay{}

	submitter, relay, err := (&productionVerifyExecutor{cfg: TaskRunnerConfig{VerifyResultRelay: stub}}).resultExit("", task)
	if err != nil || submitter != nil || relay == nil {
		t.Fatalf("relay-only node: submitter = %v, relay = %v, err = %v; want the relay as the only exit", submitter, relay, err)
	}
	if err := relay.RelayVerifyResult(context.Background(), verifier.ResultRelayRequest{TaskID: task.TaskID}); err != nil || stub.calls != 1 {
		t.Fatalf("relay: err = %v, calls = %d", err, stub.calls)
	}

	_, _, err = (&productionVerifyExecutor{cfg: TaskRunnerConfig{}}).resultExit("", task)
	if err == nil || !strings.Contains(err.Error(), "verifier result exit requires a workload tx client") {
		t.Fatalf("no relay, no tx: err = %v, want a refusal that names the result exit", err)
	}

	refusing := &stubVerifyResultRelay{err: connect.NewError(connect.CodeFailedPrecondition, errors.New("NEXUS_INGRESS_RELAY_NOT_OFFERED"))}
	submitter, relay, err = (&productionVerifyExecutor{cfg: TaskRunnerConfig{VerifyResultRelay: refusing, Tx: txclienttest.NewFake()}}).resultExit("service-1", task)
	if err != nil || submitter == nil || relay == nil {
		t.Fatalf("tx-capable node: submitter = %v, relay = %v, err = %v; want both exits", submitter, relay, err)
	}
	if err := relay.RelayVerifyResult(context.Background(), verifier.ResultRelayRequest{TaskID: task.TaskID}); !verifier.ResultRelayNotOffered(err) {
		t.Fatalf("deterministic refusal = %v, want ErrResultRelayNotOffered so the exit self-submits", err)
	}
	transient := &stubVerifyResultRelay{err: connect.NewError(connect.CodeUnavailable, errors.New("builder busy"))}
	if err := taskResultRelayFor(transient, task).RelayVerifyResult(context.Background(), verifier.ResultRelayRequest{}); err == nil || verifier.ResultRelayNotOffered(err) {
		t.Fatalf("transient failure = %v, want it retried rather than self-submitted", err)
	}
}
