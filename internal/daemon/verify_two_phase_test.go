package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/txclient"
	"github.com/TrueOpen/cortex/internal/txclient/txclienttest"
	"github.com/TrueOpen/cortex/internal/verifier"
)

var _ verifier.NoticeSender = (*StreamFanout)(nil)

type phaseConfirmer struct {
	token, value int
	valueCalls   []EvidenceCommitments
	tokenFor     map[string]error // Builder -> A-level refusal
	valueFor     map[string]error // Builder -> B-level refusal
}

func (c *phaseConfirmer) ConfirmWorkerTokenEvidence(_ context.Context, commitments EvidenceCommitments) (WorkerEvidence, error) {
	c.token++
	if err := c.tokenFor[commitments.BuilderOperatorAddress]; err != nil {
		return WorkerEvidence{}, err
	}
	return WorkerEvidence{InputTokenIDs: []byte{0, 0, 0, 0}, GeneratedTokenIDs: []byte{0, 0, 0, 0}, GenerationParams: []byte("{}")}, nil
}

func (c *phaseConfirmer) ConfirmWorkerValueEvidence(_ context.Context, commitments EvidenceCommitments) ([]byte, error) {
	c.value++
	c.valueCalls = append(c.valueCalls, commitments)
	if err := c.valueFor[commitments.BuilderOperatorAddress]; err != nil {
		return nil, err
	}
	return []byte("worker-values"), nil
}

type twoPhaseProfileReader struct{}

func (twoPhaseProfileReader) CurrentModelProfile(context.Context, string, string) (chainclient.CurrentModelProfileSnapshot, error) {
	var p chainclient.CurrentModelProfileSnapshot
	p.Profile.RequiredTopK = 4
	p.Profile.VerificationProfile.EvidenceSchemaHash = chainclient.ProtoBytes32(bytes.Repeat([]byte{0x77}, 32))
	p.Profile.VerificationProfile.EvidenceSchema.RequiredInferEvidence = []chainclient.CurrentInferEvidenceRequirementSnapshot{
		{EvidenceKind: int32(nodewire.EvidenceKindWorkerValueOpening), CommitmentSchemaVersion: nodewire.WorkerValueCommitmentSchemaVersionV3, MaxEncodedSizeBytes: chainclient.Uint64String(1 << 20)},
		{EvidenceKind: int32(nodewire.EvidenceKindWorkerTokenOpening), CommitmentSchemaVersion: nodewire.WorkerTokenCommitmentSchemaVersionV1, MaxEncodedSizeBytes: chainclient.Uint64String(1 << 20)},
	}
	return p, nil
}

type fixedTaskBuilders struct {
	builders []string
	err      error
}

func (f fixedTaskBuilders) SelectedTaskBuilders(context.Context, string) ([]string, error) {
	return f.builders, f.err
}

type twoPhase struct {
	exec      *productionVerifyExecutor
	output    *recordingOutputConfirmer
	task      store.VerifyTask
	taskHash  codec.Hash
	root      string
	ev        *evidence.Store
	confirmer *phaseConfirmer
}

func newTwoPhase(t *testing.T) twoPhase {
	t.Helper()
	db := vsStore(t)
	root := t.TempDir()
	ev, err := evidence.NewStore(root, db)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := strings.Repeat("aa", 32)
	taskID := identity.TaskIDString(sessionID, 1)
	receiptHash := codec.HashBytes([]byte("accepted-infer-receipt"))
	outputHash := codec.HashBytes([]byte("committed-output"))
	confirmer := &phaseConfirmer{}
	output := &recordingOutputConfirmer{pkg: builderclient.OutputPackage{
		TaskID: taskID, OutputHash: outputHash,
		SignedInferReceipt: &builderclient.SignedInferReceipt{ChainID: "chain", TaskID: taskID, OutputHash: outputHash.String()},
	}}
	exec := newProductionVerifyExecutor(TaskRunnerConfig{
		OutputConfirmer: output, EvidenceConfirmer: confirmer, ProfileReader: twoPhaseProfileReader{}, Evidence: ev,
		LocalVerifierAddress: "verifier-1", ChainID: "chain", TaskDataAuth: taskRunnerTaskDataAuth(t),
		Tx: txclienttest.NewFake(), SignerAddress: "service-1", TxFeeCap: txclient.Coin{Amount: 25, Denom: "utrueopen"},
		VerifierMemberReader: fixedVerifierMemberReader{snapshot: chainclient.VerifierCandidateMemberSnapshot{
			CandidateMemberRefSnapshot: chainclient.CandidateMemberRefSnapshot{
				CandidatePoolSnapshotID: chainclient.ProtoBytes32(bytes.Repeat([]byte{0x11}, 32)),
				Slot:                    2, SlotVersion: 1, OperatorAddress: "verifier-1",
			},
			InferReceiptHash: chainclient.ProtoBytes32(receiptHash[:]), ExpiryHeight: 20,
		}},
	}).(*productionVerifyExecutor)
	task := store.VerifyTask{
		TaskID: taskID, SessionID: sessionID, OrderSequence: 1, OrderDigest: codec.HashBytes([]byte("accepted-order")),
		ModelID: testModelID, ProfileVersion: 1, Capability: "llm-text",
		WorkerAddress: "worker-1", BuilderOperatorAddress: "builder-1",
		OutputDigest: outputHash, InferReceiptDigest: receiptHash,
		VerifyRound: 1, OpenVerifyHeight: 10, CommitDeadlineHeight: 30, RevealDeadlineHeight: 60, DeadlineHeight: 80,
		AssignedVerifiers: []string{"verifier-1"}, Stage: string(layout.StageQueued),
	}
	return twoPhase{exec: exec, output: output, task: task, taskHash: codec.HashBytes([]byte("task-hash")), root: root, ev: ev, confirmer: confirmer}
}

func requireNoBLevelDirectory(t *testing.T, root string) {
	t.Helper()
	marker := filepath.Join("evidence", "worker", "value")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && strings.HasSuffix(path, marker) {
			return fmt.Errorf("B-level directory %s exists before the commit", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// ADR-0023 decision 4 at the executor: the commit half downloads the A level
// only, and no evidence/worker/value/ directory exists.
func TestVerifyCommitHalfDownloadsNoBLevelEvidence(t *testing.T) {
	p := newTwoPhase(t)
	_, _, err := p.exec.RunVerify(context.Background(), p.taskHash, p.task)
	if err == nil || err.Error() != "model client is required" {
		t.Fatalf("RunVerify() error = %v, want the model boundary after the A-level download", err)
	}
	if p.confirmer.token != 1 || p.confirmer.value != 0 {
		t.Fatalf("token/value downloads = %d/%d, want 1/0", p.confirmer.token, p.confirmer.value)
	}
	requireNoBLevelDirectory(t, p.root)
	if _, err := p.ev.ReadTaskKind(context.Background(), p.taskHash, verifierWorkerReceiptEvidenceKind); err != nil {
		t.Fatalf("the receipt the A-level set was bound to is not persisted: %v", err)
	}
}

// CD §6.2 V7a: the fixed Task Builders are tried in order; the receiving
// Builder is only the fallback when no reader is wired.
func TestVerifyCommitHalfTriesTheFixedTaskBuildersInOrder(t *testing.T) {
	p := newTwoPhase(t)
	p.exec.cfg.TaskBuilders = fixedTaskBuilders{builders: []string{"b0", "b1"}}
	p.confirmer.tokenFor = map[string]error{"b0": errors.New("b0 down")}
	if _, _, err := p.exec.RunVerify(context.Background(), p.taskHash, p.task); err == nil || err.Error() != "model client is required" {
		t.Fatalf("RunVerify() error = %v, want b1 to serve the A level", err)
	}
	if len(p.output.received) != 2 || p.output.received[0].BuilderOperatorAddress != "b0" || p.output.received[1].BuilderOperatorAddress != "b1" {
		t.Fatalf("output confirmations = %+v, want b0 then b1", p.output.received)
	}
	p.exec.cfg.TaskBuilders = fixedTaskBuilders{err: errors.New("rpc down")}
	if _, _, err := p.exec.RunVerify(context.Background(), p.taskHash, p.task); !builderclient.IsRetryable(err) {
		t.Fatalf("an unreadable Task Builder set = %v, want a retryable wait", err)
	}
}

type fakeCommitRows struct {
	row chainclient.VerifyCommitSnapshot
	err error
}

func (f fakeCommitRows) VerifyCommit(context.Context, string, uint32, string) (chainclient.VerifyCommitSnapshot, error) {
	return f.row, f.err
}

func TestRevealGateRequiresThisNodesCommitRow(t *testing.T) {
	p := newTwoPhase(t)
	ctx := context.Background()
	task := p.task
	task.Stage = string(layout.StageCommitted)
	persistence := &evidenceVerifierPersistence{taskHash: p.taskHash, task: &task, evidence: p.ev}
	if stop, err := p.exec.revealGate(ctx, task, persistence); err != nil || !strings.Contains(stop, "no signed commit is persisted") {
		t.Fatalf("no commit: stop %q, %v", stop, err)
	}
	committed := codec.HashBytes([]byte("commit"))
	record, _ := json.Marshal(map[string]any{"task_id": p.task.TaskID, "verify_round": p.task.VerifyRound, "commit_hash": committed.String()})
	if err := writeTaskEvidence(ctx, p.ev, p.taskHash, p.task.SessionID, p.task.TaskID, verifier.CommitStateEvidenceKind, record); err != nil {
		t.Fatal(err)
	}
	if _, err := p.exec.revealGate(ctx, task, persistence); !builderclient.IsRetryable(err) {
		t.Fatalf("no reader: %v, want a retryable refusal", err)
	}
	for name, tc := range map[string]struct {
		rows      fakeCommitRows
		stop      string
		retryable bool
	}{
		"absent":     {fakeCommitRows{err: chainclient.ErrNotFound}, "holds no commit", false},
		"other":      {fakeCommitRows{row: chainclient.VerifyCommitSnapshot{CommitHash: bytes.Repeat([]byte{9}, 32)}}, "commit_hash", false},
		"unreadable": {fakeCommitRows{err: errors.New("rpc down")}, "", true},
		"accepted":   {fakeCommitRows{row: chainclient.VerifyCommitSnapshot{CommitHash: committed[:]}}, "", false},
	} {
		t.Run(name, func(t *testing.T) {
			p.exec.cfg.VerifyCommitReader = tc.rows
			stop, err := p.exec.revealGate(ctx, task, persistence)
			if tc.retryable {
				if !builderclient.IsRetryable(err) || stop != "" {
					t.Fatalf("stop = %q, err = %v; want a retryable read failure", stop, err)
				}
				return
			}
			if err != nil || (tc.stop == "") != (stop == "") || !strings.Contains(stop, tc.stop) {
				t.Fatalf("stop = %q, err = %v; want %q", stop, err, tc.stop)
			}
		})
	}
}

func TestValuePhaseUsesThePersistedReceiptAndTheFixedBuilders(t *testing.T) {
	p := newTwoPhase(t)
	ctx := context.Background()
	if _, _, err := p.exec.RunVerify(ctx, p.taskHash, p.task); err == nil {
		t.Fatal("the fixture has no model; the A phase must still run first")
	}
	task := p.task
	persistence := &evidenceVerifierPersistence{taskHash: p.taskHash, task: &task, evidence: p.ev}
	p.confirmer.valueFor = map[string]error{"builder-0": errors.New("down")}
	values, receipt, served, err := p.exec.confirmWorkerValueEvidence(ctx, p.taskHash, task, persistence, []string{"builder-0", "builder-1", "builder-2"})
	if err != nil || string(values) != "worker-values" || receipt == nil || receipt.TaskID != task.TaskID || served != "builder-1" {
		t.Fatalf("value phase = %q, %+v, %q, %v", values, receipt, served, err)
	}
	if p.confirmer.value != 2 || p.confirmer.valueCalls[1].BuilderOperatorAddress != "builder-1" {
		t.Fatalf("value downloads = %d", p.confirmer.value)
	}
}

func TestTryBuildersStopsAtTheFirstBuilderThatDelivers(t *testing.T) {
	var asked []string
	served, err := tryBuilders(context.Background(), levelA, []string{"b0", "b1", "b2"}, func(_ context.Context, b string) error {
		asked = append(asked, b)
		if b == "b0" {
			return errors.New("down")
		}
		return nil
	})
	if err != nil || served != "b1" || strings.Join(asked, ",") != "b0,b1" {
		t.Fatalf("served %q, asked %v, %v", served, asked, err)
	}
	_, err = tryBuilders(context.Background(), levelA, []string{"b0", "b1"}, func(context.Context, string) error { return errors.New("down") })
	var none *builderUnavailable
	if !errors.As(err, &none) || len(none.failed) != 2 || none.level != levelA {
		t.Fatalf("err = %v, want builderUnavailable naming both", err)
	}
	if _, err := tryBuilders(context.Background(), levelA, nil, func(context.Context, string) error { return nil }); err == nil {
		t.Fatal("an empty Task Builder set was served")
	}
}
