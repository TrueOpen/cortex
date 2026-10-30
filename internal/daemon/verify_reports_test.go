package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/txclient"
	"github.com/TrueOpen/cortex/internal/txclient/txclienttest"
	"github.com/TrueOpen/cortex/internal/verifier"
)

type reportFixture struct {
	exec        *productionVerifyExecutor
	tx          *txclienttest.Fake
	task        store.VerifyTask
	persistence *evidenceVerifierPersistence
}

func newReportFixture(t *testing.T, height uint64) *reportFixture {
	t.Helper()
	ev, err := evidence.NewStore(t.TempDir(), vsStore(t))
	if err != nil {
		t.Fatal(err)
	}
	tx := txclienttest.NewFake()
	f := &reportFixture{tx: tx}
	f.exec = newProductionVerifyExecutor(TaskRunnerConfig{
		LocalVerifierAddress: "verifier-1", ChainID: "chain", Evidence: ev,
		Tx: tx, SignerAddress: "service-1", TxFeeCap: txclient.Coin{Amount: 25, Denom: "utrueopen"},
		ChainStatus: fixedChainStatus{height: height, chainID: "chain"},
	}).(*productionVerifyExecutor)
	sessionID := strings.Repeat("cd", 32)
	f.task = store.VerifyTask{
		TaskID: identity.TaskIDString(sessionID, 1), SessionID: sessionID, VerifyRound: 1,
		CommitDeadlineHeight: 200, RevealDeadlineHeight: 400, Stage: string(layout.StageQueued),
	}
	f.persistence = &evidenceVerifierPersistence{taskHash: codec.HashBytes([]byte("report-task")), task: &f.task, evidence: ev}
	return f
}

var reportBuilders = []string{"b0", "b1", "b2"}

func unavailableA() error {
	return &builderUnavailable{level: levelA, builders: reportBuilders, failed: map[string]error{"b0": errors.New("down"), "b2": errors.New("down")}}
}

func (f *reportFixture) sent(t *testing.T) []txclient.ReportDataUnavailableMessage {
	t.Helper()
	var out []txclient.ReportDataUnavailableMessage
	for _, r := range f.tx.Requests() {
		if r.Kind != txclient.MsgReportDataUnavailable {
			continue
		}
		var m txclient.ReportDataUnavailableMessage
		if err := json.Unmarshal(r.Payload, &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

// S7 Q8: a full failed pass far from the deadline is only a retry.
func TestReportOrWaitWaitsOutsideTheMargin(t *testing.T) {
	f := newReportFixture(t, 100)
	attempt := unavailableA()
	task, err := f.exec.reportOrWait(context.Background(), f.task, f.persistence, reportBuilders, "", attempt)
	var wait *reportWindowWait
	if !errors.Is(err, attempt) || !errors.As(err, &wait) || task.Stage == "failed" || len(f.tx.Requests()) != 0 {
		t.Fatalf("task %+v, err %v; want the attempt kept, unreported, far from the deadline", task, err)
	}
	if wait.Height != 200-dataUnavailableReportMarginBlocks {
		t.Fatalf("next attempt at height %d, want the window's first block %d", wait.Height, 200-dataUnavailableReportMarginBlocks)
	}
	// The B-level window never schedules at or below the commit deadline.
	b := f.task
	b.Stage = string(layout.StageCommitted)
	b.RevealDeadlineHeight = 210
	if h := reportWindowHeight(b, levelB, b.RevealDeadlineHeight); h != 201 {
		t.Fatalf("B-level window height = %d, want commit deadline + 1", h)
	}
}

func TestReportOrWaitReportsOnceInsideTheMargin(t *testing.T) {
	f := newReportFixture(t, 185)
	for range 2 {
		task, err := f.exec.reportOrWait(context.Background(), f.task, f.persistence, reportBuilders, "", unavailableA())
		if err != nil || task.Stage != "failed" || !strings.Contains(task.LastError, "reported A-level data unavailable") {
			t.Fatalf("task %+v, err %v", task, err)
		}
	}
	sent := f.sent(t)
	if len(sent) != 1 || sent[0].UnavailableTaskBuilderBitmap.Hex() != "05" || sent[0].EvidenceKind != txclient.EvidenceKindUnspecified ||
		sent[0].Reason != txclient.DataUnavailableReasonBuilderUnavailable {
		t.Fatalf("reports = %+v, want one A-level BUILDER_UNAVAILABLE for b0 and b2", sent)
	}
	if f.tx.Requests()[0].DeadlineHeight != 200 {
		t.Fatal("the A-level report must time out at the commit deadline")
	}
}

// S7 Q9: content that matches its commitment but is illegal is reported at
// once, against the Builder that served it.
func TestReportOrWaitReportsInvalidEvidenceAtOnce(t *testing.T) {
	f := newReportFixture(t, 100)
	attempt := errors.Join(errors.New("verify"), verifier.ErrWorkerEvidenceInvalid)
	task, err := f.exec.reportOrWait(context.Background(), f.task, f.persistence, reportBuilders, "b1", attempt)
	if err != nil || task.Stage != "failed" {
		t.Fatalf("task %+v, err %v", task, err)
	}
	sent := f.sent(t)
	if len(sent) != 1 || sent[0].UnavailableTaskBuilderBitmap.Hex() != "02" || sent[0].Reason != txclient.DataUnavailableReasonWorkerEvidenceInvalid {
		t.Fatalf("reports = %+v, want WORKER_EVIDENCE_INVALID naming the serving Builder", sent)
	}
}

func TestReportOrWaitUsesTheValueKindWhileRevealing(t *testing.T) {
	f := newReportFixture(t, 390)
	f.task.Stage = string(layout.StageCommitted)
	attempt := &builderUnavailable{level: levelB, builders: reportBuilders, failed: map[string]error{"b1": errors.New("not REVEALING yet")}}
	task, err := f.exec.reportOrWait(context.Background(), f.task, f.persistence, reportBuilders, "", attempt)
	if err != nil || task.Stage != "failed" || !strings.Contains(task.LastError, "does not reveal") {
		t.Fatalf("task %+v, err %v", task, err)
	}
	sent := f.sent(t)
	if len(sent) != 1 || sent[0].EvidenceKind != txclient.EvidenceKindWorkerValueOpening || f.tx.Requests()[0].DeadlineHeight != 400 {
		t.Fatalf("reports = %+v, want one B-level report bounded by the reveal deadline", sent)
	}
}

func TestReportOrWaitPassesOtherErrorsThrough(t *testing.T) {
	f := newReportFixture(t, 199)
	attempt := errors.New("model client is required")
	if task, err := f.exec.reportOrWait(context.Background(), f.task, f.persistence, reportBuilders, "b0", attempt); err != attempt || task.Stage == "failed" {
		t.Fatalf("task %+v, err %v", task, err)
	}
	// Invalid content with no serving Builder cannot be attributed.
	invalid := errors.Join(errors.New("verify"), verifier.ErrWorkerEvidenceInvalid)
	if task, err := f.exec.reportOrWait(context.Background(), f.task, f.persistence, reportBuilders, "", invalid); err != invalid || task.Stage == "failed" {
		t.Fatalf("task %+v, err %v", task, err)
	}
}

// A report that does not land leaves the round owed and the attempt retryable.
func TestReportOrWaitKeepsTheRoundWhenTheReportFails(t *testing.T) {
	f := newReportFixture(t, 185)
	f.tx.RejectNext(txclient.MsgReportDataUnavailable, "verifier not selected")
	attempt := unavailableA()
	task, err := f.exec.reportOrWait(context.Background(), f.task, f.persistence, reportBuilders, "", attempt)
	var wait *reportWindowWait
	if err == nil || !errors.Is(err, attempt) || task.Stage == "failed" || !errors.As(err, &wait) || wait.Height != 186 {
		t.Fatalf("task %+v, err %v; want the attempt kept and retried at the next block", task, err)
	}
}

type failingProfileReader struct{}

func (failingProfileReader) CurrentModelProfile(context.Context, string, string) (chainclient.CurrentModelProfileSnapshot, error) {
	return chainclient.CurrentModelProfileSnapshot{}, errors.New("keeper rpc down")
}

// I4: a fault of this node -- a profile it cannot read, an evidence store it
// cannot write -- is never reported as the Builders' data being unavailable,
// even inside the report window.
func TestLocalFailuresNeverProduceADataUnavailableReport(t *testing.T) {
	for name, breakIt := range map[string]func(*twoPhase){
		"profile": func(p *twoPhase) { p.exec.cfg.ProfileReader = failingProfileReader{} },
		"disk":    func(p *twoPhase) { p.exec.cfg.Evidence = nil },
	} {
		t.Run(name, func(t *testing.T) {
			p := newTwoPhase(t)
			tx := txclienttest.NewFake()
			p.exec.cfg.Tx = tx
			// Height 15 against commit deadline 30: inside the 20-block margin.
			p.exec.cfg.ChainStatus = fixedChainStatus{height: 15, chainID: "chain"}
			p.exec.cfg.TaskBuilders = fixedTaskBuilders{builders: []string{"builder-1", "builder-2"}}
			breakIt(&p)
			task, _, err := p.exec.RunVerify(context.Background(), p.taskHash, p.task)
			if err == nil || !errors.Is(err, errVerifierLocal) || task.Stage == "failed" {
				t.Fatalf("RunVerify() = %+v, %v; want the local failure returned for a retry", task, err)
			}
			for _, r := range tx.Requests() {
				if r.Kind == txclient.MsgReportDataUnavailable {
					t.Fatal("a local failure was reported as data unavailability")
				}
			}
			if name == "profile" && (p.confirmer.token != 0 || len(p.output.received) != 0) {
				t.Fatalf("a Builder was asked (%d outputs, %d token bundles) before the local profile read", len(p.output.received), p.confirmer.token)
			}
			if name == "disk" && len(p.output.received) != 1 {
				t.Fatalf("output confirmations = %d, want the pass to stop at the first local failure", len(p.output.received))
			}
		})
	}
}

// I3: after the A-level report, replaying the round (VerifyReady re-admits it
// as queued) does not fetch, verify or commit.
func TestAReportedRoundNeverCommits(t *testing.T) {
	p := newTwoPhase(t)
	tx := txclienttest.NewFake()
	p.exec.cfg.Tx = tx
	p.exec.cfg.ChainStatus = fixedChainStatus{height: 15, chainID: "chain"}
	p.exec.cfg.TaskBuilders = fixedTaskBuilders{builders: []string{"b0", "b1"}}
	p.confirmer.tokenFor = map[string]error{"b0": errors.New("down"), "b1": errors.New("down")}
	stopped, _, err := p.exec.RunVerify(context.Background(), p.taskHash, p.task)
	if err != nil || stopped.Stage != "failed" || len(tx.Requests()) != 1 || tx.Requests()[0].Kind != txclient.MsgReportDataUnavailable {
		t.Fatalf("first attempt = %+v, %v, txs %d; want one report and a stop", stopped, err, len(tx.Requests()))
	}
	p.confirmer.tokenFor = nil
	asked := len(p.output.received)
	replayed := p.task // a replayed VerifyReady re-admits the round as queued
	again, _, err := p.exec.RunVerify(context.Background(), p.taskHash, replayed)
	if err != nil || again.Stage != "failed" || !strings.Contains(again.LastError, "does not commit") {
		t.Fatalf("replayed round = %+v, %v; want it stopped by the report", again, err)
	}
	if len(p.output.received) != asked || len(tx.Requests()) != 1 {
		t.Fatalf("the replayed round asked a Builder (%d → %d) or submitted (%d txs)", asked, len(p.output.received), len(tx.Requests()))
	}
}

// I3, B level: a round whose reveal was reported is not revealed.
func TestAReportedRevealIsNeverRevealed(t *testing.T) {
	p := newTwoPhase(t)
	ctx := context.Background()
	task := p.task
	task.Stage = string(layout.StageCommitted)
	if err := writeTaskEvidence(ctx, p.ev, p.taskHash, task.SessionID, task.TaskID, dataUnavailableMarkerKind(levelB), []byte(`{"invalid":false}`)); err != nil {
		t.Fatal(err)
	}
	rows := &countingCommitRows{}
	p.exec.cfg.VerifyCommitReader = rows
	stopped, _, err := p.exec.RunVerify(ctx, p.taskHash, task)
	if err != nil || stopped.Stage != "failed" || !strings.Contains(stopped.LastError, "does not reveal") || rows.calls != 0 || p.confirmer.value != 0 {
		t.Fatalf("reveal = %+v, %v (gate reads %d, B downloads %d); want a stop before the gate", stopped, err, rows.calls, p.confirmer.value)
	}
}

type countingCommitRows struct{ calls int }

func (c *countingCommitRows) VerifyCommit(context.Context, string, uint32, string) (chainclient.VerifyCommitSnapshot, error) {
	c.calls++
	return chainclient.VerifyCommitSnapshot{}, chainclient.ErrNotFound
}

// I2, the plan's example: a 100-block commit window at 6 s per block is 600 s,
// and the report window is its last 20 blocks (480-600 s). With the runner's
// 30 s -> 15 min backoff, a round failing from h=0 retries at 30, 90, 210,
// 450 s (h=75, before the window) and then 930 s, past the deadline: wall
// clock alone steps over the whole window and the report is never sent. So
// the round is also due by height: whatever the backoff says, the first pass
// at the window's first block (h=80) runs it and reports.
func TestRunnerReachesTheReportWindowWhateverTheBackoff(t *testing.T) {
	ctx := context.Background()
	f := newReportFixture(t, 10)
	chain := &movableChainStatus{height: 10, chainID: "chain"}
	f.exec.cfg.ChainStatus = chain
	db := vsStore(t)
	hash := codec.HashBytes([]byte("report-window-task"))
	task := f.task
	task.CommitDeadlineHeight, task.RevealDeadlineHeight, task.DeadlineHeight = 100, 200, 300
	seedVerifyTask(ctx, t, db, hash, task)
	attempts := 0
	runner := NewTaskRunner(TaskRunnerConfig{
		Store: db, MaxConcurrency: 1, MaxRetryAttempts: 120, ChainStatus: chain,
		RetryDelay: 30 * time.Second, MaxRetryDelay: 15 * time.Minute,
		VerifyExecutor: verifyExecutorFunc(func(ctx context.Context, h codec.Hash, task store.VerifyTask) (store.VerifyTask, bool, error) {
			attempts++
			persistence := &evidenceVerifierPersistence{taskHash: h, task: &task, evidence: f.exec.cfg.Evidence}
			updated, err := f.exec.reportOrWait(ctx, task, persistence, reportBuilders, "", unavailableA())
			return updated, false, err
		}),
	})
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	rec, err := layout.GetVerifyRecord(ctx, db, layout.StoredHash(hash))
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || rec.RetryAtHeight != 80 || time.Until(time.UnixMilli(rec.RetryAtUnixMilli)) < 25*time.Second {
		t.Fatalf("after the first failure: attempts %d, record %+v; want a 30 s backoff and a height schedule at 80", attempts, rec)
	}
	chain.set(79)
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 {
		t.Fatalf("attempts at h=79 = %d, want the backoff honoured before the window", attempts)
	}
	chain.set(80)
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	rec, err = layout.GetVerifyRecord(ctx, db, layout.StoredHash(hash))
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || rec.Stage != layout.StageFailed || len(f.sent(t)) != 1 {
		t.Fatalf("at h=80: attempts %d, stage %q, reports %d; want the window's first block to run and report", attempts, rec.Stage, len(f.sent(t)))
	}
}

// Any other failure retires the height schedule, so a stale one cannot turn
// the backoff off later.
func TestVerifyRetryHeightIsRetiredByOtherFailures(t *testing.T) {
	r := NewTaskRunner(TaskRunnerConfig{})
	task := store.VerifyTask{TaskID: "t", Stage: "queued", CommitDeadlineHeight: 100}
	r.recordVerifyRetry(&task, &reportWindowWait{err: errors.New("down"), Height: 80}, time.Now(), codec.Hash{})
	if task.RetryAtHeight != 80 || !verifyRetryHeightDue(task, chainTip{height: 80, readable: true}) {
		t.Fatalf("task %+v, want due at 80", task)
	}
	r.recordVerifyRetry(&task, errors.New("model client is required"), time.Now(), codec.Hash{})
	if task.RetryAtHeight != noRetryAtHeight || verifyRetryHeightDue(task, chainTip{height: 90, readable: true}) {
		t.Fatalf("task %+v, want the height schedule retired", task)
	}
	committed := store.VerifyTask{Stage: string(layout.StageCommitted), CommitDeadlineHeight: 100, RetryAtHeight: 80}
	if verifyRetryHeightDue(committed, chainTip{height: 150, readable: true}) {
		t.Fatal("an A-level height schedule was read after the commit")
	}
}
