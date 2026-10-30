package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

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
	if err != attempt || task.Stage == "failed" || len(f.tx.Requests()) != 0 {
		t.Fatalf("task %+v, err %v; want the attempt returned untouched far from the deadline", task, err)
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
	if err == nil || !errors.Is(err, attempt) || task.Stage == "failed" {
		t.Fatalf("task %+v, err %v; want the attempt kept with the report failure", task, err)
	}
}
