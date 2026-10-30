package daemon

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/tasktrace"
	"github.com/TrueOpen/cortex/internal/verifier"
)

// dataUnavailableReportMarginBlocks is how close to the window's deadline a
// full failed pass over the fixed Task Builders turns into a report. No doc
// fixes it (S7 Q8); the runner's retry interval must stay well inside it.
const dataUnavailableReportMarginBlocks = 20

// reportWindowWait is a full failed pass that is not reportable yet, or a
// report that did not land. The runner schedules the next attempt by height:
// it is due once the chain reaches Height even if the wall-clock backoff has
// not passed, so the 30s-to-15min backoff can never step over the report
// window (S7 Q8). A wait outside the margin points at deadline-margin; a
// failed report inside it points at the next block.
type reportWindowWait struct {
	err    error
	Height uint64
}

func (w *reportWindowWait) Error() string { return w.err.Error() }
func (w *reportWindowWait) Unwrap() error { return w.err }

// reportWindowHeight is the first height at which a level's report is due.
// The B-level window is kept above the commit deadline, so a height scheduled
// for one stage can never be read as the other's (see verifyRetryHeightDue).
func reportWindowHeight(task store.VerifyTask, level evidenceLevel, deadline uint64) uint64 {
	h := uint64(1)
	if deadline > dataUnavailableReportMarginBlocks {
		h = deadline - dataUnavailableReportMarginBlocks
	}
	if level == levelB && h <= task.CommitDeadlineHeight {
		h = task.CommitDeadlineHeight + 1
	}
	return h
}

func dataUnavailableMarkerKind(level evidenceLevel) string {
	return "verifier-data-unavailable-" + strings.ToLower(level.String())
}

// reportOrWait decides what a failed A- or B-level attempt means (CD §6.2
// V7b, V14b). Every fixed Task Builder failing near the window's deadline, or
// content that matched its commitment but is illegal, becomes one signed
// MsgReportDataUnavailable and the round stops: a node that reports does not
// commit (A) or reveal (B). Anything else is returned untouched.
func (e *productionVerifyExecutor) reportOrWait(ctx context.Context, task store.VerifyTask, persistence *evidenceVerifierPersistence, builders []string, servedBy string, attempt error) (store.VerifyTask, error) {
	if errors.Is(attempt, errVerifierLocal) {
		// This node's own fault: nothing about the Builders to report.
		return task, attempt
	}
	level := levelA
	if task.Stage == string(layout.StageCommitted) {
		level = levelB
	}
	unavailable := map[string]bool{}
	invalid := false
	var none *builderUnavailable
	switch {
	case errors.As(attempt, &none):
		level = none.level
		for builder := range none.failed {
			unavailable[builder] = true
		}
	case errors.Is(attempt, verifier.ErrWorkerEvidenceInvalid) && servedBy != "":
		invalid = true
		unavailable[servedBy] = true
	default:
		return task, attempt
	}
	deadline := task.CommitDeadlineHeight
	if level == levelB {
		deadline = task.RevealDeadlineHeight
	}
	var height uint64
	if !invalid {
		due, tip, err := e.reportDue(ctx, deadline)
		if err != nil || deadline == 0 || e.cfg.ChainStatus == nil {
			return task, attempt
		}
		if !due {
			if tip >= deadline {
				return task, attempt
			}
			return task, &reportWindowWait{err: attempt, Height: reportWindowHeight(task, level, deadline)}
		}
		height = tip
	}
	if err := e.reportDataUnavailable(ctx, task, persistence, level, invalid, builders, unavailable, deadline); err != nil {
		failed := fmt.Errorf("%w (and its MsgReportDataUnavailable failed: %v)", attempt, err)
		if height == 0 {
			return task, failed
		}
		// Inside the window: try again at the next block, before the deadline.
		return task, &reportWindowWait{err: failed, Height: height + 1}
	}
	reason, duty := "BUILDER_UNAVAILABLE", "commit"
	if invalid {
		reason = "WORKER_EVIDENCE_INVALID"
	}
	if level == levelB {
		duty = "reveal"
	}
	e.cfg.Trace.ErrorEvent("verify_data_unavailable_reported",
		tasktrace.Str("task", task.TaskID), tasktrace.Uint("verify_round", task.VerifyRound),
		tasktrace.Str("level", level.String()), tasktrace.Str("reason", reason), tasktrace.Uint("deadline_height", deadline))
	task.Stage, task.RetryAtUnixMilli = "failed", 0
	task.LastError = fmt.Sprintf("reported %s-level data unavailable (%s) for round %d; this node does not %s: %v",
		level, reason, task.VerifyRound, duty, attempt)
	return task, nil
}

// reportDue is S7 Q8: report only inside the last margin blocks before the
// window's deadline, and never once it has passed.
func (e *productionVerifyExecutor) reportDue(ctx context.Context, deadline uint64) (bool, uint64, error) {
	if deadline == 0 || e.cfg.ChainStatus == nil {
		return false, 0, nil
	}
	height, _, err := e.cfg.ChainStatus.ChainStatus(ctx)
	if err != nil {
		return false, 0, err
	}
	return height < deadline && height+dataUnavailableReportMarginBlocks >= deadline, height, nil
}

// reportDataUnavailable submits one report per (task, round, level), guarded
// by a local marker (the Keeper also keeps one per (task, round, verifier)).
func (e *productionVerifyExecutor) reportDataUnavailable(ctx context.Context, task store.VerifyTask, persistence *evidenceVerifierPersistence, level evidenceLevel, invalid bool, builders []string, unavailable map[string]bool, deadline uint64) error {
	kind := dataUnavailableMarkerKind(level)
	if _, err := persistence.ReadVerifierEvidence(ctx, kind); err == nil {
		return nil
	} else if !errors.Is(err, evidence.ErrArtifactNotFound) {
		return err
	}
	bitmap, err := verifier.UnavailableBuilderBitmap(builders, unavailable)
	if err != nil {
		return err
	}
	signerAddress, _ := resolveSigningIdentity(e.cfg, e.cfg.LocalVerifierAddress)
	submitter, err := e.commitSubmitter(signerAddress, false)
	if err != nil {
		return err
	}
	manager, ok := submitter.(*verifier.SettlementManager)
	if !ok {
		return fmt.Errorf("the verify settlement manager cannot submit a data unavailable report")
	}
	vlevel := verifier.DataLevelA
	if level == levelB {
		vlevel = verifier.DataLevelB
	}
	observation, err := manager.ReportDataUnavailable(ctx, verifier.DataUnavailableReport{
		SessionID: task.SessionID, TaskID: task.TaskID, VerifyRound: uint32(task.VerifyRound),
		Level: vlevel, Invalid: invalid, Bitmap: bitmap, DeadlineHeight: deadline,
	})
	if err != nil {
		return err
	}
	marker, err := json.Marshal(map[string]any{
		"tx_hash": observation.Tx.TxHash, "included_height": observation.Tx.IncludedHeight,
		"bitmap": hex.EncodeToString(bitmap), "invalid": invalid,
	})
	if err != nil {
		return err
	}
	return persistence.WriteEvidence(ctx, verifier.EvidenceRecord{TaskID: task.TaskID, Kind: kind, Data: marker})
}

// stopAfterReport is the structural half of "a node that reports does not
// commit (A) or reveal (B)": once this round's report marker for the level
// exists, the responsibility stops before anything is fetched or signed. done
// is true when it stopped.
func (e *productionVerifyExecutor) stopAfterReport(ctx context.Context, task store.VerifyTask, persistence *evidenceVerifierPersistence, level evidenceLevel) (store.VerifyTask, bool, error) {
	if persistence.evidence == nil {
		return task, false, nil
	}
	_, err := persistence.ReadVerifierEvidence(ctx, dataUnavailableMarkerKind(level))
	if errors.Is(err, evidence.ErrArtifactNotFound) {
		return task, false, nil
	}
	if err != nil {
		return task, false, localFailure(fmt.Errorf("read the %s-level data unavailable marker: %w", level, err))
	}
	duty := "commit"
	if level == levelB {
		duty = "reveal"
	}
	e.cfg.Trace.ErrorEvent("verify_stopped_after_report",
		tasktrace.Str("task", task.TaskID), tasktrace.Uint("verify_round", task.VerifyRound), tasktrace.Str("level", level.String()))
	task.Stage, task.RetryAtUnixMilli = "failed", 0
	task.LastError = fmt.Sprintf("this node reported %s-level data unavailable for round %d and does not %s", level, task.VerifyRound, duty)
	return task, true, nil
}
