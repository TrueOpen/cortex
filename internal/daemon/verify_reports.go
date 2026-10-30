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

func dataUnavailableMarkerKind(level evidenceLevel) string {
	return "verifier-data-unavailable-" + strings.ToLower(level.String())
}

// reportOrWait decides what a failed A- or B-level attempt means (CD §6.2
// V7b, V14b). Every fixed Task Builder failing near the window's deadline, or
// content that matched its commitment but is illegal, becomes one signed
// MsgReportDataUnavailable and the round stops: a node that reports does not
// commit (A) or reveal (B). Anything else is returned untouched.
func (e *productionVerifyExecutor) reportOrWait(ctx context.Context, task store.VerifyTask, persistence *evidenceVerifierPersistence, builders []string, servedBy string, attempt error) (store.VerifyTask, error) {
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
	if !invalid {
		due, err := e.reportDue(ctx, deadline)
		if err != nil || !due {
			return task, attempt
		}
	}
	if err := e.reportDataUnavailable(ctx, task, persistence, level, invalid, builders, unavailable, deadline); err != nil {
		return task, fmt.Errorf("%w (and its MsgReportDataUnavailable failed: %v)", attempt, err)
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
func (e *productionVerifyExecutor) reportDue(ctx context.Context, deadline uint64) (bool, error) {
	if deadline == 0 || e.cfg.ChainStatus == nil {
		return false, nil
	}
	height, _, err := e.cfg.ChainStatus.ChainStatus(ctx)
	if err != nil {
		return false, err
	}
	return height < deadline && height+dataUnavailableReportMarginBlocks >= deadline, nil
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
