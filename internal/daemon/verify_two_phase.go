package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/tasktrace"
	"github.com/TrueOpen/cortex/internal/verifier"
)

// The verify executor's half of ADR-0023: the A level (output, token bundle)
// is downloaded before the commit, the B level (value bundle) only after this
// node's commit row is on chain and the round is REVEALING. Both are fetched
// from the frozen Task Builders in order (CD §6.2 V7a, V14a).

// verifierWorkerReceiptEvidenceKind keeps the signed Worker receipt the
// A-level set was bound to, so the reveal binds the B level to the same
// commitments without downloading the output again.
const verifierWorkerReceiptEvidenceKind = "verifier-worker-infer-receipt"

type evidenceLevel uint8

const (
	levelA evidenceLevel = 1
	levelB evidenceLevel = 2
)

func (l evidenceLevel) String() string {
	if l == levelB {
		return "B"
	}
	return "A"
}

// builderUnavailable is one full pass over the fixed Task Builders in which
// none delivered the level's set (CD §6.2 V7a/V14a "依次重试固定 Task Builders").
type builderUnavailable struct {
	level    evidenceLevel
	builders []string
	failed   map[string]error
}

func (u *builderUnavailable) Error() string {
	parts := make([]string, 0, len(u.failed))
	for _, b := range u.builders {
		if err, ok := u.failed[b]; ok {
			parts = append(parts, fmt.Sprintf("%s: %v", b, err))
		}
	}
	return fmt.Sprintf("no fixed Task Builder delivered the %s-level set: %s", u.level, strings.Join(parts, "; "))
}

func (u *builderUnavailable) Unwrap() []error {
	errs := make([]error, 0, len(u.failed))
	for _, b := range u.builders {
		if err, ok := u.failed[b]; ok {
			errs = append(errs, err)
		}
	}
	return errs
}

// tryBuilders asks each fixed Task Builder in order until one delivers. A
// cancelled context ends the pass early and is not a Builder's fault.
func tryBuilders(ctx context.Context, level evidenceLevel, builders []string, fetch func(context.Context, string) error) (string, error) {
	if len(builders) == 0 {
		return "", fmt.Errorf("no fixed Task Builder to fetch the %s-level set from", level)
	}
	failed := map[string]error{}
	for _, builder := range builders {
		err := fetch(ctx, builder)
		if err == nil {
			return builder, nil
		}
		if ctx.Err() != nil {
			return "", err
		}
		failed[builder] = err
	}
	return "", &builderUnavailable{level: level, builders: builders, failed: failed}
}

// fixedTaskBuilders is the frozen Task Builder order (S7 Q13). Without a
// reader it falls back to the task's receiving Builder alone.
func (e *productionVerifyExecutor) fixedTaskBuilders(ctx context.Context, task store.VerifyTask) ([]string, error) {
	if e.cfg.TaskBuilders == nil {
		if strings.TrimSpace(task.BuilderOperatorAddress) == "" {
			return nil, fmt.Errorf("verify task %s names no receiving Builder and no Task Builder reader is wired", task.TaskID)
		}
		return []string{task.BuilderOperatorAddress}, nil
	}
	builders, err := e.cfg.TaskBuilders.SelectedTaskBuilders(ctx, task.TaskID)
	if err != nil {
		return nil, builderclient.Retryable(fmt.Errorf("read the fixed Task Builders of %s: %w", task.TaskID, err))
	}
	if len(builders) == 0 {
		return nil, builderclient.Retryable(fmt.Errorf("Keeper names no fixed Task Builders for %s yet", task.TaskID))
	}
	return builders, nil
}

// evidenceCommitments is one Builder's request for the Worker's evidence,
// bound to the receipt and the locked Profile.
func (e *productionVerifyExecutor) evidenceCommitments(ctx context.Context, task store.VerifyTask, builder string, receipt builderclient.SignedInferReceipt, output []byte, chunks []uint64) (EvidenceCommitments, error) {
	// evidence_schema_hash and required_top_k are commitment inputs the receipt
	// does not carry. They are read from the locked Profile the assignment
	// names, exactly as the Worker read them when it built the commitments.
	if e.cfg.ProfileReader == nil {
		return EvidenceCommitments{}, builderclient.Retryable(fmt.Errorf("Keeper profile reader is required to confirm Worker evidence for task %s", task.TaskID))
	}
	profile, err := e.cfg.ProfileReader.CurrentModelProfile(ctx, task.ModelID, fmt.Sprintf("%d", task.ProfileVersion))
	if err != nil {
		return EvidenceCommitments{}, builderclient.Retryable(fmt.Errorf("query locked model profile: %w", err))
	}
	limits, err := workerEvidenceLimits(profile)
	if err != nil {
		return EvidenceCommitments{}, err
	}
	return EvidenceCommitments{
		SessionID: task.SessionID, TaskID: task.TaskID, BuilderOperatorAddress: builder, Receipt: receipt,
		Output: output, OutputChunkLengths: chunks, EvidenceSchemaHash: profile.Profile.VerificationProfile.EvidenceSchemaHash.Hex(),
		MaxEncodedSizeBytes: limits, RequiredTopK: profile.Profile.RequiredTopK,
	}, nil
}

// confirmWorkerTokenEvidence is the commit phase's only Worker evidence
// download (A level). A nil confirmer is the fake transport: the Verifier's
// ref path serves it.
func (e *productionVerifyExecutor) confirmWorkerTokenEvidence(ctx context.Context, taskHash codec.Hash, task store.VerifyTask, builder string, pkg builderclient.OutputPackage) (WorkerEvidence, error) {
	if e.cfg.EvidenceConfirmer == nil {
		return WorkerEvidence{}, nil
	}
	if pkg.SignedInferReceipt == nil {
		return WorkerEvidence{}, fmt.Errorf(
			"confirmed output for task %s carries no signed infer receipt, so the required evidence commitments are unknown; "+
				"the receipt is the only chain-bound source of required_evidence_commitments", task.TaskID)
	}
	commitments, err := e.evidenceCommitments(ctx, task, builder, *pkg.SignedInferReceipt, pkg.Output, pkg.OutputChunkLengths)
	if err != nil {
		return WorkerEvidence{}, err
	}
	tokens, err := e.cfg.EvidenceConfirmer.ConfirmWorkerTokenEvidence(ctx, commitments)
	if err != nil {
		return WorkerEvidence{}, err
	}
	if len(tokens.WorkerValues) > 0 {
		return WorkerEvidence{}, fmt.Errorf("%w: the A-level confirmer returned worker_values", verifier.ErrBLevelBeforeCommit)
	}
	raw, err := json.Marshal(pkg.SignedInferReceipt)
	if err != nil {
		return WorkerEvidence{}, err
	}
	if err := writeTaskEvidence(ctx, e.cfg.Evidence, taskHash, task.SessionID, task.TaskID, verifierWorkerReceiptEvidenceKind, raw); err != nil {
		return WorkerEvidence{}, fmt.Errorf("persist the Worker receipt the A-level set was bound to: %w", err)
	}
	return tokens, nil
}

// revealGate is CD §6.2 V13/V14: B-level evidence is read only once this
// node's own commit row is on chain with the persisted commit_hash (the
// caller has already required REVEALING). A non-empty stop means the reveal
// can never happen (S7 Q6).
func (e *productionVerifyExecutor) revealGate(ctx context.Context, task store.VerifyTask, persistence verifier.Persistence) (string, error) {
	committed, ok, err := verifier.PersistedCommitHash(ctx, persistence, task.TaskID, task.VerifyRound)
	if err != nil {
		return "", err
	}
	if !ok {
		return fmt.Sprintf("no signed commit is persisted for task %s round %d; there is nothing to reveal", task.TaskID, task.VerifyRound), nil
	}
	if e.cfg.VerifyCommitReader == nil {
		if e.cfg.FakeOutput {
			return "", nil
		}
		return "", builderclient.Retryable(fmt.Errorf("the Keeper VerifyCommit reader is required before the reveal reads B-level evidence (CD §6.2 V13)"))
	}
	row, err := e.cfg.VerifyCommitReader.VerifyCommit(ctx, task.TaskID, uint32(task.VerifyRound), e.cfg.LocalVerifierAddress)
	switch {
	case errors.Is(err, chainclient.ErrNotFound):
		return fmt.Sprintf("the round is REVEALING and Keeper holds no commit from %s for task %s round %d", e.cfg.LocalVerifierAddress, task.TaskID, task.VerifyRound), nil
	case err != nil:
		return "", builderclient.Retryable(fmt.Errorf("query this node's commit row: %w", err))
	case len(row.CommitHash) != 32 || codec.Hash(row.CommitHash) != committed:
		return fmt.Sprintf("Keeper holds commit_hash %x for this node, the persisted commit is %s", row.CommitHash, committed), nil
	}
	return "", nil
}

// confirmWorkerValueEvidence is CD §6.2 V14a, after revealGate. It returns
// nothing when the confirmer is the fake transport or the reveal material is
// already persisted (a retried reveal does not read the B level twice).
func (e *productionVerifyExecutor) confirmWorkerValueEvidence(ctx context.Context, taskHash codec.Hash, task store.VerifyTask, persistence verifier.Persistence, builders []string) ([]byte, *builderclient.SignedInferReceipt, string, error) {
	if e.cfg.EvidenceConfirmer == nil {
		return nil, nil, "", nil
	}
	if done, err := verifier.HasRevealMaterial(ctx, persistence); err != nil || done {
		return nil, nil, "", err
	}
	if e.cfg.Evidence == nil {
		return nil, nil, "", fmt.Errorf("task runner evidence store is required for the B-level download")
	}
	raw, err := e.cfg.Evidence.ReadTaskKind(ctx, taskHash, verifierWorkerReceiptEvidenceKind)
	if err != nil {
		return nil, nil, "", fmt.Errorf("read the Worker receipt the commit was bound to: %w", err)
	}
	var receipt builderclient.SignedInferReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return nil, nil, "", fmt.Errorf("decode the persisted Worker receipt: %w", err)
	}
	var values []byte
	served, err := tryBuilders(ctx, levelB, builders, func(ctx context.Context, builder string) error {
		commitments, err := e.evidenceCommitments(ctx, task, builder, receipt, nil, nil)
		if err != nil {
			return err
		}
		v, err := e.cfg.EvidenceConfirmer.ConfirmWorkerValueEvidence(ctx, commitments)
		if err != nil {
			e.cfg.Trace.ErrorEvent("evidence_confirm_failed", tasktrace.Str("kind", "reveal"), tasktrace.Str("task", task.TaskID),
				tasktrace.Str("builder", builder), tasktrace.Err("error", err))
			return err
		}
		values = v
		return nil
	})
	if err != nil {
		return nil, nil, "", err
	}
	return values, &receipt, served, nil
}

// resultSubmitter is the reveal's MsgSubmitVerifyResult exit. A fake-output
// node without a tx client signs and finalizes without submitting (S7 Q7).
func (e *productionVerifyExecutor) resultSubmitter(serviceAddress string) (verifier.ResultSubmitter, error) {
	if resolveWorkloadTx(e.cfg) == nil && e.cfg.FakeOutput {
		return nil, nil
	}
	submitter, err := e.commitSubmitter(serviceAddress, false)
	if err != nil {
		return nil, err
	}
	exit, ok := submitter.(verifier.ResultSubmitter)
	if !ok {
		return nil, fmt.Errorf("the verify settlement manager cannot submit a result")
	}
	return exit, nil
}
