package verifier

import (
	"context"
	"errors"
	"fmt"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/nodewire"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
)

// NoticeSender queues one VerifyResultSubmittedNoticeV1 on every Builder
// stream (daemon.StreamFanout).
type NoticeSender interface {
	SendVerifyResultSubmitted(ctx context.Context, notice *nexusv1.VerifyResultSubmittedNoticeV1, expiryHeight uint64) error
}

type submittedPhase string

const (
	noticeAfterCommit submittedPhase = "commit"
	noticeAfterResult submittedPhase = "result"
)

// notifySubmitted sends the phase's notice once (CD §6.2 V12, V15). The wire
// notice has no phase field, so the two notices may be byte-identical; each
// is still queued once, guarded by its own local marker. A failure leaves no
// marker and is retryable unless the sender refused the notice itself.
func (v *Verifier) notifySubmitted(ctx context.Context, state TaskState, phase submittedPhase) error {
	if v.cfg.Notices == nil {
		return nil
	}
	kind := "verifier-submitted-notice-" + string(phase)
	if reader, ok := v.cfg.Persistence.(verifierEvidenceReader); ok {
		if _, err := reader.ReadVerifierEvidence(ctx, kind); err == nil {
			return nil
		} else if !errors.Is(err, evidence.ErrArtifactNotFound) {
			return builderclient.Retryable(fmt.Errorf("read %s marker: %w", kind, err))
		}
	}
	// The notice is useful only while the phase it reports is open.
	expiry := state.CommitDeadlineHeight
	if phase == noticeAfterResult {
		expiry = state.RevealDeadlineHeight
	}
	if expiry == 0 {
		expiry = state.VerifyDeadlineHeight
	}
	facts, err := v.taskFacts(ctx, state.TaskID)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("accepted task hash for the submitted notice: %w", err))
	}
	taskID, err := hash32FromHex("task_id", state.TaskID)
	if err != nil {
		return err
	}
	key, err := nodewire.VerifyCommitKey(v.cfg.ChainID, taskID[:], uint32(state.VerifyRound), v.cfg.VerifierAddress)
	if err != nil {
		return err
	}
	notice := &nexusv1.VerifyResultSubmittedNoticeV1{
		TaskId: taskID[:], TaskHash: append([]byte(nil), facts.AcceptedTaskHash...), VerifyRound: uint32(state.VerifyRound),
		CommitKey: key[:], OperatorAddress: v.cfg.VerifierAddress, ServiceAuthorizationNonce: v.cfg.ServiceAuthorizationNonce,
	}
	if err := dispatchwire.SignVerifyResultSubmitted(ctx, notice, func(ctx context.Context, d [32]byte) ([]byte, error) {
		return v.signDigest(ctx, codec.Hash(d))
	}); err != nil {
		return err
	}
	if err := v.cfg.Notices.SendVerifyResultSubmitted(ctx, notice, expiry); err != nil {
		if builderclient.IsPermanent(err) {
			return err
		}
		return builderclient.Retryable(fmt.Errorf("queue the %s submitted notice: %w", phase, err))
	}
	if v.cfg.Persistence == nil {
		return nil
	}
	raw, err := dispatchwire.Raw(notice)
	if err != nil {
		return err
	}
	return v.cfg.Persistence.WriteEvidence(ctx, EvidenceRecord{TaskID: state.TaskID, Kind: kind, Data: raw, Ref: evidenceRef(raw)})
}
