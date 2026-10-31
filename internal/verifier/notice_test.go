package verifier

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/txclient"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
)

type recordingNotices struct {
	notices  []*nexusv1.VerifyResultSubmittedNoticeV1
	expiries []uint64
	err      error
}

func (r *recordingNotices) SendVerifyResultSubmitted(_ context.Context, n *nexusv1.VerifyResultSubmittedNoticeV1, expiry uint64) error {
	if r.err != nil {
		return r.err
	}
	r.notices = append(r.notices, n)
	r.expiries = append(r.expiries, expiry)
	return nil
}

// CD §6.2 V12/V15: one notice after the commit is handed off, one after the result.
func TestSubmittedNoticeFollowsTheCommitAndTheResultOnceEach(t *testing.T) {
	h := newHarness(t)
	notices := &recordingNotices{}
	h.verifier.cfg.Notices = notices
	h.verifier.cfg.ResultSubmitter = testResultSubmitter(h.tx)
	state := h.validTask()
	state.OpenVerifyAccepted = true
	verifyLocally(t, h, state)
	if len(notices.notices) != 1 || notices.expiries[0] != state.CommitDeadlineHeight {
		t.Fatalf("after commit: %d notices, expiries %v", len(notices.notices), notices.expiries)
	}
	h.verifier = New(h.verifier.cfg)
	verifyLocally(t, h, state) // resumes the persisted commit
	if len(notices.notices) != 1 {
		t.Fatalf("a resumed commit re-sent its notice: %d", len(notices.notices))
	}
	revealLocally(t, h, state)
	if len(notices.notices) != 2 || notices.expiries[1] != state.RevealDeadlineHeight {
		t.Fatalf("after result: %d notices, expiries %v", len(notices.notices), notices.expiries)
	}
	h.verifier = New(h.verifier.cfg)
	revealLocally(t, h, state)
	if len(notices.notices) != 2 {
		t.Fatalf("a repeated reveal re-sent its notice: %d", len(notices.notices))
	}
	taskID, _ := hex.DecodeString(state.TaskID)
	wantKey, err := nodewire.VerifyCommitKey(h.verifier.cfg.ChainID, taskID, uint32(state.VerifyRound), fixtureVerifierAddress)
	if err != nil {
		t.Fatal(err)
	}
	accepted := servedTaskFacts(state.TaskID).AcceptedTaskHash
	for i, n := range notices.notices {
		if !bytes.Equal(n.GetTaskId(), taskID) || !bytes.Equal(n.GetTaskHash(), accepted) || n.GetVerifyRound() != 1 ||
			!bytes.Equal(n.GetCommitKey(), wantKey[:]) || n.GetOperatorAddress() != fixtureVerifierAddress ||
			n.GetServiceAuthorizationNonce() != 11 || len(n.GetServiceSignature()) != 64 {
			t.Fatalf("notice %d = %+v", i, n)
		}
	}
}

func TestSubmittedNoticeFailureIsRetryableAndNotRecorded(t *testing.T) {
	h := newHarness(t)
	notices := &recordingNotices{err: errors.New("no Builder stream accepted it")}
	h.verifier.cfg.Notices = notices
	state := h.validTask()
	state.OpenVerifyAccepted = true
	if _, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state); !builderclient.IsRetryable(err) {
		t.Fatalf("error = %v, want a retryable notice failure", err)
	}
	notices.err = nil
	verifyLocally(t, h, state)
	if len(notices.notices) != 1 {
		t.Fatalf("notices after the retry = %d, want 1", len(notices.notices))
	}
}

// A permanent refusal (an invalid notice) is not dressed up as retryable.
func TestSubmittedNoticePermanentFailureStaysPermanent(t *testing.T) {
	h := newHarness(t)
	h.verifier.cfg.Notices = &recordingNotices{err: builderclient.Permanent(errors.New("invalid notice"))}
	state := h.validTask()
	state.OpenVerifyAccepted = true
	if _, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state); !builderclient.IsPermanent(err) {
		t.Fatalf("error = %v, want the permanent refusal kept", err)
	}
}

// The daemon resumes a persisted commit through ResumePersistedCommit directly.
// A first delivery that fails and a resumed one that lands must still queue
// the commit notice, exactly once.
func TestResumedCommitSendsItsNoticeOnce(t *testing.T) {
	h := newHarness(t)
	notices := &recordingNotices{}
	h.verifier.cfg.Notices = notices
	state := h.validTask()
	state.OpenVerifyAccepted = true
	h.tx.RejectNext(txclient.MsgSubmitVerifyCommit, "mempool full")
	if _, err := h.verifier.HandleOpenVerifyAccepted(context.Background(), state); err == nil {
		t.Fatal("a rejected commit was reported as delivered")
	}
	if len(notices.notices) != 0 {
		t.Fatalf("notices after a failed delivery = %d, want 0", len(notices.notices))
	}
	for range 2 {
		resumed := New(h.verifier.cfg)
		if _, ok, err := resumed.ResumePersistedCommit(context.Background(), state); err != nil || !ok {
			t.Fatalf("resume = %v, %v", ok, err)
		}
	}
	if len(notices.notices) != 1 || notices.expiries[0] != state.CommitDeadlineHeight {
		t.Fatalf("notices = %d (expiries %v), want exactly one commit notice", len(notices.notices), notices.expiries)
	}
}
