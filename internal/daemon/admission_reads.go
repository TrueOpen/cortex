package daemon

import (
	"context"
	"sync"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/policy"
	"github.com/TrueOpen/cortex/internal/tasktrace"
)

// admissionReads holds the chain reads a Worker admission makes after the
// stored-admission check: the chain tip, handraise eligibility, the
// CandidatePool member and the envelope authorization nonce. None feeds
// another, so they are issued together. admitOrder still consumes them one by
// one in its original order, so the first failure it meets, and therefore the
// fate of the frame, is the same as when they are read one after another; only
// reads that order would have skipped are wasted.
type admissionReads struct {
	tip    chainTip
	tipDur time.Duration

	precheck       policy.WorkerPrecheckInput
	expiry         uint64
	eligibilityErr error
	eligibilityOK  bool
	eligibilityDur time.Duration

	member    chainclient.CandidateMemberRefSnapshot
	memberErr error
	memberDur time.Duration

	nonce    uint64
	nonceErr error
	nonceDur time.Duration
}

// readAdmission prefetches the reads together. Everything after the tip is
// prefetched only when the candidate's capability resolved, because admitOrder
// refuses before reading it otherwise. An accessor whose read was not
// prefetched reads on demand.
func (r *TaskRunner) readAdmission(ctx context.Context, candidate WorkerHandraiseCandidate, withEligibility bool) *admissionReads {
	reads := &admissionReads{}
	timed := func(d *time.Duration, read func()) func() {
		return func() {
			startedAt := time.Now()
			read()
			*d = time.Since(startedAt)
		}
	}
	var wg sync.WaitGroup
	wg.Go(timed(&reads.tipDur, func() { reads.tip = r.currentChainTip(ctx) }))
	if withEligibility {
		reads.eligibilityOK = true
		wg.Go(timed(&reads.eligibilityDur, func() {
			reads.precheck, reads.expiry, reads.eligibilityErr = r.workerEligibility(ctx, candidate)
		}))
	}
	if withEligibility && r.cfg.CandidateMemberReader != nil {
		wg.Go(timed(&reads.memberDur, func() {
			reads.member, reads.memberErr = r.cfg.CandidateMemberReader.CurrentCandidateMember(ctx, r.cfg.LocalWorkerAddress)
		}))
	}
	if withEligibility && r.cfg.TaskDataAuth != nil {
		wg.Go(timed(&reads.nonceDur, func() {
			reads.nonce, _, reads.nonceErr = r.cfg.TaskDataAuth.CommittedBusEnvelopeIdentity(ctx)
		}))
	}
	wg.Wait()
	return reads
}

func (a *admissionReads) chainTip() chainTip {
	return a.tip
}

func (a *admissionReads) eligibility(ctx context.Context, r *TaskRunner, candidate WorkerHandraiseCandidate) (policy.WorkerPrecheckInput, uint64, error) {
	if a.eligibilityOK {
		return a.precheck, a.expiry, a.eligibilityErr
	}
	startedAt := time.Now()
	a.precheck, a.expiry, a.eligibilityErr = r.workerEligibility(ctx, candidate)
	a.eligibilityDur = time.Since(startedAt)
	return a.precheck, a.expiry, a.eligibilityErr
}

func (a *admissionReads) candidateMember(ctx context.Context, r *TaskRunner) (chainclient.CandidateMemberRefSnapshot, error) {
	if a.eligibilityOK {
		return a.member, a.memberErr
	}
	startedAt := time.Now()
	a.member, a.memberErr = r.cfg.CandidateMemberReader.CurrentCandidateMember(ctx, r.cfg.LocalWorkerAddress)
	a.memberDur = time.Since(startedAt)
	return a.member, a.memberErr
}

func (a *admissionReads) envelopeNonce(ctx context.Context, r *TaskRunner) (uint64, error) {
	if a.eligibilityOK {
		return a.nonce, a.nonceErr
	}
	startedAt := time.Now()
	a.nonce, _, a.nonceErr = r.cfg.TaskDataAuth.CommittedBusEnvelopeIdentity(ctx)
	a.nonceDur = time.Since(startedAt)
	return a.nonce, a.nonceErr
}

func (a *admissionReads) trace(r *TaskRunner, taskID string) {
	r.cfg.Trace.Event("admission_reads",
		tasktrace.Str("task", taskID),
		tasktrace.Millis("tip_ms", a.tipDur), tasktrace.Millis("eligibility_ms", a.eligibilityDur),
		tasktrace.Millis("member_ms", a.memberDur), tasktrace.Millis("nonce_ms", a.nonceDur))
}
