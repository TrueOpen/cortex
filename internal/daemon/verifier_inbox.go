package daemon

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/tasktrace"
)

// The OPEN_VERIFY inbox. A Verifier call is applied once per business key
// (task_id, verify_round) whichever Builders deliver it (CD §6.2 V1), and it
// stays owed until it is answered: the call usually arrives before the
// verifier candidate window it must bind to is READY, and nothing redelivers
// it (see task_runner_nexus.go raiseVerifierHand).
//
//	verifier-inbox/<task_id hex>/<verify_round>   verifierInboxEntry (JSON)
const (
	verifierInboxPrefix = "verifier-inbox/"
	inboxPending        = "pending"
	inboxDone           = "done"
	inboxRefused        = "refused"
	inboxAbandoned      = "abandoned"
)

type verifierInboxEntry struct {
	Trigger verifierHandraiseTrigger `json:"trigger"`
	// Builders is every Builder that delivered the call, first first.
	Builders []string `json:"builders"`
	State    string   `json:"state"`
	Attempts uint64   `json:"attempts"`
	// FirstHeight is the first attempt's readable chain height; GiveUpHeight
	// is FirstHeight + the verify deadline delta. Both stay zero until a
	// readable tip is seen.
	FirstHeight  uint64 `json:"first_height"`
	LastHeight   uint64 `json:"last_height"`
	GiveUpHeight uint64 `json:"give_up_height"`
	LastError    string `json:"last_error,omitempty"`
}

type verifierInbox struct {
	st   *store.Store
	span uint64 // blocks from the first readable attempt to giving up
}

func verifierInboxKey(taskID string, round uint32) []byte {
	return fmt.Appendf(nil, "%s%s/%d", verifierInboxPrefix, taskID, round)
}

func putInboxEntry(b *store.Batch, key []byte, e verifierInboxEntry) error {
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return b.Set(key, raw)
}

// admit records one OPEN_VERIFY. fresh is true only for the first delivery of
// this (task_id, verify_round); later ones, from any Builder, only append
// their sender. A record that no longer decodes is replaced by this delivery.
func (b verifierInbox) admit(ctx context.Context, builder string, trigger verifierHandraiseTrigger) (fresh bool, err error) {
	key := verifierInboxKey(trigger.TaskID, trigger.VerifyRound)
	err = b.st.ApplyBatch(ctx, func(batch *store.Batch) error {
		fresh = false
		raw, err := batch.Get(key)
		if errors.Is(err, store.ErrNotFound) {
			fresh = true
			return putInboxEntry(batch, key, verifierInboxEntry{Trigger: trigger, Builders: []string{builder}, State: inboxPending})
		}
		if err != nil {
			return err
		}
		var e verifierInboxEntry
		if json.Unmarshal(raw, &e) != nil {
			fresh = true
			return putInboxEntry(batch, key, verifierInboxEntry{Trigger: trigger, Builders: []string{builder}, State: inboxPending})
		}
		if slices.Contains(e.Builders, builder) {
			return nil
		}
		e.Builders = append(e.Builders, builder)
		return putInboxEntry(batch, key, e)
	})
	return fresh, err
}

func (b verifierInbox) load(ctx context.Context, taskID string, round uint32) (verifierInboxEntry, bool, error) {
	raw, err := b.st.GetRaw(ctx, verifierInboxKey(taskID, round))
	if errors.Is(err, store.ErrNotFound) {
		return verifierInboxEntry{}, false, nil
	}
	if err != nil {
		return verifierInboxEntry{}, false, err
	}
	var e verifierInboxEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return verifierInboxEntry{}, false, fmt.Errorf("decode verifier inbox entry %s/%d: %w", taskID, round, err)
	}
	return e, true, nil
}

// update re-reads key inside one batch and applies fn, so a concurrent admit
// appending a Builder is never overwritten. A missing entry is left missing.
func (b verifierInbox) update(ctx context.Context, key []byte, fn func(*verifierInboxEntry)) error {
	return b.st.ApplyBatch(ctx, func(batch *store.Batch) error {
		raw, err := batch.Get(key)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		var e verifierInboxEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			return fmt.Errorf("decode verifier inbox entry %q: %w", key, err)
		}
		fn(&e)
		return putInboxEntry(batch, key, e)
	})
}

// maxVerifierInboxAttempts bounds one round when the tip is unreadable and
// the height bound cannot be evaluated.
const maxVerifierInboxAttempts = 64

// inboxExpiry names why a pending round is abandoned, or "" while it is
// still owed an attempt.
func inboxExpiry(e verifierInboxEntry, tip chainTip) string {
	if tip.readable && e.GiveUpHeight > 0 && tip.height > e.GiveUpHeight {
		return fmt.Sprintf("verify deadline bound height %d passed at chain height %d", e.GiveUpHeight, tip.height)
	}
	if e.Attempts >= maxVerifierInboxAttempts {
		return fmt.Sprintf("handraise attempts reached the bound %d", maxVerifierInboxAttempts)
	}
	return ""
}

// take splits the pending entries into the ones whose bound has passed
// (marked abandoned here) and the ones due now. Due is gated on the height
// having moved: the window materializes at a block boundary, so a second
// query inside one height can only return the first one's answer.
func (b verifierInbox) take(ctx context.Context, tip chainTip) (due, abandoned []verifierInboxEntry, err error) {
	var pending []verifierInboxEntry
	err = b.st.ScanPrefix(ctx, []byte(verifierInboxPrefix), func(_, value []byte) error {
		var e verifierInboxEntry
		if json.Unmarshal(value, &e) == nil && e.State == inboxPending {
			pending = append(pending, e)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	for _, e := range pending {
		if reason := inboxExpiry(e, tip); reason != "" {
			key := verifierInboxKey(e.Trigger.TaskID, e.Trigger.VerifyRound)
			if err := b.update(ctx, key, func(x *verifierInboxEntry) { x.State, x.LastError = inboxAbandoned, reason }); err != nil {
				return nil, nil, err
			}
			e.State, e.LastError = inboxAbandoned, reason
			abandoned = append(abandoned, e)
			continue
		}
		if e.Attempts > 0 && tip.readable && e.LastHeight >= tip.height {
			continue
		}
		due = append(due, e)
	}
	return due, abandoned, nil
}

// settle records one attempt. Only a retryable refusal keeps the round owed:
// an unmarked error is a call contradicting Keeper authority and a Permanent
// one is a closed window, and asking again would re-decide a question the
// chain has answered.
func (b verifierInbox) settle(ctx context.Context, trigger verifierHandraiseTrigger, tip chainTip, attempt error) error {
	return b.update(ctx, verifierInboxKey(trigger.TaskID, trigger.VerifyRound), func(e *verifierInboxEntry) {
		e.Attempts++
		if tip.readable {
			e.LastHeight = tip.height
			if e.FirstHeight == 0 {
				e.FirstHeight, e.GiveUpHeight = tip.height, tip.height+b.span
			}
		}
		switch {
		case attempt == nil:
			e.State, e.LastError = inboxDone, ""
		case builderclient.IsRetryable(attempt):
			e.LastError = attempt.Error()
		default:
			e.State, e.LastError = inboxRefused, attempt.Error()
		}
	})
}

// prune drops settled entries one span after their bound (they keep
// absorbing late duplicates until then) and entries that no longer decode.
func (b verifierInbox) prune(ctx context.Context, tip chainTip) error {
	if !tip.readable {
		return nil
	}
	var stale [][]byte
	err := b.st.ScanPrefix(ctx, []byte(verifierInboxPrefix), func(key, value []byte) error {
		var e verifierInboxEntry
		if json.Unmarshal(value, &e) != nil ||
			(e.State != inboxPending && (e.GiveUpHeight == 0 || tip.height > e.GiveUpHeight+b.span)) {
			stale = append(stale, append([]byte(nil), key...))
		}
		return nil
	})
	if err != nil || len(stale) == 0 {
		return err
	}
	return b.st.ApplyBatch(ctx, func(batch *store.Batch) error {
		for _, key := range stale {
			if err := batch.Delete(key); err != nil {
				return err
			}
		}
		return nil
	})
}

// drainVerifierInbox is the poll loop's half of the inbox: it answers every
// owed OPEN_VERIFY once per block until it is done, refused or past its
// bound. It never returns an error: RunOnce's error stops the daemon.
func (r *TaskRunner) drainVerifierInbox(ctx context.Context, tip chainTip) {
	if r == nil || r.cfg.Store == nil || ctx.Err() != nil {
		return
	}
	inbox := verifierInbox{st: r.cfg.Store, span: r.cfg.VerifyDeadlineDeltaHeight}
	report := func(record, msg string, count uint64) {
		if r.cfg.Diagnostic != nil {
			r.cfg.Diagnostic(TaskRunnerDiagnostic{Source: "verifier_inbox", Record: record, Error: msg, Count: int64(count)})
		}
	}
	due, abandoned, err := inbox.take(ctx, tip)
	if err != nil {
		report("", err.Error(), 0)
		return
	}
	for _, e := range abandoned {
		r.cfg.Trace.ErrorEvent("verifier_handraise_abandoned",
			tasktrace.Str("task", e.Trigger.TaskID), tasktrace.Uint("verify_round", uint64(e.Trigger.VerifyRound)),
			tasktrace.Uint("attempts", e.Attempts), tasktrace.Uint("first_height", e.FirstHeight),
			tasktrace.Uint("current_height", tip.height), tasktrace.Str("reason", e.LastError))
		r.forgetChainWait(chainWaitKey(e.Trigger.TaskID, e.Trigger.VerifyRound))
		report(e.Trigger.TaskID, "Verifier handraise abandoned: "+e.LastError, e.Attempts)
	}
	for _, e := range due {
		if ctx.Err() != nil {
			return
		}
		taskID, _ := hex.DecodeString(e.Trigger.TaskID)
		attempt := r.builderFrameVerdict("nexus_open_verify", taskID, r.raiseVerifierHand(ctx, e.Trigger))
		if err := inbox.settle(ctx, e.Trigger, tip, attempt); err != nil {
			report(e.Trigger.TaskID, err.Error(), 0)
		}
	}
	if err := inbox.prune(ctx, tip); err != nil {
		report("", err.Error(), 0)
	}
}
