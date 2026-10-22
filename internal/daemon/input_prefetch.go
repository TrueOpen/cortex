package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/tasktrace"
	busv1 "github.com/TrueOpen/cortex/proto/bus/v1"
)

const (
	// inputPrefetchTTL bounds how long a prefetched input waits for the
	// executor. The chain confirms an assignment within a few blocks of the
	// notification; an input nobody took by then is dropped, and the attempt
	// that eventually runs fetches for itself.
	inputPrefetchTTL = 60 * time.Second
	// inputPrefetchDownloadTimeout bounds the download itself, retries
	// included. It is separate from the TTL: the TTL is how long finished
	// bytes may wait, this is how long a Builder may take to deliver them.
	inputPrefetchDownloadTimeout = 15 * time.Second
	// inputPrefetchTakeWait bounds how long the executor waits for a download
	// still in flight. Past it the executor cancels the prefetch and fetches
	// for itself, so a hung prefetch costs at most this much over today.
	inputPrefetchTakeWait = 2 * time.Second
	// inputPrefetchMaxEntries and inputPrefetchMaxBytes bound the memory the
	// prefetches can hold: at most this many inputs of at most this size each.
	// A larger input, or one whose size the order did not state, is fetched by
	// the executor as before.
	inputPrefetchMaxEntries = 8
	inputPrefetchMaxBytes   = uint64(8 << 20)
	// inputPrefetchAttempts bounds the downloads one prefetch makes. A
	// Builder authorizes the input for the Worker its own chain view says was
	// selected, so a Builder whose node is a block behind refuses the first
	// try; the next one, a moment later, usually succeeds.
	inputPrefetchAttempts = 4
	inputPrefetchBackoff  = 100 * time.Millisecond
	// inputPrefetchRoleDenied is the text a Builder puts in its PermissionDenied
	// answer when the requester does not hold the download role for the task
	// in the Builder's own chain view.
	inputPrefetchRoleDenied = "download role"
)

// inputPrefetch is one task input download started when a Builder announced
// that this node won the assignment, before the local chain view confirms it.
//
// The bytes stay in memory. Nothing is written to the evidence store or the
// task documents until the executor takes them, and the executor runs only for
// an assignment the chain has confirmed and the reconciler has recorded. An
// input that is never taken -- the chain named another Worker, the task ended,
// or nobody asked within inputPrefetchTTL -- is dropped.
type inputPrefetch struct {
	ref       TaskInputRef
	startedAt time.Time
	cancel    context.CancelFunc
	expiry    *time.Timer
	done      chan struct{}
	// taken is closed when the executor claims the entry; a failed download
	// is then not retried.
	taken chan struct{}
	// Written by the download goroutine before done is closed.
	input    []byte
	err      error
	attempts int
	elapsed  time.Duration
}

// inputPrefetches holds the in-flight and finished prefetches by task hash.
type inputPrefetches struct {
	mu      sync.Mutex
	entries map[codec.Hash]*inputPrefetch
	closed  bool
	wg      sync.WaitGroup
	trace   *tasktrace.Trace

	ttl        time.Duration
	download   time.Duration
	takeWait   time.Duration
	maxEntries int
	maxBytes   uint64
	attempts   int
	backoff    time.Duration
}

func newInputPrefetches(trace *tasktrace.Trace) *inputPrefetches {
	return &inputPrefetches{
		entries: make(map[codec.Hash]*inputPrefetch), trace: trace,
		ttl: inputPrefetchTTL, download: inputPrefetchDownloadTimeout, takeWait: inputPrefetchTakeWait, maxEntries: inputPrefetchMaxEntries, maxBytes: inputPrefetchMaxBytes,
		attempts: inputPrefetchAttempts, backoff: inputPrefetchBackoff,
	}
}

// start begins downloading ref unless a prefetch for the task already exists,
// the set is full or closed, or the input is too large to hold. It never
// blocks on the download.
func (s *inputPrefetches) start(ctx context.Context, resolver TaskInputResolver, ref TaskInputRef) (bool, string) {
	if s == nil || resolver == nil {
		return false, "unavailable"
	}
	if ref.InputSizeBytes == 0 || ref.InputSizeBytes > s.maxBytes {
		return false, "input_size"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.closed:
		return false, "closed"
	case s.entries[ref.TaskHash] != nil:
		return false, "duplicate"
	case len(s.entries) >= s.maxEntries:
		return false, "capacity"
	}
	fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), min(s.download, s.ttl))
	entry := &inputPrefetch{ref: ref, startedAt: time.Now(), cancel: cancel, done: make(chan struct{}), taken: make(chan struct{})}
	s.entries[ref.TaskHash] = entry
	entry.expiry = time.AfterFunc(s.ttl, func() { s.discard(ref.TaskHash, "expired") })
	// The download stops when the handler's context does (shutdown), when the
	// entry is discarded, or at the TTL, whichever comes first.
	stop := context.AfterFunc(ctx, cancel)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer stop()
		defer close(entry.done)
	retry:
		for entry.attempts < s.attempts {
			entry.attempts++
			input, err := resolver.ResolveTaskInput(fetchCtx, ref)
			if err == nil && codec.HashBytes(input) != codec.Hash(ref.PayloadHash) {
				err = fmt.Errorf("prefetched task input hash does not match the signed order's input hash")
			}
			entry.input, entry.err = input, err
			if err == nil || fetchCtx.Err() != nil || entry.attempts >= s.attempts || !prefetchRetryable(err) {
				break
			}
			// Once the executor is waiting, the chain has confirmed the
			// assignment and the executor's own fetch is the faster retry.
			timer := time.NewTimer(s.backoff * time.Duration(entry.attempts))
			select {
			case <-fetchCtx.Done():
				timer.Stop()
				break retry
			case <-entry.taken:
				timer.Stop()
				break retry
			case <-timer.C:
			}
		}
		if entry.err != nil {
			entry.input = nil
		}
		entry.elapsed = time.Since(entry.startedAt)
		traceEvent := s.trace.Event
		if entry.err != nil {
			traceEvent = s.trace.ErrorEvent
		}
		traceEvent("input_prefetch_completed",
			tasktrace.Str("task", ref.TaskID), tasktrace.Hash("task_hash", ref.TaskHash),
			tasktrace.Str("builder", ref.BuilderOperatorAddress),
			tasktrace.Int("attempts", entry.attempts), tasktrace.Int("input_bytes", len(entry.input)),
			tasktrace.Millis("elapsed_ms", entry.elapsed), tasktrace.Err("error", entry.err))
	}()
	return true, ""
}

// take hands the prefetched input for ref to the one executor that asks for
// it, waiting up to takeWait for a download still in flight. It returns no
// bytes -- and the caller fetches for itself -- when there is none, when it
// was started for a different input, when it failed, or when it is still
// running at the bound. Whatever the outcome, the entry is removed: a
// prefetch is used at most once.
func (s *inputPrefetches) take(ctx context.Context, ref TaskInputRef) ([]byte, time.Duration, string) {
	if s == nil {
		return nil, 0, "none"
	}
	s.mu.Lock()
	entry := s.entries[ref.TaskHash]
	if entry != nil {
		delete(s.entries, ref.TaskHash)
		entry.expiry.Stop()
	}
	s.mu.Unlock()
	if entry == nil {
		return nil, 0, "none"
	}
	close(entry.taken)
	if !sameInputRef(entry.ref, ref) {
		entry.cancel()
		return nil, 0, "ref_mismatch"
	}
	waitStartedAt := time.Now()
	bound := time.NewTimer(s.takeWait)
	defer bound.Stop()
	select {
	case <-entry.done:
	case <-ctx.Done():
		entry.cancel()
		return nil, time.Since(waitStartedAt), "cancelled"
	case <-bound.C:
		// select picks at random when both are ready; a download that
		// finished right at the bound is still used.
		select {
		case <-entry.done:
		default:
			entry.cancel()
			return nil, time.Since(waitStartedAt), "timeout"
		}
	}
	entry.cancel()
	if entry.err != nil {
		return nil, time.Since(waitStartedAt), "failed"
	}
	return entry.input, time.Since(waitStartedAt), "used"
}

// sameInputRef reports whether a prefetch made for a was made for the input b
// names. PayloadCID is left out: it is a location hint the reconciler never
// fills (the chain no longer carries it) and the Nexus resolver never reads,
// while the bytes are bound by PayloadHash, which is compared, and checked
// again against the chain's accepted payload hash by the executor.
func sameInputRef(a, b TaskInputRef) bool {
	a.PayloadCID, b.PayloadCID = "", ""
	return a == b
}

// prefetchRetryable reports whether a failed prefetch download may succeed on
// a later attempt: a failure the task-data client classified as retryable, or
// the Builder refusing the download role because its own chain view has not
// reached the assignment yet. A hash or size mismatch, and every other
// refusal, ends the prefetch at once; each attempt is a signed request to the
// Builder, and the executor fetches for itself anyway.
func prefetchRetryable(err error) bool {
	if err == nil || builderclient.IsPermanent(err) {
		return false
	}
	if builderclient.IsRetryable(err) {
		return true
	}
	return connect.CodeOf(err) == connect.CodePermissionDenied && strings.Contains(err.Error(), inputPrefetchRoleDenied)
}

// discard drops the prefetch for a task without using it: the chain assigned
// it elsewhere, the task ended, or it expired.
func (s *inputPrefetches) discard(taskHash codec.Hash, reason string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	entry := s.entries[taskHash]
	if entry != nil {
		delete(s.entries, taskHash)
		entry.expiry.Stop()
	}
	s.mu.Unlock()
	if entry == nil {
		return
	}
	entry.cancel()
	s.trace.Event("input_prefetch_discarded",
		tasktrace.Str("task", entry.ref.TaskID), tasktrace.Hash("task_hash", taskHash),
		tasktrace.Str("reason", reason))
}

// close cancels every prefetch and waits for the downloads to return, so none
// outlives the runner. Later starts are refused.
func (s *inputPrefetches) close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	entries := s.entries
	s.entries = make(map[codec.Hash]*inputPrefetch)
	s.mu.Unlock()
	for _, entry := range entries {
		entry.expiry.Stop()
		entry.cancel()
	}
	s.wg.Wait()
}

// prefetchAssignedInput starts downloading the task input as soon as a
// WORKER_ASSIGNMENT_NOTIFY names this node the winner, so the download runs
// while the local chain view catches up with the assignment instead of after
// it.
//
// Nothing here is authority. The reference is rebuilt from this node's own
// candidate admission -- the signed order it bid on and the Builder that
// broadcast it -- and checked against the frame; the bytes are checked against
// the signed order's input hash; and the executor uses them only for an
// assignment the chain confirmed, with exactly this reference, after checking
// them again against the chain's accepted payload hash. A Builder releases the
// input only to the Worker its chain view selected, so this does not let a
// candidate that lost read the input either.
//
// It is skipped when the assignment is already recorded locally: the executor
// is then about to run, or running, and fetches for itself.
func (r *TaskRunner) prefetchAssignedInput(ctx context.Context, taskID string, message *busv1.WorkerAssignmentNotifyV1) {
	if r.prefetches == nil || r.cfg.InputResolver == nil || r.cfg.Store == nil {
		return
	}
	taskHash := codec.Hash(message.GetTaskHash())
	skip := func(reason string) {
		r.cfg.Trace.Event("input_prefetch_skipped",
			tasktrace.Str("task", taskID), tasktrace.Hash("task_hash", taskHash), tasktrace.Str("reason", reason))
	}
	if _, err := layout.GetInferRecord(ctx, r.cfg.Store, layout.StoredHash(taskHash)); err == nil {
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		skip("store_error")
		return
	}
	admission, err := layout.GetCandidateAdmission(ctx, r.cfg.Store, layout.StoredHash(taskHash))
	if err != nil {
		skip("no_candidate_admission")
		return
	}
	hash, facts, err := admittedOrderFacts(admission)
	if err != nil || hash != taskHash || identity.TaskIDString(facts.SessionID, facts.OrderSequence) != taskID {
		skip("admission_mismatch")
		return
	}
	inputHash, err := decodeHash32Hex(strings.TrimPrefix(facts.InputHash, "0x"))
	if err != nil {
		skip("input_hash")
		return
	}
	if notified := message.GetInputHash(); len(notified) != 0 && !bytes.Equal(notified, inputHash[:]) {
		skip("input_hash_mismatch")
		return
	}
	builder := strings.TrimSpace(admission.BroadcastingBuilder)
	if builder == "" || builder != admission.BroadcastingBuilder {
		skip("no_builder")
		return
	}
	// The size the reconciler copies into the assignment record, so the
	// reference matches the one the executor builds.
	size := admission.InputSizeBytes
	ref := TaskInputRef{
		SessionID: facts.SessionID, TaskID: taskID, TaskHash: taskHash,
		PayloadHash: chainclient.HexHash(inputHash), BuilderOperatorAddress: builder, InputSizeBytes: size,
	}
	started, reason := r.prefetches.start(ctx, r.cfg.InputResolver, ref)
	if !started {
		if reason != "duplicate" {
			skip(reason)
		}
		return
	}
	r.cfg.Trace.Event("input_prefetch_started",
		tasktrace.Str("task", taskID), tasktrace.Hash("task_hash", taskHash),
		tasktrace.Str("builder", builder), tasktrace.Uint("input_size_bytes", size),
		tasktrace.Uint("finalized_height", message.GetFinalizedHeight()),
		tasktrace.Str("input_hash", hex.EncodeToString(inputHash[:])))
}
