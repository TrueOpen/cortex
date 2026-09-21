package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/store"
)

func TestKeeperPollerReplaysWholeBlockBeforeAdvancingHeight(t *testing.T) {
	ctx := context.Background()
	db := openPollerTestStore(t)
	hashA := codec.HashWithDomain("TEST_TASK", []byte("a"))
	hashB := codec.HashWithDomain("TEST_TASK", []byte("b"))
	page := chainclient.KeeperEventsPage{
		ChainHeight: 20, FinalizedHeight: 12, LastPosition: chainclient.BlockEndPosition(12), RangeStartHeight: 1, RangeEndHeight: 12, RangeComplete: true,
		Events: []chainclient.KeeperEvent{
			{Type: chainclient.KeeperEventAssignmentFailed, TaskID: "task-a", SessionID: "session-1", OrderDigest: hashA, Height: 12},
			{Type: chainclient.KeeperEventAssignmentFailed, TaskID: "task-b", SessionID: "session-1", OrderDigest: hashB, Height: 12},
		},
	}
	keeper := &scriptedKeeperEvents{pages: []chainclient.KeeperEventsPage{page, page}, taskReader: terminalTaskReader(map[string]codec.Hash{"task-a": hashA, "task-b": hashB})}
	applied := map[codec.Hash]bool{}
	calls := 0
	poller := NewKeeperPoller(db, keeper, NewReconciler(ReconcilerOptions{TaskReader: keeper.taskReader}), KeeperPollerConfig{
		EffectSink: func(_ context.Context, effects []ReconcilerEffect) error {
			calls++
			for i, effect := range effects {
				applied[effect.TaskHash] = true
				if calls == 1 && i == 0 {
					return errors.New("manager stopped midway through block")
				}
			}
			return nil
		},
	})

	if err := poller.RunOnce(ctx); err == nil {
		t.Fatal("RunOnce() = nil, want partial block failure")
	}
	if height, err := db.KeeperLastProcessedHeight(ctx); err != nil || height != 0 {
		t.Fatalf("height after partial block = %d, %v; want 0", height, err)
	}
	if err := poller.RunOnce(ctx); err != nil {
		t.Fatalf("replayed RunOnce() error = %v", err)
	}
	if height, err := db.KeeperLastProcessedHeight(ctx); err != nil || height != 12 {
		t.Fatalf("height after replay = %d, %v; want 12", height, err)
	}
	if !applied[hashA] || !applied[hashB] {
		t.Fatalf("applied task hashes = %#v, want both block effects", applied)
	}
}

func TestKeeperPollerCommitsCompletedBlocksIndependently(t *testing.T) {
	ctx := context.Background()
	db := openPollerTestStore(t)
	hashA := codec.HashWithDomain("TEST_TASK", []byte("a"))
	hashB := codec.HashWithDomain("TEST_TASK", []byte("b"))
	keeper := &scriptedKeeperEvents{pages: []chainclient.KeeperEventsPage{{
		ChainHeight: 20, FinalizedHeight: 12, LastPosition: chainclient.BlockEndPosition(12), RangeStartHeight: 1, RangeEndHeight: 12, RangeComplete: true,
		Events: []chainclient.KeeperEvent{
			{Type: chainclient.KeeperEventAssignmentFailed, TaskID: "task-a", SessionID: "session-1", OrderDigest: hashA, Height: 11},
			{Type: chainclient.KeeperEventAssignmentFailed, TaskID: "task-b", SessionID: "session-1", OrderDigest: hashB, Height: 12},
		},
	}}, taskReader: terminalTaskReader(map[string]codec.Hash{"task-a": hashA, "task-b": hashB})}
	poller := NewKeeperPoller(db, keeper, NewReconciler(ReconcilerOptions{TaskReader: keeper.taskReader}), KeeperPollerConfig{
		EffectSink: func(_ context.Context, effects []ReconcilerEffect) error {
			if len(effects) == 1 && effects[0].TaskHash == hashB {
				return errors.New("block 12 failed")
			}
			return nil
		},
	})

	if err := poller.RunOnce(ctx); err == nil {
		t.Fatal("RunOnce() = nil, want block 12 failure")
	}
	if height, err := db.KeeperLastProcessedHeight(ctx); err != nil || height != 11 {
		t.Fatalf("height = %d, %v; want completed block 11", height, err)
	}
}

func TestKeeperPollerResumesFromKeeperHeightAndReportsCommittedLag(t *testing.T) {
	ctx := context.Background()
	db := openPollerTestStore(t)
	if _, err := db.AdvanceKeeperLastProcessedHeight(ctx, 44); err != nil {
		t.Fatalf("seed Keeper height: %v", err)
	}
	keeper := &scriptedKeeperEvents{pages: []chainclient.KeeperEventsPage{{
		ChainHeight: 50, FinalizedHeight: 46, LastPosition: chainclient.BlockEndPosition(46), RangeStartHeight: 45, RangeEndHeight: 46, RangeComplete: true,
	}}}
	var lag []uint64
	poller := NewKeeperPoller(db, keeper, NewReconciler(ReconcilerOptions{}), KeeperPollerConfig{
		ObserveChainProgress: func(progress ChainProgress) { lag = append(lag, progress.Lag()) },
	})

	if err := poller.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if got := keeper.positions; len(got) != 1 || got[0] != chainclient.BlockEndPosition(44) {
		t.Fatalf("positions = %#v, want block end 44", got)
	}
	if height, err := db.KeeperLastProcessedHeight(ctx); err != nil || height != 46 {
		t.Fatalf("height = %d, %v; want 46", height, err)
	}
	if !reflect.DeepEqual(lag, []uint64{6, 4}) {
		t.Fatalf("lag = %v, want [6 4] around durable commit", lag)
	}
}

func TestKeeperPollerDoesNotAdvancePastIncompleteRange(t *testing.T) {
	ctx := context.Background()
	db := openPollerTestStore(t)
	if _, err := db.AdvanceKeeperLastProcessedHeight(ctx, 40); err != nil {
		t.Fatal(err)
	}
	keeper := &scriptedKeeperEvents{pages: []chainclient.KeeperEventsPage{{
		ChainHeight: 50, FinalizedHeight: 46, RangeStartHeight: 41, RangeEndHeight: 43,
		RangeComplete: false, NextPageToken: "continue-43",
	}}}
	poller := NewKeeperPoller(db, keeper, NewReconciler(ReconcilerOptions{}), KeeperPollerConfig{})
	if err := poller.RunOnce(ctx); err == nil {
		t.Fatal("RunOnce() = nil, want incomplete range error")
	}
	if height, err := db.KeeperLastProcessedHeight(ctx); err != nil || height != 40 {
		t.Fatalf("height = %d, %v; want unchanged 40", height, err)
	}
}

// The name is the contract: an unscanned gap must not move the cursor. Nothing
// can rebuild the affected responsibilities without those events, so "skip" is
// never an answer - only "wait" (retryable) or "stop".
func TestKeeperPollerDoesNotAdvanceAcrossUnscannedGap(t *testing.T) {
	ctx := context.Background()
	db := openPollerTestStore(t)
	if _, err := db.AdvanceKeeperLastProcessedHeight(ctx, 40); err != nil {
		t.Fatal(err)
	}
	keeper := &scriptedKeeperEvents{pages: []chainclient.KeeperEventsPage{{
		ChainHeight: 50, FinalizedHeight: 46, RangeStartHeight: 42, RangeEndHeight: 46,
		RangeComplete: true, LastPosition: chainclient.BlockEndPosition(46),
	}}}
	poller := NewKeeperPoller(db, keeper, NewReconciler(ReconcilerOptions{}), KeeperPollerConfig{})
	err := poller.RunOnce(ctx)
	if err == nil {
		t.Fatal("RunOnce() = nil; height 41 was never scanned and the cursor moved past it")
	}
	if !chainclient.IsRetryable(err) {
		t.Fatalf("RunOnce() error = %v, want it retryable so Run backs off instead of exiting", err)
	}
	if height, err := db.KeeperLastProcessedHeight(ctx); err != nil || height != 40 {
		t.Fatalf("height = %d, %v; want the cursor held at 40", height, err)
	}
}

// A reposition is a rewind by a number the chain chose, so the refusal is checked
// before it is obeyed: it must concern this node's actual cursor and must actually
// be a regression. Otherwise one malformed answer rescans from genesis.
func TestKeeperPollerRefusesUnusableCursorRepositions(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		refusal *chainclient.CursorAheadOfChainError
	}{
		{name: "rewind to genesis", refusal: &chainclient.CursorAheadOfChainError{CursorHeight: 100, ChainHeight: 0}},
		{name: "stale cursor in the refusal", refusal: &chainclient.CursorAheadOfChainError{CursorHeight: 70, ChainHeight: 50}},
		{name: "not a regression", refusal: &chainclient.CursorAheadOfChainError{CursorHeight: 100, ChainHeight: 100}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			db := openPollerTestStore(t)
			if _, err := db.AdvanceKeeperLastProcessedHeight(ctx, 100); err != nil {
				t.Fatal(err)
			}
			poller := NewKeeperPoller(db, &scriptedKeeperEvents{err: testCase.refusal}, NewReconciler(ReconcilerOptions{}), KeeperPollerConfig{})
			if err := poller.RunOnce(ctx); err == nil {
				t.Fatal("RunOnce() = nil, want the reposition refused")
			}
			if height, err := db.KeeperLastProcessedHeight(ctx); err != nil || height != 100 {
				t.Fatalf("height = %d, %v; want the cursor untouched at 100", height, err)
			}
		})
	}
}

func TestKeeperPollerDoesNotRegressHeight(t *testing.T) {
	ctx := context.Background()
	db := openPollerTestStore(t)
	if _, err := db.AdvanceKeeperLastProcessedHeight(ctx, 50); err != nil {
		t.Fatal(err)
	}
	keeper := &scriptedKeeperEvents{pages: []chainclient.KeeperEventsPage{{FinalizedHeight: 49}}}
	poller := NewKeeperPoller(db, keeper, NewReconciler(ReconcilerOptions{}), KeeperPollerConfig{})
	if err := poller.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if height, _ := db.KeeperLastProcessedHeight(ctx); height != 50 {
		t.Fatalf("height = %d, want monotonic 50", height)
	}
}

func TestKeeperPollerReportsCursorAboveTipRefusal(t *testing.T) {
	ctx := context.Background()
	db := openPollerTestStore(t)
	if _, err := db.AdvanceKeeperLastProcessedHeight(ctx, 33161); err != nil {
		t.Fatal(err)
	}
	refusal := &chainclient.CursorAheadOfChainError{ChainID: "trueopen-localnet-1", CursorHeight: 33161, ChainHeight: 13134}
	keeper := &scriptedKeeperEvents{err: refusal}
	var observed []ChainProgress
	poller := NewKeeperPoller(db, keeper, NewReconciler(ReconcilerOptions{}), KeeperPollerConfig{
		ObserveChainProgress: func(progress ChainProgress) { observed = append(observed, progress) },
	})
	// A reposition is progress, not a failed poll: charging it against the shared
	// retry budget would kill the node for recovering exactly as intended when a
	// reorg retreats over several passes.
	if err := poller.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce() error = %v, want the reposition treated as progress", err)
	}
	if len(observed) < 1 || observed[0].CursorHeight != 33161 || observed[0].ChainHeight != 13134 || observed[0].Refusal == nil || observed[0].Lag() != 0 {
		t.Fatalf("observed = %#v", observed)
	}
	if height, err := db.KeeperLastProcessedHeight(ctx); err != nil || height != 13134 {
		t.Fatalf("height = %d, %v; want cursor repositioned to authoritative 13134", height, err)
	}
}

// A finalized block is permanent, so an event this binary cannot turn into an
// effect stays unusable no matter how often it is re-read. Returning that
// upwards stopped the poller, and because the height is committed only after a
// whole block succeeds, the restart re-read the same block and stopped again --
// one unreadable task_id wedged the node forever. The block must instead cost
// exactly one quarantine record and carry the cursor past it.
func TestKeeperPollerAdvancesPastAnEventItCanNeverUse(t *testing.T) {
	ctx := context.Background()
	db := openPollerTestStore(t)
	hash := codec.HashWithDomain("TEST_TASK", []byte("good"))
	keeper := &scriptedKeeperEvents{pages: []chainclient.KeeperEventsPage{{
		ChainHeight: 20, FinalizedHeight: 12, LastPosition: chainclient.BlockEndPosition(12), RangeStartHeight: 1, RangeEndHeight: 12, RangeComplete: true,
		Events: []chainclient.KeeperEvent{
			{Type: chainclient.KeeperEventAssignmentFailed, TaskID: "task-unreadable", SessionID: "session-1", Height: 12},
			{Type: chainclient.KeeperEventAssignmentFailed, TaskID: "task-good", SessionID: "session-1", Height: 12},
		},
	}}}
	keeper.taskReader = taskReaderFunc(func(_ context.Context, sessionID, taskID string) (chainclient.TaskSnapshot, error) {
		if taskID != "task-good" {
			return chainclient.TaskSnapshot{}, errors.New("Keeper QueryTask task_id must be 32-byte hex")
		}
		return validTaskSnapshot(sessionID, taskID, hash), nil
	})
	var quarantined []chainclient.KeeperEvent
	var applied []codec.Hash
	poller := NewKeeperPoller(db, keeper, NewReconciler(ReconcilerOptions{
		TaskReader:         keeper.taskReader,
		OnQuarantinedEvent: func(event chainclient.KeeperEvent) { quarantined = append(quarantined, event) },
	}), KeeperPollerConfig{
		EffectSink: func(_ context.Context, effects []ReconcilerEffect) error {
			for _, effect := range effects {
				applied = append(applied, effect.TaskHash)
			}
			return nil
		},
	})

	if err := poller.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce() error = %v, want the block applied around the unusable event", err)
	}
	if height, err := db.KeeperLastProcessedHeight(ctx); err != nil || height != 12 {
		t.Fatalf("height = %d, %v; want the cursor past block 12", height, err)
	}
	if len(applied) != 1 || applied[0] != hash {
		t.Fatalf("applied = %#v, want only the usable event's effect", applied)
	}
	if len(quarantined) != 1 || !strings.Contains(quarantined[0].QuarantineReason, "must be 32-byte hex") {
		t.Fatalf("quarantined = %#v, want one record naming the encoding refusal", quarantined)
	}
}

// The counterpart gate: skipping is only ever right for a permanent fact. A
// retryable failure says the RPC was unreachable, not that the event is
// unusable, so the poller must keep the cursor where it is and re-read the same
// block rather than quarantine an event it never actually got an answer about.
func TestKeeperPollerRetriesRatherThanSkippingATransientKeeperFailure(t *testing.T) {
	ctx := context.Background()
	db := openPollerTestStore(t)
	keeper := &scriptedKeeperEvents{pages: []chainclient.KeeperEventsPage{{
		ChainHeight: 20, FinalizedHeight: 12, LastPosition: chainclient.BlockEndPosition(12), RangeStartHeight: 1, RangeEndHeight: 12, RangeComplete: true,
		Events: []chainclient.KeeperEvent{
			{Type: chainclient.KeeperEventAssignmentFailed, TaskID: "task-a", SessionID: "session-1", Height: 12},
		},
	}}}
	keeper.taskReader = taskReaderFunc(func(context.Context, string, string) (chainclient.TaskSnapshot, error) {
		return chainclient.TaskSnapshot{}, chainclient.Retryable(errors.New("Keeper RPC /abci_query returned 503 Service Unavailable"))
	})
	var quarantined []chainclient.KeeperEvent
	poller := NewKeeperPoller(db, keeper, NewReconciler(ReconcilerOptions{
		TaskReader:         keeper.taskReader,
		OnQuarantinedEvent: func(event chainclient.KeeperEvent) { quarantined = append(quarantined, event) },
	}), KeeperPollerConfig{EffectSink: func(context.Context, []ReconcilerEffect) error { return nil }})

	err := poller.RunOnce(ctx)
	if err == nil || !chainclient.IsRetryable(err) {
		t.Fatalf("RunOnce() error = %v, want a retryable failure surfaced to the poll loop", err)
	}
	if height, storeErr := db.KeeperLastProcessedHeight(ctx); storeErr != nil || height != 0 {
		t.Fatalf("height = %d, %v; want the cursor held for a re-read", height, storeErr)
	}
	if len(quarantined) != 0 {
		t.Fatalf("quarantined = %#v, want nothing skipped on a transport failure", quarantined)
	}
}

type scriptedKeeperEvents struct {
	pages      []chainclient.KeeperEventsPage
	positions  []chainclient.EventPosition
	taskReader KeeperTaskReader
	err        error
}

type taskReaderFunc func(context.Context, string, string) (chainclient.TaskSnapshot, error)

func (f taskReaderFunc) Task(ctx context.Context, sessionID, taskID string) (chainclient.TaskSnapshot, error) {
	return f(ctx, sessionID, taskID)
}

func terminalTaskReader(hashes map[string]codec.Hash) KeeperTaskReader {
	return taskReaderFunc(func(_ context.Context, sessionID, taskID string) (chainclient.TaskSnapshot, error) {
		hash, ok := hashes[taskID]
		if !ok {
			return chainclient.TaskSnapshot{}, errors.New("unknown task")
		}
		return validTaskSnapshot(sessionID, taskID, hash), nil
	})
}

func (k *scriptedKeeperEvents) FinalizedEvents(_ context.Context, position chainclient.EventPosition) (chainclient.KeeperEventsPage, error) {
	k.positions = append(k.positions, position)
	if k.err != nil {
		return chainclient.KeeperEventsPage{}, k.err
	}
	if len(k.pages) == 0 {
		return chainclient.KeeperEventsPage{}, nil
	}
	page := k.pages[0]
	k.pages = k.pages[1:]
	return page, nil
}

func TestKeeperPollerRecoversFromEventGap(t *testing.T) {
	ctx := context.Background()
	db := openPollerTestStore(t)
	if _, err := db.AdvanceKeeperLastProcessedHeight(ctx, 40); err != nil {
		t.Fatal(err)
	}
	hash := codec.HashWithDomain("TEST_TASK", []byte("gap-task"))
	gapEvent := chainclient.KeeperEvent{
		Type: chainclient.KeeperEventAssignmentFailed, TaskID: "gap-task", SessionID: "session-1",
		OrderDigest: hash, Height: 41,
	}
	// First call returns a page that starts after the current cursor, creating
	// a gap. Second call returns the events for the missing range.
	keeper := &scriptedKeeperEvents{
		pages: []chainclient.KeeperEventsPage{
			{ChainHeight: 50, FinalizedHeight: 46, RangeStartHeight: 42, RangeEndHeight: 46, RangeComplete: true, LastPosition: chainclient.BlockEndPosition(46)},
			{ChainHeight: 50, FinalizedHeight: 41, RangeStartHeight: 41, RangeEndHeight: 41, RangeComplete: true, LastPosition: chainclient.BlockEndPosition(41), Events: []chainclient.KeeperEvent{gapEvent}},
		},
		taskReader: terminalTaskReader(map[string]codec.Hash{"gap-task": hash}),
	}
	var applied int
	poller := NewKeeperPoller(db, keeper, NewReconciler(ReconcilerOptions{TaskReader: keeper.taskReader}), KeeperPollerConfig{
		EffectSink: func(_ context.Context, effects []ReconcilerEffect) error {
			applied += len(effects)
			return nil
		},
	})
	if err := poller.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce() error = %v, want gap recovery", err)
	}
	if applied != 1 {
		t.Fatalf("applied effects = %d, want 1", applied)
	}
	// The recovery page is applied and the cursor lands on it. The original page
	// was fetched against a cursor that no longer exists, so this pass stops here
	// rather than applying it: a recovery page overlapping it would leave the
	// cursor mid-range and validateKeeperEventsRange would refuse it permanently.
	if height, err := db.KeeperLastProcessedHeight(ctx); err != nil || height != 41 {
		t.Fatalf("height = %d, %v; want the cursor on the recovered range", height, err)
	}
	// Progress, not a stall: the next pass re-queries from 41 and consumes 42-46.
	keeper.pages = []chainclient.KeeperEventsPage{{
		ChainHeight: 50, FinalizedHeight: 46, RangeStartHeight: 42, RangeEndHeight: 46,
		RangeComplete: true, LastPosition: chainclient.BlockEndPosition(46),
	}}
	if err := poller.RunOnce(ctx); err != nil {
		t.Fatalf("second RunOnce() error = %v", err)
	}
	if height, err := db.KeeperLastProcessedHeight(ctx); err != nil || height != 46 {
		t.Fatalf("height = %d, %v; want the cursor advanced to 46 on the next pass", height, err)
	}
}

func TestKeeperPollerRecoversFromCursorAheadOfChain(t *testing.T) {
	ctx := context.Background()
	db := openPollerTestStore(t)
	if _, err := db.AdvanceKeeperLastProcessedHeight(ctx, 100); err != nil {
		t.Fatal(err)
	}
	refusal := &chainclient.CursorAheadOfChainError{ChainID: "trueopen-localnet-1", CursorHeight: 100, ChainHeight: 50}
	keeper := &scriptedKeeperEvents{err: refusal}
	poller := NewKeeperPoller(db, keeper, NewReconciler(ReconcilerOptions{}), KeeperPollerConfig{})
	if err := poller.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce() error = %v, want regression recovery", err)
	}
	if height, err := db.KeeperLastProcessedHeight(ctx); err != nil || height != 50 {
		t.Fatalf("height = %d, %v; want cursor repositioned to authoritative 50", height, err)
	}
}

// The recovery query is a fresh query, so finality can have advanced and the page
// it returns can overlap the page that exposed the gap. Applying that original
// page afterwards would leave the cursor mid-range, and validateKeeperEventsRange
// refuses a page that does not start at processedHeight+1 with a permanent error -
// turning a successfully filled gap into a dead poller.
func TestKeeperPollerSurvivesAnOverlappingGapRecoveryPage(t *testing.T) {
	ctx := context.Background()
	db := openPollerTestStore(t)
	if _, err := db.AdvanceKeeperLastProcessedHeight(ctx, 40); err != nil {
		t.Fatal(err)
	}
	keeper := &scriptedKeeperEvents{pages: []chainclient.KeeperEventsPage{
		// Exposes the gap at 41.
		{ChainHeight: 50, FinalizedHeight: 46, RangeStartHeight: 42, RangeEndHeight: 46, RangeComplete: true, LastPosition: chainclient.BlockEndPosition(46)},
		// Recovery covers 41 but also overlaps 42-43.
		{ChainHeight: 50, FinalizedHeight: 43, RangeStartHeight: 41, RangeEndHeight: 43, RangeComplete: true, LastPosition: chainclient.BlockEndPosition(43)},
	}}
	poller := NewKeeperPoller(db, keeper, NewReconciler(ReconcilerOptions{}), KeeperPollerConfig{})

	if err := poller.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce() error = %v, want the overlapping recovery accepted", err)
	}
	if height, err := db.KeeperLastProcessedHeight(ctx); err != nil || height != 43 {
		t.Fatalf("height = %d, %v; want the cursor on the recovery page", height, err)
	}
}

// A reorg that keeps retreating repositions correctly on every pass, so it must
// not spend the poll retry budget - but it cannot be unlimited either.
func TestKeeperPollerBoundsConsecutiveRepositions(t *testing.T) {
	ctx := context.Background()
	db := openPollerTestStore(t)
	start := uint64(maxConsecutiveRepositions + 10)
	if _, err := db.AdvanceKeeperLastProcessedHeight(ctx, start); err != nil {
		t.Fatal(err)
	}
	keeper := &scriptedKeeperEvents{}
	poller := NewKeeperPoller(db, keeper, NewReconciler(ReconcilerOptions{}), KeeperPollerConfig{})

	// Each pass retreats the authoritative tip by one, so every reposition is a
	// valid regression against the cursor just written.
	for i := range maxConsecutiveRepositions {
		cursor := start - uint64(i)
		keeper.err = &chainclient.CursorAheadOfChainError{CursorHeight: cursor, ChainHeight: cursor - 1}
		if err := poller.RunOnce(ctx); err != nil {
			t.Fatalf("reposition %d returned %v, want it treated as progress", i+1, err)
		}
	}
	cursor := start - uint64(maxConsecutiveRepositions)
	keeper.err = &chainclient.CursorAheadOfChainError{CursorHeight: cursor, ChainHeight: cursor - 1}
	if err := poller.RunOnce(ctx); err == nil {
		t.Fatal("RunOnce() = nil, want a chain that never settles to fail")
	}
}

func openPollerTestStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "poller.db"))
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
