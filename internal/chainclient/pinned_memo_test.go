package chainclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	hubv1 "github.com/TrueOpen/cortex/proto/hub/v1"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
)

func memoClient(t *testing.T) *KeeperABCIClient {
	t.Helper()
	return NewKeeperABCIClientWithTransport("http://node", newFakeKeeperNode(t, 100)).EnableReadCache(time.Hour)
}

func countedRead(calls *atomic.Int64, value string, err error) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		calls.Add(1)
		return value, err
	}
}

// One read per arguments and height; a different height or different
// arguments read again.
func TestMemoPinnedReusesOnlyTheSameReadAtTheSameHeight(t *testing.T) {
	client := memoClient(t)
	var calls atomic.Int64
	key := pinnedReadKey{kind: "k", args: "a", height: 100}
	for i := 0; i < 3; i++ {
		got, err := memoPinned(context.Background(), client, key, countedRead(&calls, "v100", nil))
		if err != nil || got != "v100" {
			t.Fatalf("read = %q, %v", got, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("reads at one height = %d, want 1", calls.Load())
	}
	if got, _ := memoPinned(context.Background(), client, pinnedReadKey{kind: "k", args: "a", height: 101}, countedRead(&calls, "v101", nil)); got != "v101" {
		t.Fatalf("read at the next height = %q, want a fresh read", got)
	}
	if got, _ := memoPinned(context.Background(), client, pinnedReadKey{kind: "k", args: "b", height: 100}, countedRead(&calls, "b100", nil)); got != "b100" {
		t.Fatalf("read with other arguments = %q, want a fresh read", got)
	}
	if got, _ := memoPinned(context.Background(), client, pinnedReadKey{kind: "other", args: "a", height: 100}, countedRead(&calls, "o100", nil)); got != "o100" {
		t.Fatalf("read of another kind = %q, want a fresh read", got)
	}
	if calls.Load() != 4 {
		t.Fatalf("reads = %d, want 4", calls.Load())
	}
}

// Failures are not kept, and nothing is kept without the read cache or for
// an unpinned read.
func TestMemoPinnedKeepsOnlySuccessfulPinnedReads(t *testing.T) {
	client := memoClient(t)
	var calls atomic.Int64
	key := pinnedReadKey{kind: "k", args: "a", height: 100}
	if _, err := memoPinned(context.Background(), client, key, countedRead(&calls, "", errors.New("node unavailable"))); err == nil {
		t.Fatal("failed read returned no error")
	}
	if got, err := memoPinned(context.Background(), client, key, countedRead(&calls, "v", nil)); err != nil || got != "v" || calls.Load() != 2 {
		t.Fatalf("read after a failure = %q, %v, calls %d; want a fresh read", got, err, calls.Load())
	}

	uncached := NewKeeperABCIClientWithTransport("http://node", newFakeKeeperNode(t, 100))
	calls.Store(0)
	for i := 0; i < 2; i++ {
		if _, err := memoPinned(context.Background(), uncached, key, countedRead(&calls, "v", nil)); err != nil {
			t.Fatal(err)
		}
		if _, err := memoPinned(context.Background(), client, pinnedReadKey{kind: "k", args: "a"}, countedRead(&calls, "v", nil)); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 4 {
		t.Fatalf("reads = %d, want every uncached or unpinned read made", calls.Load())
	}
}

// Concurrent callers for one read share it; a waiter whose shared read failed
// reads for itself.
func TestMemoPinnedSharesAReadInFlight(t *testing.T) {
	client := memoClient(t)
	key := pinnedReadKey{kind: "k", args: "a", height: 100}
	gate := make(chan struct{})
	var calls atomic.Int64
	read := func(context.Context) (string, error) {
		if calls.Add(1) == 1 {
			<-gate
			return "", errors.New("shared read failed")
		}
		return "v", nil
	}
	var wg sync.WaitGroup
	results := make([]string, 4)
	errs := make([]error, 4)
	wg.Go(func() { results[0], errs[0] = memoPinned(context.Background(), client, key, read) })
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	for i := 1; i < 4; i++ {
		wg.Go(func() { results[i], errs[i] = memoPinned(context.Background(), client, key, read) })
	}
	time.Sleep(20 * time.Millisecond)
	close(gate)
	wg.Wait()
	if errs[0] == nil {
		t.Fatal("the failed shared read reported success")
	}
	for i := 1; i < 4; i++ {
		if errs[i] != nil || results[i] != "v" {
			t.Fatalf("waiter %d = %q, %v; want its own successful read", i, results[i], errs[i])
		}
	}
}

// Entries far below the newest height are dropped.
func TestMemoPinnedKeepsOnlyRecentHeights(t *testing.T) {
	client := memoClient(t)
	var calls atomic.Int64
	for height := uint64(100); height < 100+2*serviceKeyMemoHeights; height++ {
		if _, err := memoPinned(context.Background(), client, pinnedReadKey{kind: "k", height: height}, countedRead(&calls, "v", nil)); err != nil {
			t.Fatal(err)
		}
	}
	client.readCache.mu.Lock()
	kept := len(client.readCache.pinned)
	client.readCache.mu.Unlock()
	if kept != serviceKeyMemoHeights {
		t.Fatalf("kept entries = %d, want %d", kept, serviceKeyMemoHeights)
	}
}

// candidatePoolNode answers /abci_info and the two CandidatePool queries in
// memory, counting the queries. It opens no listener.
type candidatePoolNode struct {
	t       *testing.T
	height  atomic.Uint64
	queries atomic.Int64
}

func (n *candidatePoolNode) RoundTrip(r *http.Request) (*http.Response, error) {
	encode := func(result any) (*http.Response, error) {
		body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": -1, "result": result})
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{}}, nil
	}
	height := n.height.Load()
	switch r.URL.Path {
	case "/abci_info":
		return encode(map[string]any{"response": map[string]any{"last_block_height": strconv.FormatUint(height, 10)}})
	case "/abci_query":
		n.queries.Add(1)
		path, _ := strconv.Unquote(r.URL.Query().Get("path"))
		var response proto.Message
		switch {
		case strings.HasSuffix(path, "CurrentCandidatePool"):
			response = &hubv1.QueryCurrentCandidatePoolResponse{Snapshot: &hubv1.CandidatePoolSnapshotViewV1{
				SnapshotId: bytes.Repeat([]byte{0x11}, 32), Status: 2, EffectiveHeight: 1, ExpiresHeight: height + 1000,
			}}
		case strings.HasSuffix(path, "CandidatePoolMembers"):
			response = &hubv1.QueryCandidatePoolMembersResponse{
				Members: []*hubv1.CandidatePoolMemberViewV1{{CandidateSlot: 3, SlotVersion: height, OperatorAddress: "trueopen1operator"}},
				Page:    &sharedv1.QueryPageResponseV1{},
			}
		default:
			n.t.Errorf("unexpected query %q", path)
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(bytes.NewReader(nil)), Header: http.Header{}}, nil
		}
		payload, err := proto.Marshal(response)
		if err != nil {
			return nil, err
		}
		return encode(map[string]any{"response": map[string]any{
			"code": 0, "value": base64.StdEncoding.EncodeToString(payload), "height": r.URL.Query().Get("height"),
		}})
	}
	return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(bytes.NewReader(nil)), Header: http.Header{}}, nil
}

// Two admissions in one block read the CandidatePool member once; the next
// block reads it again and sees that block's state.
func TestCurrentCandidateMemberIsReadOncePerCommittedHeight(t *testing.T) {
	node := &candidatePoolNode{t: t}
	node.height.Store(100)
	client := NewKeeperABCIClientWithTransport("http://node", node).EnableReadCache(time.Nanosecond)
	for i := 0; i < 2; i++ {
		member, err := client.CurrentCandidateMember(context.Background(), "trueopen1operator")
		if err != nil || member.SlotVersion != 100 {
			t.Fatalf("member = %+v, %v", member, err)
		}
	}
	if got := node.queries.Load(); got != 2 {
		t.Fatalf("queries at one height = %d, want the pool and members read once", got)
	}
	node.height.Store(101)
	time.Sleep(time.Millisecond)
	member, err := client.CurrentCandidateMember(context.Background(), "trueopen1operator")
	if err != nil || member.SlotVersion != 101 {
		t.Fatalf("member at the next height = %+v, %v; want a fresh read", member, err)
	}
	if got := node.queries.Load(); got != 4 {
		t.Fatalf("queries = %d, want a second pair at the new height", got)
	}
	// A different operator is a different read.
	if _, err := client.CurrentCandidateMember(context.Background(), "trueopen1someoneelse"); err == nil {
		t.Fatal("an operator that is not a member was found")
	}
}

// A committed height that goes backwards for good (a reset chain) clears
// every height memo: the new chain passes through the same heights with
// different state.
func TestHeightRegressionClearsTheHeightMemos(t *testing.T) {
	node := newFakeKeeperNode(t, 100)
	client := NewKeeperABCIClientWithTransport("http://node", node).EnableReadCache(time.Nanosecond)
	if _, _, err := client.CommittedCurrentServiceKey(context.Background(), ParticipantTypeCortexNode, "trueopen1operator"); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	if _, err := memoPinned(context.Background(), client, pinnedReadKey{kind: "k", height: 100}, countedRead(&calls, "old chain", nil)); err != nil {
		t.Fatal(err)
	}
	node.height.Store(10)
	time.Sleep(time.Millisecond)
	if height, err := client.CommittedHeight(context.Background()); err != nil || height != 10 {
		t.Fatalf("height after the reset = %d, %v; want 10", height, err)
	}
	client.readCache.mu.Lock()
	keys, pinned := len(client.readCache.serviceKeys), len(client.readCache.pinned)
	client.readCache.mu.Unlock()
	if keys != 0 || pinned != 0 {
		t.Fatalf("memo entries after the reset: service keys %d, pinned %d; want none", keys, pinned)
	}
	got, err := memoPinned(context.Background(), client, pinnedReadKey{kind: "k", height: 100}, countedRead(&calls, "new chain", nil))
	if err != nil || got != "new chain" {
		t.Fatalf("read at height 100 after the reset = %q, %v; want a fresh read", got, err)
	}
}

// A read that was in flight across the reset does not store its answer.
func TestReadInFlightAcrossAResetIsNotKept(t *testing.T) {
	node := newFakeKeeperNode(t, 100)
	client := NewKeeperABCIClientWithTransport("http://node", node).EnableReadCache(time.Nanosecond)
	if _, err := client.CommittedHeight(context.Background()); err != nil {
		t.Fatal(err)
	}
	gate, entered := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := memoPinned(context.Background(), client, pinnedReadKey{kind: "k", height: 100}, func(context.Context) (string, error) {
			close(entered)
			<-gate
			return "old chain", nil
		})
		done <- err
	}()
	<-entered
	node.height.Store(10)
	time.Sleep(time.Millisecond)
	if _, err := client.CommittedHeight(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	client.readCache.mu.Lock()
	pinned := len(client.readCache.pinned)
	client.readCache.mu.Unlock()
	if pinned != 0 {
		t.Fatalf("pinned entries = %d, want the pre-reset answer dropped", pinned)
	}
}
