package chainclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
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

// fakeKeeperNode answers /abci_info and CurrentServiceKey queries in memory, so
// these tests open no listener.
type fakeKeeperNode struct {
	t         *testing.T
	height    atomic.Uint64
	failInfo  atomic.Bool
	failNext  atomic.Int64
	infoCalls atomic.Int64
	keyCalls  atomic.Int64
	gate      chan struct{}
	binding   func(participant sharedv1.ParticipantType, operator string) *hubv1.CurrentServiceKeyViewV1
}

func (n *fakeKeeperNode) RoundTrip(r *http.Request) (*http.Response, error) {
	encode := func(result any) (*http.Response, error) {
		body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": -1, "result": result})
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{}}, nil
	}
	switch r.URL.Path {
	case "/abci_info":
		n.infoCalls.Add(1)
		if n.gate != nil {
			<-n.gate
		}
		if n.failInfo.Load() || n.failNext.Add(-1) >= 0 {
			return &http.Response{StatusCode: http.StatusBadGateway, Status: "502 Bad Gateway", Body: io.NopCloser(bytes.NewReader(nil)), Header: http.Header{}}, nil
		}
		return encode(map[string]any{"response": map[string]any{"last_block_height": strconv.FormatUint(n.height.Load(), 10)}})
	case "/abci_query":
		n.keyCalls.Add(1)
		var request hubv1.QueryCurrentServiceKeyRequest
		if err := decodeTestABCIData(r.URL.Query().Get("data"), &request); err != nil {
			n.t.Errorf("decode request: %v", err)
		}
		payload, err := marshalTestProto(&hubv1.QueryCurrentServiceKeyResponse{Binding: n.binding(request.ParticipantType, request.OperatorAddress)})
		if err != nil {
			n.t.Fatalf("marshal binding: %v", err)
		}
		return encode(map[string]any{"response": map[string]any{
			"code":   0,
			"value":  base64.StdEncoding.EncodeToString(payload),
			"height": r.URL.Query().Get("height"),
		}})
	}
	return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(bytes.NewReader(nil)), Header: http.Header{}}, nil
}

func newFakeKeeperNode(t *testing.T, height uint64) *fakeKeeperNode {
	node := &fakeKeeperNode{t: t}
	node.height.Store(height)
	node.binding = func(participant sharedv1.ParticipantType, operator string) *hubv1.CurrentServiceKeyViewV1 {
		binding := commitBoundaryBinding()
		binding.ParticipantType = participant
		binding.OperatorAddress = operator
		if participant == sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER {
			binding.ParticipantStatus = &hubv1.CurrentServiceKeyViewV1_BuilderServiceKeyStatus{BuilderServiceKeyStatus: hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_ACTIVE}
		}
		return binding
	}
	return node
}

func TestCommittedHeightReadsEveryTimeWithoutReadCache(t *testing.T) {
	node := newFakeKeeperNode(t, 100)
	client := NewKeeperABCIClientWithTransport("http://node", node)
	for i := 0; i < 3; i++ {
		if _, err := client.CommittedHeight(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if got := node.infoCalls.Load(); got != 3 {
		t.Fatalf("abci_info calls = %d, want 3", got)
	}
}

func TestCommittedHeightReusedWithinMaxAge(t *testing.T) {
	node := newFakeKeeperNode(t, 100)
	client := NewKeeperABCIClientWithTransport("http://node", node).EnableReadCache(time.Hour)
	for i := 0; i < 3; i++ {
		height, err := client.CommittedHeight(context.Background())
		if err != nil || height != 100 {
			t.Fatalf("height = %d, %v", height, err)
		}
	}
	if got := node.infoCalls.Load(); got != 1 {
		t.Fatalf("abci_info calls = %d, want 1", got)
	}
}

func TestCommittedHeightRereadAfterMaxAge(t *testing.T) {
	node := newFakeKeeperNode(t, 100)
	client := NewKeeperABCIClientWithTransport("http://node", node).EnableReadCache(time.Nanosecond)
	if height, _ := client.CommittedHeight(context.Background()); height != 100 {
		t.Fatalf("first height = %d", height)
	}
	node.height.Store(101)
	time.Sleep(time.Millisecond)
	if height, _ := client.CommittedHeight(context.Background()); height != 101 {
		t.Fatalf("second height = %d, want 101", height)
	}
	if got := node.infoCalls.Load(); got != 2 {
		t.Fatalf("abci_info calls = %d, want 2", got)
	}
}

func TestCommittedHeightRefusesLowerHeightOnlyWithinGuard(t *testing.T) {
	node := newFakeKeeperNode(t, 101)
	client := NewKeeperABCIClientWithTransport("http://node", node).EnableReadCache(20 * time.Millisecond)
	if height, _ := client.CommittedHeight(context.Background()); height != 101 {
		t.Fatalf("first height = %d", height)
	}
	// A replica one block behind: refused while the higher height is recent.
	node.height.Store(99)
	time.Sleep(30 * time.Millisecond)
	if height, _ := client.CommittedHeight(context.Background()); height != 101 {
		t.Fatalf("height within guard = %d, want 101", height)
	}
	// Still low after the guard window: a reset chain, accepted.
	time.Sleep(heightGuardFactor * 20 * time.Millisecond)
	if height, _ := client.CommittedHeight(context.Background()); height != 99 {
		t.Fatalf("height after guard = %d, want 99", height)
	}
}

func TestCommittedHeightWaiterRereadsAfterSharedFailure(t *testing.T) {
	node := newFakeKeeperNode(t, 100)
	node.gate = make(chan struct{})
	node.failNext.Store(1)
	client := NewKeeperABCIClientWithTransport("http://node", node).EnableReadCache(time.Hour)
	leaderDone := make(chan error, 1)
	go func() {
		_, err := client.CommittedHeight(context.Background())
		leaderDone <- err
	}()
	for node.infoCalls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	waiterDone := make(chan uint64, 1)
	go func() {
		height, _ := client.CommittedHeight(context.Background())
		waiterDone <- height
	}()
	time.Sleep(20 * time.Millisecond)
	// The shared read fails; the waiter then reads for itself and succeeds.
	close(node.gate)
	if err := <-leaderDone; err == nil {
		t.Fatal("leader read should have failed")
	}
	if height := <-waiterDone; height != 100 {
		t.Fatalf("waiter height = %d, want 100", height)
	}
}

func TestCommittedHeightWaiterHonoursItsContext(t *testing.T) {
	node := newFakeKeeperNode(t, 100)
	node.gate = make(chan struct{})
	defer close(node.gate)
	client := NewKeeperABCIClientWithTransport("http://node", node).EnableReadCache(time.Hour)
	go func() { _, _ = client.CommittedHeight(context.Background()) }()
	for node.infoCalls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := client.CommittedHeight(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
}

func TestCommittedHeightConcurrentCallersShareOneRead(t *testing.T) {
	node := newFakeKeeperNode(t, 100)
	node.gate = make(chan struct{})
	client := NewKeeperABCIClientWithTransport("http://node", node).EnableReadCache(time.Hour)
	var wg sync.WaitGroup
	results := make([]uint64, 8)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], _ = client.CommittedHeight(context.Background())
		}(i)
	}
	// Let every caller reach the in-flight read before it completes.
	for node.infoCalls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(node.gate)
	wg.Wait()
	for i, height := range results {
		if height != 100 {
			t.Fatalf("caller %d height = %d", i, height)
		}
	}
	if got := node.infoCalls.Load(); got != 1 {
		t.Fatalf("abci_info calls = %d, want 1", got)
	}
}

func TestCommittedHeightFailureIsNotCached(t *testing.T) {
	node := newFakeKeeperNode(t, 100)
	node.failInfo.Store(true)
	client := NewKeeperABCIClientWithTransport("http://node", node).EnableReadCache(time.Hour)
	if _, err := client.CommittedHeight(context.Background()); err == nil {
		t.Fatal("expected the failed read to surface")
	}
	node.failInfo.Store(false)
	height, err := client.CommittedHeight(context.Background())
	if err != nil || height != 100 {
		t.Fatalf("height = %d, %v", height, err)
	}
	if got := node.infoCalls.Load(); got != 2 {
		t.Fatalf("abci_info calls = %d, want 2", got)
	}
}

func TestServiceKeyReusedAtSameCommittedHeight(t *testing.T) {
	node := newFakeKeeperNode(t, 100)
	client := NewKeeperABCIClientWithTransport("http://node", node).EnableReadCache(time.Hour)
	for i := 0; i < 3; i++ {
		binding, height, err := client.CommittedCurrentServiceKey(context.Background(), ParticipantTypeCortexNode, "trueopen1operator")
		if err != nil || height != 100 || binding.OperatorAddress != "trueopen1operator" {
			t.Fatalf("binding = %#v height = %d err = %v", binding, height, err)
		}
		if _, err := client.CurrentServiceKey(context.Background(), ParticipantTypeBuilder, "trueopen1builder", 0); err != nil {
			t.Fatal(err)
		}
	}
	if got := node.infoCalls.Load(); got != 1 {
		t.Fatalf("abci_info calls = %d, want 1", got)
	}
	if got := node.keyCalls.Load(); got != 2 {
		t.Fatalf("CurrentServiceKey queries = %d, want 2 (one per identity)", got)
	}
}

func TestServiceKeyRereadWhenHeightMoves(t *testing.T) {
	node := newFakeKeeperNode(t, 100)
	client := NewKeeperABCIClientWithTransport("http://node", node).EnableReadCache(time.Nanosecond)
	if _, _, err := client.CommittedCurrentServiceKey(context.Background(), ParticipantTypeCortexNode, "trueopen1operator"); err != nil {
		t.Fatal(err)
	}
	// The key is revoked in block 101; the next read must see it.
	node.height.Store(101)
	node.binding = func(participant sharedv1.ParticipantType, operator string) *hubv1.CurrentServiceKeyViewV1 {
		binding := commitBoundaryBinding()
		binding.ParticipantStatus = &hubv1.CurrentServiceKeyViewV1_CortexServiceKeyStatus{CortexServiceKeyStatus: hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_REVOKED}
		return binding
	}
	time.Sleep(time.Millisecond)
	binding, height, err := client.CommittedCurrentServiceKey(context.Background(), ParticipantTypeCortexNode, "trueopen1operator")
	if err != nil {
		t.Fatal(err)
	}
	if height != 101 || binding.Status != "REVOKED" {
		t.Fatalf("height = %d status = %q, want 101 REVOKED", height, binding.Status)
	}
	if got := node.keyCalls.Load(); got != 2 {
		t.Fatalf("CurrentServiceKey queries = %d, want 2", got)
	}
}

func TestServiceKeyMemoKeepsOnlyRecentHeights(t *testing.T) {
	node := newFakeKeeperNode(t, 100)
	client := NewKeeperABCIClientWithTransport("http://node", node).EnableReadCache(time.Hour)
	for height := uint64(100); height < 110; height++ {
		if _, err := client.CurrentServiceKey(context.Background(), ParticipantTypeCortexNode, "trueopen1operator", height); err != nil {
			t.Fatal(err)
		}
	}
	client.readCache.mu.Lock()
	size := len(client.readCache.serviceKeys)
	client.readCache.mu.Unlock()
	if size != serviceKeyMemoHeights {
		t.Fatalf("memo entries = %d, want %d", size, serviceKeyMemoHeights)
	}
}

func TestEnableConnectionPoolRaisesIdleConnsPerHost(t *testing.T) {
	client := NewKeeperABCIClientWithTransport("http://node", &http.Transport{}).EnableConnectionPool()
	transport, ok := client.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T", client.http.Transport)
	}
	if transport.MaxIdleConnsPerHost != keeperIdleConnsPerHost {
		t.Fatalf("MaxIdleConnsPerHost = %d, want %d", transport.MaxIdleConnsPerHost, keeperIdleConnsPerHost)
	}
}

func decodeTestABCIData(data string, message proto.Message) error {
	raw, err := hex.DecodeString(strings.TrimPrefix(data, "0x"))
	if err != nil {
		return err
	}
	return proto.Unmarshal(raw, message)
}
