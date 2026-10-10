package chainclient

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
	gogoproto "github.com/cosmos/gogoproto/proto"
)

// countingTransport counts chain round trips. Both of them matter here: reading
// the limits costs a committed-height read and a params query, one after the
// other, and the point of the cache is that a later read costs neither.
type countingTransport struct {
	mu sync.Mutex
	n  int
}

func (c *countingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return http.DefaultTransport.RoundTrip(request)
}

func (c *countingTransport) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// outputStreamLimitsServer serves task params, optionally withholding them
// until the caller says otherwise, so a test can fail one read and then let the
// next succeed.
func outputStreamLimitsServer(t *testing.T, serve *atomic.Bool) (*KeeperABCIClient, *countingTransport) {
	t.Helper()
	server := newABCITestServer(t, func(path, _ string, _ []byte) (gogoproto.Message, uint32, string) {
		if path != taskQuery+"Params" {
			t.Errorf("unexpected query %q", path)
		}
		if serve != nil && !serve.Load() {
			return &taskv1.QueryTaskParamsResponse{}, 0, ""
		}
		return &taskv1.QueryTaskParamsResponse{Params: &taskv1.TaskParamsV1{
			SchemaVersion: 1,
			Evidence:      &taskv1.EvidenceLimitParamsV1{MaxOutputMmrLeaves: 65536, MinOutputStreamFrameBytes: 16},
		}}, 0, ""
	})
	t.Cleanup(server.Close)
	transport := &countingTransport{}
	return NewKeeperABCIClientWithTransport(server.URL, transport), transport
}

// TestOutputStreamLimitsAreReadFromTheChainOnce is why the cache exists. Both
// limits are genesis-only, so re-reading them per task buys nothing and costs
// two sequential chain round trips on the critical path between a task being
// admitted and generation starting -- measured at 291ms on devnet, which is
// 7% of the first frame a caller waits for.
func TestOutputStreamLimitsAreReadFromTheChainOnce(t *testing.T) {
	client, transport := outputStreamLimitsServer(t, nil)

	first, err := client.OutputStreamLimits(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	afterFirst := transport.count()
	if afterFirst == 0 {
		t.Fatal("the first read reached no chain at all")
	}

	second, err := client.OutputStreamLimits(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := transport.count(); got != afterFirst {
		t.Fatalf("round trips = %d after a second read, want the %d the first one cost", got, afterFirst)
	}
	if second != first {
		t.Fatalf("second read = %+v, want the retained %+v", second, first)
	}
}

// TestOutputStreamLimitsRetryAfterAFailedRead keeps a transient chain failure
// from becoming a permanent one. Nothing is retained unless it was read, so the
// node does not spend its life serving an error it hit once at startup.
func TestOutputStreamLimitsRetryAfterAFailedRead(t *testing.T) {
	var serve atomic.Bool
	client, _ := outputStreamLimitsServer(t, &serve)

	if _, err := client.OutputStreamLimits(context.Background()); err == nil {
		t.Fatal("a chain that served no params was accepted")
	}

	serve.Store(true)
	limits, err := client.OutputStreamLimits(context.Background())
	if err != nil {
		t.Fatalf("the failed read was retained instead of retried: %v", err)
	}
	if limits.MinOutputStreamFrameBytes != 16 || limits.MaxOutputMMRLeaves != 65536 {
		t.Fatalf("limits = %+v", limits)
	}
}

// TestOutputStreamLimitsAreReadOnceUnderConcurrentTasks covers the shape this
// actually runs in: several tasks are admitted at once and each asks for the
// limits before generating. They must collapse into one read rather than one
// per task, and must not race for the retained value.
func TestOutputStreamLimitsAreReadOnceUnderConcurrentTasks(t *testing.T) {
	client, transport := outputStreamLimitsServer(t, nil)

	var wg sync.WaitGroup
	results := make([]OutputStreamLimitsSnapshot, 8)
	errs := make([]error, 8)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = client.OutputStreamLimits(context.Background())
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("task %d: %v", i, err)
		}
		if results[i] != results[0] {
			t.Fatalf("task %d read %+v, task 0 read %+v", i, results[i], results[0])
		}
	}
	// One committed-height read and one params query, for all eight tasks.
	if got := transport.count(); got != 2 {
		t.Fatalf("round trips = %d for 8 concurrent tasks, want the 2 a single read costs", got)
	}
}
