package dispatchstream

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	"github.com/TrueOpen/cortex/proto/nexus/v1/nexusv1connect"
)

// waitFor bounds every blocking test step; nothing in these tests sleeps.
const waitFor = 5 * time.Second

// fakeNexus is a Builder ingress that only implements DispatchStream. Each
// accepted stream is handed to the test as a fakeConn and stays open until
// the test ends it (disconnect) or the client goes away.
type fakeNexus struct {
	nexusv1connect.UnimplementedIngressAPIHandler
	conns chan *fakeConn
}

type fakeConn struct {
	t      *testing.T
	stream *connect.BidiStream[nexusv1.DispatchStreamRequest, nexusv1.DispatchStreamResponse]
	sends  chan sendReq
	end    chan struct{}
	gone   chan struct{}
}

// sendReq runs Send on the handler goroutine: connect writes the end-of-stream
// from that goroutine when the handler returns, so a Send from any other
// goroutine would race with it.
type sendReq struct {
	frame *nexusv1.DispatchStreamFrameV1
	done  chan error
}

func (f *fakeNexus) DispatchStream(ctx context.Context, s *connect.BidiStream[nexusv1.DispatchStreamRequest, nexusv1.DispatchStreamResponse]) error {
	c := &fakeConn{stream: s, sends: make(chan sendReq), end: make(chan struct{}), gone: make(chan struct{})}
	defer close(c.gone)
	select {
	case f.conns <- c:
	case <-ctx.Done():
		return ctx.Err()
	}
	for {
		select {
		case r := <-c.sends:
			r.done <- s.Send(&nexusv1.DispatchStreamResponse{Frame: r.frame})
		case <-c.end:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func startFakeNexus(t *testing.T) (*fakeNexus, *httptest.Server) {
	t.Helper()
	f := &fakeNexus{conns: make(chan *fakeConn, 8)}
	_, h := nexusv1connect.NewIngressAPIHandler(f)
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return f, srv
}

// next returns the next accepted connection.
func (f *fakeNexus) next(t *testing.T) *fakeConn {
	t.Helper()
	select {
	case c := <-f.conns:
		c.t = t
		return c
	case <-time.After(waitFor):
		t.Fatal("no DispatchStream connection")
		return nil
	}
}

// recv returns the next frame the Session sent, failing the test on timeout
// or stream end.
func (c *fakeConn) recv() *nexusv1.DispatchStreamFrameV1 {
	c.t.Helper()
	f, err := c.tryRecv()
	if err != nil {
		c.t.Fatalf("fake recv: %v", err)
	}
	return f
}

func (c *fakeConn) tryRecv() (*nexusv1.DispatchStreamFrameV1, error) {
	type result struct {
		req *nexusv1.DispatchStreamRequest
		err error
	}
	ch := make(chan result, 1)
	go func() {
		req, err := c.stream.Receive()
		ch <- result{req, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		return r.req.GetFrame(), nil
	case <-time.After(waitFor):
		return nil, errors.New("timed out")
	}
}

// recvBusiness skips keepalive probes and returns the next non-keepalive frame.
func (c *fakeConn) recvSkippingKeepalive() *nexusv1.DispatchStreamFrameV1 {
	c.t.Helper()
	for {
		f := c.recv()
		if f.GetKeepalive() == nil {
			return f
		}
	}
}

func (c *fakeConn) send(f *nexusv1.DispatchStreamFrameV1) {
	c.t.Helper()
	r := sendReq{frame: f, done: make(chan error, 1)}
	select {
	case c.sends <- r:
	case <-c.gone:
		c.t.Fatal("fake send: stream already closed")
	case <-time.After(waitFor):
		c.t.Fatal("fake send: timed out")
	}
	if err := <-r.done; err != nil {
		c.t.Fatalf("fake send: %v", err)
	}
}

// disconnect ends the RPC from the Builder side.
func (c *fakeConn) disconnect() {
	close(c.end)
	<-c.gone
}

// waitGone waits for the client to drop this stream.
func (c *fakeConn) waitGone() {
	c.t.Helper()
	select {
	case <-c.gone:
	case <-time.After(waitFor):
		c.t.Fatal("session did not drop the stream")
	}
}
