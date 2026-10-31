// Package streamtest is a Builder-side DispatchStream for tests outside
// package dispatchstream. It accepts Sessions over TLS and HTTP/2, matches
// each stream to its Builder by the binding's builder_operator, acks every
// Cortex business frame, echoes keepalives, and lets a test push Builder
// frames under consecutive cursors. It checks no Cortex signature.
package streamtest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/TrueOpen/cortex/internal/builderclient"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	"github.com/TrueOpen/cortex/proto/nexus/v1/nexusv1connect"
)

const wait = 5 * time.Second

// Server is a Builder ingress that only implements DispatchStream.
type Server struct {
	nexusv1connect.UnimplementedIngressAPIHandler
	srv   *httptest.Server
	mu    sync.Mutex
	conns map[string]chan *Conn
}

// Start serves until the test ends.
func Start(t testing.TB) *Server {
	t.Helper()
	s := &Server{conns: map[string]chan *Conn{}}
	_, h := nexusv1connect.NewIngressAPIHandler(s)
	s.srv = httptest.NewUnstartedServer(h)
	s.srv.EnableHTTP2 = true
	s.srv.StartTLS()
	t.Cleanup(s.srv.Close)
	return s
}

// URL is the https origin, as a descriptor publishes it.
func (s *Server) URL() string { return s.srv.URL }

// Pin is the certificate's tls_pubkey_hash, as a descriptor publishes it.
func (s *Server) Pin() string { return builderclient.TLSPubkeyHash(s.srv.Certificate()) }

func (s *Server) queue(builder string) chan *Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	q, ok := s.conns[builder]
	if !ok {
		q = make(chan *Conn, 8)
		s.conns[builder] = q
	}
	return q
}

// Next returns the next stream builder's Session bound.
func (s *Server) Next(t testing.TB, builder string) *Conn {
	t.Helper()
	select {
	case c := <-s.queue(builder):
		return c
	case <-time.After(wait):
		t.Fatalf("no DispatchStream bound for %s", builder)
		return nil
	}
}

// Conn is one bound stream, seen from the Builder.
type Conn struct {
	Builder string
	Nonce   []byte
	in      chan *nexusv1.DispatchStreamFrameV1
	out     chan *nexusv1.DispatchStreamFrameV1
	acked   chan uint64
	cursor  atomic.Uint64
	done    chan struct{}
}

// DispatchStream serves one Session. Every Send runs on this goroutine:
// connect writes the end of stream from it when the handler returns.
func (s *Server) DispatchStream(ctx context.Context, st *connect.BidiStream[nexusv1.DispatchStreamRequest, nexusv1.DispatchStreamResponse]) error {
	first, err := st.Receive()
	if err != nil {
		return err
	}
	b := first.GetFrame().GetBinding()
	if b == nil {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("the first frame must be the binding"))
	}
	c := &Conn{Builder: b.GetBuilderOperator(), Nonce: first.GetFrame().GetStreamNonce(),
		in: make(chan *nexusv1.DispatchStreamFrameV1, 64), out: make(chan *nexusv1.DispatchStreamFrameV1, 64),
		acked: make(chan uint64, 64), done: make(chan struct{})}
	defer close(c.done)
	recvErr := make(chan error, 1)
	go func() {
		for {
			req, err := st.Receive()
			if err != nil {
				recvErr <- err
				return
			}
			f := req.GetFrame()
			var reply, business *nexusv1.DispatchStreamFrameV1
			switch {
			case f.GetAck() != nil:
				select {
				case c.acked <- f.GetAck().GetAckedCursor():
				default:
				}
				continue
			case f.GetKeepalive() != nil:
				reply = &nexusv1.DispatchStreamFrameV1{StreamNonce: c.Nonce, Message: &nexusv1.DispatchStreamFrameV1_Keepalive{Keepalive: f.GetKeepalive()}}
			default:
				reply = &nexusv1.DispatchStreamFrameV1{StreamNonce: c.Nonce, Message: &nexusv1.DispatchStreamFrameV1_Ack{Ack: &nexusv1.StreamAckV1{AckedCursor: f.GetCursor()}}}
				business = f
			}
			select {
			case c.out <- reply:
			case <-c.done:
				return
			}
			if business != nil {
				select {
				case c.in <- business:
				case <-c.done:
					return
				}
			}
		}
	}()
	select {
	case s.queue(c.Builder) <- c:
	case <-ctx.Done():
		return ctx.Err()
	}
	for {
		select {
		case f := <-c.out:
			if err := st.Send(&nexusv1.DispatchStreamResponse{Frame: f}); err != nil {
				return err
			}
		case err := <-recvErr:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// TryRecv returns the next Cortex business frame within d.
func (c *Conn) TryRecv(d time.Duration) (*nexusv1.DispatchStreamFrameV1, bool) {
	select {
	case f := <-c.in:
		return f, true
	case <-time.After(d):
		return nil, false
	}
}

// RecvUntil skips Cortex business frames until keep accepts one.
func (c *Conn) RecvUntil(t testing.TB, what string, keep func(*nexusv1.DispatchStreamFrameV1) bool) *nexusv1.DispatchStreamFrameV1 {
	t.Helper()
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if f, ok := c.TryRecv(time.Until(deadline)); ok && keep(f) {
			return f
		}
	}
	t.Fatalf("%s: no %s from Cortex", c.Builder, what)
	return nil
}

// Push sends msg, a Builder business message, under the next cursor.
func (c *Conn) Push(t testing.TB, msg proto.Message) uint64 {
	t.Helper()
	f := &nexusv1.DispatchStreamFrameV1{StreamNonce: c.Nonce, Cursor: c.cursor.Add(1)}
	if err := setVariant(f, msg); err != nil {
		t.Fatal(err)
	}
	select {
	case c.out <- f:
	case <-c.done:
		t.Fatalf("%s: stream closed", c.Builder)
	}
	return f.GetCursor()
}

// WaitAcked waits until Cortex acked cursor.
func (c *Conn) WaitAcked(t testing.TB, cursor uint64) {
	t.Helper()
	deadline := time.After(wait)
	for {
		select {
		case got := <-c.acked:
			if got >= cursor {
				return
			}
		case <-deadline:
			t.Fatalf("%s: cursor %d never acked", c.Builder, cursor)
		}
	}
}

var frameOneof = (&nexusv1.DispatchStreamFrameV1{}).ProtoReflect().Descriptor().Oneofs().ByName("message")

func setVariant(f *nexusv1.DispatchStreamFrameV1, msg proto.Message) error {
	name := msg.ProtoReflect().Descriptor().FullName()
	fields := frameOneof.Fields()
	for i := 0; i < fields.Len(); i++ {
		if fd := fields.Get(i); fd.Message() != nil && fd.Message().FullName() == name {
			f.ProtoReflect().Set(fd, protoreflect.ValueOfMessage(msg.ProtoReflect()))
			return nil
		}
	}
	return fmt.Errorf("%s is not a DispatchStreamFrameV1 variant", name)
}
