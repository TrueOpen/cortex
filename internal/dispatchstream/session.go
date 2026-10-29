package dispatchstream

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/store"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	"github.com/TrueOpen/cortex/proto/nexus/v1/nexusv1connect"
)

const frameName = "nexus.v1.DispatchStreamFrameV1"

// Config configures one Builder's DispatchStream session.
type Config struct {
	ChainID         string
	BuilderOperator string
	CortexOperator  string

	// HTTPClient and BaseURL reach the Builder's Nexus ingress (the pinned TLS
	// client from builder endpoints). The session builds its own connect
	// client over them with a raw-bytes codec, so every received frame is
	// checked by wire's strict decoder before anything unmarshals it; an
	// injected generated client could not guarantee that.
	HTTPClient    connect.HTTPClient
	BaseURL       string
	ClientOptions []connect.ClientOption

	Sign       dispatchwire.DigestSigner
	AuthNonce  func(context.Context) (uint64, error) // current service_authorization_nonce
	BuilderKey func(context.Context) ([]byte, error) // QueryCurrentServiceKey(BUILDER, op)
	Store      *store.Store
	Handler    Handler

	KeepaliveEvery time.Duration // default 15s
	MaxMissed      int           // default 3
	Backoff        func(attempt int) time.Duration
	Now            func() time.Time
	// Height is the latest known chain height, for height-bound expiry of
	// outbound messages. Zero means unknown: nothing expires by height.
	Height         func() uint64
	DedupRetention time.Duration // default DefaultDedupRetention
	Rand           io.Reader     // stream nonces; default crypto/rand
	Logger         *slog.Logger
}

// Outgoing is a signed Cortex business message to deliver to the Builder.
// Exactly one expiry bound is required; an expired message is never resent.
type Outgoing struct {
	Message            proto.Message
	ExpiresAtUnixMilli int64  // local wall clock, e.g. accept/reject deadline
	ExpiryHeight       uint64 // chain height, e.g. handraise expiry_height
}

// Session is the Cortex end of one Builder's DispatchStream.
type Session struct {
	cfg     Config
	client  *connect.Client[rawFrame, rawFrame]
	outbox  *outbox
	dedup   *dedup
	kick    chan struct{}
	running atomic.Bool
}

func New(cfg Config) (*Session, error) {
	var missing []string
	for name, absent := range map[string]bool{
		"ChainID": cfg.ChainID == "", "BuilderOperator": cfg.BuilderOperator == "",
		"CortexOperator": cfg.CortexOperator == "", "HTTPClient": cfg.HTTPClient == nil,
		"BaseURL": cfg.BaseURL == "", "Sign": cfg.Sign == nil, "AuthNonce": cfg.AuthNonce == nil,
		"BuilderKey": cfg.BuilderKey == nil, "Store": cfg.Store == nil, "Handler": cfg.Handler == nil,
	} {
		if absent {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("dispatchstream: config missing %s", strings.Join(missing, ", "))
	}
	if cfg.KeepaliveEvery <= 0 {
		cfg.KeepaliveEvery = 15 * time.Second
	}
	if cfg.MaxMissed <= 0 {
		cfg.MaxMissed = 3
	}
	if cfg.Backoff == nil {
		cfg.Backoff = defaultBackoff
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Height == nil {
		cfg.Height = func() uint64 { return 0 }
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	cfg.Logger = cfg.Logger.With("component", "dispatchstream", "builder", cfg.BuilderOperator)
	opts := append([]connect.ClientOption{connect.WithCodec(rawCodec{})}, cfg.ClientOptions...)
	return &Session{
		cfg: cfg,
		client: connect.NewClient[rawFrame, rawFrame](cfg.HTTPClient,
			strings.TrimRight(cfg.BaseURL, "/")+nexusv1connect.IngressAPIDispatchStreamProcedure, opts...),
		outbox: newOutbox(cfg.Store, cfg.BuilderOperator),
		dedup:  newDedup(cfg.Store, cfg.BuilderOperator, cfg.DedupRetention),
		kick:   make(chan struct{}, 1),
	}, nil
}

func defaultBackoff(attempt int) time.Duration {
	d := 200 * time.Millisecond
	for i := 0; i < attempt && d < 30*time.Second; i++ {
		d *= 2
	}
	return min(d, 30*time.Second)
}

// Enqueue strictly validates and persists a business message, then wakes the
// session to send it. It returns once the message is durable; delivery
// follows on the current or a later binding until acked or expired.
func (s *Session) Enqueue(ctx context.Context, p Outgoing) error {
	v, err := variantOf(p.Message)
	if err != nil {
		return err
	}
	raw, err := dispatchwire.Raw(p.Message)
	if err != nil {
		return err
	}
	if err := dispatch.ValidateMessage(dispatchwire.Name(p.Message), raw); err != nil {
		return fmt.Errorf("dispatchstream: outbound %s: %w", dispatchwire.Name(p.Message), err)
	}
	if _, err := s.outbox.put(ctx, pending{Variant: v, Payload: raw, ExpiresAtUnixMilli: p.ExpiresAtUnixMilli, ExpiryHeight: p.ExpiryHeight}); err != nil {
		return err
	}
	select {
	case s.kick <- struct{}{}:
	default:
	}
	return nil
}

// Run connects, serves and reconnects until ctx ends. It returns ctx.Err().
func (s *Session) Run(ctx context.Context) error {
	if !s.running.CompareAndSwap(false, true) {
		return errors.New("dispatchstream: session already running")
	}
	defer s.running.Store(false)
	for attempt := 0; ; {
		progressed, err := s.serve(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if progressed {
			attempt = 0
		}
		s.cfg.Logger.Warn("dispatch stream disconnected; reconnecting", "err", err, "attempt", attempt)
		t := time.NewTimer(s.cfg.Backoff(attempt))
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		attempt++
	}
}

// conn is the per-binding state; only serve's goroutine touches it.
type conn struct {
	stream  *connect.BidiStreamForClient[rawFrame, rawFrame]
	nonce   []byte
	in      inbound
	out     outbound
	ka      keepalive
	seqOf   map[uint64]uint64 // outbound cursor -> outbox seq
	sentSeq uint64            // highest outbox seq sent on this binding
}

type received struct {
	raw []byte
	err error
}

// serve runs one binding. progressed reports whether the peer sent at least
// one valid frame, which resets the backoff.
func (s *Session) serve(ctx context.Context) (progressed bool, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.prune(ctx)

	bindingFrame, nonce, err := s.newBinding(ctx)
	if err != nil {
		return false, err
	}
	c := &conn{stream: s.client.CallBidiStream(ctx), nonce: nonce, seqOf: map[uint64]uint64{}}
	frames := make(chan received)
	var wg sync.WaitGroup
	defer func() {
		cancel()
		_ = c.stream.CloseRequest()
		_ = c.stream.CloseResponse()
		wg.Wait()
	}()
	if err := c.stream.Send(&rawFrame{b: wrapEnvelope(bindingFrame)}); err != nil {
		return false, fmt.Errorf("send binding: %w", err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			var r received
			msg, err := c.stream.Receive()
			if err != nil {
				r.err = err
			} else {
				r.raw = msg.b
			}
			select {
			case frames <- r:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	if err := s.sendPending(ctx, c); err != nil {
		return false, err
	}
	ticker := time.NewTicker(s.cfg.KeepaliveEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return progressed, ctx.Err()
		case <-s.kick:
			if err := s.sendPending(ctx, c); err != nil {
				return progressed, err
			}
		case <-ticker.C:
			v, ok := c.ka.probe(uint64(max(s.cfg.Now().UnixMilli(), 0)))
			if !ok {
				if c.ka.missed >= s.cfg.MaxMissed {
					return progressed, fmt.Errorf("peer missed %d keepalive periods", c.ka.missed)
				}
				continue
			}
			if err := s.sendControl(c, &nexusv1.StreamKeepaliveV1{SentAtMs: v}); err != nil {
				return progressed, err
			}
		case r := <-frames:
			if r.err != nil {
				return progressed, fmt.Errorf("receive: %w", r.err)
			}
			if err := s.handleFrame(ctx, c, r.raw); err != nil {
				return progressed, err
			}
			progressed = true
		}
	}
}

func (s *Session) prune(ctx context.Context) {
	if err := s.outbox.prune(ctx, s.cfg.Now().UnixMilli(), s.cfg.Height()); err != nil {
		s.cfg.Logger.Warn("prune dispatch outbox", "err", err)
	}
	if err := s.dedup.prune(ctx); err != nil {
		s.cfg.Logger.Warn("prune dispatch dedup claims", "err", err)
	}
}

// sendPending sends, in order, every retained unexpired message not yet sent
// on this binding. On a fresh binding that is the replay of everything unacked.
func (s *Session) sendPending(ctx context.Context, c *conn) error {
	ps, err := s.outbox.replayable(ctx, s.cfg.Now().UnixMilli(), s.cfg.Height())
	if err != nil {
		return err
	}
	for _, p := range ps {
		if p.Seq <= c.sentSeq {
			continue
		}
		cursor, err := c.out.assign()
		if err != nil {
			return err
		}
		if err := c.stream.Send(&rawFrame{b: wrapEnvelope(encodeFrame(c.nonce, cursor, p.Variant, p.Payload))}); err != nil {
			return fmt.Errorf("send cursor %d: %w", cursor, err)
		}
		c.seqOf[cursor] = p.Seq
		c.sentSeq = p.Seq
	}
	return nil
}

func (s *Session) sendControl(c *conn, msg proto.Message) error {
	frame, err := encodeControl(c.nonce, msg)
	if err != nil {
		return err
	}
	return c.stream.Send(&rawFrame{b: wrapEnvelope(frame)})
}

// handleFrame applies one received frame. Any returned error drops the
// binding; the peer then replays whatever this side has not acked.
func (s *Session) handleFrame(ctx context.Context, c *conn, envelope []byte) error {
	raw, err := unwrapEnvelope(envelope)
	if err != nil {
		return err
	}
	// Strict decode on the bytes as received. wire's decoder recurses into
	// every nested message, so the inner business message is strictly
	// validated here too and its deterministic re-encoding below carries
	// exactly the fields the Builder signed.
	if err := dispatch.ValidateMessage(frameName, raw); err != nil {
		return fmt.Errorf("strict decode: %w", err)
	}
	frame := &nexusv1.DispatchStreamFrameV1{}
	if err := proto.Unmarshal(raw, frame); err != nil {
		return fmt.Errorf("unmarshal frame: %w", err)
	}
	if !bytes.Equal(frame.GetStreamNonce(), c.nonce) {
		return errors.New("frame nonce does not match the binding")
	}
	v, msg, _ := inner(frame) // ValidateMessage guarantees exactly one
	switch {
	case v == variantAck:
		prev := c.out.acked
		if err := c.out.ack(frame.GetAck().GetAckedCursor()); err != nil {
			return err
		}
		for cur := prev + 1; cur <= c.out.acked; cur++ {
			if err := s.outbox.done(ctx, c.seqOf[cur]); err != nil {
				return err
			}
			delete(c.seqOf, cur)
		}
		return nil
	case v == variantKeepalive:
		if echo, reply := c.ka.received(frame.GetKeepalive().GetSentAtMs()); reply {
			return s.sendControl(c, &nexusv1.StreamKeepaliveV1{SentAtMs: echo})
		}
		return nil
	case !v.fromBuilder():
		return fmt.Errorf("variant %d is not sent by a Builder", v)
	}

	switch verdict := c.in.accept(frame.GetCursor()); verdict {
	case cursorDuplicate:
		return nil
	case cursorNew:
	default:
		return fmt.Errorf("inbound cursor %d after %d: %s", frame.GetCursor(), c.in.ackable(), verdict)
	}
	if err := s.verifyBuilder(ctx, msg); err != nil {
		return err
	}
	key, err := s.dedup.key(v, msg)
	if err != nil {
		return err
	}
	// The claim is durable before the Handler runs, so the Handler sees each
	// message at most once even across reconnects and restarts. A crash after
	// the claim but before the Handler finishes loses the message; stream
	// messages are hints and chain state remains the authority (see plan
	// Architecture), so that is preferred over a double delivery.
	first, err := s.dedup.claim(ctx, key)
	if err != nil {
		return err
	}
	if first {
		if herr := s.cfg.Handler.HandleFrame(ctx, s.cfg.BuilderOperator, frame); herr != nil {
			if builderclient.IsRetryable(herr) {
				if rerr := s.dedup.release(ctx, key); rerr != nil {
					s.cfg.Logger.Error("release dedup claim; the redelivery will be dropped", "err", rerr, "variant", v)
				}
				return fmt.Errorf("handler (retryable, frame left unacked): %w", herr)
			}
			s.cfg.Logger.Warn("dispatch frame rejected by handler; acking", "err", herr, "variant", v, "cursor", frame.GetCursor())
		}
	} else {
		s.cfg.Logger.Debug("dispatch frame already delivered; acking replay", "variant", v, "cursor", frame.GetCursor())
	}
	return s.sendControl(c, &nexusv1.StreamAckV1{AckedCursor: c.in.ackable()})
}

// verifyBuilder checks builder_service_signature against the Builder's
// current on-chain key. Variants that are not themselves Builder-signed
// (offer, handraise_root) carry signed sub-messages that their business
// handlers verify in context (ticket, root + inclusion proof).
func (s *Session) verifyBuilder(ctx context.Context, msg proto.Message) error {
	key, err := s.cfg.BuilderKey(ctx)
	if err != nil {
		return fmt.Errorf("resolve Builder service key: %w", err)
	}
	if err := dispatchwire.VerifyBuilderSigned(msg, key); err != nil && !errors.Is(err, dispatchwire.ErrNotBuilderSigned) {
		return err
	}
	return nil
}

// rawFrame carries one stream message's protobuf bytes untouched.
type rawFrame struct{ b []byte }

// rawCodec replaces connect's "proto" codec for this client so the session
// sees the exact bytes the Builder sent and sends exactly the bytes it built.
type rawCodec struct{}

func (rawCodec) Name() string { return "proto" }

func (rawCodec) Marshal(v any) ([]byte, error) {
	f, ok := v.(*rawFrame)
	if !ok {
		return nil, fmt.Errorf("dispatchstream: raw codec cannot marshal %T", v)
	}
	return f.b, nil
}

func (rawCodec) Unmarshal(data []byte, v any) error {
	f, ok := v.(*rawFrame)
	if !ok {
		return fmt.Errorf("dispatchstream: raw codec cannot unmarshal into %T", v)
	}
	f.b = append([]byte(nil), data...) // connect reuses its read buffers
	return nil
}
