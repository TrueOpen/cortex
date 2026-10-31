package dispatchstream

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
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

	Sign      dispatchwire.DigestSigner
	AuthNonce func(context.Context) (uint64, error) // current service_authorization_nonce
	// BuilderKey resolves the Builder's current on-chain service key
	// (QueryCurrentServiceKey(BUILDER, op)). It is called for every
	// Builder-signed frame; caching with rotation awareness is the caller's
	// job (daemon's builderKeyCache).
	BuilderKey func(context.Context) ([]byte, error)
	Store      *store.Store
	Handler    Handler

	KeepaliveEvery time.Duration // default 15s
	PruneEvery     time.Duration // outbox + dedup prune while bound; default 10m
	MaxMissed      int           // default 3
	// HandlerTimeout bounds one Handler call. It must be below
	// KeepaliveEvery*MaxMissed (the loop is blocked while a Handler runs);
	// default half of that. This only bounds our own keepalive window: the
	// Builder's liveness threshold is its own deployment setting, so the
	// daemon keeps it below one keepalive period
	// (dispatch.stream.handler_timeout_ms).
	HandlerTimeout time.Duration
	Backoff        func(attempt int) time.Duration
	Now            func() time.Time // default time.Now
	// Height is the latest known chain height, for height-bound expiry of
	// outbound messages; required. Zero means unknown: nothing expires by
	// height.
	Height         func() uint64
	DedupRetention time.Duration // default DefaultDedupRetention
	Rand           io.Reader     // stream nonces; default crypto/rand
	// OnBound, when set, is called with the Builder operator after each new
	// binding frame is sent and before any replay. It must not block. The
	// standing handraise uses it to sign a fresh handraise for every binding
	// (CD §4.2.0 "流断开 … 并重发常驻举手").
	OnBound func(builder string)
	Logger  *slog.Logger
}

// ErrInvalidOutgoing marks an Enqueue refusal of the message itself (wrong
// variant, not strictly decodable, unsigned, no expiry): enqueueing it again
// can never succeed. Any other Enqueue error is a failure to persist it.
var ErrInvalidOutgoing = errors.New("dispatchstream: invalid outbound message")

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
	dedup   deliveries
	kick    chan struct{}
	running atomic.Bool

	// keepaliveTicks replaces the keepalive ticker when set (tests).
	keepaliveTicks <-chan time.Time
	// sendFrame sends one business frame; nil means c.stream.Send (tests).
	sendFrame func(*conn, *rawFrame) error

	// bootSeq is the outbox sequence when this Session was built: anything at
	// or below it may have been sent by an earlier process.
	bootSeq uint64
	sentMu  sync.Mutex
	sent    map[uint64]time.Time
	// forgotten is the highest sequence dropped from sent; at or below it the
	// answer stays the conservative "maybe sent".
	forgotten uint64

	stateMu sync.Mutex
	state   SessionState
}

// SessionState is one Builder stream as readiness reports it (CD §14.1
// "各 Builder 直连流状态").
type SessionState struct {
	Bound     bool      // a binding was sent and the connection is being served
	Since     time.Time // when Bound last changed
	Attempt   int       // reconnect attempts since the last progress
	LastError string    // why the last connection ended; "" while bound
}

// State returns the current connection state.
func (s *Session) State() SessionState {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.state
}

func (s *Session) setState(bound bool, attempt int, err error) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.state.Bound != bound || s.state.Since.IsZero() {
		s.state.Since = s.cfg.Now()
	}
	s.state.Bound, s.state.Attempt, s.state.LastError = bound, attempt, ""
	if err != nil {
		s.state.LastError = err.Error()
	}
}

// New builds a Session. There must be exactly one Session per Builder per
// store: the outbox sequence, outbound replay and dedup records are keyed by
// Builder and assume a single writer.
func New(cfg Config) (*Session, error) {
	var missing []string
	for name, absent := range map[string]bool{
		"ChainID": cfg.ChainID == "", "BuilderOperator": cfg.BuilderOperator == "",
		"CortexOperator": cfg.CortexOperator == "", "HTTPClient": cfg.HTTPClient == nil,
		"BaseURL": cfg.BaseURL == "", "Sign": cfg.Sign == nil, "AuthNonce": cfg.AuthNonce == nil,
		"BuilderKey": cfg.BuilderKey == nil, "Store": cfg.Store == nil, "Handler": cfg.Handler == nil,
		"Height": cfg.Height == nil,
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
	if cfg.PruneEvery <= 0 {
		cfg.PruneEvery = 10 * time.Minute
	}
	if cfg.MaxMissed <= 0 {
		cfg.MaxMissed = 3
	}
	window := cfg.KeepaliveEvery * time.Duration(cfg.MaxMissed)
	if cfg.HandlerTimeout <= 0 {
		cfg.HandlerTimeout = window / 2
	}
	if cfg.HandlerTimeout >= window {
		return nil, fmt.Errorf("dispatchstream: HandlerTimeout %v must be below KeepaliveEvery*MaxMissed %v", cfg.HandlerTimeout, window)
	}
	if cfg.Backoff == nil {
		cfg.Backoff = defaultBackoff
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	cfg.Logger = cfg.Logger.With("component", "dispatchstream", "builder", cfg.BuilderOperator)
	// The package's codec and read bound go last so caller options cannot
	// override them.
	opts := append(append([]connect.ClientOption(nil), cfg.ClientOptions...),
		connect.WithCodec(rawCodec{}),
		connect.WithReadMaxBytes(maxEnvelopeBytes),
	)
	out := newOutbox(cfg.Store, cfg.BuilderOperator, cfg.Logger)
	boot, err := out.lastSeq(context.Background())
	if err != nil {
		return nil, fmt.Errorf("dispatchstream: read outbox sequence: %w", err)
	}
	return &Session{
		cfg: cfg,
		client: connect.NewClient[rawFrame, rawFrame](cfg.HTTPClient,
			strings.TrimRight(cfg.BaseURL, "/")+nexusv1connect.IngressAPIDispatchStreamProcedure, opts...),
		outbox:  out,
		dedup:   newDedup(cfg.Store, cfg.BuilderOperator, cfg.DedupRetention, cfg.Now, cfg.Logger),
		kick:    make(chan struct{}, 1),
		bootSeq: boot,
		sent:    map[uint64]time.Time{},
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
func (s *Session) Enqueue(ctx context.Context, p Outgoing) (seq uint64, err error) {
	rec, err := s.checkOutgoing(p)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrInvalidOutgoing, err)
	}
	seq, err = s.outbox.put(ctx, rec)
	if err != nil {
		return 0, err
	}
	select {
	case s.kick <- struct{}{}:
	default:
	}
	return seq, nil
}

// checkOutgoing is Enqueue's validation of the message itself.
func (s *Session) checkOutgoing(p Outgoing) (pending, error) {
	v, err := variantOf(p.Message)
	if err != nil {
		return pending{}, err
	}
	raw, err := dispatchwire.Raw(p.Message)
	if err != nil {
		return pending{}, err
	}
	name := dispatchwire.Name(p.Message)
	if err := dispatch.ValidateMessage(name, raw); err != nil {
		return pending{}, fmt.Errorf("dispatchstream: outbound %s: %w", name, err)
	}
	// The largest frame this message can ever ride in (full nonce, maximal
	// cursor) must still pass the peer's strict decoder.
	worst := encodeFrame(make([]byte, dispatch.StreamNonceSize), math.MaxUint64, v, raw)
	if err := dispatch.ValidateMessage(frameName, worst); err != nil {
		return pending{}, fmt.Errorf("dispatchstream: outbound %s does not fit a stream frame: %w", name, err)
	}
	sig := p.Message.ProtoReflect().Descriptor().Fields().ByName("service_signature")
	if sig == nil {
		return pending{}, fmt.Errorf("dispatchstream: outbound %s is not Cortex-signed", name)
	}
	if n := len(p.Message.ProtoReflect().Get(sig).Bytes()); n != dispatch.SignatureSize {
		return pending{}, fmt.Errorf("dispatchstream: outbound %s carries a %d-byte signature, want %d", name, n, dispatch.SignatureSize)
	}
	rec := pending{Variant: v, Payload: raw, ExpiresAtUnixMilli: p.ExpiresAtUnixMilli, ExpiryHeight: p.ExpiryHeight}
	return rec, rec.validate()
}

// Run connects, serves and reconnects until ctx ends. It returns ctx.Err().
func (s *Session) Run(ctx context.Context) error {
	if !s.running.CompareAndSwap(false, true) {
		return errors.New("dispatchstream: session already running")
	}
	defer s.running.Store(false)
	defer s.setState(false, 0, errors.New("session stopped"))
	for attempt := 0; ; {
		progressed, err := s.serve(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if progressed {
			attempt = 0
		}
		s.setState(false, attempt, err)
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

// serve runs one binding. progressed reports business progress -- a business
// frame handled to completion or one of ours acked -- which resets the
// backoff. Control frames alone do not count.
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
		wg.Wait() // the reader is out of Receive before the response closes
		_ = c.stream.CloseResponse()
	}()
	if err := c.stream.Send(&rawFrame{b: wrapEnvelope(bindingFrame)}); err != nil {
		return false, fmt.Errorf("send binding: %w", err)
	}
	if s.cfg.OnBound != nil {
		s.cfg.OnBound(s.cfg.BuilderOperator)
	}
	s.setState(true, 0, nil)
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
	ticks := s.keepaliveTicks
	if ticks == nil {
		ticker := time.NewTicker(s.cfg.KeepaliveEvery)
		defer ticker.Stop()
		ticks = ticker.C
	}
	pruneTicker := time.NewTicker(s.cfg.PruneEvery)
	defer pruneTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return progressed, ctx.Err()
		case <-s.kick:
			if err := s.sendPending(ctx, c); err != nil {
				return progressed, err
			}
		case <-pruneTicker.C:
			s.prune(ctx)
		case <-ticks:
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
			business, err := s.handleFrame(ctx, c, r.raw)
			if business {
				progressed = true
			}
			if err != nil {
				return progressed, err
			}
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
	s.forgetSent(s.cfg.Now().Add(-sentMemory))
}

// sentMemory bounds how long WasSent remembers a transmission exactly.
// Callers ask within an accept window (seconds).
const sentMemory = 24 * time.Hour

// WasSent reports whether the business message Enqueue returned seq for may
// have reached the Builder: this Session picked it for a stream (it is marked
// before the Send is attempted, and a message that expired by then is marked
// and skipped), or it was enqueued before this Session was built (an earlier
// process may have sent it). False means it was certainly never transmitted -- the only case
// in which a Cortex may treat a signed accept as never given (CD §4.2.0, C4).
func (s *Session) WasSent(seq uint64) bool {
	if seq <= s.bootSeq {
		return true
	}
	s.sentMu.Lock()
	defer s.sentMu.Unlock()
	if seq <= s.forgotten {
		return true
	}
	_, ok := s.sent[seq]
	return ok
}

func (s *Session) markSent(seq uint64) {
	s.sentMu.Lock()
	defer s.sentMu.Unlock()
	if _, ok := s.sent[seq]; !ok {
		s.sent[seq] = s.cfg.Now()
	}
}

func (s *Session) forgetSent(before time.Time) {
	s.sentMu.Lock()
	defer s.sentMu.Unlock()
	for seq, at := range s.sent {
		if at.Before(before) {
			delete(s.sent, seq)
			s.forgotten = max(s.forgotten, seq)
		}
	}
}

// sendPending sends, in order, every retained unexpired message not yet sent
// on this binding. On a fresh binding that is the replay of everything unacked.
func (s *Session) sendPending(ctx context.Context, c *conn) error {
	ps, err := s.outbox.replayable(ctx, s.cfg.Now().UnixMilli(), s.cfg.Height(), c.sentSeq)
	if err != nil {
		return err
	}
	send := s.sendFrame
	if send == nil {
		send = func(c *conn, f *rawFrame) error { return c.stream.Send(f) }
	}
	for _, p := range ps {
		// Marked before Send: a failed Send may still have put bytes on the
		// wire, and a false "maybe sent" is safe where a false "not sent" is
		// not (WasSent).
		s.markSent(p.Seq)
		// Re-checked after marking: a caller that saw this message unsent at
		// its deadline may already have given it up, so it must not go out
		// now. Clock and height are the ones that caller reads.
		if p.expired(s.cfg.Now().UnixMilli(), s.cfg.Height()) {
			c.sentSeq = p.Seq
			continue
		}
		cursor, err := c.out.assign()
		if err != nil {
			return err
		}
		if err := send(c, &rawFrame{b: wrapEnvelope(encodeFrame(c.nonce, cursor, p.Variant, p.Payload))}); err != nil {
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

// handleFrame applies one received frame. business reports progress (see
// serve). Any returned error drops the binding; the peer then replays
// whatever this side has not acked.
func (s *Session) handleFrame(ctx context.Context, c *conn, envelope []byte) (business bool, err error) {
	var cursor uint64
	label := "frame"
	defer func() {
		if err != nil {
			prefix := "dispatchstream: "
			if strings.HasPrefix(err.Error(), prefix) {
				prefix = "" // inner error already names the package
			}
			err = fmt.Errorf("%scursor %d %s: %w", prefix, cursor, label, err)
		}
	}()
	raw, err := unwrapEnvelope(envelope)
	if err != nil {
		return false, err
	}
	// Strict decode on the bytes as received; it recurses into the inner
	// message. Signature and digest are then taken from the received inner
	// bytes, never from a re-encoding.
	if err := dispatch.ValidateMessage(frameName, raw); err != nil {
		return false, fmt.Errorf("strict decode: %w", err)
	}
	frame := &nexusv1.DispatchStreamFrameV1{}
	if err := proto.Unmarshal(raw, frame); err != nil {
		return false, fmt.Errorf("unmarshal frame: %w", err)
	}
	if !bytes.Equal(frame.GetStreamNonce(), c.nonce) {
		return false, errors.New("frame nonce does not match the binding")
	}
	v, msg, _ := inner(frame) // ValidateMessage guarantees exactly one
	cursor, label = frame.GetCursor(), variantName(v)
	switch {
	case v == variantAck:
		prev := c.out.acked
		if err := c.out.ack(frame.GetAck().GetAckedCursor()); err != nil {
			return false, err
		}
		for cur := prev + 1; cur <= c.out.acked; cur++ {
			if err := s.outbox.done(ctx, c.seqOf[cur]); err != nil {
				return true, err
			}
			delete(c.seqOf, cur)
		}
		return c.out.acked > prev, nil
	case v == variantKeepalive:
		if echo, reply := c.ka.received(frame.GetKeepalive().GetSentAtMs()); reply {
			return false, s.sendControl(c, &nexusv1.StreamKeepaliveV1{SentAtMs: echo})
		}
		return false, nil
	case !v.fromBuilder():
		return false, fmt.Errorf("variant %d is not sent by a Builder", v)
	}

	name := variantName(v)
	in, err := innerRaw(raw, v)
	if err != nil {
		return false, err
	}
	digest, err := messageDigest(name, in, msg)
	if err != nil {
		return false, fmt.Errorf("%s digest: %w", name, err)
	}
	// Inbound cursors must be contiguous within a binding (PHASE1_CONTRACT;
	// Nexus enforces the same): a repeat, identical or not, is a violation
	// that ends the stream like a gap does. Replays across bindings are
	// absorbed by the dedup records below, not by cursor.
	if verdict := c.in.accept(cursor); verdict != cursorNew {
		return false, fmt.Errorf("inbound cursor %d after %d: %s", cursor, c.in.ackable(), verdict)
	}
	if err := s.verifyBuilder(ctx, name, in); err != nil {
		return false, err
	}

	// At-least-once: the record is "received" before the Handler runs and
	// "done" after it finishes; only "done" suppresses a replay, and the ack
	// follows "done". A crash in between redelivers.
	key := s.dedup.key(v, digest)
	done, err := s.dedup.delivered(ctx, key)
	if err != nil {
		return false, err
	}
	if done {
		s.cfg.Logger.Debug("dispatch frame already handled; acking replay", "variant", v, "cursor", cursor)
	} else {
		if err := s.dedup.mark(ctx, key, stateReceived); err != nil {
			return false, err
		}
		hctx, hcancel := context.WithTimeout(ctx, s.cfg.HandlerTimeout)
		herr := s.cfg.Handler.HandleFrame(hctx, s.cfg.BuilderOperator, frame)
		timedOut := errors.Is(hctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil
		hcancel()
		if ctx.Err() != nil {
			// The session is shutting down: whatever the Handler reported, the
			// delivery is left "received" and unacked, so it is redelivered.
			return false, fmt.Errorf("session stopped during handler: %w", ctx.Err())
		}
		// A nil result is success even past the deadline: the work is done.
		// An error after the deadline is taken as caused by it, so retryable.
		if herr != nil && timedOut {
			return false, fmt.Errorf("handler exceeded %v (retryable, frame left unacked): %w", s.cfg.HandlerTimeout, herr)
		}
		if herr != nil {
			if builderclient.IsRetryable(herr) || errors.Is(herr, context.Canceled) || errors.Is(herr, context.DeadlineExceeded) {
				return false, fmt.Errorf("handler (retryable, frame left unacked): %w", herr)
			}
			s.cfg.Logger.Warn("dispatch frame rejected by handler; acking", "err", herr, "variant", v, "cursor", cursor)
		}
		if err := s.dedup.mark(ctx, key, stateDone); err != nil {
			return false, err
		}
	}
	return true, s.sendControl(c, &nexusv1.StreamAckV1{AckedCursor: c.in.ackable()})
}

// verifyBuilder checks builder_service_signature on the received inner bytes
// against the Builder's current on-chain key. Variants that are not
// themselves Builder-signed (offer, handraise_root) are left to their
// Handlers (see Handler).
func (s *Session) verifyBuilder(ctx context.Context, name string, in []byte) error {
	key, err := s.cfg.BuilderKey(ctx)
	if err != nil {
		return fmt.Errorf("resolve Builder service key: %w", err)
	}
	if err := dispatchwire.VerifyBuilderSignedRaw(name, in, key); err != nil && !errors.Is(err, dispatchwire.ErrNotBuilderSigned) {
		return err
	}
	return nil
}
