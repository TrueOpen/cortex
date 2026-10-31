package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/diagnostics"
	"github.com/TrueOpen/cortex/internal/dispatchstream"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/store"
)

// DependencyDispatchStreams is the aggregate stream row: ready while at least
// one active Builder stream is bound. It gates /readyz, never the workload
// controller (S9 Q4).
const DependencyDispatchStreams = "dispatch_streams"

// StreamDependencyName is one Builder stream's readiness row.
func StreamDependencyName(builder string) string { return "dispatch_stream:" + builder }

type DispatchStreamsConfig struct {
	ChainID, Operator  string
	Builders, Retiring []string
	Stream             config.DispatchStreamConfig
	Endpoints          BuilderEndpointResolver
	Members            builderMembership // nil: no membership read
	HTTP               connect.HTTPClient
	Downgrade          bool
	Keys               builderServiceKeyReader
	Sign               dispatchwire.DigestSigner
	Height             func() uint64
	Store              *store.Store
	Now                func() time.Time
	Logger             *slog.Logger
}

// DispatchStreams is one dispatchstream.Session per configured Builder, the
// router they share as Handler, and the Verifier fan-out over the active
// ones. The Runtime builds it; DispatchPlane binds the owners and runs it.
type DispatchStreams struct {
	cfg      DispatchStreamsConfig
	router   *dispatchRouter
	order    []string
	sessions map[string]*dispatchstream.Session
	retiring map[string]bool
	fanout   *StreamFanout
	plane    atomic.Pointer[DispatchPlane]
	mu       sync.Mutex
	retired  map[string]bool
}

func NewDispatchStreams(cfg DispatchStreamsConfig) (*DispatchStreams, error) {
	if len(cfg.Builders) == 0 || cfg.Endpoints == nil || cfg.HTTP == nil || cfg.Keys == nil || cfg.Sign == nil || cfg.Height == nil || cfg.Store == nil {
		return nil, fmt.Errorf("dispatch streams: incomplete config")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &DispatchStreams{cfg: cfg, router: &dispatchRouter{keys: map[string]*builderKeyCache{}},
		sessions: map[string]*dispatchstream.Session{}, retiring: map[string]bool{}, retired: map[string]bool{}}
	for _, b := range cfg.Retiring {
		s.retiring[b] = true
	}
	s.order = slices.Sorted(slices.Values(append(append([]string(nil), cfg.Builders...), cfg.Retiring...)))
	authNonce := func(ctx context.Context) (uint64, error) {
		k, _, err := cfg.Keys.CommittedCurrentServiceKey(ctx, chainclient.ParticipantTypeCortexNode, cfg.Operator)
		if err != nil {
			return 0, err
		}
		if k.Status != "ACTIVE" {
			return 0, fmt.Errorf("this node's service key is %s", k.Status)
		}
		return k.AuthorizationNonce.Uint64(), nil
	}
	active := map[string]HandraiseEnqueuer{}
	for _, b := range s.order {
		keys := &builderKeyCache{builder: b, chain: cfg.Keys, height: cfg.Height}
		s.router.keys[b] = keys
		sess, err := dispatchstream.New(dispatchstream.Config{
			ChainID: cfg.ChainID, BuilderOperator: b, CortexOperator: cfg.Operator,
			HTTPClient: &descriptorClient{builder: b, endpoints: cfg.Endpoints, members: cfg.Members, http: cfg.HTTP, downgrade: cfg.Downgrade},
			BaseURL:    dispatchStreamBase, Sign: cfg.Sign, AuthNonce: authNonce, BuilderKey: keys.Key,
			Store: cfg.Store, Handler: s.router, KeepaliveEvery: cfg.Stream.Keepalive(), MaxMissed: cfg.Stream.MaxMissed,
			HandlerTimeout: cfg.Stream.HandlerTimeout(), Backoff: streamBackoff(cfg.Stream.ReconnectMin(), cfg.Stream.ReconnectMax()),
			Now: cfg.Now, Height: cfg.Height, OnBound: s.router.onBound, Logger: cfg.Logger,
		})
		if err != nil {
			return nil, err
		}
		s.sessions[b] = sess
		if !s.retiring[b] {
			active[b] = sess
		}
	}
	fanout, err := NewStreamFanout(active, cfg.Logger)
	if err != nil {
		return nil, err
	}
	s.fanout = fanout
	return s, nil
}

func streamBackoff(minD, maxD time.Duration) func(int) time.Duration {
	if minD <= 0 {
		minD = 200 * time.Millisecond
	}
	if maxD <= 0 {
		maxD = 30 * time.Second
	}
	maxD = max(maxD, minD)
	return func(attempt int) time.Duration {
		d := minD
		for i := 0; i < attempt && d < maxD; i++ {
			d *= 2
		}
		return min(d, maxD)
	}
}

// Fanout is the Verifier FrameSender and NoticeSender (S7).
func (s *DispatchStreams) Fanout() *StreamFanout { return s.fanout }

// Plane is the bound plane, or nil before NewDispatchPlane.
func (s *DispatchStreams) Plane() *DispatchPlane { return s.plane.Load() }

func (s *DispatchStreams) markRetired(b string) {
	s.mu.Lock()
	s.retired[b] = true
	s.mu.Unlock()
}

func (s *DispatchStreams) isRetired(b string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retired[b]
}

// Statuses is one optional row per Builder stream and the aggregate row.
func (s *DispatchStreams) Statuses() []diagnostics.DependencyStatus {
	out := make([]diagnostics.DependencyStatus, 0, len(s.order)+1)
	bound := false
	for _, b := range s.order {
		st := s.sessions[b].State()
		row := diagnostics.DependencyStatus{Name: StreamDependencyName(b), Configured: true, Ready: st.Bound, Error: st.LastError, Optional: true}
		switch {
		case s.isRetired(b):
			row.Ready, row.Error = true, "retired: delete it from dispatch.retiring_builders"
		case st.Bound:
			bound = bound || !s.retiring[b]
		case row.Error == "":
			row.Error = "not connected"
		}
		out = append(out, row)
	}
	agg := diagnostics.DependencyStatus{Name: DependencyDispatchStreams, Configured: true, Ready: bound}
	if !bound {
		agg.Error = "no configured Builder stream is bound"
	}
	return append(out, agg)
}
