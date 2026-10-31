package daemon

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/TrueOpen/cortex/internal/builderclient"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
)

var errPlaneNotBound = errors.New("dispatch plane is not bound yet")

// dispatchRouter is every Builder Session's Handler (CD §4.2.0). The owners
// need the Sessions as their enqueuers, so they are bound after the Sessions
// exist (S3's atomic.Pointer pattern); Sessions only run after binding, and a
// frame that arrives earlier is retryable and stays unacked.
type dispatchRouter struct {
	handraise atomic.Pointer[StandingHandraiser]
	dispatch  atomic.Pointer[Dispatcher]
	verifier  atomic.Pointer[VerifierStream]
	keys      map[string]*builderKeyCache // read-only after construction
}

func (r *dispatchRouter) HandleFrame(ctx context.Context, from string, f *nexusv1.DispatchStreamFrameV1) error {
	switch {
	case f.GetHandraiseRoot() != nil:
		h := r.handraise.Load()
		if h == nil {
			return builderclient.Retryable(errPlaneNotBound)
		}
		return h.HandleRootNotice(ctx, from, f.GetHandraiseRoot())
	case f.GetOffer() != nil, f.GetRevoke() != nil, f.GetInputResponse() != nil, f.GetRecordResult() != nil:
		d := r.dispatch.Load()
		if d == nil {
			return builderclient.Retryable(errPlaneNotBound)
		}
		return d.HandleFrame(ctx, from, f)
	case f.GetOpenVerify() != nil, f.GetVerifierAssignment() != nil:
		v := r.verifier.Load()
		if v == nil {
			return builderclient.Retryable(errPlaneNotBound)
		}
		return v.HandleFrame(ctx, from, f)
	}
	return fmt.Errorf("dispatch router: frame variant has no handler")
}

// onBound is every Session's OnBound: a fresh Builder key read, a fresh
// standing handraise (S3 Q5), and input re-requests for the Builder's open
// tickets (S4 Q14). It never blocks.
func (r *dispatchRouter) onBound(builder string) {
	if k := r.keys[builder]; k != nil {
		k.Invalidate()
	}
	if h := r.handraise.Load(); h != nil {
		h.Rebound(builder)
	}
	if d := r.dispatch.Load(); d != nil {
		d.Rebound(builder)
	}
}
