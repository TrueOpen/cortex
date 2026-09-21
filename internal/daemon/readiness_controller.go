package daemon

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/diagnostics"
)

type WorkloadReadiness struct {
	ServiceAddress string
	// ServicePubkey is the compressed secp256k1 public key Keeper binds to the
	// current service address. Nexus role signatures carry it.
	ServicePubkey     string
	Identity          diagnostics.DependencyStatus
	ModelSupport      diagnostics.DependencyStatus
	ModelService      diagnostics.DependencyStatus
	Nexus             diagnostics.DependencyStatus
	BuilderDescriptor diagnostics.DependencyStatus
	TxBroadcaster     diagnostics.DependencyStatus
	// Chain, Keeper and Store are probed on every pass. They used to be reported
	// from a startup constant that hardcoded readiness, so they stayed "ready"
	// through an outage that had already killed the process once.
	Chain  diagnostics.DependencyStatus
	Keeper diagnostics.DependencyStatus
	Store  diagnostics.DependencyStatus
	// ChainSync reports whether consumed Keeper events have caught up to the
	// chain tip within keeper.max_lag_blocks. A node replaying a backlog after
	// downtime is not ready to take new work, but it must keep consuming events
	// so it can catch up -- so staleness gates activation here rather than
	// stopping the poller.
	ChainSync diagnostics.DependencyStatus
	// EnvelopeAuth reports whether this node can authenticate inbound bus
	// traffic right now. Construction success is not enough: an unreadable
	// current-key view or an unwritable replay store makes every inbound frame
	// unverifiable, and a node in that state must stop claiming it can take work.
	EnvelopeAuth diagnostics.DependencyStatus
	// NATSIdentity reports whether this node can still sign the on-chain binding
	// it presents to NATS (ADR-0016 decision three). It gates the workload
	// whenever the row is Configured -- a node that cannot sign its binding
	// cannot reach the bus, so it must stop taking new work (see
	// workloadDependenciesReady); on the creds/token path the row is optional and
	// unconfigured, and gates nothing. The observability health map keeps this
	// dependency optional because that map cannot see the configuration and so
	// cannot make that distinction.
	NATSIdentity      diagnostics.DependencyStatus
	DependenciesReady bool
}

func (r WorkloadReadiness) Ready() bool {
	return r.DependenciesReady && r.Identity.Ready && r.ModelSupport.Ready && r.ChainSync.Ready && r.ServiceAddress != ""
}

// DependencyStatuses lists every boundary this snapshot probed, in the order it
// should be reported. Callers that fan a snapshot out -- to the health
// endpoint, to the readiness log -- walk this instead of naming fields one by
// one: a dependency added to the struct and forgotten in one of those callers
// is exactly how a boundary stops being reported without anyone noticing.
func (r WorkloadReadiness) DependencyStatuses() []diagnostics.DependencyStatus {
	return []diagnostics.DependencyStatus{
		r.Identity,
		r.ModelSupport,
		r.ModelService,
		r.Nexus,
		r.BuilderDescriptor,
		r.EnvelopeAuth,
		r.NATSIdentity,
		r.TxBroadcaster,
		r.Chain,
		r.Keeper,
		r.Store,
		r.ChainSync,
	}
}

type ReadinessControllerConfig struct {
	Interval time.Duration
	Check    func(context.Context) WorkloadReadiness
	// Start must call started once its runners have actually been launched.
	// Until then the controller keeps workload readiness false.
	Start   func(context.Context, WorkloadReadiness, func()) error
	Stop    func()
	Observe func(WorkloadReadiness)
	// ObserveWorkload reports whether the workload runners are currently
	// running. It is called on every transition so readiness can distinguish a
	// node that is serving from one whose boundaries are merely reachable.
	ObserveWorkload func(running bool)
	// OnRetryableFailure reports a workload start that failed for a reason the
	// next attempt may resolve, so an operator can see it while the controller
	// keeps retrying.
	OnRetryableFailure func(error)
}

type ReadinessController struct {
	cfg ReadinessControllerConfig
}

func NewReadinessController(cfg ReadinessControllerConfig) *ReadinessController {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Second
	}
	return &ReadinessController{cfg: cfg}
}

func (c *ReadinessController) Run(ctx context.Context) error {
	if c == nil || c.cfg.Check == nil || c.cfg.Start == nil {
		return errors.New("readiness controller check and start functions are required")
	}

	var workloadCancel context.CancelFunc
	var workloadCtx context.Context
	var workloadDone <-chan error
	var activeServiceAddress string
	reportWorkload := func(running bool) {
		if c.cfg.ObserveWorkload != nil {
			c.cfg.ObserveWorkload(running)
		}
	}
	reportWorkload(false)
	stopWorkload := func() {
		if workloadCancel == nil {
			return
		}
		workloadCancel()
		<-workloadDone
		if c.cfg.Stop != nil {
			c.cfg.Stop()
		}
		workloadCancel = nil
		workloadCtx = nil
		workloadDone = nil
		activeServiceAddress = ""
		reportWorkload(false)
	}
	defer stopWorkload()

	for {
		readiness := c.cfg.Check(ctx)
		if c.cfg.Observe != nil {
			c.cfg.Observe(readiness)
		}
		if workloadCancel != nil && (!readiness.Ready() || readiness.ServiceAddress != activeServiceAddress) {
			stopWorkload()
		}
		if readiness.Ready() && workloadCancel == nil {
			var cancel context.CancelFunc
			workloadCtx, cancel = context.WithCancel(ctx)
			done := make(chan error, 1)
			workloadCancel = cancel
			workloadDone = done
			activeServiceAddress = readiness.ServiceAddress
			go func() {
				var startedOnce sync.Once
				done <- c.cfg.Start(workloadCtx, readiness, func() {
					startedOnce.Do(func() { reportWorkload(true) })
				})
			}()
		}

		timer := time.NewTimer(c.cfg.Interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case err := <-workloadDone:
			if !timer.Stop() {
				<-timer.C
			}
			cleanShutdown := isContextShutdown(workloadCtx, err)
			workloadCancel = nil
			workloadCtx = nil
			workloadDone = nil
			activeServiceAddress = ""
			reportWorkload(false)
			if c.cfg.Stop != nil {
				c.cfg.Stop()
			}
			// If parent shutdown and workload completion become ready together,
			// select may observe workloadDone first. Exit here rather than loop
			// once more and launch a replacement during shutdown.
			if ctx.Err() != nil {
				return nil
			}
			switch {
			case err == nil || cleanShutdown:
			case builderclient.IsRetryable(err):
				// A retryable workload failure must not take the daemon down.
				// The common case is a JetStream durable still bound to a
				// previous instance of this operator, which the server releases
				// on its own within tens of seconds. Deleting the consumer to
				// force the issue would discard its ack position and replay the
				// whole retention window, so the correct response is to wait and
				// retry -- while /readyz reports the node as not serving, so a
				// genuine double-start is visible rather than silent.
				if c.cfg.OnRetryableFailure != nil {
					c.cfg.OnRetryableFailure(err)
				}
				if !waitForReadinessRetry(ctx, c.cfg.Interval) {
					return nil
				}
			default:
				return err
			}
		case <-timer.C:
		}
	}
}

func waitForReadinessRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
