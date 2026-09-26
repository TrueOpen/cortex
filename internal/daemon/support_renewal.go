package daemon

import (
	"context"
	"fmt"
	"time"

	"github.com/TrueOpen/cortex/internal/config"
)

// SupportRenewer keeps this node's declared model support fresh.
//
// Support freshness expires on a window the chain sets, and an expired support
// is not a degraded state: the handraise path refuses the node outright
// ("Keeper model support is stale"), so the node stops being offered work while
// looking healthy in every other respect. Until now the only thing that renewed
// it was an operator remembering to run `cortexctl daily-support`.
//
// It renews early rather than at expiry. The confirmation is a transaction: it
// has to be built, broadcast and included, and a node that starts trying in the
// last block of the window has one attempt and no room for a full mempool or a
// brief chain outage. Renewing at SupportRenewalThreshold of the window leaves
// the rest of it as retry budget.
type SupportRenewer struct {
	cfg SupportRenewerConfig
}

// SupportConfirmer renews the declared support for one model. It is the same
// operation `cortexctl daily-support` performs, reached through the registry.
type SupportConfirmer interface {
	RenewDailySupport(ctx context.Context, modelID string) error
}

type SupportRenewerConfig struct {
	Identity  config.LocalIdentityConfig
	Keeper    KeeperIdentityReader
	Height    func(context.Context) (uint64, error)
	Confirmer SupportConfirmer
	Interval  time.Duration
	// EpochLength converts a height into the epoch the committed-scope
	// freshness test is expressed in. Zero disables that branch, leaving the
	// height-window branch, which is the one a node without a committed scope
	// is judged by anyway.
	EpochLength uint64
	// OnRenewal and OnFailure report what happened. Failures are reported
	// rather than returned: see Run.
	OnRenewal func(modelID string, remaining uint64)
	OnFailure func(modelID string, err error)
}

// SupportRenewalThreshold is the fraction of the freshness window that must
// remain for support to be left alone. Below it, renewal is attempted.
//
// A quarter rather than a half: renewing at half the window doubles the
// transaction rate for no benefit, and the chain charges for each one. A
// quarter of the current 180-epoch window is still tens of epochs of retry
// budget.
const SupportRenewalThreshold = 4

func NewSupportRenewer(cfg SupportRenewerConfig) *SupportRenewer {
	if cfg.Keeper == nil || cfg.Confirmer == nil || cfg.Height == nil {
		return nil
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	return &SupportRenewer{cfg: cfg}
}

// Run renews on a timer until ctx ends.
//
// It never returns an error for a failed renewal, and that is deliberate rather
// than lax. cortexd runs its runners as a group in which one returning an error
// stops the whole runtime, so a renewer that propagated a transient chain
// failure would take the node down over something the next tick would have
// fixed. A renewal that keeps failing shows up as a repeated log line and then,
// eventually, as the stale-support refusal it was meant to prevent -- a visible
// degradation rather than an outage.
func (r *SupportRenewer) Run(ctx context.Context) error {
	if r == nil {
		return nil
	}
	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()
	for {
		r.RunOnce(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// RunOnce checks every configured profile and renews the ones running out.
func (r *SupportRenewer) RunOnce(ctx context.Context) {
	profiles, err := r.cfg.Identity.ModelProfiles()
	if err != nil || len(profiles) == 0 {
		return
	}
	height, err := r.cfg.Height(ctx)
	if err != nil || height == 0 {
		return
	}
	params, err := r.cfg.Keeper.Params(ctx)
	if err != nil {
		return
	}
	window := params.DailySupportWindowBlocks.Uint64()
	if window == 0 {
		return
	}
	// One confirmation renews every configured profile, because Node keeps one
	// record per (epoch, operator) -- see dailySupportProfiles in cortexd. So
	// the first profile that needs renewing triggers it, and the rest are
	// covered by the same transaction; checking them all afterwards would only
	// produce redundant transactions.
	for _, profile := range profiles {
		remaining, needed, err := r.remainingFreshness(ctx, profile.ModelID, profile.ProfileVersion, height, window)
		if err != nil {
			r.report(profile.ModelID, err)
			return
		}
		if !needed {
			continue
		}
		if err := r.cfg.Confirmer.RenewDailySupport(ctx, profile.ModelID); err != nil {
			r.report(profile.ModelID, fmt.Errorf("renew daily support: %w", err))
			return
		}
		if r.cfg.OnRenewal != nil {
			r.cfg.OnRenewal(profile.ModelID, remaining)
		}
		return
	}
}

// remainingFreshness reports how much of the window is left and whether that is
// little enough to renew.
//
// The two branches mirror the handraise eligibility test exactly, and have to:
// a renewer using a different rule from the one that judges staleness would
// report support as fresh right up until the handraise that refuses it.
func (r *SupportRenewer) remainingFreshness(ctx context.Context, modelID string, profileVersion uint32, height, window uint64) (uint64, bool, error) {
	support, err := r.cfg.Keeper.ModelSupport(ctx, r.cfg.Identity.OperatorAddress, modelID, fmt.Sprintf("%d", profileVersion))
	if err != nil {
		return 0, false, err
	}
	if !support.DeclaredSupport {
		// Never declared, or withdrawn. Renewal confirms an existing
		// declaration and is not the operation that creates one.
		return 0, false, nil
	}
	if r.cfg.EpochLength > 0 && support.SupportFreshUntilEpoch.Uint64() > 0 {
		currentEpoch := height / r.cfg.EpochLength
		freshUntil := support.SupportFreshUntilEpoch.Uint64()
		if currentEpoch >= freshUntil {
			return 0, true, nil
		}
		remainingEpochs := freshUntil - currentEpoch
		windowEpochs := window / r.cfg.EpochLength
		if windowEpochs == 0 {
			return remainingEpochs, false, nil
		}
		return remainingEpochs, remainingEpochs*SupportRenewalThreshold <= windowEpochs, nil
	}
	last := support.LastRefreshHeight.Uint64()
	// A refresh height ahead of the tip is not a freshness question; it means
	// this read and the height came from different views of the chain. Leaving
	// it alone is right: the next tick reads a consistent pair.
	if last == 0 || last > height {
		return 0, false, nil
	}
	elapsed := height - last
	if elapsed >= window {
		return 0, true, nil
	}
	remaining := window - elapsed
	return remaining, remaining*SupportRenewalThreshold <= window, nil
}

func (r *SupportRenewer) report(modelID string, err error) {
	if r.cfg.OnFailure != nil {
		r.cfg.OnFailure(modelID, err)
	}
}
