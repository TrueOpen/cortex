package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

type renewalConfirmer struct {
	calls []string
	err   error
}

func (c *renewalConfirmer) RenewDailySupport(_ context.Context, modelID string) error {
	c.calls = append(c.calls, modelID)
	return c.err
}

// renewalFixture builds a renewer whose support row is `elapsed` blocks past its
// last refresh, inside a window of `window` blocks.
//
// mutate runs before the reader is placed in the config, because
// staticKeeperIdentityReader is a value type: once it is stored in the
// interface it has been copied, and a later edit to the caller's variable would
// change nothing while looking like it had.
func renewalFixture(t *testing.T, window, elapsed uint64, mutate func(*staticKeeperIdentityReader)) (*SupportRenewer, *renewalConfirmer) {
	t.Helper()
	reader := readyKeeperIdentityReader()
	reader.params.DailySupportWindowBlocks = chainclient.NewUint64String(window)
	reader.support.DeclaredSupport = true
	reader.support.SupportFreshUntilEpoch = 0
	const height = 100000
	reader.support.LastRefreshHeight = chainclient.NewUint64String(height - elapsed)
	if mutate != nil {
		mutate(&reader)
	}

	confirmer := &renewalConfirmer{}
	renewer := NewSupportRenewer(SupportRenewerConfig{
		Identity:  readyLocalIdentity(),
		Keeper:    reader,
		Confirmer: confirmer,
		Height:    func(context.Context) (uint64, error) { return height, nil },
	})
	if renewer == nil {
		t.Fatal("NewSupportRenewer returned nil for a complete configuration")
	}
	return renewer, confirmer
}

// TestSupportRenewerRenewsBeforeTheWindowCloses is the behaviour this exists
// for. Support that expires stops the node from being offered work, and until
// now only an operator remembering `cortexctl daily-support` prevented that.
func TestSupportRenewerRenewsBeforeTheWindowCloses(t *testing.T) {
	// 800 of an 1000-block window elapsed: a quarter remains, which is the
	// threshold.
	renewer, confirmer := renewalFixture(t, 1000, 800, nil)

	renewer.RunOnce(context.Background())

	if len(confirmer.calls) != 1 {
		t.Fatalf("renewals = %v, want exactly one", confirmer.calls)
	}
}

// TestSupportRenewerLeavesFreshSupportAlone keeps the renewer from submitting a
// transaction on every tick. The chain charges for each one.
func TestSupportRenewerLeavesFreshSupportAlone(t *testing.T) {
	renewer, confirmer := renewalFixture(t, 1000, 100, nil)

	renewer.RunOnce(context.Background())

	if len(confirmer.calls) != 0 {
		t.Fatalf("renewals = %v, want none while the window is mostly unused", confirmer.calls)
	}
}

// TestSupportRenewerRenewsExpiredSupport covers the case the threshold does not:
// a node that was down past its own expiry still has to recover.
func TestSupportRenewerRenewsExpiredSupport(t *testing.T) {
	renewer, confirmer := renewalFixture(t, 1000, 1200, nil)

	renewer.RunOnce(context.Background())

	if len(confirmer.calls) != 1 {
		t.Fatalf("renewals = %v, want one for already-expired support", confirmer.calls)
	}
}

// TestSupportRenewerIgnoresUndeclaredSupport pins the boundary between renewing
// and declaring. Renewal confirms an existing declaration; it is not the
// operation that creates one, and a node that never declared support must not
// acquire it by running.
func TestSupportRenewerIgnoresUndeclaredSupport(t *testing.T) {
	renewer, confirmer := renewalFixture(t, 1000, 900, func(r *staticKeeperIdentityReader) {
		r.support.DeclaredSupport = false
	})

	renewer.RunOnce(context.Background())

	if len(confirmer.calls) != 0 {
		t.Fatalf("renewals = %v, want none without a declaration", confirmer.calls)
	}
}

// TestSupportRenewerIgnoresARefreshAheadOfTheTip guards against acting on an
// inconsistent pair of reads. A last-refresh height above the tip is not a
// freshness fact, it means the support row and the height came from different
// views; renewing on it would submit a transaction for no reason.
func TestSupportRenewerIgnoresARefreshAheadOfTheTip(t *testing.T) {
	renewer, confirmer := renewalFixture(t, 1000, 900, func(r *staticKeeperIdentityReader) {
		r.support.LastRefreshHeight = chainclient.NewUint64String(200000)
	})

	renewer.RunOnce(context.Background())

	if len(confirmer.calls) != 0 {
		t.Fatalf("renewals = %v, want none for an inconsistent read", confirmer.calls)
	}
}

// TestSupportRenewerReportsFailuresWithoutStopping is the property that keeps a
// transient failure from becoming an outage. cortexd runs its runners as a
// group where one returning an error stops the whole runtime, so this runner
// must report and continue.
func TestSupportRenewerReportsFailuresWithoutStopping(t *testing.T) {
	renewer, confirmer := renewalFixture(t, 1000, 900, nil)
	confirmer.err = errors.New("broadcast refused")
	var reported []string
	renewer.cfg.OnFailure = func(modelID string, err error) { reported = append(reported, modelID+": "+err.Error()) }
	renewer.cfg.Interval = time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := renewer.Run(ctx); err != nil {
		t.Fatalf("Run() = %v, want nil: a failed renewal must not stop the runtime", err)
	}
	if len(reported) == 0 {
		t.Fatal("a failed renewal was neither returned nor reported")
	}
}

// TestNewSupportRenewerRefusesAnIncompleteConfiguration keeps a half-wired
// renewer from looking like a working one.
func TestNewSupportRenewerRefusesAnIncompleteConfiguration(t *testing.T) {
	reader := readyKeeperIdentityReader()
	height := func(context.Context) (uint64, error) { return 1, nil }
	for name, cfg := range map[string]SupportRenewerConfig{
		"no keeper":    {Confirmer: &renewalConfirmer{}, Height: height},
		"no confirmer": {Keeper: reader, Height: height},
		"no height":    {Keeper: reader, Confirmer: &renewalConfirmer{}},
	} {
		t.Run(name, func(t *testing.T) {
			if NewSupportRenewer(cfg) != nil {
				t.Fatal("NewSupportRenewer accepted an incomplete configuration")
			}
		})
	}
}
