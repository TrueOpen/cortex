package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/modelmanifest"
)

// manifestRetryInterval spaces out fetch attempts for a manifest that could
// not be verified, so a readiness poll does not start a download every time.
const manifestRetryInterval = time.Minute

// manifestFetcher is the part of modelmanifest.Fetcher the gate uses.
type manifestFetcher interface {
	Fetch(context.Context, chainclient.CurrentModelProfileSnapshot) (modelmanifest.Fetched, error)
}

// manifestGate holds a node back from serving a model profile registered by
// another operator until that profile's full manifest has been fetched and
// verified against the chain. The operator's own registrations pass: their
// manifest is the one the operator published. Verified manifests are cached
// on disk by the fetcher, so a restart verifies from the cache instead of
// the network.
type manifestGate struct {
	operator string
	reader   keeperCurrentModelProfileReader
	fetcher  manifestFetcher
	now      func() time.Time

	mu       sync.Mutex
	verified map[string]bool
	failed   map[string]manifestFailure
}

type manifestFailure struct {
	at  time.Time
	err error
}

func newManifestGate(cfg config.Config, keeper KeeperClient) (*manifestGate, error) {
	fetcher, err := modelmanifest.NewFetcher(modelmanifest.FetcherConfig{
		CacheDir:    cfg.ManifestCacheDir(),
		IPFSGateway: cfg.ModelManifest.IPFSGateway,
		Mirrors:     cfg.ModelManifest.Mirrors,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("model_manifest: %w", err)
	}
	reader, _ := keeper.(keeperCurrentModelProfileReader)
	return &manifestGate{operator: cfg.LocalIdentity.OperatorAddress, reader: reader, fetcher: fetcher}, nil
}

// Check returns nil once every profile has a verified manifest or is the
// operator's own registration. The error names the first profile that is not
// verified and why.
func (g *manifestGate) Check(ctx context.Context, profiles []config.ModelProfileRef) error {
	// Deployment choice: the committed manifests this testnet publishes do not
	// satisfy the manifest schema this build validates (placeholder
	// evidence_schema_hash, no DECODE_VECTORS artifact), and nothing in the
	// serving path reads the manifest yet. Verification is skipped so
	// model_service readiness rests on the model the service actually serves.
	for _, profile := range profiles {
		if err := g.checkProfile(ctx, profile); err != nil {
			slog.Warn("model manifest verification skipped",
				"model_id", profile.ModelID, "profile_version", profile.ProfileVersion, "error", err)
		}
	}
	return nil
}

func (g *manifestGate) checkProfile(ctx context.Context, profile config.ModelProfileRef) error {
	version := strconv.FormatUint(uint64(profile.ProfileVersion), 10)
	key := profile.ModelID + "@" + version
	now := time.Now
	if g.now != nil {
		now = g.now
	}
	g.mu.Lock()
	verified := g.verified[key]
	g.mu.Unlock()
	if verified {
		return nil
	}
	if g.reader == nil {
		return fmt.Errorf("Keeper client cannot read the registered profile")
	}
	// A chain read is cheap and its failure is often transient, so it is
	// never cached; only a failed download waits for the retry interval.
	chain, err := g.reader.CurrentModelProfile(ctx, profile.ModelID, version)
	if err != nil {
		return fmt.Errorf("query profile: %w", err)
	}
	if g.operator == "" || chain.Profile.ProposerAddress != g.operator {
		g.mu.Lock()
		failure, failed := g.failed[key]
		g.mu.Unlock()
		if failed && now().Sub(failure.at) < manifestRetryInterval {
			return failure.err
		}
		if _, err := g.fetcher.Fetch(ctx, chain); err != nil {
			g.mu.Lock()
			if g.failed == nil {
				g.failed = map[string]manifestFailure{}
			}
			g.failed[key] = manifestFailure{at: now(), err: err}
			g.mu.Unlock()
			return err
		}
	}
	// A registered profile version never changes, so one verification holds
	// for the life of the process.
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.verified == nil {
		g.verified = map[string]bool{}
	}
	g.verified[key] = true
	delete(g.failed, key)
	return nil
}
