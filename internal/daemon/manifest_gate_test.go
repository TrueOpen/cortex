package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/modelmanifest"
	"github.com/TrueOpen/cortex/internal/modelservice"
)

const gateOperator = "trueopen1operator"

type gateProfileReader struct {
	proposer string
	err      error
}

func (r gateProfileReader) CurrentModelProfile(_ context.Context, modelID, _ string) (chainclient.CurrentModelProfileSnapshot, error) {
	if r.err != nil {
		return chainclient.CurrentModelProfileSnapshot{}, r.err
	}
	return chainclient.CurrentModelProfileSnapshot{Profile: chainclient.CurrentProfileSnapshot{ModelID: modelID, ProposerAddress: r.proposer}}, nil
}

type gateFetcher struct {
	calls int
	err   error
}

func (f *gateFetcher) Fetch(context.Context, chainclient.CurrentModelProfileSnapshot) (modelmanifest.Fetched, error) {
	f.calls++
	return modelmanifest.Fetched{}, f.err
}

func gateProfiles() []config.ModelProfileRef {
	return []config.ModelProfileRef{{ModelID: bindTestModelID, ProfileVersion: 1, Capability: "llm_text_v1"}}
}

func TestManifestGatePassesTheOperatorsOwnRegistration(t *testing.T) {
	fetcher := &gateFetcher{err: errors.New("unreachable")}
	gate := &manifestGate{operator: gateOperator, reader: gateProfileReader{proposer: gateOperator}, fetcher: fetcher}
	if err := gate.Check(context.Background(), gateProfiles()); err != nil {
		t.Fatal(err)
	}
	if fetcher.calls != 0 {
		t.Fatalf("own registration was fetched %d times", fetcher.calls)
	}
}

func TestManifestGateHoldsAnotherOperatorsProfileUntilVerified(t *testing.T) {
	clock := time.Unix(1_000, 0)
	fetcher := &gateFetcher{err: errors.New("manifest abc not obtained: cache: missing")}
	gate := &manifestGate{
		operator: gateOperator, reader: gateProfileReader{proposer: "trueopen1someoneelse"}, fetcher: fetcher,
		now: func() time.Time { return clock },
	}
	err := gate.Check(context.Background(), gateProfiles())
	if err == nil || !strings.Contains(err.Error(), bindTestModelID+"@1 manifest not verified") || !strings.Contains(err.Error(), "not obtained") {
		t.Fatalf("unverified manifest: %v", err)
	}
	// Within the retry interval the reason is repeated without a new fetch.
	if err := gate.Check(context.Background(), gateProfiles()); err == nil || fetcher.calls != 1 {
		t.Fatalf("retried too early: %v, %d fetches", err, fetcher.calls)
	}
	// After it, the fetch is tried again; once verified it stays verified.
	clock = clock.Add(manifestRetryInterval)
	fetcher.err = nil
	if err := gate.Check(context.Background(), gateProfiles()); err != nil || fetcher.calls != 2 {
		t.Fatalf("retry: %v, %d fetches", err, fetcher.calls)
	}
	fetcher.err = errors.New("would fail")
	if err := gate.Check(context.Background(), gateProfiles()); err != nil || fetcher.calls != 2 {
		t.Fatalf("verified manifest was fetched again: %v, %d fetches", err, fetcher.calls)
	}
}

// A chain read error is reported but not held: the next check reads again.
func TestManifestGateReportsChainErrorsWithoutHoldingThem(t *testing.T) {
	gate := &manifestGate{operator: gateOperator, reader: gateProfileReader{err: chainclient.ErrNotFound}, fetcher: &gateFetcher{}}
	if err := gate.Check(context.Background(), gateProfiles()); !errors.Is(err, chainclient.ErrNotFound) {
		t.Fatalf("chain error: %v", err)
	}
	gate.reader = gateProfileReader{proposer: gateOperator}
	if err := gate.Check(context.Background(), gateProfiles()); err != nil {
		t.Fatalf("recovered chain was not read again: %v", err)
	}
	unreadable := &manifestGate{operator: gateOperator, fetcher: &gateFetcher{}}
	if err := unreadable.Check(context.Background(), gateProfiles()); err == nil || !strings.Contains(err.Error(), "cannot read the registered profile") {
		t.Fatalf("missing reader: %v", err)
	}
}

// Until the manifest is verified, model_service readiness is red with the
// gate's reason, even though the model itself is bound and served.
func TestModelServiceReadinessIsRedUntilTheManifestIsVerified(t *testing.T) {
	local := modelservice.NewLocalService(vllmServing(t, "org/model").URL, "local", 1, 0, 0)
	cfg := config.Config{LocalIdentity: config.LocalIdentityConfig{
		OperatorAddress: gateOperator, SupportedModelProfiles: []string{bindTestModelID + "@1=llm_text_v1"}, ModelServiceID: "local",
	}}
	fetcher := &gateFetcher{err: errors.New("manifest not obtained: mirror: 404")}
	rt := &Runtime{
		cfg:          cfg,
		Dependencies: Dependencies{Keeper: bindTestKeeper{model: bindTestModel("HUGGINGFACE", "org/model")}, Model: local},
		manifestGate: &manifestGate{operator: gateOperator, reader: gateProfileReader{proposer: "trueopen1someoneelse"}, fetcher: fetcher},
	}
	status := rt.checkModelServiceReadiness(context.Background())
	if status.Ready || !strings.Contains(status.Error, "manifest not verified") || !strings.Contains(status.Error, "mirror: 404") {
		t.Fatalf("model_service = %+v, want red with the manifest reason", status)
	}
	rt.manifestGate = &manifestGate{operator: gateOperator, reader: gateProfileReader{proposer: "trueopen1someoneelse"}, fetcher: &gateFetcher{}}
	if status := rt.checkModelServiceReadiness(context.Background()); !status.Ready {
		t.Fatalf("model_service = %+v after verification", status)
	}
}

func TestNewManifestGateUsesTheConfiguredSources(t *testing.T) {
	cfg := config.Config{Store: config.StoreConfig{Path: "/var/lib/cortex/store"}}
	if got := cfg.ManifestCacheDir(); got != "/var/lib/cortex/manifests" {
		t.Fatalf("default cache dir %q", got)
	}
	cfg.ModelManifest.CacheDir = "/srv/manifests"
	if got := cfg.ManifestCacheDir(); got != "/srv/manifests" {
		t.Fatalf("configured cache dir %q", got)
	}
	cfg.ModelManifest.Mirrors = []string{"http://mirror.example/m"}
	if _, err := newManifestGate(cfg, nil); err == nil || !strings.Contains(err.Error(), "model_manifest") {
		t.Fatalf("http mirror was accepted: %v", err)
	}
	cfg.ModelManifest.Mirrors = []string{"https://mirror.example/m"}
	cfg.ModelManifest.IPFSGateway = "http://127.0.0.1:8080"
	if _, err := newManifestGate(cfg, nil); err != nil {
		t.Fatal(err)
	}
}
