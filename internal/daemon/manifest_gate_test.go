package daemon

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
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

// captureManifestWarnings routes the default slog logger into a buffer for the
// duration of the test and returns the buffer. Tests in this package do not run
// in parallel, so swapping the process-wide default is safe here.
func captureManifestWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

const manifestSkippedWarning = "model manifest verification skipped"

// The enforcing behaviour (holding the profile until its manifest verifies) is
// intentionally disabled by the deployment choice documented in
// manifestGate.Check. Verification is still attempted and its failure is
// logged; re-enabling enforcement means returning that error from Check again
// and flipping the readiness assertions in these tests.
func TestManifestGateLogsButDoesNotHoldAnUnverifiedProfile(t *testing.T) {
	logs := captureManifestWarnings(t)
	clock := time.Unix(1_000, 0)
	fetcher := &gateFetcher{err: errors.New("manifest abc not obtained: cache: missing")}
	gate := &manifestGate{
		operator: gateOperator, reader: gateProfileReader{proposer: "trueopen1someoneelse"}, fetcher: fetcher,
		now: func() time.Time { return clock },
	}
	if err := gate.Check(context.Background(), gateProfiles()); err != nil {
		t.Fatalf("unverified manifest held the profile: %v", err)
	}
	if fetcher.calls != 1 {
		t.Fatalf("verification was not attempted: %d fetches", fetcher.calls)
	}
	if got := logs.String(); !strings.Contains(got, manifestSkippedWarning) || !strings.Contains(got, bindTestModelID) || !strings.Contains(got, "not obtained") {
		t.Fatalf("verification failure was not logged: %q", got)
	}
	// Within the retry interval the failure is reported again without a new fetch.
	logs.Reset()
	if err := gate.Check(context.Background(), gateProfiles()); err != nil || fetcher.calls != 1 {
		t.Fatalf("retried too early: %v, %d fetches", err, fetcher.calls)
	}
	if !strings.Contains(logs.String(), "not obtained") {
		t.Fatalf("cached failure was not logged: %q", logs.String())
	}
	// After it, the fetch is tried again; once verified it stays verified and
	// nothing more is logged.
	clock = clock.Add(manifestRetryInterval)
	fetcher.err = nil
	logs.Reset()
	if err := gate.Check(context.Background(), gateProfiles()); err != nil || fetcher.calls != 2 {
		t.Fatalf("retry: %v, %d fetches", err, fetcher.calls)
	}
	fetcher.err = errors.New("would fail")
	if err := gate.Check(context.Background(), gateProfiles()); err != nil || fetcher.calls != 2 {
		t.Fatalf("verified manifest was fetched again: %v, %d fetches", err, fetcher.calls)
	}
	if logs.Len() != 0 {
		t.Fatalf("verified manifest still logged a warning: %q", logs.String())
	}
}

// A chain read error is logged but neither held nor cached: the next check
// reads the chain again. See the note above on the disabled enforcement.
func TestManifestGateLogsChainErrorsWithoutHoldingThem(t *testing.T) {
	logs := captureManifestWarnings(t)
	fetcher := &gateFetcher{}
	gate := &manifestGate{operator: gateOperator, reader: gateProfileReader{err: chainclient.ErrNotFound}, fetcher: fetcher}
	if err := gate.Check(context.Background(), gateProfiles()); err != nil {
		t.Fatalf("chain error held the profile: %v", err)
	}
	if got := logs.String(); !strings.Contains(got, manifestSkippedWarning) || !strings.Contains(got, chainclient.ErrNotFound.Error()) {
		t.Fatalf("chain error was not logged: %q", got)
	}
	if fetcher.calls != 0 {
		t.Fatalf("fetched without a chain profile: %d fetches", fetcher.calls)
	}
	// The failed read was not cached as verified, so a recovered chain is read
	// again and its manifest verifies without a warning.
	gate.reader = gateProfileReader{proposer: "trueopen1someoneelse"}
	logs.Reset()
	if err := gate.Check(context.Background(), gateProfiles()); err != nil || fetcher.calls != 1 {
		t.Fatalf("recovered chain was not read again: %v, %d fetches", err, fetcher.calls)
	}
	if logs.Len() != 0 {
		t.Fatalf("verified profile still logged a warning: %q", logs.String())
	}
	unreadable := &manifestGate{operator: gateOperator, fetcher: &gateFetcher{}}
	if err := unreadable.Check(context.Background(), gateProfiles()); err != nil {
		t.Fatalf("missing reader held the profile: %v", err)
	}
	if !strings.Contains(logs.String(), "cannot read the registered profile") {
		t.Fatalf("missing reader was not logged: %q", logs.String())
	}
}

// With enforcement disabled (see manifestGate.Check), an unverified manifest
// no longer turns model_service red: readiness rests on the model the service
// actually serves, and the verification failure is only logged.
func TestModelServiceReadinessLogsButDoesNotHoldAnUnverifiedManifest(t *testing.T) {
	logs := captureManifestWarnings(t)
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
	if status := rt.checkModelServiceReadiness(context.Background()); !status.Ready || status.Error != "" {
		t.Fatalf("model_service = %+v, want ready despite the unverified manifest", status)
	}
	if fetcher.calls != 1 {
		t.Fatalf("readiness did not attempt verification: %d fetches", fetcher.calls)
	}
	if got := logs.String(); !strings.Contains(got, manifestSkippedWarning) || !strings.Contains(got, "mirror: 404") {
		t.Fatalf("verification failure was not logged: %q", got)
	}
	logs.Reset()
	rt.manifestGate = &manifestGate{operator: gateOperator, reader: gateProfileReader{proposer: "trueopen1someoneelse"}, fetcher: &gateFetcher{}}
	if status := rt.checkModelServiceReadiness(context.Background()); !status.Ready {
		t.Fatalf("model_service = %+v after verification", status)
	}
	if logs.Len() != 0 {
		t.Fatalf("verified manifest still logged a warning: %q", logs.String())
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
