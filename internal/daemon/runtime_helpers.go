package daemon

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"os"
	"strings"
	"time"

	"github.com/SingaXYZ/cortex/internal/config"
	"github.com/SingaXYZ/cortex/internal/diagnostics"
	"github.com/SingaXYZ/cortex/internal/signer"
	"github.com/SingaXYZ/cortex/internal/tasktrace"
)

// nexusDurablePrefix is the JetStream durable identity for this node: the
// operator address alone.
//
// Duties used to be folded in. A JetStream durable stores its own ack position,
// so adding or removing a duty renamed every durable -- the old consumers were
// orphaned server-side and the new ones restarted from DeliverAll, replaying
// the whole retention window. Duty is already expressed by which subjects the
// node subscribes to, so it does not belong in the consumer name as well.
func nexusDurablePrefix(cfg config.Config) string {
	return strings.TrimSpace(cfg.LocalIdentity.OperatorAddress)
}

func (r *Runtime) SupportsDynamicReadiness() bool {
	return r != nil && r.cfg.UsesRealDependencies()
}

// SigningClient returns the signer built at startup so callers reuse one
// instance rather than reopening key material.
func (r *Runtime) SigningClient() signer.Signer {
	if r == nil {
		return nil
	}
	return r.signingClient
}

// TaskTrace is the per-task protocol trace sink this runtime was built with, so
// a task runner built from the runtime reports its milestones to the same place
// the output confirmer does. Nil-safe and silent when no observer was supplied.
func (r *Runtime) TaskTrace() *tasktrace.Trace {
	if r == nil {
		return nil
	}
	return r.taskTrace
}

// checkLocalSignerKeys ensures cortexd loads only its online service key. The
// operator key controls funds and lifecycle operations and must remain offline.
func checkLocalSignerKeys(signingClient signer.Signer, cfg config.Config) error {
	local, ok := signingClient.(*signer.LocalSigner)
	if !ok {
		return nil
	}
	_, loaded := local.AddressFor(cfg.LocalIdentity.ServiceKeyRef)
	if !loaded {
		return fmt.Errorf("signer key file has no service key %s", cfg.LocalIdentity.ServiceKeyRef)
	}
	for _, key := range local.Keys() {
		slog.Info("signer loaded key", slog.String("key_ref", key.Ref), slog.String("address", key.Address))
	}
	return nil
}

// bech32HRP extracts the human-readable prefix from a configured bech32
// address so a local key file does not have to repeat it.
func bech32HRP(address string) string {
	trimmed := strings.TrimSpace(address)
	if cut := strings.LastIndex(trimmed, "1"); cut > 0 {
		return trimmed[:cut]
	}
	return ""
}

func (r *Runtime) ChainStatus(ctx context.Context) (uint64, string, error) {
	if r == nil || r.chainStatus == nil {
		return 0, "", fmt.Errorf("CometBFT chain status client is required")
	}
	return r.chainStatus.ChainStatus(ctx)
}

func runtimePollInterval(milliseconds uint64) time.Duration {
	interval := time.Duration(milliseconds) * time.Millisecond
	if interval <= 0 {
		return time.Second
	}
	return interval
}

func setDependencyReady(deps *Dependencies, name string) {
	for i := range deps.Diagnostics.Dependencies {
		if deps.Diagnostics.Dependencies[i].Name == name {
			deps.Diagnostics.Dependencies[i].Ready = true
			deps.Diagnostics.Dependencies[i].Configured = true
			deps.Diagnostics.Dependencies[i].Error = ""
			return
		}
	}
}

func setDependencyStatus(deps *Dependencies, status diagnostics.DependencyStatus) {
	for i := range deps.Diagnostics.Dependencies {
		if deps.Diagnostics.Dependencies[i].Name == status.Name {
			deps.Diagnostics.Dependencies[i] = status
			return
		}
	}
	deps.Diagnostics.Dependencies = append(deps.Diagnostics.Dependencies, status)
}

func workloadDependenciesReady(report diagnostics.Diagnostics, requireTxBroadcaster bool, dynamic ...diagnostics.DependencyStatus) bool {
	// The live status wins over the boot report: a dependency probed on this
	// pass describes the node now, the report describes it at startup.
	lookup := func(name string) (diagnostics.DependencyStatus, bool) {
		for _, candidate := range dynamic {
			if candidate.Name == name {
				return candidate, true
			}
		}
		return report.Dependency(name)
	}
	names := []string{"chain", "model_service", "store", "keeper", "nexus", "nexus_envelope_auth", "builder_descriptor"}
	if requireTxBroadcaster {
		names = append(names, "tx_broadcaster")
	}
	// The on-chain identity is gated only when nats_user_key_file is configured: a
	// binding that cannot be signed means this machine cannot reach the bus and should
	// not take on new work (ADR-0016 decision three). The creds/token path reports
	// optional-not-configured, which is not a missing dependency.
	if status, ok := lookup(natsIdentityDependency); ok && status.Configured {
		names = append(names, natsIdentityDependency)
	}
	for _, name := range names {
		status, ok := lookup(name)
		if !ok || !status.Ready {
			return false
		}
	}
	return true
}

func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	var firstErr error
	for _, closer := range r.closers {
		if closer == nil {
			continue
		}
		if err := closer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if r.Store != nil {
		if err := r.Store.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func runtimeClosers(values ...any) []interface{ Close() error } {
	var closers []interface{ Close() error }
	for _, value := range values {
		closer, ok := value.(interface{ Close() error })
		if ok {
			closers = append(closers, closer)
		}
	}
	return closers
}

// nexusNATSAuth hands the NATS transport and authentication settings from the config
// to builderclient (ADR-0016). A non-nil identity selects the on-chain identity path
// (decision three), and creds and token are ignored.
func nexusNATSAuth(cfg config.NexusConfig, token string, identity builderclient.ChainIdentityProvider) builderclient.NATSAuth {
	return builderclient.NATSAuth{
		URL: cfg.NATSURL, Token: token,
		CredsFile: cfg.NATSCredsFile, CAFile: cfg.NATSCAFile,
		ChainIdentity: identity,
	}
}

func loadNexusToken(cfg config.NexusConfig) (string, error) {
	if cfg.AuthTokenFile == "" {
		return "", nil
	}
	token, err := os.ReadFile(cfg.AuthTokenFile)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(token)), nil
}

func applyDependencyError(deps *Dependencies, name string, message string) {
	for i := range deps.Diagnostics.Dependencies {
		if deps.Diagnostics.Dependencies[i].Name == name {
			deps.Diagnostics.Dependencies[i].Ready = false
			deps.Diagnostics.Dependencies[i].Error = message
			return
		}
	}
}
