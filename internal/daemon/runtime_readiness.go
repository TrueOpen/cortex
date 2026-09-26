package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/diagnostics"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/natsidentity"
	"github.com/TrueOpen/cortex/internal/signer"
)

// cosmosTxCapableProbe keeps the tx capability diagnostic honest when the
// signer cannot produce chain transactions. The result gates workload only
// when a direct transaction path is enabled.
func cosmosTxCapableProbe(signingClient signer.Signer, next ReadinessProbe) ReadinessProbe {
	if signingClient == nil {
		return next
	}
	return readinessProbeFunc(func(ctx context.Context) error {
		if !signingClient.CanSignCosmosTx() {
			return fmt.Errorf("signer cannot produce Cosmos transactions")
		}
		if next == nil {
			return nil
		}
		return next.Probe(ctx)
	})
}

// verifyWorkloadSigner checks the node can actually sign as the service
// address Keeper reports before the workload is allowed to activate. A local
// signer loads once at startup, so a key added afterwards is not picked up,
// and a key whose derived address does not match would only fail at the first
// signature.
func verifyWorkloadSigner(ctx context.Context, signingClient signer.Signer, cfg config.Config, binding chainclient.ServiceKeySnapshot) error {
	if signingClient == nil {
		return fmt.Errorf("current service signer is required")
	}
	serviceAddress := binding.ServiceAddress
	local, ok := signingClient.(*signer.LocalSigner)
	if ok {
		ref := cfg.LocalIdentity.ServiceKeyRef
		address, loaded := local.AddressFor(ref)
		if !loaded {
			return fmt.Errorf("signer has no service key %s; restart cortexd after adding the keystore", ref)
		}
		if address != serviceAddress {
			return fmt.Errorf("service key %s signs as %s, but Keeper reports the current service address as %s", ref, address, serviceAddress)
		}
		keys := local.Keys()
		if len(keys) != 1 || !strings.EqualFold(keys[0].CompressedPubkey, binding.ServicePubkey) {
			return fmt.Errorf("loaded service public key does not match Keeper current service binding")
		}
	} else if _, remote := signingClient.(*signer.Client); !remote {
		return fmt.Errorf("unsupported signer implementation %T cannot prove the current service binding", signingClient)
	}
	digest := workloadSignerProofDigest(cfg, binding)
	signature, err := signingClient.SignDigest(ctx, signer.DigestRequest{
		KeyRef: cfg.LocalIdentity.ServiceKeyRef, ExpectedSignerAddress: binding.ServiceAddress, Digest: digest,
	})
	if err != nil {
		return fmt.Errorf("prove current service key possession: %w", err)
	}
	if err := signer.VerifyDigestSignature(binding.ServicePubkey, digest, signature); err != nil {
		return fmt.Errorf("prove current service key possession: %w", err)
	}
	return nil
}

func workloadSignerProofDigest(cfg config.Config, binding chainclient.ServiceKeySnapshot) codec.Hash {
	return codec.HashWithDomain("TRUEOPEN_SERVICE_KEY_READINESS_V1",
		[]byte(cfg.ChainID), []byte("CORTEX_NODE"), []byte(cfg.LocalIdentity.OperatorAddress), []byte(binding.ServiceAddress),
		[]byte(binding.ServicePubkey), codec.Uint64Bytes(binding.AuthorizationNonce.Uint64()))
}

// ensureWorkloadSignerProof proves a local immutable key once per Keeper
// binding. HTTP signers are re-proven periodically so an unavailable or
// misbehaving remote signer still makes readiness fail closed, without
// producing an HSM signature on every Keeper poll.
func (r *Runtime) ensureWorkloadSignerProof(ctx context.Context, binding chainclient.ServiceKeySnapshot) error {
	if r.trustInjectedSignerForTests {
		return nil
	}
	digest := workloadSignerProofDigest(r.cfg, binding)
	_, local := r.signingClient.(*signer.LocalSigner)
	now := time.Now()

	r.signerProofMu.Lock()
	defer r.signerProofMu.Unlock()
	if r.signerProofValid && r.signerProofDigest == digest && (local || now.Before(r.signerProofValidUntil)) {
		return nil
	}
	if err := verifyWorkloadSigner(ctx, r.signingClient, r.cfg, binding); err != nil {
		r.signerProofValid = false
		return err
	}
	r.signerProofDigest = digest
	r.signerProofValid = true
	if local {
		r.signerProofValidUntil = time.Time{}
	} else {
		interval := time.Duration(r.cfg.Signer.ReadinessProofIntervalMS) * time.Millisecond
		if interval <= 0 {
			interval = 30 * time.Second
		}
		r.signerProofValidUntil = time.Now().Add(interval)
	}
	return nil
}

func (r *Runtime) CheckWorkloadReadiness(ctx context.Context) WorkloadReadiness {
	identityStatus := unprobed("keeper_identity", r.cfg.LocalIdentity.OperatorAddress)
	modelStatus := unprobed("model_support", strings.Join(r.cfg.LocalIdentity.SupportedModelProfiles, ","))
	modelServiceStatus, nexusStatus, txStatus, descriptorStatus, natsIdentity := r.checkRuntimeDependencyReadiness(ctx)
	envelopeAuthStatus := r.envelopeAuthStatus()
	keeperStatus := r.checkKeeperReadiness(ctx)
	storeStatus := r.checkStoreReadiness(ctx)
	// The chain is probed once here and reused: the chain dependency, workload
	// gating, and the identity check below all need the same answer, and the
	// height comes from the same call.
	chainStatus, chainHeight := r.checkChainReadiness(ctx)
	readiness := WorkloadReadiness{
		Identity:          identityStatus,
		ModelSupport:      modelStatus,
		ModelService:      modelServiceStatus,
		Nexus:             nexusStatus,
		BuilderDescriptor: descriptorStatus,
		TxBroadcaster:     txStatus,
		Chain:             chainStatus,
		Keeper:            keeperStatus,
		Store:             storeStatus,
		ChainSync:         r.chainSyncStatus(),
		EnvelopeAuth:      envelopeAuthStatus,
		NATSIdentity:      natsIdentity,
		// chain, keeper and store are passed as live results. They are no longer
		// startup constants, so reading them from the boot report would gate the
		// workload on a value that is never refreshed.
		DependenciesReady: workloadDependenciesReady(r.Dependencies.Diagnostics, r.cfg.RequiresWorkloadTx(),
			modelServiceStatus, nexusStatus, txStatus, descriptorStatus, envelopeAuthStatus,
			chainStatus, keeperStatus, storeStatus, natsIdentity),
	}
	identityReader, identityOK := r.Dependencies.Keeper.(KeeperIdentityReader)
	if !identityOK {
		readiness.Identity.Error = "Keeper identity query client is required"
		readiness.ModelSupport.Error = "Keeper identity query client is required"
		r.publishReadiness(readiness)
		return readiness
	}
	if !chainStatus.Ready {
		// Identity cannot be established without a usable chain view, and the
		// chain status already explains why.
		readiness.Identity.Error = chainStatus.Error
	} else {
		binding, identityErr := checkKeeperCoreServiceKey(ctx, r.cfg.LocalIdentity, identityReader, chainHeight)
		if identityErr != nil {
			readiness.Identity.Error = identityErr.Error()
		} else if signerErr := r.ensureWorkloadSignerProof(ctx, binding); signerErr != nil {
			readiness.Identity.Error = signerErr.Error()
		} else {
			markReady(&readiness.Identity)
			readiness.ServiceAddress = binding.ServiceAddress
			readiness.ServicePubkey = binding.ServicePubkey
		}
	}
	if err := checkKeeperModelReadiness(ctx, r.cfg.LocalIdentity, identityReader); err != nil {
		readiness.ModelSupport.Error = err.Error()
	} else {
		markReady(&readiness.ModelSupport)
	}
	r.publishReadiness(readiness)
	return readiness
}

// checkChainReadiness probes the chain boundary and returns the observed height
// for callers that need it. A chain id that does not match the configured one is
// a failure: consuming another chain's state is worse than consuming none.
func (r *Runtime) checkChainReadiness(ctx context.Context) (diagnostics.DependencyStatus, uint64) {
	status := unprobed("chain", r.cfg.Node.RPCEndpoint)
	if r == nil || r.chainStatus == nil {
		status.Error = "CometBFT chain status client is required"
		return status, 0
	}
	height, chainID, err := r.chainStatus.ChainStatus(ctx)
	switch {
	case err != nil:
		status.Error = "query CometBFT chain status: " + err.Error()
		return status, 0
	case strings.TrimSpace(chainID) != strings.TrimSpace(r.cfg.ChainID):
		status.Error = fmt.Sprintf("CometBFT chain id %q does not match configured %q", chainID, r.cfg.ChainID)
		return status, 0
	}
	markReady(&status)
	return status, height
}

// markReady flips a status to ready and drops the explanation that belonged to
// the not-ready state. Leaving a stale Error behind makes a ready dependency read
// as if it had failed.
func markReady(status *diagnostics.DependencyStatus) {
	if status == nil {
		return
	}
	status.Ready = true
	status.Error = ""
}

func (r *Runtime) checkRuntimeDependencyReadiness(ctx context.Context) (diagnostics.DependencyStatus, diagnostics.DependencyStatus, diagnostics.DependencyStatus, diagnostics.DependencyStatus, diagnostics.DependencyStatus) {
	type result struct {
		name   string
		status diagnostics.DependencyStatus
	}
	results := make(chan result, 5)
	go func() { results <- result{name: "model_service", status: r.checkModelServiceReadiness(ctx)} }()
	go func() {
		results <- result{name: "nexus", status: r.checkDependencyReadiness(ctx, "nexus", r.nexusProbe)}
	}()
	go func() {
		results <- result{name: "tx_broadcaster", status: r.checkDependencyReadiness(ctx, "tx_broadcaster", r.txProbe)}
	}()
	go func() {
		results <- result{name: "builder_descriptor", status: r.checkBuilderDescriptorReadiness(ctx)}
	}()
	// The identity probe is a chain read as well and runs alongside the others:
	// chaining it behind them would add a round trip to every readiness poll
	// (ADR-0016 decision three).
	go func() {
		results <- result{name: natsIdentityDependency, status: r.natsIdentityReadiness(ctx)}
	}()

	var modelService diagnostics.DependencyStatus
	var nexus diagnostics.DependencyStatus
	var txBroadcaster diagnostics.DependencyStatus
	var builderDescriptor diagnostics.DependencyStatus
	var natsIdentity diagnostics.DependencyStatus
	for range 5 {
		probeResult := <-results
		switch probeResult.name {
		case "model_service":
			modelService = probeResult.status
		case "nexus":
			nexus = probeResult.status
		case "tx_broadcaster":
			txBroadcaster = probeResult.status
		case "builder_descriptor":
			builderDescriptor = probeResult.status
		case natsIdentityDependency:
			natsIdentity = probeResult.status
		}
	}
	return modelService, nexus, txBroadcaster, builderDescriptor, natsIdentity
}

// checkBuilderDescriptorReadiness cross-checks the configured Nexus ingress
// against the Builder's authoritative on-chain descriptor. A conflict between
// bootstrap configuration and the chain view must hold the workload down; the
// configured endpoint is never used as a fallback.
func (r *Runtime) checkBuilderDescriptorReadiness(ctx context.Context) diagnostics.DependencyStatus {
	if !r.cfg.Nexus.VerifiesBuilderDescriptor() {
		return builderDescriptorStatus(r.cfg, true, "")
	}
	if r.builderDirectory == nil {
		return builderDescriptorStatus(r.cfg, false, "Builder service descriptor resolver is unavailable")
	}
	configured := strings.TrimSpace(r.cfg.Nexus.BuilderOperatorAddress)
	// A configured operator narrows what this node accepts, so a configured
	// operator the chain has removed from the BuilderSet leaves the node unable
	// to receive anything legitimate. That is a conflict between local
	// configuration and consensus, and it holds the workload down rather than
	// being resolved in configuration's favour. A Keeper that cannot answer the
	// membership question at all leaves the configured Builder unchecked against
	// consensus, which is the same refusal: reporting unready keeps the node
	// startable and legible instead of skipping the check.
	if r.builderMembers == nil {
		return builderDescriptorStatus(r.cfg, false,
			"current BuilderSet is unreadable, so configured Builder "+configured+" cannot be checked for membership")
	}
	member, err := r.builderMembers.HasBuilder(ctx, configured)
	switch {
	case err != nil:
		return builderDescriptorStatus(r.cfg, false, "read current BuilderSet membership: "+err.Error())
	case !member:
		return builderDescriptorStatus(r.cfg, false,
			"configured Builder "+configured+" is not in the current BuilderSet")
	}
	identity, err := r.builderDirectory.Resolve(ctx, configured)
	if err != nil {
		return builderDescriptorStatus(r.cfg, false, "resolve Builder service descriptor: "+err.Error())
	}
	// The cross-check is opt-in, because the descriptor is the authority and the
	// configured value only ever agreed or disagreed with it. An operator who
	// sets it is asking "is the Builder I think I configured the one the chain
	// published", which catches a stale or wrong-network config at startup
	// instead of at the first dial; an operator who leaves it out has simply not
	// asked, and the node uses the descriptor either way.
	if r.cfg.Nexus.IngressURL != "" {
		if err := identity.SameEndpoint(r.cfg.Nexus.IngressURL); err != nil {
			return builderDescriptorStatus(r.cfg, false, err.Error())
		}
	}
	status := builderDescriptorStatus(r.cfg, true, "")
	status.Endpoint = identity.Endpoint
	return status
}

// checkKeeperReadiness exercises the Keeper query client itself. It shares an
// endpoint with the chain probe but is a different client: one can be
// misconfigured or failing while the other works, which is what a devnet
// serving `/status` while returning 500 from `/block_results` looks like.
func (r *Runtime) checkKeeperReadiness(ctx context.Context) diagnostics.DependencyStatus {
	status := unprobed("keeper", r.cfg.Node.RPCEndpoint)
	if r == nil || r.Dependencies.Keeper == nil {
		status.Error = "Keeper query client is required"
		return status
	}
	if _, err := r.Dependencies.Keeper.ChainHeight(ctx); err != nil {
		status.Error = "query Keeper chain height: " + err.Error()
		return status
	}
	status.Ready = true
	status.Error = ""
	return status
}

func (r *Runtime) checkStoreReadiness(ctx context.Context) diagnostics.DependencyStatus {
	status := unprobed("store", r.cfg.Store.Path)
	if r == nil || r.Store == nil {
		status.Error = "store is required"
		return status
	}
	if err := r.Store.Ping(ctx); err != nil {
		status.Error = "ping store: " + err.Error()
		return status
	}
	if err := r.Store.ProbeWrite(ctx); err != nil {
		status.Error = "write store probe: " + err.Error()
		return status
	}
	status.Ready = true
	status.Error = ""
	return status
}

func (r *Runtime) DiagnosticsSnapshot() diagnostics.Diagnostics {
	if r == nil {
		return diagnostics.Diagnostics{}
	}
	r.diagnosticsMu.RLock()
	report := cloneDiagnostics(r.diagnostics)
	r.diagnosticsMu.RUnlock()
	// Ask the Binder for the binding state directly: it changes with every
	// (re)connect, and a copy kept in the snapshot would go stale.
	if r.natsIdentity != nil {
		status := r.natsIdentity.Status()
		report.NexusNATSIdentity = &diagnostics.NATSIdentityStatus{
			UserPublicKey:   status.UserPublicKey,
			SentinelAccount: status.SentinelAccount,
			BindingNonce:    status.BindingNonce,
			IssuedAtUnixMS:  status.IssuedAtUnixMS,
			LastError:       status.LastError,
		}
	}
	return report
}

func (r *Runtime) setDiagnosticsSnapshot(report diagnostics.Diagnostics) {
	if r == nil {
		return
	}
	r.diagnosticsMu.Lock()
	r.diagnostics = cloneDiagnostics(report)
	r.diagnosticsMu.Unlock()
}

func (r *Runtime) publishReadiness(readiness WorkloadReadiness) {
	if r == nil {
		return
	}
	r.diagnosticsMu.Lock()
	report := cloneDiagnostics(r.diagnostics)
	setDiagnosticDependencyStatus(&report, readiness.Identity)
	setDiagnosticDependencyStatus(&report, readiness.ModelSupport)
	setDiagnosticDependencyStatus(&report, readiness.ModelService)
	setDiagnosticDependencyStatus(&report, readiness.Nexus)
	setDiagnosticDependencyStatus(&report, readiness.BuilderDescriptor)
	setDiagnosticDependencyStatus(&report, readiness.EnvelopeAuth)
	setDiagnosticDependencyStatus(&report, readiness.NATSIdentity)
	setDiagnosticDependencyStatus(&report, readiness.TxBroadcaster)
	setDiagnosticDependencyStatus(&report, readiness.Chain)
	setDiagnosticDependencyStatus(&report, readiness.Keeper)
	setDiagnosticDependencyStatus(&report, readiness.Store)
	r.diagnostics = report
	r.diagnosticsMu.Unlock()
}

func setDiagnosticDependencyStatus(report *diagnostics.Diagnostics, status diagnostics.DependencyStatus) {
	if report == nil || strings.TrimSpace(status.Name) == "" {
		return
	}
	for index := range report.Dependencies {
		if report.Dependencies[index].Name == status.Name {
			report.Dependencies[index] = status
			return
		}
	}
	report.Dependencies = append(report.Dependencies, status)
}

func cloneDiagnostics(report diagnostics.Diagnostics) diagnostics.Diagnostics {
	report.Dependencies = append([]diagnostics.DependencyStatus(nil), report.Dependencies...)
	report.SecurityWarnings = append([]string(nil), report.SecurityWarnings...)
	return report
}

func (r *Runtime) checkModelServiceReadiness(ctx context.Context) diagnostics.DependencyStatus {
	status := realStatus("model_service", modelEndpoint(r.cfg), false, "model service client is required")
	if r == nil || r.Dependencies.Model == nil {
		return status
	}
	if local, ok := r.Dependencies.Model.(*modelservice.LocalService); ok {
		if err := bindLocalModels(ctx, r.Dependencies.Keeper, local, configuredModelIDs(r.cfg)); err != nil {
			status.Error = err.Error()
			return status
		}
	}
	if err := probeModelClientHealth(ctx, r.cfg, r.Dependencies.Model); err != nil {
		status.Error = err.Error()
		return status
	}
	status.Ready = true
	status.Configured = true
	status.Error = ""
	return status
}

func (r *Runtime) checkDependencyReadiness(ctx context.Context, name string, probe ReadinessProbe) diagnostics.DependencyStatus {
	status, ok := r.Dependencies.Diagnostics.Dependency(name)
	if !ok || probe == nil {
		return status
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := probe.Probe(probeCtx); err != nil {
		status.Ready = false
		// Report what the probe said, not that it was called. The probe is the
		// only thing that knows why - "signer cannot produce Cosmos
		// transactions" is exact and actionable - and the fixed string used
		// here replaced it, including overwriting the precise reason startup
		// had already logged once. checkModelServiceReadiness has always
		// reported err.Error(); this path was the outlier.
		//
		// Scrubbed rather than discarded: a probe error may quote the URL it
		// dialled, and a configured URL may carry userinfo. The credential is
		// what must not reach a log line; the reason is what has to.
		status.Error = fmt.Sprintf("%s readiness probe failed: %s", name, r.scrubReadinessDetail(err.Error()))
		return status
	}
	status.Ready = true
	status.Configured = true
	status.Error = ""
	return status
}

// scrubReadinessDetail replaces any configured credential-bearing URL that a
// probe error quoted with its redacted form. Only the userinfo is removed: the
// host is already published in DependencyStatus.Endpoint, so dropping the whole
// URL would cost information without protecting anything.
func (r *Runtime) scrubReadinessDetail(detail string) string {
	if r == nil {
		return detail
	}
	for _, configured := range []string{r.cfg.Nexus.NATSURL, r.cfg.Signer.URI, r.cfg.Keeper.APIURL} {
		configured = strings.TrimSpace(configured)
		if configured == "" || !strings.Contains(detail, configured) {
			continue
		}
		if redacted := diagnostics.RedactEndpoint(configured); redacted != configured {
			detail = strings.ReplaceAll(detail, configured, redacted)
		}
	}
	return detail
}

func readinessProbeFrom(value any) ReadinessProbe {
	probe, _ := value.(ReadinessProbe)
	return probe
}

func firstReadinessProbe(preferred ReadinessProbe, fallback ReadinessProbe) ReadinessProbe {
	if preferred != nil {
		return preferred
	}
	return fallback
}

// natsIdentityReadinessProbe uses the Binder's Credential as the probe: whether a
// presentable binding can be signed here and now is this dependency's definition of
// readiness (ADR-0016 decision three). No Binder means no probe.
func natsIdentityReadinessProbe(binder *natsidentity.Binder) ReadinessProbe {
	if binder == nil {
		return nil
	}
	return readinessProbeFunc(func(ctx context.Context) error {
		_, err := binder.Credential(ctx)
		return err
	})
}

// natsIdentityReadiness reports whether the on-chain identity binding is still
// usable. With no Binder wired it returns the config line's optional-not-configured
// status - that is the creds/token path, not something missing.
func (r *Runtime) natsIdentityReadiness(ctx context.Context) diagnostics.DependencyStatus {
	if r == nil {
		return diagnostics.DependencyStatus{}
	}
	if r.natsIdentityProbe == nil {
		// Runtime assembly has already set this line to what it actually is (Binder or no
		// Binder), so copy it as is.
		if status, ok := r.Dependencies.Diagnostics.Dependency(natsIdentityDependency); ok {
			return status
		}
		return natsIdentityStatus(r.cfg)
	}
	status := r.checkDependencyReadiness(ctx, natsIdentityDependency, r.natsIdentityProbe)
	if strings.TrimSpace(status.Name) == "" {
		status = natsIdentityStatus(r.cfg)
	}
	return status
}

func nexusReadinessProbe(publisher builderclient.Publisher, subscriber builderclient.Subscriber) ReadinessProbe {
	publisherProbe := readinessProbeFrom(publisher)
	subscriberProbe := readinessProbeFrom(subscriber)
	if publisherProbe == nil || subscriberProbe == nil {
		return nil
	}
	return readinessProbeFunc(func(ctx context.Context) error {
		if err := publisherProbe.Probe(ctx); err != nil {
			return err
		}
		return subscriberProbe.Probe(ctx)
	})
}

func shouldProbeModelServiceHealth(cfg config.Config, opts RuntimeOptions, transport modelservice.Transport, transportErr error) bool {
	return cfg.UsesRealDependencies() &&
		opts.ModelTransport == nil &&
		transport != nil &&
		transportErr == nil &&
		strings.EqualFold(strings.TrimSpace(cfg.ModelManagement.Transport), "grpc")
}

func probeModelServiceHealth(ctx context.Context, cfg config.Config, transport modelservice.Transport) error {
	return probeModelClientHealth(ctx, cfg, modelservice.NewRemoteClient(transport))
}

func probeModelClientHealth(ctx context.Context, cfg config.Config, client modelservice.Client) error {
	if client == nil {
		return fmt.Errorf("modelservice health check failed: client unavailable")
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	modelServiceID := strings.TrimSpace(cfg.LocalIdentity.ModelServiceID)
	resp, err := client.Health(probeCtx, modelservice.HealthRequest{
		RequestID:      "runtime-readiness",
		ModelServiceID: modelServiceID,
		DeadlineMS:     5000,
	})
	if err != nil {
		return sanitizeModelServiceHealthCallError(err)
	}
	if resp.Error != nil {
		return fmt.Errorf("modelservice health unhealthy: %s", sanitizeModelServiceHealthResponseError(resp.Error))
	}
	if !resp.Healthy {
		return fmt.Errorf("modelservice health unhealthy")
	}
	return nil
}

func sanitizeModelServiceHealthCallError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("modelservice health check failed: deadline exceeded")
	}
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("modelservice health check failed: canceled")
	}
	if modelservice.IsRetryable(err) {
		return fmt.Errorf("modelservice health check failed: retryable transport error")
	}
	msg := strings.TrimSpace(err.Error())
	if msg == "" {
		return fmt.Errorf("modelservice health check failed")
	}
	if code, _, ok := strings.Cut(msg, ":"); ok {
		msg = strings.TrimSpace(code)
	}
	return fmt.Errorf("modelservice health check failed: %s", msg)
}

func sanitizeModelServiceHealthResponseError(err *modelservice.ServiceError) string {
	if err == nil {
		return "reported error"
	}
	code := strings.TrimSpace(err.Code)
	if code == "" {
		return "reported error"
	}
	if err.Retryable {
		return code + " retryable"
	}
	return code
}
