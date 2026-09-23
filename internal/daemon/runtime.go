package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/builderdirectory"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/diagnostics"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/natsidentity"
	"github.com/TrueOpen/cortex/internal/observability"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/store/once"
	"github.com/TrueOpen/cortex/internal/taskdataauth"
	"github.com/TrueOpen/cortex/internal/tasktrace"
	"github.com/TrueOpen/cortex/internal/txclient"
)

type Runtime struct {
	Store *store.Store
	// BuilderEndpoints resolves the Nexus endpoint of a Builder operator, so
	// task material goes to the Builder that owns the task.
	BuilderEndpoints  BuilderEndpointResolver
	Dependencies      Dependencies
	KeeperEvents      KeeperEventClient
	TaskInputResolver TaskInputResolver
	TaskDataAuth      *taskdataauth.Authenticator
	// OutputConfirmer proves a task's output is held by the receiving Builder
	// before the Verifier commits to it. Nil when the task-data plane is not
	// fully configured, which the Verifier paths refuse on.
	OutputConfirmer OutputConfirmer
	// EvidenceConfirmer downloads the WORKER_VALUE_OPENING artifacts the locked
	// Profile requires and binds them to the receipt's on-chain evidence
	// commitment. Nil outside real mode.
	EvidenceConfirmer EvidenceConfirmer
	// VerifyCommitRelay hands a Verifier's signed commit to the receiving Builder
	// for on-chain relay; nil when the node lacks the task-data plane.
	VerifyCommitRelay VerifyCommitRelay
	// taskTrace is the per-task protocol trace sink this runtime was built
	// with. It is held so the task runner built afterwards traces into the same
	// sink as the output confirmer built here.
	taskTrace                   *tasktrace.Trace
	Reconciler                  *Reconciler
	ServiceAddress              string
	ServicePubkey               string
	WorkloadTx                  txclient.Client
	ProtocolTx                  *ProtocolTxAdapters
	workloadMu                  sync.RWMutex
	cfg                         config.Config
	chainStatus                 ChainStatusReader
	signingClient               signer.Signer
	trustInjectedSignerForTests bool
	signerProofMu               sync.Mutex
	signerProofDigest           codec.Hash
	signerProofValidUntil       time.Time
	signerProofValid            bool
	workloadTxFactory           func(string) txclient.Client
	nexusProbe                  ReadinessProbe
	txProbe                     ReadinessProbe
	// natsIdentity is the on-chain identity binding this machine uses to join NATS
	// (ADR-0016 decision three). It exists only when real mode configured
	// nats_user_key_file and the runtime builds the NATS connection itself; on a node
	// using creds/token it is nil.
	natsIdentity      *natsidentity.Binder
	natsIdentityProbe ReadinessProbe
	builderDirectory  *builderdirectory.Resolver
	builderMembers    *builderdirectory.Membership
	// envelopeAuthError is the last failure of this node's own authentication
	// inputs, guarded by workloadMu.
	envelopeAuthError string
	closers           []interface{ Close() error }
	diagnosticsMu     sync.RWMutex
	diagnostics       diagnostics.Diagnostics
	// chainProgress is the last Keeper poll's view of the durable cursor and
	// the chain tip. It starts unknown so a node that has not polled yet does
	// not look caught up.
	chainProgressMu    sync.RWMutex
	chainProgress      ChainProgress
	chainProgressKnown bool
}

// ObserveChainProgress records what the last Keeper poll saw. The poller calls
// it after every page, and after a poll it refused.
func (r *Runtime) ObserveChainProgress(progress ChainProgress) {
	if r == nil {
		return
	}
	r.chainProgressMu.Lock()
	r.chainProgress = progress
	r.chainProgressKnown = true
	r.chainProgressMu.Unlock()

	// Publish the raw heights too. A refusal stops the workload through
	// readiness, but an operator still has to be able to see why without
	// opening the compact store.
	refusal := ""
	if progress.Refusal != nil {
		refusal = progress.Refusal.Error()
	}
	r.diagnosticsMu.Lock()
	r.diagnostics.ChainCursorHeight = progress.CursorHeight
	r.diagnostics.ChainTipHeight = progress.ChainHeight
	r.diagnostics.ChainLagBlocks = progress.Lag()
	r.diagnostics.ChainCursorRefusal = refusal
	r.diagnosticsMu.Unlock()
}

func (r *Runtime) chainProgressSnapshot() (ChainProgress, bool) {
	r.chainProgressMu.RLock()
	defer r.chainProgressMu.RUnlock()
	return r.chainProgress, r.chainProgressKnown
}

// chainSyncStatus reports whether consumed events are close enough to the chain
// tip for the node to take on new work.
func (r *Runtime) chainSyncStatus() diagnostics.DependencyStatus {
	status := diagnostics.DependencyStatus{
		Name:       "chain_sync",
		Endpoint:   diagnostics.RedactEndpoint(r.cfg.Node.RPCEndpoint),
		Configured: true,
	}
	progress, known := r.chainProgressSnapshot()
	// A refused poll is checked before max_lag_blocks. It is not a staleness
	// question at all: the cursor describes a chain this endpoint has never
	// reached, and leaving max_lag_blocks unset must not make that read ready.
	if known && progress.Refusal != nil {
		status.Error = progress.Refusal.Error()
		return status
	}
	maxLag := r.cfg.Keeper.MaxLagBlocks
	if maxLag == 0 {
		// No configured bound: staleness is not gated.
		status.Ready = true
		return status
	}
	if !known {
		status.Error = "Keeper event lag is not known yet"
		return status
	}
	if lag := progress.Lag(); lag > maxLag {
		status.Error = fmt.Sprintf("Keeper event lag %d exceeds max %d; catching up", lag, maxLag)
		return status
	}
	status.Ready = true
	return status
}

type RuntimeOptions struct {
	ModelClient                modelservice.Client
	ModelTransport             modelservice.Transport
	NexusPublisher             builderclient.Publisher
	NexusSubscriber            builderclient.Subscriber
	TaskDataClient             builderclient.TaskDataClient
	NexusEnvelopeAuthenticator builderclient.BusEnvelopeAuthenticator
	NexusEnvelopeSigner        builderclient.BusEnvelopeSigner
	TxClient                   txclient.Client
	Keeper                     KeeperClient
	KeeperEvents               KeeperEventClient
	ChainStatus                ChainStatusReader
	SigningClient              signer.Signer
	// TrustInjectedSignerForTests explicitly bypasses Keeper public-key proof
	// for test doubles. Production callers must leave it false.
	TrustInjectedSignerForTests bool
	TaskInputResolver           TaskInputResolver
	// BuilderDirectory overrides the descriptor resolver built from config so
	// tests can supply their own HTTP client. Production callers leave it nil.
	BuilderDirectory *builderdirectory.Resolver
	// NATSSentinel overrides the AUTH sentinel source built from the Builder
	// ingress so tests need no ingress to serve one. Production callers leave it
	// nil and the sentinel is fetched from the chosen Builder.
	NATSSentinel        natsidentity.SentinelSource
	NexusReadinessProbe ReadinessProbe
	TxReadinessProbe    ReadinessProbe
	// NexusPublishObserver reports every outbound bus publish this node makes.
	// cortexd supplies the one that logs; a nil observer leaves the send path
	// exactly as it was.
	NexusPublishObserver func(builderclient.PublishCompletion)
	// TaskTraceObserver receives the per-task protocol trace lines, digests
	// included (see TaskTrace). cortexd supplies the one that logs; nil is
	// silent. The runtime hands the same trace to the output confirmer it
	// builds, and exposes it through Runtime.TaskTrace so the task runner
	// cortexd builds afterwards traces into the same sink.
	TaskTraceObserver func(observability.LogRecord)
}

type ChainStatusReader interface {
	ChainStatus(context.Context) (uint64, string, error)
}

type ReadinessProbe interface {
	Probe(context.Context) error
}

type readinessProbeFunc func(context.Context) error

func (f readinessProbeFunc) Probe(ctx context.Context) error { return f(ctx) }

func BuildRuntime(ctx context.Context, cfg config.Config) (*Runtime, error) {
	return BuildRuntimeWithOptions(ctx, cfg, RuntimeOptions{})
}

func BuildRuntimeWithOptions(ctx context.Context, cfg config.Config, opts RuntimeOptions) (*Runtime, error) {
	db, err := store.Open(ctx, cfg.Store.Path)
	if err != nil {
		return nil, err
	}
	// Bind before anything reads a cursor, snapshot or queue row: state from
	// another chain must stop the node, not be mixed with this chain's.
	if err := db.BindChainIdentity(ctx, cfg.ChainID); err != nil {
		_ = db.Close()
		return nil, err
	}

	token, err := loadNexusToken(cfg.Nexus)
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	taskDataClient := opts.TaskDataClient
	if taskDataClient == nil && cfg.UsesRealDependencies() {
		// The endpoint policy is the same switch that lets builderdirectory
		// accept a plaintext http:// endpoint from the on-chain descriptor at
		// all, so the transport cannot dial what resolution would have refused.
		taskDataClient = builderclient.NewConnectTaskDataClientWithDefaults(token,
			builderclient.TaskDataTransport{
				AllowInsecureEndpoint: cfg.Nexus.AllowInsecureDescriptor,
				DowngradeEndpointTLS:  cfg.Nexus.DowngradeDescriptorTLS,
			})
	}

	var transport modelservice.Transport
	if opts.ModelClient == nil {
		transport, err = modelservice.NewTransport(modelservice.RuntimeTransportConfig{
			Kind:     cfg.ModelManagement.Transport,
			Endpoint: cfg.ModelManagement.Endpoint,
			TLS:      modelservice.GRPCTLS{CAFile: cfg.ModelManagement.TLS.CAFile, PubkeyHash: cfg.ModelManagement.TLS.PubkeyHash},
		})
	}
	if opts.ModelClient != nil {
		err = nil
	} else if opts.ModelTransport != nil {
		transport = opts.ModelTransport
		err = nil
	}
	var transportErr error
	if err != nil {
		if !errors.Is(err, modelservice.ErrRuntimeTransportUnavailable) {
			_ = db.Close()
			return nil, err
		}
		transportErr = err
		transport = nil
	}
	if shouldProbeModelServiceHealth(cfg, opts, transport, transportErr) {
		if err := probeModelServiceHealth(ctx, cfg, transport); err != nil {
			transportErr = err
		}
	}

	// A single cleanup path for every construction failure below. The list grows
	// as construction proceeds, so one closure covers every failure site no
	// matter how much has been built by then.
	constructed := []any{transport}
	failRuntime := func(err error) (*Runtime, error) {
		for _, closer := range runtimeClosers(constructed...) {
			_ = closer.Close()
		}
		_ = db.Close()
		return nil, err
	}

	keeperClient := opts.Keeper
	if keeperClient == nil && cfg.UsesRealDependencies() {
		keeperClient = chainclient.NewKeeperABCIClient(cfg.Node.RPCEndpoint)
	}
	txClient := opts.TxClient
	// Build the signer once. A local key file would otherwise be decrypted on
	// every construction site, and the password read as many times. It is built
	// before the NATS connections because the chain identity binding below signs
	// with it.
	signingClient := opts.SigningClient
	if signingClient == nil && cfg.UsesRealDependencies() {
		signingClient, err = signer.Open(cfg.Signer.URI, signer.OpenOptions{
			PasswordEnv:   cfg.Signer.PasswordEnv,
			PasswordFile:  cfg.Signer.PasswordFile,
			PasswordStdin: cfg.Signer.PasswordStdin,
			HRP:           bech32HRP(cfg.LocalIdentity.OperatorAddress),
			KeyRefs: []signer.KeyRef{
				{Ref: cfg.LocalIdentity.ServiceKeyRef},
			},
		})
		if err != nil {
			return failRuntime(fmt.Errorf("open signer: %w", err))
		}
		if err := checkLocalSignerKeys(signingClient, cfg); err != nil {
			return failRuntime(err)
		}
	}

	// These two are assembled further down, but the sentinel source has to be handed
	// to the Binder here: declare them early and let the accessor functions read them
	// on the first connect, by which time they have long since taken shape.
	var builderMembers *builderdirectory.Membership
	var builderEndpointResolver BuilderEndpointResolver

	// Joining NATS with the on-chain identity (ADR-0016 decision three): as long as at
	// least one connection is built by the runtime it has to carry the identity; only
	// when both are injected test doubles is there no connection to attach one to. This
	// section is fail-closed - once nats_user_key_file is configured the binding must
	// really be made, never quietly falling back to creds/token.
	var natsIdentity *natsidentity.Binder
	if (opts.NexusPublisher == nil || opts.NexusSubscriber == nil) && cfg.UsesRealDependencies() &&
		strings.TrimSpace(cfg.Nexus.NATSUserKeyFile) != "" {
		serviceKeys, ok := keeperClient.(natsidentity.ServiceKeyReader)
		if !ok {
			return failRuntime(fmt.Errorf("nats chain identity requires a Keeper client that can read service keys"))
		}
		userKey, created, err := natsidentity.LoadOrCreateUserKey(cfg.Nexus.NATSUserKeyFile)
		if err != nil {
			return failRuntime(err)
		}
		// An operator-mode nats-server requires CONNECT to carry a user JWT its own account
		// can verify before it asks the auth callback, so the credential also needs the AUTH
		// sentinel (public material) served by a Builder ingress.
		sentinel := opts.NATSSentinel
		if sentinel == nil {
			sentinel, err = natsidentity.NewIngressSentinelSource(natsSentinelIngress{
				operator:  strings.TrimSpace(cfg.Nexus.BuilderOperatorAddress),
				members:   func() *builderdirectory.Membership { return builderMembers },
				endpoints: func() BuilderEndpointResolver { return builderEndpointResolver },
				transport: builderclient.TaskDataTransport{
					AllowInsecureEndpoint: cfg.Nexus.AllowInsecureDescriptor,
					DowngradeEndpointTLS:  cfg.Nexus.DowngradeDescriptorTLS,
				},
			}, nil)
			if err != nil {
				return failRuntime(err)
			}
		}
		natsIdentity, err = natsidentity.New(natsidentity.Config{
			ServiceKeys: serviceKeys, Signer: signingClient,
			ChainID: cfg.ChainID, OperatorAddress: strings.TrimSpace(cfg.LocalIdentity.OperatorAddress),
			ServiceKeyRef: strings.TrimSpace(cfg.LocalIdentity.ServiceKeyRef), UserKey: userKey,
			Sentinel: sentinel,
		})
		if err != nil {
			return failRuntime(err)
		}
		if created {
			pub, _ := userKey.PublicKey()
			slog.Info("generated nats user key", "file", cfg.Nexus.NATSUserKeyFile, "public_key", pub)
		}
	}
	// An explicit nil interface: a nil *Binder stored in an interface is no longer nil,
	// and the creds/token path would be taken for a configured on-chain identity.
	var chainIdentity builderclient.ChainIdentityProvider
	if natsIdentity != nil {
		chainIdentity = natsIdentity
	}

	// The two NATS connections are built here: the identity binding has to exist before
	// them. The connections themselves are lazy (they dial on first use), so deferring
	// their construction changes nothing observable.
	var publisher builderclient.Publisher
	var publisherErr error
	if opts.NexusPublisher != nil {
		publisher = opts.NexusPublisher
	} else if cfg.UsesRealDependencies() {
		publisher, publisherErr = builderclient.NewNATSPublisherWithAuth(nexusNATSAuth(cfg.Nexus, token, chainIdentity))
	}
	var subscriber builderclient.Subscriber
	var subscriberErr error
	if opts.NexusSubscriber != nil {
		subscriber = opts.NexusSubscriber
	} else if cfg.UsesRealDependencies() {
		subscriber, subscriberErr = builderclient.NewNATSSubscriberWithAuth(nexusNATSAuth(cfg.Nexus, token, chainIdentity), cfg.Nexus.JetStreamStream, nexusDurablePrefix(cfg))
	}
	constructed = append(constructed, publisher, subscriber)

	deps, err := BuildDependencies(cfg, DependencyOptions{
		ModelClient:                opts.ModelClient,
		ModelTransport:             transport,
		NexusPublisher:             publisher,
		NexusSubscriber:            subscriber,
		NexusEnvelopeAuthenticator: opts.NexusEnvelopeAuthenticator,
		NexusEnvelopeSigner:        opts.NexusEnvelopeSigner,
		NexusToken:                 token,
		TaskDataClient:             taskDataClient,
		TxClient:                   txClient,
		Keeper:                     keeperClient,
		NexusPublishObserver:       opts.NexusPublishObserver,
	})
	if err != nil {
		return failRuntime(err)
	}
	if transportErr != nil {
		applyDependencyError(&deps, "model_service", transportErr.Error())
	}
	// A runtime without a Binder has no binding to judge: downgrade this line to
	// optional-not-configured. Otherwise the readiness gate stays stuck on a dependency
	// that will never be probed.
	if natsIdentity == nil {
		setDependencyStatus(&deps, diagnostics.DependencyStatus{
			Name:     natsIdentityDependency,
			Endpoint: diagnostics.RedactEndpoint(cfg.Nexus.NATSURL),
			Optional: true,
		})
	}
	if publisherErr != nil {
		applyDependencyError(&deps, "nexus", publisherErr.Error())
	}
	if subscriberErr != nil {
		applyDependencyError(&deps, "nexus", subscriberErr.Error())
	}
	keeperEvents := opts.KeeperEvents
	if keeperEvents == nil && cfg.UsesRealDependencies() {
		keeperEvents = chainclient.NewCometEventClient(chainclient.CometEventClientConfig{
			RPCURL:  cfg.Node.RPCEndpoint,
			ChainID: cfg.ChainID,
		})
	}
	chainStatus := opts.ChainStatus
	if chainStatus == nil {
		chainStatus, _ = keeperEvents.(ChainStatusReader)
	}
	var workloadTxFactory func(string) txclient.Client
	if txClient == nil && cfg.UsesRealDependencies() && cfg.Tx.Enabled {
		if confirmationReader, ok := keeperClient.(txclient.KeeperConfirmationReader); ok {
			newBroadcaster := func(txSigner txclient.Signer, gasPayer string) txclient.Client {
				return txclient.NewBroadcaster(txclient.BroadcasterConfig{
					ChainID: cfg.ChainID, GasPayer: gasPayer, MaxFeeAmount: cfg.Tx.MaxFeeAmount, FeeDenom: cfg.Tx.FeeDenom,
					MaxAttempts: cfg.Tx.MaxAttempts, PollAttempts: cfg.Tx.PollAttempts, PollInterval: runtimePollInterval(cfg.Keeper.PollIntervalMS), GasLimit: cfg.Tx.GasLimit,
					Signer: txSigner, RPC: txclient.NewCosmosHTTPClient(txclient.CosmosHTTPConfig{Endpoint: cfg.Node.RESTEndpoint}),
					Confirmer: txclient.NewKeeperConfirmer(confirmationReader),
				})
			}
			if signingClient != nil && signingClient.CanSignCosmosTx() {
				workloadTxFactory = func(serviceAddress string) txclient.Client {
					serviceSigner := txclient.NewCosmosSigner(txclient.CosmosSignerConfig{Client: signingClient, KeyRef: cfg.LocalIdentity.ServiceKeyRef, SignerAddress: serviceAddress})
					return newBroadcaster(serviceSigner, serviceAddress)
				}
				setDependencyReady(&deps, "tx_broadcaster")
			} else {
				applyDependencyError(&deps, "tx_broadcaster", "signer cannot produce Cosmos transactions")
			}
		}
	} else if txClient != nil && cfg.UsesRealDependencies() && cfg.Tx.Enabled {
		workloadTxFactory = func(string) txclient.Client { return deps.Tx }
	}
	// Membership is the chain's own answer to which Builders may address this
	// node on the bus. It is constructed before the reconciler so a BuilderSet
	// update can drop the cached set on the spot.
	if cfg.UsesRealDependencies() {
		if setReader, ok := deps.Keeper.(builderdirectory.MembershipReader); ok {
			builderMembers, err = builderdirectory.NewMembership(setReader, builderdirectory.MembershipOptions{})
			if err != nil {
				return nil, err
			}
		}
	}

	var reconciler *Reconciler
	if cfg.UsesRealDependencies() && deps.Keeper != nil {
		taskReader, _ := deps.Keeper.(KeeperTaskReader)
		modelReader, _ := deps.Keeper.(KeeperModelRegistryReader)
		reconciler = NewReconciler(ReconcilerOptions{
			TaskReader:  taskReader,
			ModelReader: modelReader,
			// Quarantined events are skipped so the cursor can advance past
			// permanent chain history the node cannot parse. Skipping silently
			// would hide a contract mismatch, so log every one.
			OnQuarantinedEvent: func(event chainclient.KeeperEvent) {
				slog.Error("quarantined Keeper event",
					slog.String("type", event.RawType),
					slog.String("position", event.Position.String()),
					slog.String("error", event.QuarantineReason))
			},
			// A new BuilderSet takes effect on the next frame, not at the end of
			// the membership cache window.
			OnBuilderSetUpdated: func() { builderMembers.Invalidate() },
			// The last resort for a terminal event whose task the chain can no
			// longer answer for: the accepted task hash this node already keyed
			// its own documents by. Both lookups are by task_id and return that
			// same hash, so which document survives at the moment the task ends
			// does not matter.
			LocalTaskHash: func(ctx context.Context, taskID string) (codec.Hash, bool) {
				if hash, _, err := layout.FindInferRecordByTaskID(ctx, db, taskID); err == nil {
					return codec.Hash(hash), true
				}
				if hash, _, err := layout.FindVerifyRecordByTaskID(ctx, db, taskID); err == nil {
					return codec.Hash(hash), true
				}
				return codec.Hash{}, false
			},
		})
	}

	builderDirectory := opts.BuilderDirectory
	if builderDirectory == nil && cfg.UsesRealDependencies() {
		descriptorReader, ok := deps.Keeper.(builderdirectory.KeeperReader)
		switch {
		case ok:
			builderDirectory, err = builderdirectory.New(descriptorReader, builderdirectory.Options{
				AllowInsecure: cfg.Nexus.AllowInsecureDescriptor,
			})
			if err != nil {
				return failRuntime(err)
			}
		case cfg.Nexus.VerifiesBuilderDescriptor():
			return failRuntime(fmt.Errorf("nexus.builder_operator_address requires a Keeper client that can read service descriptors"))
		}
	}

	if cfg.UsesRealDependencies() {
		serviceKeys, _ := deps.Keeper.(builderServiceKeyReader)
		// Task data is always resolved from the receiving Builder's verified
		// descriptor. The configured ingress remains a readiness/bootstrap hint
		// for legacy paths and is never substituted for per-task chain authority.
		builderEndpointResolver = newBuilderEndpoints(builderDirectory, serviceKeys, "", "", false)
	}

	var taskDataAuth *taskdataauth.Authenticator
	inputResolver := opts.TaskInputResolver
	inputMode := cfg.TaskExecution.InputResolverMode()
	if inputResolver == nil && cfg.UsesRealDependencies() && inputMode == config.InputResolverFixture {
		inputResolver, err = NewFixtureTaskInputResolver(cfg.TaskExecution.FixtureRoot)
		if err != nil {
			return failRuntime(err)
		}
	}

	// Every real-mode node can be drawn as a Worker, and a Worker needs this
	// authenticator for output even when fake model transport supplies fixture
	// input. An injected resolver is a test-only replacement for the task-data
	// boundary; production leaves it nil.
	//
	// The Verifier's output confirmation runs over the same signed surface and
	// reuses this authenticator rather than requiring one of its own. Since duty
	// selection is retired, the two roles now impose the same requirement and the
	// condition collapses to "real mode with no injected resolver".
	requiresTaskDataAuth := cfg.UsesRealDependencies() && opts.TaskInputResolver == nil
	if requiresTaskDataAuth {
		if deps.TaskData == nil {
			return failRuntime(fmt.Errorf("task-data Worker runtime requires a task-data client"))
		}
		serviceKeys, ok := deps.Keeper.(taskdataauth.CurrentServiceKeyReader)
		if !ok {
			return failRuntime(fmt.Errorf("task-data Worker runtime requires a Keeper client that can read service keys"))
		}
		// Startup reads the binding from the latest committed state rather than
		// pinning a height from /status: a node that has just restarted alongside
		// its peers can see a block store height the application has not committed
		// yet, and pinning it made the chain refuse the query and the node refuse
		// to start.
		binding, _, err := serviceKeys.CommittedCurrentServiceKey(ctx, chainclient.ParticipantTypeCortexNode,
			strings.TrimSpace(cfg.LocalIdentity.OperatorAddress))
		if err != nil {
			return failRuntime(fmt.Errorf("resolve current service identity for task-data authentication: %w", err))
		}
		taskDataAuth, err = taskdataauth.New(taskdataauth.Config{
			ServiceKeys: serviceKeys, Signer: signingClient,
			ChainID: cfg.ChainID, OperatorAddress: strings.TrimSpace(cfg.LocalIdentity.OperatorAddress),
			ServiceAddress: binding.ServiceAddress, ServicePubkey: binding.ServicePubkey,
			ServiceKeyRef: strings.TrimSpace(cfg.LocalIdentity.ServiceKeyRef), ExpiryBlocks: inputTaskDataExpiryBlocks,
		})
		if err != nil {
			return failRuntime(err)
		}
	}
	if inputResolver == nil && cfg.UsesRealDependencies() && inputMode == config.InputResolverNexus {
		inputResolver, err = NewNexusTaskInputResolver(NexusTaskInputResolverConfig{
			TaskData:  deps.TaskData,
			Endpoints: builderEndpointResolver,
			Auth:      taskDataAuth,
		})
		if err != nil {
			return failRuntime(err)
		}
	}

	// The Verifier's output confirmation replaces FetchOutputRef. Every input is
	// chain-backed except the output body, which is read from the receiving
	// Builder over the task-data plane (or, when this node has a shared package
	// store, from that store). deps.OutputPackages is deliberately NOT a
	// condition here: it is populated only under the fake model transport, so
	// requiring it left every node running a real model transport without a
	// confirmer, which meant no Verifier could ever raise its hand and the
	// handraise window expired into TASK_FAILURE_CLASS_INSUFFICIENT_VERIFIER.
	// When a condition below is absent the confirmer stays nil and the two call
	// sites refuse to sign, naming what to configure.
	taskTrace := &tasktrace.Trace{Emit: opts.TaskTraceObserver}
	var outputConfirmer OutputConfirmer
	if cfg.UsesRealDependencies() &&
		deps.TaskData != nil && taskDataAuth != nil && builderEndpointResolver != nil {
		outputConfirmer, err = NewNexusOutputConfirmer(NexusOutputConfirmerConfig{
			TaskData:  deps.TaskData,
			Endpoints: builderEndpointResolver,
			Auth:      taskDataAuth,
			// Optional and normally nil: only the fake model transport
			// populates it. See NexusOutputConfirmerConfig.Packages.
			Packages:       deps.OutputPackages,
			ChainID:        cfg.ChainID,
			MaxOutputBytes: cfg.TaskExecution.MaxOutputBytes,
			Trace:          taskTrace,
		})
		if err != nil {
			return failRuntime(err)
		}
	}
	// The evidence half of V7a, built under exactly the conditions the output
	// half is: same plane, same role, same authenticator. A node with no
	// confirmer falls back to addressing the artifacts by model-service ref,
	// which is the fake model transport's path and empty on a real chain -- see
	// verifier.HandleOpenVerifyAccepted.
	var evidenceConfirmer EvidenceConfirmer
	if cfg.UsesRealDependencies() &&
		deps.TaskData != nil && taskDataAuth != nil && builderEndpointResolver != nil {
		evidenceConfirmer, err = NewNexusEvidenceConfirmer(NexusEvidenceConfirmerConfig{
			TaskData: deps.TaskData, Endpoints: builderEndpointResolver, Auth: taskDataAuth,
			ChainID: cfg.ChainID, Trace: taskTrace,
		})
		if err != nil {
			return failRuntime(err)
		}
	}
	var verifyCommitRelay VerifyCommitRelay
	if cfg.UsesRealDependencies() &&
		deps.TaskData != nil && taskDataAuth != nil && builderEndpointResolver != nil {
		verifyCommitRelay, err = NewNexusVerifyCommitRelay(NexusVerifyCommitRelayConfig{
			TaskData: deps.TaskData, Endpoints: builderEndpointResolver, Auth: taskDataAuth,
			ChainID: cfg.ChainID, Trace: taskTrace,
		})
		if err != nil {
			return nil, err
		}
	}

	// Nexus BusEnvelope authentication. Without this the workload dependency can
	// only be satisfied by an injected test double, which is what kept real-mode
	// nodes from ever activating. trusted_nats_dev deliberately builds neither:
	// there the NATS transport and its subject ACL are the boundary, and the
	// envelopes on that bus are unsigned by design.
	//
	// A construction failure takes the workload out of readiness rather than
	// killing startup: the node stays observable and diagnosable, which is what
	// the design asks of this dependency.
	envelopeSigner := opts.NexusEnvelopeSigner
	envelopeAuthenticator := opts.NexusEnvelopeAuthenticator
	var envelopeAuthErrors []string
	// The runtime is built below, so the failure sink is late bound: an
	// authentication failure caused by this node's own dependencies has to reach
	// the diagnostics of a runtime that does not exist yet.
	var envelopeRuntime *Runtime
	reportEnvelopeAuthOutcome := func(err error) {
		switch {
		case envelopeRuntime == nil:
		case err == nil:
			envelopeRuntime.clearEnvelopeAuthFailure()
		default:
			envelopeRuntime.recordEnvelopeAuthFailure(err)
		}
	}
	if cfg.UsesRealDependencies() && !cfg.Nexus.TrustedNATSDev() && envelopeAuthenticator == nil {
		serviceKeys, ok := deps.Keeper.(envelopeServiceKeyReader)
		switch {
		case !ok:
			envelopeAuthErrors = append(envelopeAuthErrors,
				"nexus.envelope_auth_mode strict requires a Keeper client that can read service keys")
		case builderMembers == nil:
			envelopeAuthErrors = append(envelopeAuthErrors,
				"nexus.envelope_auth_mode strict requires a Keeper client that can read the current BuilderSet")
		default:
			envelopeAuthenticator, err = NewBusEnvelopeAuthenticator(BusEnvelopeAuthenticatorConfig{
				ChainID:             cfg.ChainID,
				Keeper:              serviceKeys,
				Members:             builderMembers,
				PeerOperatorAddress: cfg.Nexus.BuilderOperatorAddress,
				TTL:                 cfg.Nexus.EnvelopeTTL(),
				ClockSkew:           cfg.Nexus.EnvelopeClockSkew(),
				OnDependencyOutcome: reportEnvelopeAuthOutcome,
				StoreOnce:           once.New(db),
			})
			if err != nil {
				envelopeAuthenticator = nil
				envelopeAuthErrors = append(envelopeAuthErrors, err.Error())
			}
		}
	}

	runtime := &Runtime{
		Store:                       db,
		Dependencies:                deps,
		KeeperEvents:                keeperEvents,
		TaskInputResolver:           inputResolver,
		TaskDataAuth:                taskDataAuth,
		OutputConfirmer:             outputConfirmer,
		EvidenceConfirmer:           evidenceConfirmer,
		VerifyCommitRelay:           verifyCommitRelay,
		taskTrace:                   taskTrace,
		Reconciler:                  reconciler,
		cfg:                         cfg,
		chainStatus:                 chainStatus,
		signingClient:               signingClient,
		trustInjectedSignerForTests: opts.TrustInjectedSignerForTests,
		workloadTxFactory:           workloadTxFactory,
		nexusProbe:                  firstReadinessProbe(opts.NexusReadinessProbe, nexusReadinessProbe(publisher, subscriber)),
		natsIdentity:                natsIdentity,
		natsIdentityProbe:           natsIdentityReadinessProbe(natsIdentity),
		txProbe:                     firstReadinessProbe(opts.TxReadinessProbe, cosmosTxCapableProbe(signingClient, readinessProbeFrom(deps.Tx))),
		closers:                     runtimeClosers(constructed...),
		builderDirectory:            builderDirectory,
		builderMembers:              builderMembers,
		BuilderEndpoints:            builderEndpointResolver,
	}
	envelopeRuntime = runtime
	runtime.setDiagnosticsSnapshot(deps.Diagnostics)
	// The outbound signer resolves its identity from the activated workload, so
	// it can only be built once the runtime exists.
	if cfg.UsesRealDependencies() && !cfg.Nexus.TrustedNATSDev() && envelopeSigner == nil {
		envelopeSigner, err = NewBusEnvelopeSigner(BusEnvelopeSignerConfig{
			Signer:         signingClient,
			KeyRef:         cfg.LocalIdentity.ServiceKeyRef,
			ServiceAddress: runtime.workloadServiceAddress,
		})
		if err != nil {
			envelopeSigner = nil
			envelopeAuthErrors = append(envelopeAuthErrors, err.Error())
		}
	}
	runtime.Dependencies.NexusEnvelopeSigner = envelopeSigner
	runtime.Dependencies.NexusEnvelopeAuthenticator = envelopeAuthenticator
	switch {
	case len(envelopeAuthErrors) > 0:
		// Both constructions can fail for different reasons, and an operator
		// needs the first cause as much as the last one. The reason is also kept
		// on the runtime so the live status below does not replace it with a
		// generic message on the next readiness pass.
		reason := strings.Join(envelopeAuthErrors, "; ")
		runtime.envelopeAuthError = reason
		applyDependencyError(&runtime.Dependencies, "nexus_envelope_auth", reason)
	case envelopeSigner != nil && envelopeAuthenticator != nil:
		setDependencyReady(&runtime.Dependencies, "nexus_envelope_auth")
	}
	runtime.setDiagnosticsSnapshot(runtime.Dependencies.Diagnostics)
	if cfg.UsesRealDependencies() {
		readiness := runtime.CheckWorkloadReadiness(ctx)
		setDependencyStatus(&runtime.Dependencies, readiness.Identity)
		setDependencyStatus(&runtime.Dependencies, readiness.ModelSupport)
		setDependencyStatus(&runtime.Dependencies, readiness.BuilderDescriptor)
		if readiness.Ready() {
			if err := runtime.ActivateWorkload(readiness.ServiceAddress, readiness.ServicePubkey); err != nil {
				_ = runtime.Close()
				return nil, err
			}
		}
	}
	return runtime, nil
}
