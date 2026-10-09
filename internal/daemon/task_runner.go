package daemon

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/taskdataauth"
	"github.com/TrueOpen/cortex/internal/taskfacts"
	"github.com/TrueOpen/cortex/internal/tasktrace"
	"github.com/TrueOpen/cortex/internal/txclient"
	"github.com/TrueOpen/cortex/internal/worker"
)

type CandidateMemberReader interface {
	CurrentCandidateMember(context.Context, string) (chainclient.CandidateMemberRefSnapshot, error)
}

// VerifierMemberReader is one window with two readings, and which one a caller
// wants depends entirely on the phase it is in. The handraise path is bounded by
// the interval it may act in; the verify path runs strictly after that interval
// closes and needs the frozen set. Keeping them as separate methods is what
// stopped the verify path from asking the handraise question and retrying a
// refusal that could never become an acceptance.
type VerifierMemberReader interface {
	VerifierCandidateMember(context.Context, string, uint32, string) (chainclient.VerifierCandidateMemberSnapshot, error)
	FrozenVerifierWindowMember(context.Context, string, uint32, string) (chainclient.VerifierCandidateMemberSnapshot, error)
}

type TaskRunnerConfig struct {
	Store           *store.Store
	Evidence        *evidence.Store
	Model           modelservice.Client
	Builder         builderclient.Client
	TaskData        builderclient.TaskDataClient
	TaskDataAuth    *taskdataauth.Authenticator
	OutputPackages  builderclient.OutputPackageStore
	OutputConfirmer OutputConfirmer
	// EvidenceConfirmer downloads the WORKER_VALUE_OPENING artifacts off the
	// task-data plane. Nil falls back to addressing them by model-service ref,
	// which only the fake model transport can serve.
	EvidenceConfirmer EvidenceConfirmer
	// VerifyCommitRelay hands the signed verify commit to the receiving Builder
	// for relay. Optional: nil keeps the pre-relay behaviour (self-submit only).
	VerifyCommitRelay          VerifyCommitRelay
	FakeOutput, TrustedNATSDev bool
	// FakeBus is a test-only seam and must never become configuration
	// reachable. TrustedNATSDev only drops the envelope signature layer;
	// FakeBus additionally passes verifyTaskOrder=false to
	// validateNexusOrderBroadcast, which skips canonical TaskOrderV1 decoding,
	// the task_hash-commits-signed_order check, and all eleven
	// payload-matches-signed_order comparisons (task_runner_util.go:60-75). A
	// deployment running with it set would accept an OrderBroadcast whose
	// fields contradict the order its own Builder signed.
	FakeBus bool
	// WakeKeeperPoll asks the Keeper poller for a scan now. It is set after the
	// poller is built, because the poller is built around this runner. Nil is
	// the ordinary state in tests and in the fake-bus deployment, and costs
	// nothing: the bus frame that would have woken the poller is retried on the
	// bus instead, exactly as it was before.
	//
	// It carries no authority. The scan it asks for reads and validates the
	// chain the same way a tick does, so a frame that lies about chain state
	// buys nothing but one early scan.
	WakeKeeperPoll                 func(WakeSource)
	EnvelopeTTL, EnvelopeClockSkew time.Duration
	HandraiseEligibility           HandraiseEligibility
	NexusEnvelopeAuthenticator     builderclient.BusEnvelopeAuthenticator
	NexusEnvelopeSigner            builderclient.BusEnvelopeSigner
	ReceivingBuilder               worker.ReceivingBuilderProvider
	// TaskFacts serves TaskCoreState.accepted_task_hash and
	// TaskAssignmentViewV1.generation_params_digest to the Worker receipt path
	// and the Verifier result path. Both are frozen signed fields with no local
	// derivation, so both paths refuse when it is absent.
	CandidateMemberReader CandidateMemberReader
	TaskFacts             taskfacts.Reader
	VerifierMemberReader  VerifierMemberReader
	Tx                    txclient.Client
	// TxProvider returns the CURRENT workload tx client, and it is what the
	// verifier commit exit must use. The task runner is constructed before the
	// Keeper confirms this node's service key, so Tx above is nil at
	// construction time on every dynamic-readiness node -- the same reason
	// ServiceIdentity exists beside SignerAddress. Nil falls back to Tx.
	TxProvider func() txclient.Client
	TxGasPayer string
	TxFeeCap   txclient.Coin
	// CommitExitFeeCap bounds one verifier commit self-submission. Zero means
	// TxFeeCap.
	CommitExitFeeCap                                                  txclient.Coin
	LocalWorkerAddress, LocalVerifierAddress, ModelServiceID, ChainID string
	SignerAddress, SignerKeyRef, SignerPubkey                         string
	Signer                                                            signer.DigestSigner
	ServiceIdentity                                                   func() (address string, pubkey string)
	InferDeadlineDeltaHeights, VerifyDeadlineDeltaHeight              uint64
	// MaxOutputBytes bounds the verifier's output artifact fetch. Zero lets the
	// verifier apply its own default; it never means unbounded.
	MaxOutputBytes           uint64
	BatchSize                int
	MaxConcurrency           uint32
	PollInterval, RetryDelay time.Duration
	// MaxRetryDelay caps the exponential backoff retryAt applies to RetryDelay.
	// Zero defaults; it is never below RetryDelay.
	MaxRetryDelay               time.Duration
	ChainStatus                 ChainStatusReader
	MaxRetryAttempts            int
	MaxSessionAdmissions        int
	InputResolver               TaskInputResolver
	ProfileCapabilities         map[string]string
	ProfileReader               KeeperProfileReader
	TaskReader                  KeeperTaskReader
	OperatorAddress, LeaseOwner string
	Diagnostic                  func(TaskRunnerDiagnostic)
	// OnQuarantinedEffect reports a Keeper effect that was skipped because it
	// conflicted with a durable record. Nothing retries it and the poll cursor
	// advances past the event, so this callback is the only trace that one task
	// diverged from Keeper authority.
	OnQuarantinedEffect func(ReconcilerEffect, error)
	// Trace reports every protocol milestone a task passes through, digests
	// included. Nil is silent; cortexd supplies the sink that logs.
	Trace          *tasktrace.Trace
	InferExecutor  InferExecutor
	VerifyExecutor VerifyExecutor
	// CrashHook, if non-nil, is forwarded to worker.Config and invoked at
	// named durable-handoff points. Tests use it to simulate crashes between
	// commits.
	CrashHook func(point string) error
}
type KeeperProfileReader interface {
	CurrentModelProfile(context.Context, string, string) (chainclient.CurrentModelProfileSnapshot, error)
}

type TaskRunnerDiagnostic struct {
	Source, Record, Error string
	RetryAt               time.Time
	Count                 int64
	// Waiting marks the refusals that are the protocol working: a chain state
	// this node is required to wait for has not materialized yet. It is not a
	// severity knob -- every other field means the same thing on both -- it
	// exists so the sink can stop calling a wait a failure.
	Waiting bool
}

type ActiveTaskRecord struct {
	QueueID, TaskID, Role, Stage, Status, LastError string
	RetryCount                                      uint32
	RetryAtUnixMilli                                int64
	DueHeight                                       uint64
	// AutoHalted, HaltCode and HaltReason surface layout.AutoHalt on the admin
	// socket. Without them an operator reading a stopped node cannot tell a task
	// that exhausted its retries from one the scheduler deliberately stopped
	// calling the model for, and only the second has a remedy.
	AutoHalted bool
	HaltCode   string
	HaltReason string
}
type TaskInputRef struct {
	SessionID, TaskID, PayloadCID string
	TaskHash                      codec.Hash
	PayloadHash                   chainclient.HexHash
	BuilderOperatorAddress        string
	// InputSizeBytes is the user-signed size from the accepted TaskOrderV1.
	// Zero means unknown and requires a metadata round trip before fetching.
	InputSizeBytes uint64
}
type TaskInputResolver interface {
	ResolveTaskInput(context.Context, TaskInputRef) ([]byte, error)
}
type InferExecutor interface {
	RunInfer(context.Context, codec.Hash, store.InferTask) (store.InferTask, bool, error)
}
type VerifyExecutor interface {
	RunVerify(context.Context, codec.Hash, store.VerifyTask) (store.VerifyTask, bool, error)
}

type TaskRunner struct {
	cfg          TaskRunnerConfig
	wakeup       chan struct{}
	mu           sync.Mutex
	infer        map[codec.Hash]store.InferTask
	verify       map[codec.Hash]store.VerifyTask
	admitMu      sync.Mutex
	sessions     map[string]sessionAdmission
	sessionOrder []string
	// recoveryMu guards recoveryChecked, the set of task hashes whose committed
	// local objects this process has already audited. See
	// localObjectsRecoveryReason.
	recoveryMu      sync.Mutex
	recoveryChecked map[codec.Hash]struct{}
	// waitMu guards chainWaits, the per-task-round count of how many times this
	// process has been told to wait for a chain state. See traceChainWait.
	waitMu     sync.Mutex
	chainWaits map[string]uint64
	// redriveMu guards handraiseRedrives, the task-rounds whose Verifier
	// handraise is still owed an attempt because the transport that delivered
	// the call will not deliver it again. See task_runner_handraise_redrive.go.
	redriveMu         sync.Mutex
	handraiseRedrives map[string]*verifierHandraiseRedrive
	// handraiseMu serializes Verifier handraise attempts. Two attempts at one
	// task-round must not overlap: the at-most-once claim only suppresses a
	// duplicate once the first attempt has *completed* it, so overlapping
	// attempts would both find the claim incomplete and both publish a
	// candidacy. Two sources reach here independently - the inbox runner and the
	// poll loop's re-drive - so ordering them is not optional.
	//
	// handraiseMu also guards handraiseBlockWaits, the per-task-round record of
	// the block at which this round last refused with a chain-state wait. See
	// repeatedHandraiseBlockWait.
	handraiseMu         sync.Mutex
	handraiseBlockWaits map[string]handraiseBlockWait
	// orderRedriveMu guards orderRedrives, the broadcast orders this node
	// refused because it was momentarily full and still owes an attempt. See
	// task_runner_order_redrive.go.
	orderRedriveMu sync.Mutex
	orderRedrives  map[string]*workerOrderRedrive
}

type sessionAdmission struct {
	sequence uint64
	taskHash codec.Hash
}

// SetKeeperPollWake closes the loop the constructor cannot: the Keeper poller
// is built around this runner, so it can only be handed back afterwards. Until
// it is -- and in every deployment that runs without a poller -- a frame that
// outruns the cursor is retried on the bus alone, which is the behaviour this
// shortens rather than replaces.
func (r *TaskRunner) SetKeeperPollWake(wake func(WakeSource)) {
	if r == nil {
		return
	}
	r.cfg.WakeKeeperPoll = wake
}

func NewTaskRunner(cfg TaskRunnerConfig) *TaskRunner {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = time.Second
	}
	if cfg.VerifyDeadlineDeltaHeight == 0 {
		cfg.VerifyDeadlineDeltaHeight = 40
	}
	if cfg.MaxConcurrency == 0 {
		cfg.MaxConcurrency = 1
	}
	if cfg.RetryDelay <= 0 {
		cfg.RetryDelay = time.Minute
	}
	// Fifteen minutes is the ceiling an unattended node may put between two
	// attempts at one responsibility, not a target: the growth starts at
	// RetryDelay and most failures clear long before reaching it. The bound
	// exists because the alternative -- unbounded doubling -- would push a retry
	// past the task's own chain deadline and turn a recoverable outage into a
	// missed window.
	if cfg.MaxRetryDelay <= 0 {
		cfg.MaxRetryDelay = 15 * time.Minute
	}
	if cfg.MaxRetryDelay < cfg.RetryDelay {
		cfg.MaxRetryDelay = cfg.RetryDelay
	}
	if cfg.MaxRetryAttempts <= 0 {
		cfg.MaxRetryAttempts = 120
	}
	if cfg.MaxSessionAdmissions <= 0 {
		cfg.MaxSessionAdmissions = 4096
	}
	if cfg.VerifyExecutor == nil && cfg.Model != nil && cfg.LocalVerifierAddress != "" {
		cfg.VerifyExecutor = newProductionVerifyExecutor(cfg)
	}
	runner := &TaskRunner{
		cfg:             cfg,
		wakeup:          make(chan struct{}, 1),
		sessions:        make(map[string]sessionAdmission),
		recoveryChecked: make(map[codec.Hash]struct{}),
		chainWaits:      make(map[string]uint64),

		handraiseRedrives: make(map[string]*verifierHandraiseRedrive),
		orderRedrives:     make(map[string]*workerOrderRedrive),
	}
	if runner.cfg.InferExecutor == nil && cfg.Model != nil && cfg.LocalWorkerAddress != "" {
		runner.cfg.InferExecutor = newProductionInferExecutor(cfg, runner.persistInferCheckpoint)
	}
	return runner
}

func (r *TaskRunner) Wake() {
	if r != nil {
		select {
		case r.wakeup <- struct{}{}:
		default:
		}
	}
}

func (r *TaskRunner) ActiveTasks() (map[codec.Hash]store.InferTask, map[codec.Hash]store.VerifyTask) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return copyInfer(r.infer), copyVerify(r.verify)
}

func (r *TaskRunner) ListActiveTasks(ctx context.Context) ([]ActiveTaskRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	inferHashes, inferRecords, err := layout.ListInferRecords(ctx, r.cfg.Store)
	if err != nil {
		return nil, err
	}
	verifyHashes, verifyRecords, err := layout.ListVerifyRecords(ctx, r.cfg.Store)
	if err != nil {
		return nil, err
	}
	rows := make([]ActiveTaskRecord, 0, len(inferRecords)+len(verifyRecords))
	for i, task := range inferRecords {
		rows = append(rows, ActiveTaskRecord{QueueID: "infer:" + hex.EncodeToString(inferHashes[i][:]), TaskID: task.TaskID, Role: "worker", Stage: "infer", Status: string(task.Stage), RetryCount: task.RetryCount, RetryAtUnixMilli: task.RetryAtUnixMilli, DueHeight: task.DeadlineHeight, LastError: task.LastError, AutoHalted: task.AutoHalted, HaltCode: task.HaltCode, HaltReason: task.HaltReason})
	}
	for i, task := range verifyRecords {
		rows = append(rows, ActiveTaskRecord{QueueID: "verify:" + hex.EncodeToString(verifyHashes[i][:]), TaskID: task.TaskID, Role: "verifier", Stage: "verify", Status: string(task.Stage), RetryCount: task.RetryCount, RetryAtUnixMilli: task.RetryAtUnixMilli, DueHeight: task.DeadlineHeight, LastError: task.LastError, AutoHalted: task.AutoHalted, HaltCode: task.HaltCode, HaltReason: task.HaltReason})
	}
	slices.SortFunc(rows, func(a, b ActiveTaskRecord) int { return strings.Compare(a.QueueID, b.QueueID) })
	return rows, nil
}

func (r *TaskRunner) RequeueActiveTask(ctx context.Context, queueID, reason string, retryAt time.Time) (ActiveTaskRecord, error) {
	parts := strings.SplitN(queueID, ":", 2)
	if len(parts) != 2 {
		return ActiveTaskRecord{}, fmt.Errorf("task queue %q does not exist", queueID)
	}
	raw, err := hex.DecodeString(parts[1])
	if err != nil || len(raw) != 32 {
		return ActiveTaskRecord{}, fmt.Errorf("task queue %q does not exist", queueID)
	}
	var hash codec.Hash
	copy(hash[:], raw)
	r.mu.Lock()
	defer r.mu.Unlock()
	switch parts[0] {
	case "infer":
		record, err := layout.GetInferRecord(ctx, r.cfg.Store, layout.StoredHash(hash))
		if err != nil {
			return ActiveTaskRecord{}, err
		}
		if record.Stage != layout.StageFailed {
			return ActiveTaskRecord{}, fmt.Errorf("task queue %q does not exist or is not failed", queueID)
		}
		// The operator asking for this responsibility to run again IS the act
		// that may release an auto-halt, and it is the only one. It happens
		// before the merge because mergeAutoHalt cannot express a clear -- that
		// is what stops a replayed Keeper assignment from doing it silently.
		if err := layout.ClearInferAutoHalt(ctx, r.cfg.Store, layout.StoredHash(hash)); err != nil {
			return ActiveTaskRecord{}, err
		}
		record.AutoHalt = layout.AutoHalt{}
		record.Stage = layout.StageQueued
		record.RetryCount = 0
		record.RetryAtUnixMilli = retryAt.UnixMilli()
		record.LastError = reason
		if err := layout.MergeInfer(ctx, r.cfg.Store, layout.StoredHash(hash), record); err != nil {
			return ActiveTaskRecord{}, err
		}
		r.Wake()
		return ActiveTaskRecord{QueueID: queueID, TaskID: record.TaskID, Role: "worker", Stage: "infer", Status: string(record.Stage), RetryAtUnixMilli: record.RetryAtUnixMilli, DueHeight: record.DeadlineHeight, LastError: record.LastError}, nil
	case "verify":
		record, err := layout.GetVerifyRecord(ctx, r.cfg.Store, layout.StoredHash(hash))
		if err != nil {
			return ActiveTaskRecord{}, err
		}
		if record.Stage != layout.StageFailed {
			return ActiveTaskRecord{}, fmt.Errorf("task queue %q does not exist or is not failed", queueID)
		}
		if err := layout.ClearVerifyAutoHalt(ctx, r.cfg.Store, layout.StoredHash(hash)); err != nil {
			return ActiveTaskRecord{}, err
		}
		record.AutoHalt = layout.AutoHalt{}
		record.Stage = layout.StageQueued
		record.RetryCount = 0
		record.RetryAtUnixMilli = retryAt.UnixMilli()
		record.LastError = reason
		if err := layout.MergeVerify(ctx, r.cfg.Store, layout.StoredHash(hash), record); err != nil {
			return ActiveTaskRecord{}, err
		}
		r.Wake()
		return ActiveTaskRecord{QueueID: queueID, TaskID: record.TaskID, Role: "verifier", Stage: "verify", Status: string(record.Stage), RetryAtUnixMilli: record.RetryAtUnixMilli, DueHeight: record.DeadlineHeight, LastError: record.LastError}, nil
	default:
		return ActiveTaskRecord{}, fmt.Errorf("task queue %q does not exist", queueID)
	}
}

func (r *TaskRunner) Run(ctx context.Context) error {
	for {
		if err := r.RunOnce(ctx); err != nil {
			return err
		}
		timer := time.NewTimer(r.cfg.PollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-r.wakeup:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
		}
	}
}
