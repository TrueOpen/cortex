package outbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/SingaXYZ/cortex/internal/builderclient"
)

type InboxRunnerConfig struct {
	ModelIDs []string
	TaskIDs  []string
	AllTasks bool
	// Process authenticates, validates, admits, and acts on the exact received
	// frame. Returning a retryable error leaves the source message unacknowledged.
	Process func(context.Context, builderclient.NATSMessage) error
	// Refuse is called when a permanent Process error is acknowledged rather
	// than returned. Returning nil from the handler is what makes JetStream
	// Ack; the error still has to leave the process or the refusal is silent.
	Refuse func(error)
	// OnCompletion reports successfully processed and deduplicated deliveries.
	// It runs before the subscriber performs any JetStream acknowledgement.
	OnCompletion func(InboxMessageCompletion)
}

const (
	// InboxMessageResultProcessed means the delivery completed the configured processor.
	InboxMessageResultProcessed = "processed"
	// InboxMessageResultDeduplicated means an earlier identical delivery completed.
	InboxMessageResultDeduplicated = "deduplicated"
)

// InboxMessageCompletion contains safe correlation metadata for a successful delivery.
type InboxMessageCompletion struct {
	Subject, TaskID, MessageID string
	Kind                       builderclient.BusMessageKind
	JetStream                  bool
	SizeBytes                  int
	Result                     string
	Duration                   time.Duration
}

type InboxRunner struct {
	subscriber builderclient.Subscriber
	cfg        InboxRunnerConfig
	mu         sync.Mutex
	admission  map[string]admissionEntry
}

type admissionState uint8
type admissionEntry struct {
	state     admissionState
	expiresAt time.Time
}

const (
	admissionProcessing admissionState = iota + 1
	admissionProcessed
	admissionRefused
)

func NewInboxRunner(subscriber builderclient.Subscriber, cfg InboxRunnerConfig) *InboxRunner {
	return &InboxRunner{subscriber: subscriber, cfg: cfg, admission: make(map[string]admissionEntry)}
}

func InboxSubjects(cfg InboxRunnerConfig) []string {
	var subjects []string
	for _, modelID := range cfg.ModelIDs {
		if strings.TrimSpace(modelID) != "" {
			subjects = append(subjects, builderclient.NATSTaskOpenSubject(modelID))
		}
	}
	if cfg.AllTasks {
		subjects = appendRoleSubjects(subjects, "*")
	}
	for _, taskID := range cfg.TaskIDs {
		if strings.TrimSpace(taskID) != "" {
			subjects = appendRoleSubjects(subjects, taskID)
		}
	}
	return subjects
}

func (r *InboxRunner) Start(ctx context.Context) ([]builderclient.Subscription, error) {
	if r.subscriber == nil {
		return nil, fmt.Errorf("nexus subscriber is required")
	}
	if r.cfg.Process == nil {
		return nil, fmt.Errorf("inbox processing hook is required")
	}
	subjects := InboxSubjects(r.cfg)

	subscriptions := make([]builderclient.Subscription, 0, len(subjects))
	for _, subject := range subjects {
		sub, err := r.subscriber.Subscribe(ctx, subject, r.processMessage)
		if err != nil {
			for _, established := range subscriptions {
				if releaseErr := established.Unsubscribe(); releaseErr != nil {
					err = fmt.Errorf("%w (releasing an established subscription also failed: %v)", err, releaseErr)
				}
			}
			return nil, err
		}
		subscriptions = append(subscriptions, sub)
	}
	return subscriptions, nil
}

func (r *InboxRunner) processMessage(ctx context.Context, msg builderclient.NATSMessage) error {
	started := time.Now()
	digest := builderInboxDigest(msg)
	expiresAt := time.Now().UTC().Add(time.Minute)
	completion := InboxMessageCompletion{
		Subject:   strings.TrimSpace(msg.Subject),
		JetStream: msg.JetStream,
		SizeBytes: len(msg.Data),
	}
	if envelope, err := builderclient.DecodeBusEnvelope(msg.Data); err == nil {
		if envelope.ExpiresAtUnixMs > 0 {
			expiresAt = time.UnixMilli(envelope.ExpiresAtUnixMs).UTC()
		}
		completion.Kind = envelope.Kind
		completion.MessageID = envelope.MessageID
	}
	r.mu.Lock()
	now := time.Now().UTC()
	for key, existing := range r.admission {
		if now.After(existing.expiresAt) {
			delete(r.admission, key)
		}
	}
	entry := r.admission[digest]
	if entry.state == 0 {
		r.admission[digest] = admissionEntry{state: admissionProcessing, expiresAt: expiresAt}
	}
	r.mu.Unlock()
	if entry.state == admissionProcessed {
		r.reportCompletion(completion, InboxMessageResultDeduplicated, started)
		return nil
	}
	if entry.state == admissionRefused {
		return nil
	}
	if entry.state == admissionProcessing {
		return builderclient.Retryable(fmt.Errorf("Builder frame is already processing"))
	}
	err := r.cfg.Process(ctx, builderclient.NATSMessage{Subject: msg.Subject, Data: append([]byte(nil), msg.Data...), JetStream: msg.JetStream})
	if err != nil {
		if ctx.Err() != nil {
			r.mu.Lock()
			delete(r.admission, digest)
			r.mu.Unlock()
			return ctx.Err()
		}
		// verifierFrame redelivers by subject, not by verdict, so on its own it
		// would NAK a refusal that can never succeed. An asserted permanent
		// verdict therefore outranks it: the frame is acknowledged and reported
		// below instead of being redelivered until the stream gives up.
		if !builderclient.IsPermanent(err) &&
			(builderclient.IsRetryable(err) || errors.Is(err, builderclient.ErrBusEnvelopeAuthenticationUnavailable) || verifierFrame(msg.Subject)) {
			r.mu.Lock()
			delete(r.admission, digest)
			r.mu.Unlock()
			return err
		}
		// Permanent authentication/schema/admission refusal is acknowledged and
		// remembered in memory only; it must never become a durable audit row.
		// The handler still returns nil so JetStream Acks instead of NAKing
		// forever. Refuse is the only trace that the frame existed.
		r.mu.Lock()
		r.admission[digest] = admissionEntry{state: admissionRefused, expiresAt: expiresAt}
		r.mu.Unlock()
		if r.cfg.Refuse != nil {
			r.cfg.Refuse(fmt.Errorf("Nexus inbox refused %s: %w", strings.TrimSpace(msg.Subject), err))
		}
		return nil
	}

	r.mu.Lock()
	r.admission[digest] = admissionEntry{state: admissionProcessed, expiresAt: expiresAt}
	r.mu.Unlock()
	r.reportCompletion(completion, InboxMessageResultProcessed, started)
	return nil
}

func (r *InboxRunner) reportCompletion(completion InboxMessageCompletion, result string, started time.Time) {
	if r.cfg.OnCompletion == nil {
		return
	}
	completion.Result = result
	completion.Duration = time.Since(started)
	r.cfg.OnCompletion(completion)
}

// verifierFrame names the verifier-side subjects whose transient failures are
// worth a redelivery. Only the JetStream-tier ones qualify: OPEN_VERIFY is Core
// (§5.1) and has no redelivery, so claiming it here would promise something the
// transport cannot do.
func verifierFrame(subject string) bool {
	kind, _, ok := builderclient.KindForSubject(strings.TrimSpace(subject))
	return ok && (kind == builderclient.KindOutputAvailable || kind == builderclient.KindVerifierAssignmentNotify)
}

func builderInboxDigest(msg builderclient.NATSMessage) string {
	sum := sha256.Sum256(append([]byte(strings.TrimSpace(msg.Subject)+"\x00"), msg.Data...))
	return hex.EncodeToString(sum[:])
}

// appendRoleSubjects derives the inbound subject set for a task
// (interface-and-topic-list.md §5.1, §5.3). It is no longer conditional: duty selection
// is retired, so every node subscribes to both the Worker and the Verifier
// subjects. Being drawn for both roles on the same task is not a hazard the
// subscription set has to prevent -- the chain excludes the winning Worker from
// that task's Verifier candidates.
//
// What used to be one verifier subject is now two with different jobs:
// trueopen.verify.open.* is the Core-tier call that opens the handraise window and
// goes to Verifier candidates only, and trueopen.verifier-assignment.* is the
// JetStream-tier notice that the chain finalized the selected Verifier set,
// which §5.9 addresses to the winner Worker as well as the selected Verifiers.
// Both are needed on a Verifier - a node that subscribes only to the second
// never raises its hand, so it can never be named by it.
//
// trueopen.sample-ready.* is gone with SAMPLE_READY_NOTIFY (§5.9).
func appendRoleSubjects(subjects []string, taskID string) []string {
	return append(subjects,
		builderclient.NATSWorkerAssignmentSubject(taskID),
		builderclient.NATSOutputAvailableSubject(taskID),
		builderclient.NATSVerifyOpenSubject(taskID),
		builderclient.NATSVerifierAssignmentSubject(taskID))
}

func (r *InboxRunner) DrainErrors(ctx context.Context, report func(error)) error {
	if r == nil || report == nil {
		return nil
	}
	source, ok := r.subscriber.(builderclient.SubscriberErrors)
	if !ok {
		<-ctx.Done()
		return nil
	}
	errs := source.Errors()
	if errs == nil {
		<-ctx.Done()
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case err, open := <-errs:
			if !open {
				<-ctx.Done()
				return nil
			}
			if err != nil {
				report(err)
			}
			if droppedSource, ok := source.(builderclient.SubscriberDroppedErrors); ok {
				if dropped := droppedSource.TakeDroppedErrors(); dropped > 0 {
					report(fmt.Errorf("nats subscriber dropped %d error reports while its buffer was full", dropped))
				}
			}
		}
	}
}
