package builderclient

import (
	"context"
	"strings"
	"time"
)

const (
	// PublishResultPublished means the transport accepted the frame.
	PublishResultPublished = "published"
	// PublishResultFailed means the transport refused it. The error is reported
	// alongside; it is also returned to the caller unchanged.
	PublishResultFailed = "failed"
)

// PublishCompletion is the outbound counterpart of
// outbox.InboxMessageCompletion: safe correlation metadata for one attempted bus
// publish. Every field is either the caller's own request or read out of the
// frame this node built, so nothing here is peer-controlled.
type PublishCompletion struct {
	Subject, TaskID, MessageID, DedupID string
	Kind                                BusMessageKind
	JetStream                           bool
	SizeBytes                           int
	Result                              string
	// Err is the error the transport returned, unwrapped by nobody: the caller
	// receives the same value, so the retry classification a reporter sees is
	// the one that decides redelivery.
	Err      error
	Duration time.Duration
}

// NewObservedPublisher reports every publish attempt to onCompletion. A
// successful publish is otherwise silent, which leaves "did this node send the
// handraise" answerable only by elimination from the failure logs.
//
// It returns the publisher unchanged when there is nothing to report to, because
// the value is type-asserted elsewhere for its optional Probe and Close methods
// (nexusReadinessProbe and runtimeClosers in internal/daemon) and a decorator
// would hide them. For the same reason this seam is applied only where the
// Builder client is built, never to the publisher the runtime keeps for
// readiness and shutdown.
func NewObservedPublisher(publisher Publisher, onCompletion func(PublishCompletion)) Publisher {
	if publisher == nil || onCompletion == nil {
		return publisher
	}
	return observedPublisher{publisher: publisher, onCompletion: onCompletion}
}

type observedPublisher struct {
	publisher    Publisher
	onCompletion func(PublishCompletion)
}

func (p observedPublisher) Publish(ctx context.Context, req PublishRequest) error {
	started := time.Now()
	err := p.publisher.Publish(ctx, req)
	completion := PublishCompletion{
		Subject:   strings.TrimSpace(req.Subject),
		TaskID:    strings.TrimSpace(req.TaskID),
		DedupID:   strings.TrimSpace(req.DedupID),
		JetStream: isJetStreamSubject(req.Subject),
		SizeBytes: len(req.Payload),
		Result:    PublishResultPublished,
		Err:       err,
		Duration:  time.Since(started),
	}
	if err != nil {
		completion.Result = PublishResultFailed
	}
	// Best-effort, exactly as the inbox reads an arriving frame: the payload is
	// a §5.2 envelope for every contract subject, and the subject table is the
	// fallback for the frames that are not one.
	if envelope, decodeErr := DecodeBusEnvelope(req.Payload); decodeErr == nil {
		completion.Kind = envelope.Kind
		completion.MessageID = envelope.MessageID
	} else if kind, _, ok := KindForSubject(req.Subject); ok {
		completion.Kind = kind
	}
	p.onCompletion(completion)
	return err
}
