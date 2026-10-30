package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/dispatchstream"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// ErrNoStreamAccepted means not one Builder session durably accepted a
// Verifier message. It is left unmarked, so the Verifier wraps it Retryable.
var ErrNoStreamAccepted = errors.New("no Builder stream accepted the verifier message")

// StreamFanout is the Verifier's FrameSender and NoticeSender on the Phase 1
// direct stream: every Verifier message goes to every configured Builder's
// DispatchStream (CD §6.2 V6, V12, V15). Each Session's outbox makes its copy
// durable and replays it across reconnects until acked or expired.
//
// Success is "at least one Session enqueued it": any Task Builder holding the
// handraise may put it in a proposal (V6). A partial failure is logged and not
// retried here; the Builder that missed it is not owed a second copy.
type StreamFanout struct {
	builders []string
	sessions map[string]HandraiseEnqueuer
	logger   *slog.Logger
}

func NewStreamFanout(sessions map[string]HandraiseEnqueuer, logger *slog.Logger) (*StreamFanout, error) {
	if len(sessions) == 0 {
		return nil, fmt.Errorf("verifier stream fan-out needs at least one Builder session")
	}
	builders := make([]string, 0, len(sessions))
	for builder, session := range sessions {
		if builder == "" || session == nil {
			return nil, fmt.Errorf("verifier stream fan-out: Builder %q has no session", builder)
		}
		builders = append(builders, builder)
	}
	sort.Strings(builders)
	if logger == nil {
		logger = slog.Default()
	}
	return &StreamFanout{builders: builders, sessions: sessions, logger: logger.With("component", "verifier-fanout")}, nil
}

// SendVerifierHandraise queues the handraise bounded by its own expiry_height.
func (f *StreamFanout) SendVerifierHandraise(ctx context.Context, h *taskv1.VerifierHandraiseV1) error {
	if h.GetExpiryHeight() == 0 {
		return builderclient.Permanent(fmt.Errorf("VerifierHandraiseV1 without expiry_height cannot be queued"))
	}
	return f.fanout(ctx, dispatchstream.Outgoing{Message: h, ExpiryHeight: h.GetExpiryHeight()})
}

// SendVerifyResultSubmitted queues one VerifyResultSubmittedNoticeV1. The
// notice carries no expiry of its own; the caller bounds it by the deadline
// of the phase it reports.
func (f *StreamFanout) SendVerifyResultSubmitted(ctx context.Context, n *nexusv1.VerifyResultSubmittedNoticeV1, expiryHeight uint64) error {
	if expiryHeight == 0 {
		return builderclient.Permanent(fmt.Errorf("VerifyResultSubmittedNoticeV1 needs an expiry height to be queued"))
	}
	return f.fanout(ctx, dispatchstream.Outgoing{Message: n, ExpiryHeight: expiryHeight})
}

func (f *StreamFanout) fanout(ctx context.Context, out dispatchstream.Outgoing) error {
	var failed []error
	invalid := false
	for _, builder := range f.builders {
		if _, err := f.sessions[builder].Enqueue(ctx, out); err != nil {
			failed = append(failed, fmt.Errorf("Builder %s: %w", builder, err))
			invalid = invalid || errors.Is(err, dispatchstream.ErrInvalidOutgoing)
		}
	}
	switch {
	case len(failed) == 0:
		return nil
	case len(failed) < len(f.builders):
		f.logger.Warn("verifier message queued on some Builder streams only",
			"failed", len(failed), "builders", len(f.builders), "err", errors.Join(failed...))
		return nil
	case invalid:
		// The session refused the message itself: no retry can queue it.
		return builderclient.Permanent(fmt.Errorf("%w: %w", ErrNoStreamAccepted, errors.Join(failed...)))
	}
	return fmt.Errorf("%w: %w", ErrNoStreamAccepted, errors.Join(failed...))
}
