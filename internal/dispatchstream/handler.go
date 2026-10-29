package dispatchstream

import (
	"context"

	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
)

// Handler receives authenticated business frames.
//
// Delivery is at least once: a frame is recorded "received" before the
// Handler runs and "done" after, and only "done" suppresses a replay. A crash
// between the two, or a replay after DedupRetention, delivers the same signed
// message again, so Handlers MUST be idempotent per message (keyed by the
// ticket hash, task hash or similar).
//
// Errors:
//   - builderclient.Retryable(err), context.Canceled or
//     context.DeadlineExceeded: the frame is not acked; the session drops the
//     connection and the Builder redelivers it.
//   - Any other error, including an UNMARKED one: treated as permanent. It is
//     logged, the frame is marked done and acked, and it is never delivered
//     again. Transient failures MUST therefore be wrapped with
//     builderclient.Retryable, or the message is dropped.
//
// Latency: the session's single loop is blocked while a Handler runs, so a
// Handler must return within Config.HandlerTimeout (below the keepalive
// liveness window). It runs under a context with that deadline; exceeding it
// counts as retryable. Long work belongs on the Handler's own goroutines
// after durably recording what it needs.
//
// The session checks only the frame's own builder_service_signature. Handlers
// own the content checks: the BuilderMessageBindingV1 fields of open_verify
// and verifier_assignment (chain_id, builder_address, service authorization
// nonce), and the ticket / handraise root + inclusion proof checks for offer
// and handraise_root, whose outer messages are not themselves signed.
type Handler interface {
	HandleFrame(ctx context.Context, from string /*builder operator*/, frame *nexusv1.DispatchStreamFrameV1) error
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, from string, frame *nexusv1.DispatchStreamFrameV1) error

func (f HandlerFunc) HandleFrame(ctx context.Context, from string, frame *nexusv1.DispatchStreamFrameV1) error {
	return f(ctx, from, frame)
}
