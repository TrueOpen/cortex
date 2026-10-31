package dispatchwire

import (
	"context"
	"fmt"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// DigestSigner signs a 32-byte digest with the Cortex current service key and
// returns the raw64 low-S signature. The daemon adapts internal/signer to it.
type DigestSigner func(context.Context, [32]byte) ([]byte, error)

// sign clears the signature field, takes the projection digest and stores the
// signer's raw64 result. On any failure the field is left empty, never stale.
func sign(ctx context.Context, msg proto.Message, s DigestSigner, set func([]byte)) error {
	set(nil)
	if s == nil {
		return fmt.Errorf("sign %s: no signer", Name(msg))
	}
	d, err := Digest(msg)
	if err != nil {
		return err
	}
	sig, err := s(ctx, d)
	if err != nil {
		return fmt.Errorf("sign %s: %w", Name(msg), err)
	}
	if len(sig) != dispatch.SignatureSize {
		return fmt.Errorf("sign %s: signature is %d bytes, want raw%d", Name(msg), len(sig), dispatch.SignatureSize)
	}
	set(sig)
	return nil
}

// SignBinding signs the per-connection DispatchStreamBindingV1.
func SignBinding(ctx context.Context, m *nexusv1.DispatchStreamBindingV1, s DigestSigner) error {
	return sign(ctx, m, s, func(b []byte) { m.ServiceSignature = b })
}

// SignStandingHandraise signs a standing handraise for one Builder.
func SignStandingHandraise(ctx context.Context, m *taskv1.StandingHandraiseV1, s DigestSigner) error {
	return sign(ctx, m, s, func(b []byte) { m.ServiceSignature = b })
}

// SignAccept signs a DispatchAcceptV1; its Digest is dispatch_accept_digest.
func SignAccept(ctx context.Context, m *taskv1.DispatchAcceptV1, s DigestSigner) error {
	return sign(ctx, m, s, func(b []byte) { m.ServiceSignature = b })
}

// SignReject signs a DispatchRejectV1.
func SignReject(ctx context.Context, m *taskv1.DispatchRejectV1, s DigestSigner) error {
	return sign(ctx, m, s, func(b []byte) { m.ServiceSignature = b })
}

// SignInputRequest signs a DispatchInputRequestV1.
func SignInputRequest(ctx context.Context, m *nexusv1.DispatchInputRequestV1, s DigestSigner) error {
	return sign(ctx, m, s, func(b []byte) { m.ServiceSignature = b })
}

// signVerifierHandraise signs a VerifierHandraiseV1. Production signs the
// Verifier handraise on the task runner path; this covers the projection in
// the signing vectors only.
func signVerifierHandraise(ctx context.Context, m *taskv1.VerifierHandraiseV1, s DigestSigner) error {
	return sign(ctx, m, s, func(b []byte) { m.ServiceSignature = b })
}

// SignVerifyResultSubmitted signs a VerifyResultSubmittedNoticeV1.
func SignVerifyResultSubmitted(ctx context.Context, m *nexusv1.VerifyResultSubmittedNoticeV1, s DigestSigner) error {
	return sign(ctx, m, s, func(b []byte) { m.ServiceSignature = b })
}

// SignRosterRequest signs a DispatchRosterRequestV1; chain_id and
// builder_operator are inside the signature (PHASE1_CONTRACT).
func SignRosterRequest(ctx context.Context, m *nexusv1.DispatchRosterRequestV1, s DigestSigner) error {
	return sign(ctx, m, s, func(b []byte) { m.ServiceSignature = b })
}
