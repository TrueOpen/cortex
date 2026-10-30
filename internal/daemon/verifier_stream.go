package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/store"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
)

// VerifierStreamChain is the chain read the binding check needs.
type VerifierStreamChain interface {
	CommittedCurrentServiceKey(ctx context.Context, participantType, operatorAddress string) (chainclient.ServiceKeySnapshot, uint64, error)
}

type VerifierStreamConfig struct {
	ChainID string
	Chain   VerifierStreamChain
	Store   *store.Store
	// Assignment applies a VerifierAssignmentNotifyV1: TaskRunner.recordVerifierAssignment.
	Assignment func(context.Context, *nexusv1.VerifierAssignmentNotifyV1) error
	// Wake nudges the poll loop after a fresh OPEN_VERIFY: TaskRunner.Wake.
	Wake   func()
	Logger *slog.Logger
}

// ErrBuilderMessageBinding marks an OPEN_VERIFY or VERIFIER_ASSIGNMENT_NOTIFY
// whose signed BuilderMessageBindingV1 does not name this chain, the stream's
// Builder and that Builder's current service_authorization_nonce (wire
// PHASE1_CONTRACT, Builder objective evidence). Permanent: acked and dropped.
var ErrBuilderMessageBinding = errors.New("BuilderMessageBindingV1 rejected")

// maxAppliedAssignments bounds the in-process assignment dedup set.
const maxAppliedAssignments = 4096

// VerifierStream is the dispatchstream Handler for the two Verifier variants.
// The session already checked builder_service_signature against the Builder's
// current key; this owns the binding and the business-key dedup. It never
// returns Retryable for a chain wait: that would drop the whole stream.
type VerifierStream struct {
	cfg     VerifierStreamConfig
	inbox   verifierInbox
	mu      sync.Mutex
	applied map[string]struct{}
}

func NewVerifierStream(cfg VerifierStreamConfig) (*VerifierStream, error) {
	switch {
	case cfg.ChainID == "":
		return nil, fmt.Errorf("verifier stream: chain id is required")
	case cfg.Chain == nil:
		return nil, fmt.Errorf("verifier stream: Builder key reader is required")
	case cfg.Store == nil:
		return nil, fmt.Errorf("verifier stream: store is required")
	case cfg.Assignment == nil:
		return nil, fmt.Errorf("verifier stream: assignment handler is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	cfg.Logger = cfg.Logger.With("component", "verifier-stream")
	return &VerifierStream{cfg: cfg, inbox: verifierInbox{st: cfg.Store}, applied: map[string]struct{}{}}, nil
}

func (s *VerifierStream) HandleFrame(ctx context.Context, from string, f *nexusv1.DispatchStreamFrameV1) error {
	switch {
	case f.GetOpenVerify() != nil:
		return s.openVerify(ctx, from, f.GetOpenVerify())
	case f.GetVerifierAssignment() != nil:
		return s.assignment(ctx, from, f.GetVerifierAssignment())
	}
	return fmt.Errorf("verifier stream: frame variant is not a Verifier message")
}

func (s *VerifierStream) checkBinding(ctx context.Context, from string, b *nexusv1.BuilderMessageBindingV1) error {
	switch {
	case b == nil:
		return fmt.Errorf("%w: binding is missing", ErrBuilderMessageBinding)
	case b.GetChainId() != s.cfg.ChainID:
		return fmt.Errorf("%w: chain_id %q, want %q", ErrBuilderMessageBinding, b.GetChainId(), s.cfg.ChainID)
	case b.GetBuilderAddress() != from:
		return fmt.Errorf("%w: builder_address %s on the stream bound to %s", ErrBuilderMessageBinding, b.GetBuilderAddress(), from)
	}
	key, _, err := s.cfg.Chain.CommittedCurrentServiceKey(ctx, chainclient.ParticipantTypeBuilder, from)
	if errors.Is(err, chainclient.ErrNotFound) {
		return fmt.Errorf("%w: Builder %s has no current service key", ErrBuilderMessageBinding, from)
	}
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("Builder %s current service key: %w", from, err))
	}
	if key.Status != "ACTIVE" {
		return fmt.Errorf("%w: Builder %s service key is %s; it authorizes no live traffic", ErrBuilderMessageBinding, from, key.Status)
	}
	if b.GetServiceAuthorizationNonce() != key.AuthorizationNonce.Uint64() {
		return fmt.Errorf("%w: service_authorization_nonce %d, Builder %s current is %d",
			ErrBuilderMessageBinding, b.GetServiceAuthorizationNonce(), from, key.AuthorizationNonce.Uint64())
	}
	return nil
}

func (s *VerifierStream) openVerify(ctx context.Context, from string, m *nexusv1.OpenVerifyV1) error {
	if err := s.checkBinding(ctx, from, m.GetBinding()); err != nil {
		return err
	}
	trigger, err := openVerifyTrigger(from, m)
	if err != nil {
		return err
	}
	fresh, err := s.inbox.admit(ctx, from, trigger)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("record OPEN_VERIFY for %s round %d: %w", trigger.TaskID, trigger.VerifyRound, err))
	}
	if fresh && s.cfg.Wake != nil {
		s.cfg.Wake()
	}
	return nil
}

// assignment applies a VERIFIER_ASSIGNMENT_NOTIFY once per (task_id, round)
// per process. It is a wake-up hint only (CD §6.2 V7): the Keeper effect
// writes the duty, and applying it again is idempotent, so the dedup is not
// persisted and a "not yet" is acked rather than allowed to hold the stream.
func (s *VerifierStream) assignment(ctx context.Context, from string, m *nexusv1.VerifierAssignmentNotifyV1) error {
	if err := s.checkBinding(ctx, from, m.GetBinding()); err != nil {
		return err
	}
	taskID, err := taskIDHex(m.GetTaskId())
	if err != nil {
		return fmt.Errorf("VerifierAssignmentNotify: %w", err)
	}
	if m.GetVerifyRound() == 0 {
		return fmt.Errorf("VerifierAssignmentNotify verify_round 0 is invalid")
	}
	key := chainWaitKey(taskID, m.GetVerifyRound())
	s.mu.Lock()
	_, done := s.applied[key]
	s.mu.Unlock()
	if done {
		return nil
	}
	err = s.cfg.Assignment(ctx, m)
	switch {
	case err == nil:
		s.mu.Lock()
		if len(s.applied) >= maxAppliedAssignments {
			clear(s.applied)
		}
		s.applied[key] = struct{}{}
		s.mu.Unlock()
		return nil
	case builderclient.IsRetryable(err) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		s.cfg.Logger.Info("verifier assignment notice not applied yet; the Keeper effect remains the authority",
			"task", taskID, "round", m.GetVerifyRound(), "err", err)
		return nil
	}
	return err
}
