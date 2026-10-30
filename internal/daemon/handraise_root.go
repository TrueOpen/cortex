package daemon

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
)

// ErrRootForeignHandraise: the proven leaf carries a standing handraise this
// node never sent to that Builder. dispatchwire.VerifyInclusion leaves this
// check to the caller.
var ErrRootForeignHandraise = errors.New("handraise root: leaf is not a handraise this node sent to that Builder")

// Alert kinds.
const (
	AlertHandraiseNotAdmitted      = "handraise_not_admitted"
	AlertHandraiseRootEquivocation = "handraise_root_equivocation"
)

// HandraiseAlert is raised when this node's leaf turns admitted=false (CD
// §4.2.0: RTT_OVER_THRESHOLD / REJECT_RATE / INVALID_HANDRAISE /
// SERVICE_KEY_ROTATION_PENDING each need an operator), or when a Builder signs
// two roots at the same (root_height, root_version).
type HandraiseAlert struct {
	Kind    string
	Builder string
	Root    HeldRoot
}

// HandleRootNotice applies one HandraiseRootNoticeV1 from builder, the
// stream's authenticated peer. It is idempotent per root digest, as the
// at-least-once Handler contract requires. Failed reads and writes are
// builderclient.Retryable; everything else is permanent.
func (h *StandingHandraiser) HandleRootNotice(ctx context.Context, builder string, n *nexusv1.HandraiseRootNoticeV1) error {
	if _, ok := h.cfg.Builders[builder]; !ok {
		return fmt.Errorf("handraise root from unconfigured Builder %s", builder)
	}
	key, _, err := h.cfg.Chain.CommittedCurrentServiceKey(ctx, chainclient.ParticipantTypeBuilder, builder)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("Builder %s current service key: %w", builder, err))
	}
	if key.Status != "ACTIVE" {
		return fmt.Errorf("Builder %s service key is %s; its roots authorize nothing", builder, key.Status)
	}
	pub, err := hex.DecodeString(key.ServicePubkey)
	if err != nil {
		return fmt.Errorf("Builder %s service key: %w", builder, err)
	}
	inc, err := dispatchwire.VerifyInclusion(n.GetRoot(), n.GetProof(), dispatchwire.InclusionContext{
		ChainID: h.cfg.ChainID, BuilderOperator: builder, BuilderPubKey: pub,
	})
	if err != nil {
		return fmt.Errorf("handraise root from %s: %w", builder, err)
	}
	sent, err := h.db.hasSent(ctx, builder, inc.StandingDigest)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("read handraise send log: %w", err))
	}
	if !sent {
		return fmt.Errorf("%w (Builder %s, standing digest %x)", ErrRootForeignHandraise, builder, inc.StandingDigest)
	}
	height, err := h.cfg.Chain.CommittedHeight(ctx)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("committed height: %w", err))
	}
	raw, err := dispatchwire.Raw(n)
	if err != nil {
		return err
	}
	r := HeldRoot{
		Builder: builder, RootDigest: inc.RootDigest, StandingDigest: inc.StandingDigest,
		RootHeight: n.GetRoot().GetRootHeight(), RootVersion: n.GetRoot().GetRootVersion(),
		Admitted: inc.Admitted, Reason: inc.Reason, RTTMillis: inc.RTTMillis,
		ReceivedHeight: height, ReceivedAtUnixMs: h.cfg.Now().UnixMilli(), Notice: raw,
	}
	held, _, err := h.db.putRoot(ctx, r, h.cfg.RetentionBlocks)
	if err != nil {
		return builderclient.Retryable(fmt.Errorf("persist handraise root: %w", err))
	}
	// Also on a redelivery: a crash may have come between storing the root
	// and alerting on it. Both steps are idempotent; a duplicate alert is
	// acceptable, a lost one is not.
	if held.Equivocal {
		h.alert(HandraiseAlert{Kind: AlertHandraiseRootEquivocation, Builder: builder, Root: held})
	}
	h.observeAdmission(held)
	return nil
}

// observeAdmission keeps the newest root per Builder by (root_height,
// root_version) and alerts when this node's leaf turns not admitted, or
// changes reason.
func (h *StandingHandraiser) observeAdmission(r HeldRoot) {
	h.mu.Lock()
	prev, had := h.admission[r.Builder]
	newer := !had || r.RootHeight > prev.RootHeight || (r.RootHeight == prev.RootHeight && r.RootVersion > prev.RootVersion)
	if newer {
		h.admission[r.Builder] = r
	}
	h.mu.Unlock()
	if newer && !r.Admitted && (!had || prev.Admitted || prev.Reason != r.Reason) {
		h.alert(HandraiseAlert{Kind: AlertHandraiseNotAdmitted, Builder: r.Builder, Root: r})
	}
}

func (h *StandingHandraiser) alert(a HandraiseAlert) {
	h.cfg.Logger.Warn("standing handraise alert", "alert", a.Kind, "builder", a.Builder,
		"root_height", a.Root.RootHeight, "root_version", a.Root.RootVersion, "admitted", a.Root.Admitted,
		"reason", a.Root.Reason.String(), "builder_measured_rtt_ms", a.Root.RTTMillis)
	if h.cfg.Alert != nil {
		h.cfg.Alert(a)
	}
}

// HoldsRoot reports whether this node retains builder's root with this
// handraise_root_digest: any retained root, admitted=false ones included,
// not only the newest RootHistory. S4 must build
// dispatchwire.TicketContext.HeldRootDigests from it for the ticket at hand,
// {ticket.handraise_root_digest: held}, not from HeldRootDigests.
func (h *StandingHandraiser) HoldsRoot(ctx context.Context, builder string, digest [32]byte) (bool, error) {
	return h.db.holdsRoot(ctx, builder, digest)
}

// HeldRootDigests returns builder's newest RootHistory root digests, read
// from the order index alone. It is a bounded view for diagnostics; ticket
// checks use HoldsRoot.
func (h *StandingHandraiser) HeldRootDigests(ctx context.Context, builder string) (map[[32]byte]bool, error) {
	digests, err := h.db.latestRootDigests(ctx, builder, h.cfg.RootHistory)
	if err != nil {
		return nil, err
	}
	out := make(map[[32]byte]bool, len(digests))
	for _, d := range digests {
		out[d] = true
	}
	return out, nil
}

// Admission returns the newest root seen from builder since start.
func (h *StandingHandraiser) Admission(builder string) (HeldRoot, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	r, ok := h.admission[builder]
	return r, ok
}

// RootByDigest returns builder's retained root with this digest (S8).
func (h *StandingHandraiser) RootByDigest(ctx context.Context, builder string, digest [32]byte) (HeldRoot, bool, error) {
	return h.db.rootByDigest(ctx, builder, digest)
}

// RootsUpTo returns builder's retained roots with root_height <= max, newest
// first: the candidates for KC §10.17 source (b).
func (h *StandingHandraiser) RootsUpTo(ctx context.Context, builder string, maxRootHeight uint64, limit int) ([]HeldRoot, error) {
	return h.db.rootsUpTo(ctx, builder, maxRootHeight, limit)
}
