package daemon

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/config"
)

// HandraiseChainView is the chain authority the standing handraise reads.
// *chainclient.KeeperABCIClient satisfies it.
type HandraiseChainView interface {
	CommittedHeight(context.Context) (uint64, error)
	CortexNode(context.Context, string) (chainclient.CortexNodeSnapshot, error)
	ServiceBond(context.Context, string) (chainclient.ServiceBondSnapshot, error)
	CommittedCurrentServiceKey(ctx context.Context, participantType, operatorAddress string) (chainclient.ServiceKeySnapshot, uint64, error)
	CurrentCandidateMember(context.Context, string) (chainclient.CandidateMemberRefSnapshot, error)
	CommittedModelSupportScope(ctx context.Context, operatorAddress, modelID, profileVersion string) (chainclient.CommittedModelSupportScope, error)
	BuilderVrfKey(context.Context, string) (chainclient.VrfKeySnapshot, error)
}

// HandraiseLocal is the local state the gates read. S4 provides the
// lease-backed FreeSlots; S9 wires WorkloadReady to Runtime readiness and
// Draining to the operator drain controls.
type HandraiseLocal interface {
	// WorkloadReady is Runtime.CheckWorkloadReadiness(ctx).Ready(): chain sync
	// lag, identity, signer and store (CD §5.1 H1).
	WorkloadReady(context.Context) bool
	// Draining reports a node-wide drain (CD §8.4) and the profiles being
	// drained out of supported_profiles (CD §7.3).
	Draining() (node bool, profiles map[HandraiseProfile]bool)
	// FreeSlots is capacity minus accepted, not yet terminal tasks; ok=false
	// means the runtime is not ready (CD §5.1 H3).
	FreeSlots() (n uint32, ok bool)
}

// gateResult is one evaluation of the gates.
type gateResult struct {
	state     *handraiseState // nil: offer nothing
	why       string
	factual   bool   // the stop rests on chain/local facts, not on a failed read
	authNonce uint64 // current Cortex service_authorization_nonce, once read
}

type gateProfile struct {
	HandraiseProfile
	modelHex string
}

type handraiseGates struct {
	operator string
	chain    HandraiseChainView
	local    HandraiseLocal
	profiles []gateProfile // ascending
	minBid   map[string]uint64
	log      *slog.Logger
}

func newHandraiseGates(operator string, chain HandraiseChainView, local HandraiseLocal, refs []config.ModelProfileRef, minBid map[string]uint64, log *slog.Logger) (*handraiseGates, error) {
	g := &handraiseGates{operator: operator, chain: chain, local: local, minBid: minBid, log: log}
	for _, r := range refs {
		raw, err := hex.DecodeString(r.ModelID)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("standing handraise: model_id %q is not 32-byte hex", r.ModelID)
		}
		p := gateProfile{modelHex: r.ModelID}
		copy(p.ModelID[:], raw)
		p.Version = r.ProfileVersion
		g.profiles = append(g.profiles, p)
	}
	slices.SortFunc(g.profiles, func(a, b gateProfile) int { return a.compare(b.HandraiseProfile) })
	return g, nil
}

// evaluate runs CD §5.1 H1–H4 plus the service-key-rotation and drain stops.
// intervalKnown says whether an expiry_height can be computed yet.
func (g *handraiseGates) evaluate(ctx context.Context, intervalKnown bool) gateResult {
	if !g.local.WorkloadReady(ctx) {
		return gateResult{why: "H1: workload not ready"}
	}
	node, err := g.chain.CortexNode(ctx, g.operator)
	if err != nil {
		return gateResult{why: "H1: read Cortex node: " + err.Error()}
	}
	if node.OperatorAddress != g.operator || (!strings.EqualFold(node.Status, "REGISTERED") && !strings.EqualFold(node.Status, "ACTIVE")) {
		return gateResult{why: "H1: Cortex node status " + node.Status, factual: true}
	}
	bond, err := g.chain.ServiceBond(ctx, g.operator)
	if err != nil {
		return gateResult{why: "H1: read service bond: " + err.Error()}
	}
	if bond.OperatorAddress != g.operator || !bond.CandidateEligible() {
		return gateResult{why: "H1: service bond status " + bond.Status, factual: true}
	}
	key, _, err := g.chain.CommittedCurrentServiceKey(ctx, chainclient.ParticipantTypeCortexNode, g.operator)
	if err != nil {
		return gateResult{why: "H1: read service key: " + err.Error()}
	}
	if key.Status != "ACTIVE" {
		return gateResult{why: "H1: service key " + key.Status}
	}
	res := gateResult{authNonce: key.AuthorizationNonce.Uint64()}
	if key.HasPendingRotation {
		res.why, res.factual = "service key rotation pending (CD §8.4)", true
		return res
	}
	drainNode, drainProfiles := g.local.Draining()
	if drainNode {
		res.why, res.factual = "draining", true
		return res
	}
	member, err := g.chain.CurrentCandidateMember(ctx, g.operator)
	if err != nil {
		res.why = "H1: candidate member: " + err.Error()
		return res
	}
	ref, err := memberRefFrom(member, g.operator)
	if err != nil {
		res.why = "H1: " + err.Error()
		return res
	}
	if !intervalKnown {
		res.why = "block interval not observed yet"
		return res
	}
	profiles, readFailed := g.servable(ctx, bond, drainProfiles)
	if len(profiles) == 0 {
		// Only facts may close the offer (Q3): if any profile was lost to a
		// failed read, nothing is sent and the last handraise expires.
		res.why, res.factual = "H2/H4: no servable profile", !readFailed
		return res
	}
	free, ok := g.local.FreeSlots()
	if !ok {
		free = 0 // H3
	}
	res.state = &handraiseState{Member: ref, AuthNonce: res.authNonce, Profiles: profiles, FreeSlots: free}
	return res
}

// builder is the per-Builder part of H1: without a readable VRF key none of
// that Builder's tickets could be checked.
func (g *handraiseGates) builder(ctx context.Context, builder string) error {
	if _, err := g.chain.BuilderVrfKey(ctx, builder); err != nil {
		return fmt.Errorf("H1: Builder %s VRF key: %w", builder, err)
	}
	return nil
}

// servable lists the profiles H2 and H4 allow. readFailed reports a profile
// left out because its support scope could not be read (anything but
// chainclient.ErrNotFound), as opposed to a fact about it.
func (g *handraiseGates) servable(ctx context.Context, bond chainclient.ServiceBondSnapshot, draining map[HandraiseProfile]bool) (out []HandraiseProfile, readFailed bool) {
	for _, p := range g.profiles {
		if draining[p.HandraiseProfile] {
			continue
		}
		if g.minBid[config.MinPriceBidKey(p.modelHex, p.Version)] == 0 {
			g.log.Debug("profile left out of standing handraise: no min_price_bid (H4)", "model_id", p.modelHex, "profile_version", p.Version)
			continue
		}
		if err := g.support(ctx, bond, p); err != nil {
			var read errScopeRead
			readFailed = readFailed || errors.As(err, &read)
			g.log.Info("profile left out of standing handraise (H2)", "model_id", p.modelHex, "profile_version", p.Version, "err", err)
			continue
		}
		out = append(out, p.HandraiseProfile)
	}
	return out, readFailed
}

// errScopeRead marks a support scope that could not be read.
type errScopeRead struct{ err error }

func (e errScopeRead) Error() string { return "read support scope: " + e.err.Error() }
func (e errScopeRead) Unwrap() error { return e.err }

// support is H2 for one profile on the committed facts the dispatch pool is
// built from (KC §4.4), with the same rules as the Verifier eligibility in
// handraise_eligibility.go.
func (g *handraiseGates) support(ctx context.Context, bond chainclient.ServiceBondSnapshot, p gateProfile) error {
	scope, err := g.chain.CommittedModelSupportScope(ctx, g.operator, p.modelHex, strconv.FormatUint(uint64(p.Version), 10))
	if errors.Is(err, chainclient.ErrNotFound) {
		return err
	}
	if err != nil {
		return errScopeRead{err}
	}
	prof := scope.Profile
	if prof.Profile.ModelID != p.modelHex || prof.Profile.ProfileVersion.Uint32() != p.Version {
		return fmt.Errorf("Keeper profile identity does not match")
	}
	modelStatus, profileStatus := strings.ToUpper(prof.Model.Status), strings.ToUpper(prof.Profile.Status)
	if (modelStatus != "REGISTERED" && modelStatus != "ACTIVE") || (profileStatus != "REGISTERED" && profileStatus != "ACTIVE") {
		return fmt.Errorf("model %s / profile %s is not accepting work", modelStatus, profileStatus)
	}
	if floor := prof.Profile.MinStake.Uint64(); floor == 0 || bond.ActiveBond.Uint64() < floor {
		return fmt.Errorf("active bond %d is below min_stake %d", bond.ActiveBond.Uint64(), floor)
	}
	if err := scope.Capability.Validate(); err != nil {
		return err
	}
	if scope.Capability.OperatorAddress != g.operator || scope.Capability.ModelID != p.modelHex || !scope.Capability.InferenceCapability {
		return fmt.Errorf("no inference capability")
	}
	if err := scope.Support.Validate(); err != nil {
		return err
	}
	if scope.Support.OperatorAddress != g.operator || scope.Support.ModelID != p.modelHex || !scope.Support.DeclaredSupport {
		return fmt.Errorf("support is not declared")
	}
	if scope.EpochLengthBlocks == 0 {
		return fmt.Errorf("epoch length unknown")
	}
	if fresh := scope.Support.SupportFreshUntilEpoch.Uint64(); fresh == 0 || scope.Height/scope.EpochLengthBlocks >= fresh {
		return fmt.Errorf("support is stale")
	}
	if !scope.Support.SupportActive && profileStatus != "REGISTERED" {
		return fmt.Errorf("support is not active for an ACTIVE profile")
	}
	return nil
}

func memberRefFrom(m chainclient.CandidateMemberRefSnapshot, operator string) (memberRef, error) {
	if len(m.CandidatePoolSnapshotID) != 32 || m.SlotVersion == 0 || m.OperatorAddress != operator {
		return memberRef{}, fmt.Errorf("candidate member reference is incomplete or names another operator")
	}
	r := memberRef{Slot: m.Slot, SlotVersion: m.SlotVersion, Operator: m.OperatorAddress}
	copy(r.SnapshotID[:], m.CandidatePoolSnapshotID)
	return r, nil
}
