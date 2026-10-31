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
// *chainclient.KeeperABCIClient satisfies it. Every gate read is pinned to
// one committed height.
type HandraiseChainView interface {
	CommittedHeight(context.Context) (uint64, error)
	CortexNodeAt(ctx context.Context, operatorAddress string, height uint64) (chainclient.CortexNodeSnapshot, error)
	ServiceBondAt(ctx context.Context, operatorAddress string, height uint64) (chainclient.ServiceBondSnapshot, error)
	CurrentServiceKey(ctx context.Context, participantType, operatorAddress string, height uint64) (chainclient.ServiceKeySnapshot, error)
	CurrentCandidateMemberAt(ctx context.Context, operatorAddress string, height uint64) (chainclient.CandidateMemberRefSnapshot, error)
	ModelSupportScopeAt(ctx context.Context, operatorAddress, modelID, profileVersion string, height uint64) (chainclient.CommittedModelSupportScope, error)
	BuilderVrfKeyAt(ctx context.Context, operatorAddress string, height uint64) (chainclient.VrfKeySnapshot, error)
	// CommittedCurrentServiceKey serves the root path's Builder key reads.
	CommittedCurrentServiceKey(ctx context.Context, participantType, operatorAddress string) (chainclient.ServiceKeySnapshot, uint64, error)
}

// HandraiseLocal is the local state the gates read, every pass. FreeSlots is
// lease-backed (WithLeaseSlots); WorkloadReady is the Runtime's last
// readiness verdict. There are no drain controls yet, so Draining reports
// none (S9 Q10).
type HandraiseLocal interface {
	// WorkloadReady is Runtime.CheckWorkloadReadiness(ctx).Ready(): chain sync
	// lag, identity, signer and store (CD §5.1 H1).
	WorkloadReady(context.Context) bool
	// Draining reports a node-wide drain (CD §8.4) and the profiles being
	// drained out of supported_profiles (CD §7.3).
	Draining() (node bool, profiles map[HandraiseProfile]bool)
	// FreeSlots is capacity minus accepted, not yet terminal tasks; ok=false
	// means the runtime is not ready (CD §5.1 H3).
	FreeSlots(context.Context) (n uint32, ok bool)
}

// Profile verdicts.
const (
	profileExcluded   = iota // a fact (chain, drain or H4) leaves it out
	profileEligible          // H2 and H4 allow it
	profileReadFailed        // its support scope could not be read
)

type profileVerdict struct {
	HandraiseProfile
	class int
	why   string
}

// gateResult is one evaluation of the gates.
type gateResult struct {
	state     *handraiseState // offer(nil); nil: offer nothing
	why       string
	factual   bool   // the stop rests on chain/local facts, not on a failed read
	authNonce uint64 // current Cortex service_authorization_nonce, when authKnown
	authKnown bool

	open     bool           // no stop: offer() decides from the profiles
	base     handraiseState // member, nonce and free slots of an open result
	profiles []profileVerdict
}

// offer is what may be offered to a Builder whose last live offer was prev
// (nil: none). A profile whose read failed stays in if prev offered it and is
// left out otherwise, so a failed read never changes an offer and never
// causes a send (only facts may close the offer, Q3).
func (r gateResult) offer(prev *handraiseState) (*handraiseState, bool, string) {
	if !r.open {
		return nil, r.factual, r.why
	}
	st := r.base
	st.Profiles = nil
	readFailed := false
	for _, v := range r.profiles {
		switch v.class {
		case profileEligible:
			st.Profiles = append(st.Profiles, v.HandraiseProfile)
		case profileReadFailed:
			readFailed = true
			if prev != nil && slices.Contains(prev.Profiles, v.HandraiseProfile) {
				st.Profiles = append(st.Profiles, v.HandraiseProfile)
			}
		}
	}
	if len(st.Profiles) == 0 {
		return nil, !readFailed, "H2/H4: no servable profile"
	}
	return &st, false, ""
}

type gateProfile struct {
	HandraiseProfile
	modelHex string
}

// chainFacts is the chain part of the gates at one committed height. It is
// reused for every pass at that height unless a read failed.
type chainFacts struct {
	height     uint64
	stop       string // a stop before drain is considered
	factual    bool
	authNonce  uint64
	authKnown  bool
	memberErr  string
	member     memberRef
	profiles   []profileVerdict // aligned with handraiseGates.profiles
	readFailed bool
	vrfOK      map[string]bool // Builders whose VRF key was read at height
}

type handraiseGates struct {
	operator string
	chain    HandraiseChainView
	local    HandraiseLocal
	profiles []gateProfile // ascending
	minBid   map[string]uint64
	log      *slog.Logger

	// Only the evaluating goroutine touches these.
	facts        *chainFacts
	lastEligible string // the eligible set last logged
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

// evaluate runs CD §5.1 H1–H4 plus the service-key-rotation and drain stops
// at the committed height. intervalKnown says whether an expiry_height can be
// computed yet. Chain facts come from the per-height memo; the local inputs
// are read every pass.
func (g *handraiseGates) evaluate(ctx context.Context, height uint64, intervalKnown bool) gateResult {
	if !g.local.WorkloadReady(ctx) {
		return gateResult{why: "H1: workload not ready"}
	}
	f := g.chainFacts(ctx, height)
	res := gateResult{authNonce: f.authNonce, authKnown: f.authKnown}
	if f.stop != "" {
		res.why, res.factual = f.stop, f.factual
		return res
	}
	drainNode, drainProfiles := g.local.Draining()
	if drainNode {
		res.why, res.factual = "draining", true
		return res
	}
	if f.memberErr != "" {
		res.why = "H1: " + f.memberErr
		return res
	}
	if !intervalKnown {
		res.why = "block interval not observed yet"
		return res
	}
	res.profiles = make([]profileVerdict, len(f.profiles))
	copy(res.profiles, f.profiles)
	for i := range res.profiles {
		if drainProfiles[res.profiles[i].HandraiseProfile] {
			res.profiles[i].class, res.profiles[i].why = profileExcluded, "draining"
		}
	}
	g.logEligible(res.profiles)
	free, ok := g.local.FreeSlots(ctx)
	if !ok {
		free = 0 // H3
	}
	res.open = true
	res.base = handraiseState{Member: f.member, AuthNonce: f.authNonce, FreeSlots: free}
	res.state, res.factual, res.why = res.offer(nil)
	return res
}

// chainFacts returns the memo for height, reading it first if needed.
func (g *handraiseGates) chainFacts(ctx context.Context, height uint64) *chainFacts {
	if g.facts != nil && g.facts.height == height {
		return g.facts
	}
	f := &chainFacts{height: height, vrfOK: map[string]bool{}}
	// The key is read even when an earlier fact stops the offer, so a
	// withdrawal carries the current nonce.
	key, keyErr := g.chain.CurrentServiceKey(ctx, chainclient.ParticipantTypeCortexNode, g.operator, height)
	if keyErr == nil {
		f.authNonce, f.authKnown = key.AuthorizationNonce.Uint64(), true
	}
	bond, stop, factual, readErr := g.identityStop(ctx, height, key, keyErr)
	f.stop, f.factual, f.readFailed = stop, factual, readErr
	if f.stop == "" {
		member, err := g.chain.CurrentCandidateMemberAt(ctx, g.operator, height)
		if err == nil {
			f.member, err = memberRefFrom(member, g.operator)
		} else {
			f.readFailed = true
		}
		if err != nil {
			f.memberErr = "candidate member: " + err.Error()
		}
		f.profiles = g.readProfiles(ctx, height, bond, f)
	}
	if !f.readFailed {
		g.facts = f
	}
	return f
}

// identityStop is H1 on the node, bond and key, and the rotation stop.
// readErr reports a stop caused by a failed read.
func (g *handraiseGates) identityStop(ctx context.Context, height uint64, key chainclient.ServiceKeySnapshot, keyErr error) (bond chainclient.ServiceBondSnapshot, stop string, factual, readErr bool) {
	node, err := g.chain.CortexNodeAt(ctx, g.operator, height)
	if err != nil {
		return bond, "H1: read Cortex node: " + err.Error(), false, true
	}
	if node.OperatorAddress != g.operator || (!strings.EqualFold(node.Status, "REGISTERED") && !strings.EqualFold(node.Status, "ACTIVE")) {
		return bond, "H1: Cortex node status " + node.Status, true, keyErr != nil
	}
	bond, err = g.chain.ServiceBondAt(ctx, g.operator, height)
	if err != nil {
		return bond, "H1: read service bond: " + err.Error(), false, true
	}
	if bond.OperatorAddress != g.operator || !bond.CandidateEligible() {
		return bond, "H1: service bond status " + bond.Status, true, keyErr != nil
	}
	if keyErr != nil {
		return bond, "H1: read service key: " + keyErr.Error(), false, true
	}
	if key.Status != "ACTIVE" {
		// Not a fact to withdraw on: a withdrawal signed by a revoked key
		// authorizes nothing, so the last handraise just expires by height.
		return bond, "H1: service key " + key.Status, false, false
	}
	if key.HasPendingRotation {
		return bond, "service key rotation pending (CD §8.4)", true, false
	}
	return bond, "", false, false
}

// readProfiles reads H2 for every profile H4 allows, at height.
func (g *handraiseGates) readProfiles(ctx context.Context, height uint64, bond chainclient.ServiceBondSnapshot, f *chainFacts) []profileVerdict {
	out := make([]profileVerdict, len(g.profiles))
	for i, p := range g.profiles {
		out[i].HandraiseProfile = p.HandraiseProfile
		if g.minBid[config.MinPriceBidKey(p.modelHex, p.Version)] == 0 {
			out[i].why = "no min_price_bid (H4)"
			continue
		}
		err := g.support(ctx, height, bond, p)
		var read errScopeRead
		switch {
		case err == nil:
			out[i].class = profileEligible
		case errors.As(err, &read):
			out[i].class, out[i].why = profileReadFailed, err.Error()
			f.readFailed = true
		default:
			out[i].why = "H2: " + err.Error()
		}
	}
	return out
}

// logEligible logs the profiles left out, only when the eligible set changes.
func (g *handraiseGates) logEligible(vs []profileVerdict) {
	var eligible []string
	for _, v := range vs {
		if v.class == profileEligible {
			eligible = append(eligible, hex.EncodeToString(v.ModelID[:])+"@"+strconv.FormatUint(uint64(v.Version), 10))
		}
	}
	key := strings.Join(eligible, ",")
	if key == g.lastEligible {
		return
	}
	g.lastEligible = key
	for _, v := range vs {
		if v.class != profileEligible {
			g.log.Info("profile left out of standing handraise", "model_id", hex.EncodeToString(v.ModelID[:]),
				"profile_version", v.Version, "why", v.why)
		}
	}
}

// builder is the per-Builder part of H1: without a readable VRF key none of
// that Builder's tickets could be checked. A success is memoised by height.
func (g *handraiseGates) builder(ctx context.Context, height uint64, builder string) error {
	if f := g.facts; f != nil && f.height == height && f.vrfOK[builder] {
		return nil
	}
	if _, err := g.chain.BuilderVrfKeyAt(ctx, builder, height); err != nil {
		return fmt.Errorf("H1: Builder %s VRF key: %w", builder, err)
	}
	if f := g.facts; f != nil && f.height == height {
		f.vrfOK[builder] = true
	}
	return nil
}

// errScopeRead marks a support scope that could not be read.
type errScopeRead struct{ err error }

func (e errScopeRead) Error() string { return "read support scope: " + e.err.Error() }
func (e errScopeRead) Unwrap() error { return e.err }

// support is H2 for one profile on the committed facts the dispatch pool is
// built from (KC §4.4), with the same rules as the Verifier eligibility in
// handraise_eligibility.go.
func (g *handraiseGates) support(ctx context.Context, height uint64, bond chainclient.ServiceBondSnapshot, p gateProfile) error {
	scope, err := g.chain.ModelSupportScopeAt(ctx, g.operator, p.modelHex, strconv.FormatUint(uint64(p.Version), 10), height)
	if errors.Is(err, chainclient.ErrNotFound) {
		return err
	}
	if err != nil {
		return errScopeRead{err}
	}
	return scopeSupportProblem(scope, bond, g.operator, p.modelHex, p.Version)
}

// scopeSupportProblem is H2 (and CD §5.1 check 4) on an already read scope:
// nil when the profile is registered, bonded, capable, declared and fresh for
// operator. The standing handraise and the Dispatcher share it.
func scopeSupportProblem(scope chainclient.CommittedModelSupportScope, bond chainclient.ServiceBondSnapshot, operator, modelHex string, version uint32) error {
	prof := scope.Profile
	if prof.Profile.ModelID != modelHex || prof.Profile.ProfileVersion.Uint32() != version {
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
	if scope.Capability.OperatorAddress != operator || scope.Capability.ModelID != modelHex || !scope.Capability.InferenceCapability {
		return fmt.Errorf("no inference capability")
	}
	if err := scope.Support.Validate(); err != nil {
		return err
	}
	if scope.Support.OperatorAddress != operator || scope.Support.ModelID != modelHex || !scope.Support.DeclaredSupport {
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
