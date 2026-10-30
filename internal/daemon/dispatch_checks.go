package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strconv"
	"strings"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/nodewire"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

const (
	reasonNoCapacity = taskv1.DispatchRejectReasonV1_DISPATCH_REJECT_REASON_V1_NO_CAPACITY
	reasonProfile    = taskv1.DispatchRejectReasonV1_DISPATCH_REJECT_REASON_V1_PROFILE_UNAVAILABLE
	reasonExpired    = taskv1.DispatchRejectReasonV1_DISPATCH_REJECT_REASON_V1_EXPIRED
	reasonInvalid    = taskv1.DispatchRejectReasonV1_DISPATCH_REJECT_REASON_V1_INVALID_TICKET
)

// Local reject classes (CD §5.1 "可审计的 reason 类别"; Q2).
const (
	classRotationPending    = "service_key_rotation_pending"
	classOrderInvalid       = "order_invalid"
	classOrderExpired       = "order_expired"
	classStaleBoundChange   = "builder_stale_bound_change_height"
	classNodeIneligible     = "node_ineligible"
	classWinnerIneligible   = "winner_ineligible"
	classProfileUnavailable = "profile_unavailable"
	classPriceBelowMin      = "price_below_min"
	classInputMismatch      = "input_metadata_mismatch"
	classInputTooLarge      = "input_too_large"
	classNoFreeSlot         = "no_free_slot"
)

// verdict is one signed-reject decision.
type verdict struct {
	reason      taskv1.DispatchRejectReasonV1
	class       string
	builderSide bool // CD §5.1 2a: the Builder's stale ticket, not this node's reject
	detail      string
}

func refuse(reason taskv1.DispatchRejectReasonV1, class, format string, args ...any) *verdict {
	return &verdict{reason: reason, class: class, detail: fmt.Sprintf(format, args...)}
}

// prechecks runs CD §5.1 checks 2, 2a, 3, 4, 6 and 7 in that order, every
// chain read pinned to height. Check 5 is the lease. A nil verdict and nil
// error means accept; an error is a failed read (retryable).
func (d *Dispatcher) prechecks(ctx context.Context, t *taskv1.DispatchTicketV1, so *taskv1.SignedOrderV2, height uint64) (*verdict, error) {
	if v, err := d.checkOrder(ctx, t, so, height); v != nil || err != nil {
		return v, err
	}
	o := so.GetOrder()
	modelHex := hex.EncodeToString(o.GetModelId())
	version := o.GetProfileVersion()
	scope, err := d.cfg.Chain.ModelSupportScopeAt(ctx, d.cfg.Operator, modelHex, strconv.FormatUint(uint64(version), 10), height)
	haveScope := err == nil
	if err != nil && !errors.Is(err, chainclient.ErrNotFound) {
		return nil, builderclient.Retryable(fmt.Errorf("support scope: %w", err))
	}
	bond, v, err := d.checkNode(ctx, o, scope, haveScope, height)
	if v != nil || err != nil {
		return v, err
	}
	if v := d.checkProfile(modelHex, version, scope, haveScope, bond); v != nil {
		return v, nil
	}
	if v := d.checkPrice(o, modelHex, version); v != nil {
		return v, nil
	}
	return d.checkInput(t, o), nil
}

// checkOrder is check 2 (order structure, user signature, task identity,
// session, expiry, BuilderSet) and 2a (bound_change_height).
func (d *Dispatcher) checkOrder(ctx context.Context, t *taskv1.DispatchTicketV1, so *taskv1.SignedOrderV2, height uint64) (*verdict, error) {
	raw, err := dispatchwire.Raw(so)
	if err != nil {
		return refuse(reasonInvalid, classOrderInvalid, "encode order: %v", err), nil
	}
	carrier := hex.EncodeToString(raw)
	taskHash, facts, err := nodewire.TaskOrderHashAndFactsSignedOrderHex(carrier)
	if err != nil {
		return refuse(reasonInvalid, classOrderInvalid, "order: %v", err), nil
	}
	o := so.GetOrder()
	taskID := identity.TaskID(facts.SessionID, facts.OrderSequence)
	switch {
	case facts.ChainID != d.cfg.ChainID:
		return refuse(reasonInvalid, classOrderInvalid, "order chain_id %q", facts.ChainID), nil
	case !bytes.Equal(taskHash[:], t.GetTaskHash()):
		return refuse(reasonInvalid, classOrderInvalid, "order hashes to %x, the ticket binds task_hash %x", taskHash, t.GetTaskHash()), nil
	case taskID == (codec.Hash{}) || !bytes.Equal(taskID[:], t.GetTaskId()):
		return refuse(reasonInvalid, classOrderInvalid, "order derives task_id %x, the ticket binds %x", taskID, t.GetTaskId()), nil
	case len(o.GetSessionId()) != 32 || !bytes.Equal(o.GetSessionId(), t.GetSessionId()) || o.GetOrderSequence() != t.GetOrderSequence():
		return refuse(reasonInvalid, classOrderInvalid, "order session/sequence differ from the ticket"), nil
	}
	if o.GetOrderExpireHeight() <= height {
		return refuse(reasonExpired, classOrderExpired, "order_expire_height %d <= committed height %d", o.GetOrderExpireHeight(), height), nil
	}
	signer, err := nodewire.SignedOrderSigner(carrier, 0, d.cfg.FeeDenom)
	if err != nil {
		return refuse(reasonInvalid, classOrderInvalid, "user signature: %v", err), nil
	}
	user, err := nodewire.CanonicalOperatorAddressBytes("user_address", o.GetUserAddress())
	if err != nil {
		return refuse(reasonInvalid, classOrderInvalid, "%v", err), nil
	}
	session, err := d.cfg.Chain.SessionAt(ctx, o.GetSessionId(), height)
	if errors.Is(err, chainclient.ErrNotFound) {
		return refuse(reasonInvalid, classOrderInvalid, "the session is not on chain"), nil
	}
	if err != nil {
		return nil, builderclient.Retryable(fmt.Errorf("session: %w", err))
	}
	if session.Status == "CLOSED" {
		return refuse(reasonInvalid, classOrderInvalid, "the session is closed"), nil
	}
	if !bytes.Equal(signer, user) {
		delegated := len(session.SessionKey) == 20 && bytes.Equal(signer, session.SessionKey) &&
			o.GetSessionAnchorHeight() >= session.SessionKeySetHeight && height <= session.SessionKeyExpiryHeight
		if !delegated {
			return refuse(reasonInvalid, classOrderInvalid, "the order is signed by neither user_address nor a live session key"), nil
		}
	}
	set, err := d.cfg.Chain.BuilderSetAt(ctx, height)
	if err != nil {
		return nil, builderclient.Retryable(fmt.Errorf("BuilderSet: %w", err))
	}
	if set.BuilderSetID != o.GetBuilderSetId() || !bytes.Equal(set.SetHash[:], o.GetBuilderSetHash()) || !slices.Contains(set.Builders, t.GetBuilderAddress()) {
		return refuse(reasonInvalid, classOrderInvalid, "order BuilderSet %s is not the current set %s with the Builder in it", o.GetBuilderSetId(), set.BuilderSetID), nil
	}
	// Check 2a: Keeper refuses such an entry as the Builder's preflight error,
	// so this reject does not count toward this node's reject rate.
	if session.BoundChangeHeight != t.GetBoundChangeHeight() {
		v := refuse(reasonInvalid, classStaleBoundChange, "ticket bound_change_height %d, chain %d", t.GetBoundChangeHeight(), session.BoundChangeHeight)
		v.builderSide = true
		return v, nil
	}
	return nil, nil
}

// checkNode is check 3: H1 at accept time plus KC §10.1.1 step 7 winner
// eligibility, so a ticket this node could not win is refused, not accepted.
func (d *Dispatcher) checkNode(ctx context.Context, o *taskv1.TaskOrderV3, scope chainclient.CommittedModelSupportScope, haveScope bool, height uint64) (chainclient.ServiceBondSnapshot, *verdict, error) {
	var bond chainclient.ServiceBondSnapshot
	if !d.cfg.Local.WorkloadReady(ctx) {
		return bond, refuse(reasonNoCapacity, classNodeIneligible, "workload not ready"), nil
	}
	node, err := d.cfg.Chain.CortexNodeAt(ctx, d.cfg.Operator, height)
	if err != nil {
		return bond, nil, builderclient.Retryable(fmt.Errorf("Cortex node: %w", err))
	}
	if node.OperatorAddress != d.cfg.Operator || (!strings.EqualFold(node.Status, "REGISTERED") && !strings.EqualFold(node.Status, "ACTIVE")) {
		return bond, refuse(reasonNoCapacity, classNodeIneligible, "Cortex node status %s", node.Status), nil
	}
	if drain, _ := d.cfg.Local.Draining(); drain {
		return bond, refuse(reasonNoCapacity, classNodeIneligible, "draining"), nil
	}
	bond, err = d.cfg.Chain.ServiceBondAt(ctx, d.cfg.Operator, height)
	if err != nil {
		return bond, nil, builderclient.Retryable(fmt.Errorf("service bond: %w", err))
	}
	if bond.OperatorAddress != d.cfg.Operator || !bond.CandidateEligible() {
		return bond, refuse(reasonNoCapacity, classWinnerIneligible, "service bond status %s", bond.Status), nil
	}
	if !haveScope {
		return bond, nil, nil // check 4 refuses the profile
	}
	active, reserved := bond.ActiveBond.Uint64(), bond.ReservedLiability.Uint64()
	available := uint64(0)
	if active > reserved {
		available = active - reserved
	}
	if stake := scope.Profile.Profile.MinStake.Uint64(); available < stake {
		return bond, refuse(reasonNoCapacity, classWinnerIneligible, "available bond %d is below min_stake %d", available, stake), nil
	}
	lp, err := d.cfg.Chain.WorkerLiabilityParamsAt(ctx, height)
	if err != nil {
		return bond, nil, builderclient.Retryable(fmt.Errorf("liability params: %w", err))
	}
	need, err := requiredTaskLiability(o.GetGenerationParams().GetMaxOutputTokens(), o.GetPriceBid().GetAtomicUnits(),
		scope.Profile.Profile.PricingProfile.VerifyRatioBPS, active, lp)
	if err != nil {
		return bond, refuse(reasonInvalid, classOrderInvalid, "task liability: %v", err), nil
	}
	if need.Cmp(new(big.Int).SetUint64(available)) > 0 {
		return bond, refuse(reasonNoCapacity, classWinnerIneligible, "available bond %d is below required_task_liability %s", available, need), nil
	}
	return bond, nil, nil
}

// requiredTaskLiability is KC §4.1: max(min_task_liability,
// ceil(order_value*coverage_bps/10000), floor(active_bond*slash_bps/10000))
// with order_value = worker_max + verify_max, worker_max =
// floor(max_output_tokens*price_bid/1e6), verify_max =
// floor(worker_max*verify_ratio_bps/10000).
func requiredTaskLiability(maxOutputTokens uint64, priceBid string, verifyRatioBps uint32, activeBond uint64, p chainclient.WorkerLiabilityParamsSnapshot) (*big.Int, error) {
	price, ok := new(big.Int).SetString(priceBid, 10)
	if !ok || price.Sign() < 0 {
		return nil, fmt.Errorf("price_bid %q is not a decimal amount", priceBid)
	}
	workerMax := new(big.Int).Mul(new(big.Int).SetUint64(maxOutputTokens), price)
	workerMax.Quo(workerMax, big.NewInt(1_000_000))
	verifyMax := new(big.Int).Mul(workerMax, big.NewInt(int64(verifyRatioBps)))
	verifyMax.Quo(verifyMax, big.NewInt(10_000))
	orderValue := new(big.Int).Add(workerMax, verifyMax)
	coverage := new(big.Int).Mul(orderValue, big.NewInt(int64(p.OrderCoverageBps)))
	coverage.Add(coverage, big.NewInt(9_999)).Quo(coverage, big.NewInt(10_000))
	slash := new(big.Int).Mul(new(big.Int).SetUint64(activeBond), big.NewInt(int64(p.ObjectiveForgerySlashBps)))
	slash.Quo(slash, big.NewInt(10_000))
	out := new(big.Int).SetUint64(p.MinTaskLiability)
	for _, v := range []*big.Int{coverage, slash} {
		if v.Cmp(out) > 0 {
			out = v
		}
	}
	return out, nil
}

// checkProfile is check 4: local supported profile, not draining, and H2 on
// the committed scope.
func (d *Dispatcher) checkProfile(modelHex string, version uint32, scope chainclient.CommittedModelSupportScope, haveScope bool, bond chainclient.ServiceBondSnapshot) *verdict {
	p, err := profileOf(modelHex, version)
	if err != nil || !d.profiles[p] {
		return refuse(reasonProfile, classProfileUnavailable, "profile %s@%d is not in supported_model_profiles", modelHex, version)
	}
	if _, drain := d.cfg.Local.Draining(); drain[p] {
		return refuse(reasonProfile, classProfileUnavailable, "profile %s@%d is draining", modelHex, version)
	}
	if !haveScope {
		return refuse(reasonProfile, classProfileUnavailable, "no support scope on chain for %s@%d", modelHex, version)
	}
	if err := scopeSupportProblem(scope, bond, d.cfg.Operator, modelHex, version); err != nil {
		return refuse(reasonProfile, classProfileUnavailable, "H2: %v", err)
	}
	return nil
}

// checkPrice is check 6's hard part: price_bid >= local min_price_bid.
func (d *Dispatcher) checkPrice(o *taskv1.TaskOrderV3, modelHex string, version uint32) *verdict {
	floor := d.cfg.MinPriceBid[config.MinPriceBidKey(modelHex, version)]
	if floor == 0 {
		return refuse(reasonProfile, classPriceBelowMin, "no min_price_bid for %s@%d (H4)", modelHex, version)
	}
	price, err := strconv.ParseUint(o.GetPriceBid().GetAtomicUnits(), 10, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return refuse(reasonInvalid, classOrderInvalid, "price_bid: %v", err)
	}
	if err == nil && price < floor {
		return refuse(reasonProfile, classPriceBelowMin, "price_bid %d is below min_price_bid %d", price, floor)
	}
	return nil
}

// checkInput is check 7.
func (d *Dispatcher) checkInput(t *taskv1.DispatchTicketV1, o *taskv1.TaskOrderV3) *verdict {
	if !bytes.Equal(t.GetInputHash(), o.GetInputHash()) {
		return refuse(reasonInvalid, classInputMismatch, "ticket input_hash differs from the order's")
	}
	if o.GetInputSizeBytes() > d.cfg.MaxInputBytes {
		return refuse(reasonNoCapacity, classInputTooLarge, "input_size_bytes %d exceeds the local limit %d", o.GetInputSizeBytes(), d.cfg.MaxInputBytes)
	}
	return nil
}
