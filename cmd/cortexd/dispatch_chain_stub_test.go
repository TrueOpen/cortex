package main

import (
	"context"
	"errors"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/daemon"
)

// errDispatchReadNotServed answers every Phase 1 dispatch read these daemon
// tests do not exercise: the plane is built and its loops run, but no
// handraise, offer or challenge ever passes a gate.
var errDispatchReadNotServed = errors.New("dispatch read not served by this test Keeper")

// dispatchChainStub completes a test Keeper's method set to
// daemon.DispatchPlaneChain, which real mode needs for dispatch.builders. The
// committed height and dispatch params answer (zero params pass the root
// retention check), so the workload's stream runner keeps running.
type dispatchChainStub struct{}

func (dispatchChainStub) CommittedHeight(context.Context) (uint64, error) { return 1, nil }
func (dispatchChainStub) DispatchParamsAt(context.Context, uint64) (chainclient.DispatchParamsSnapshot, error) {
	return chainclient.DispatchParamsSnapshot{}, nil
}
func (dispatchChainStub) DispatchParams(context.Context) (chainclient.DispatchParamsSnapshot, error) {
	return chainclient.DispatchParamsSnapshot{}, nil
}
func (dispatchChainStub) CortexNodeAt(context.Context, string, uint64) (chainclient.CortexNodeSnapshot, error) {
	return chainclient.CortexNodeSnapshot{}, errDispatchReadNotServed
}
func (dispatchChainStub) ServiceBondAt(context.Context, string, uint64) (chainclient.ServiceBondSnapshot, error) {
	return chainclient.ServiceBondSnapshot{}, errDispatchReadNotServed
}
func (dispatchChainStub) CurrentCandidateMemberAt(context.Context, string, uint64) (chainclient.CandidateMemberRefSnapshot, error) {
	return chainclient.CandidateMemberRefSnapshot{}, errDispatchReadNotServed
}
func (dispatchChainStub) ModelSupportScopeAt(context.Context, string, string, string, uint64) (chainclient.CommittedModelSupportScope, error) {
	return chainclient.CommittedModelSupportScope{}, errDispatchReadNotServed
}
func (dispatchChainStub) BuilderVrfKeyAt(context.Context, string, uint64) (chainclient.VrfKeySnapshot, error) {
	return chainclient.VrfKeySnapshot{}, errDispatchReadNotServed
}
func (dispatchChainStub) BuilderSetAt(context.Context, uint64) (chainclient.BuilderSetSnapshot, error) {
	return chainclient.BuilderSetSnapshot{}, errDispatchReadNotServed
}
func (dispatchChainStub) DispatchEpochAt(context.Context, uint64, uint64) (chainclient.DispatchEpochSnapshot, error) {
	return chainclient.DispatchEpochSnapshot{}, errDispatchReadNotServed
}
func (dispatchChainStub) SessionAt(context.Context, []byte, uint64) (chainclient.SessionSnapshot, error) {
	return chainclient.SessionSnapshot{}, errDispatchReadNotServed
}
func (dispatchChainStub) WorkerLiabilityParamsAt(context.Context, uint64) (chainclient.WorkerLiabilityParamsSnapshot, error) {
	return chainclient.WorkerLiabilityParamsSnapshot{}, errDispatchReadNotServed
}
func (dispatchChainStub) DispatchRecord(context.Context, []byte, uint64) (chainclient.DispatchRecordSnapshot, error) {
	return chainclient.DispatchRecordSnapshot{}, errDispatchReadNotServed
}
func (dispatchChainStub) DispatchAssignment(context.Context, []byte) (chainclient.DispatchAssignmentSnapshot, error) {
	return chainclient.DispatchAssignmentSnapshot{}, errDispatchReadNotServed
}
func (dispatchChainStub) DispatchCompensationClaim(context.Context, []byte) (chainclient.DispatchClaimSnapshot, error) {
	return chainclient.DispatchClaimSnapshot{}, errDispatchReadNotServed
}
func (dispatchChainStub) DispatchCompensationClaimsByBuilder(context.Context, string) (uint64, []chainclient.DispatchClaimSnapshot, error) {
	return 0, nil, errDispatchReadNotServed
}
func (dispatchChainStub) DispatchWinnerIneligible(context.Context, []byte) (chainclient.DispatchWinnerIneligibleSnapshot, error) {
	return chainclient.DispatchWinnerIneligibleSnapshot{}, errDispatchReadNotServed
}
func (dispatchChainStub) TaskProfile(context.Context, []byte) (chainclient.TaskProfileSnapshot, error) {
	return chainclient.TaskProfileSnapshot{}, errDispatchReadNotServed
}
func (dispatchChainStub) CandidatePoolMember(context.Context, []byte, string) (chainclient.CandidateMemberRefSnapshot, error) {
	return chainclient.CandidateMemberRefSnapshot{}, errDispatchReadNotServed
}
func (dispatchChainStub) DispatchChallenge(context.Context, []byte) (chainclient.DispatchChallengeSnapshot, error) {
	return chainclient.DispatchChallengeSnapshot{}, errDispatchReadNotServed
}

var _ daemon.DispatchPlaneChain = (*recordingKeeperClient)(nil)
