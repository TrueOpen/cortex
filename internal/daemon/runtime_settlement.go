package daemon

import (
	"context"
	"fmt"

	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/txclient"
	"github.com/SingaXYZ/cortex/internal/verifier"
)

// SettleTask is an explicit operator-triggered settlement attempt. Eligibility
// comes from the Node; the caller cannot choose a signer, fee, verdict or payout.
func (r *Runtime) SettleTask(ctx context.Context, taskID string) (verifier.SettlementObservation, error) {
	if r == nil {
		return verifier.SettlementObservation{}, fmt.Errorf("settlement runtime is unavailable")
	}
	r.workloadMu.RLock()
	adapters, serviceAddress := r.ProtocolTx, r.ServiceAddress
	r.workloadMu.RUnlock()
	if adapters == nil || serviceAddress == "" || adapters.serviceAddress != serviceAddress {
		return verifier.SettlementObservation{}, fmt.Errorf("settlement requires an active workload and a Cosmos-capable transaction signer with tx.enabled")
	}
	reader, ok := r.Dependencies.Keeper.(chainclient.SettlementContextReader)
	if !ok {
		return verifier.SettlementObservation{}, fmt.Errorf("Keeper settlement context reader is unavailable")
	}
	manager := adapters.Settlement(verifier.SettlementConfig{ContextReader: reader})
	return manager.HandleStage3BuilderFailure(ctx, verifier.SettlementInput{
		Message: txclient.SettleTaskMessage{TaskID: txclient.ProtoBytes32(taskID), SubmitterAddress: serviceAddress},
	})
}
