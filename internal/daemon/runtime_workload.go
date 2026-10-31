package daemon

import (
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/txclient"
)

// ActivateWorkload opens the workload path for the Keeper-confirmed service
// identity. The compressed public key travels with the address because Nexus
// role signatures have to carry it.
func (r *Runtime) ActivateWorkload(serviceAddress string, servicePubkey string) error {
	serviceAddress = strings.TrimSpace(serviceAddress)
	if serviceAddress == "" {
		return fmt.Errorf("workload service address is required")
	}
	var workloadTx txclient.Client
	var protocolTx *ProtocolTxAdapters
	if r.workloadTxFactory != nil {
		workloadTx = r.workloadTxFactory(serviceAddress)
	}
	if r.cfg.RequiresWorkloadTx() && workloadTx == nil {
		return fmt.Errorf("workload tx client is required for an enabled direct transaction path")
	}
	if workloadTx != nil {
		protocolTx = NewProtocolTxAdapters(ProtocolTxAdapterConfig{
			Tx:              workloadTx,
			OperatorAddress: r.cfg.LocalIdentity.OperatorAddress, ServiceAddress: serviceAddress,
			GasPayer: serviceAddress, FeeCap: txclient.Coin{Amount: r.cfg.Tx.MaxFeeAmount, Denom: r.cfg.Tx.FeeDenom},
		})
	}
	r.workloadMu.Lock()
	r.ServiceAddress = serviceAddress
	r.ServicePubkey = strings.TrimSpace(servicePubkey)
	r.WorkloadTx = workloadTx
	r.ProtocolTx = protocolTx
	r.workloadMu.Unlock()
	return nil
}

func (r *Runtime) DeactivateWorkload() {
	if r == nil {
		return
	}
	r.workloadMu.Lock()
	defer r.workloadMu.Unlock()
	r.ServiceAddress = ""
	r.ServicePubkey = ""
	r.WorkloadTx = nil
	r.ProtocolTx = nil
}

func (r *Runtime) WorkloadActive() bool {
	if r == nil {
		return false
	}
	r.workloadMu.RLock()
	defer r.workloadMu.RUnlock()
	return r.ServiceAddress != ""
}

func (r *Runtime) WorkloadIdentity() (string, string) {
	if r == nil {
		return "", ""
	}
	r.workloadMu.RLock()
	defer r.workloadMu.RUnlock()
	return r.ServiceAddress, r.ServicePubkey
}

func (r *Runtime) WorkloadTxClient() txclient.Client {
	if r == nil {
		return nil
	}
	r.workloadMu.RLock()
	defer r.workloadMu.RUnlock()
	return r.WorkloadTx
}

// workloadServiceAddress returns the Keeper-confirmed service address of the
// activated workload. Bus material must not be signed before the chain confirms
// the binding, so an inactive workload is an error rather than an empty address.
func (r *Runtime) workloadServiceAddress() (string, error) {
	if r == nil {
		return "", fmt.Errorf("runtime is unavailable")
	}
	r.workloadMu.RLock()
	defer r.workloadMu.RUnlock()
	if strings.TrimSpace(r.ServiceAddress) == "" {
		return "", fmt.Errorf("workload is not active: the Keeper has not confirmed this node's current service key")
	}
	return r.ServiceAddress, nil
}
