package daemon

import (
	"github.com/SingaXYZ/cortex/internal/txclient"
	"github.com/SingaXYZ/cortex/internal/verifier"
)

// ProtocolTxAdapters binds explicit settlement and rescue operations to
// the same real Tx and active ServiceKey boundaries used by the daemon.
type ProtocolTxAdapters struct {
	tx              txclient.Client
	operatorAddress string
	serviceAddress  string
	gasPayer        string
	feeCap          txclient.Coin
}

type ProtocolTxAdapterConfig struct {
	Tx              txclient.Client
	OperatorAddress string
	ServiceAddress  string
	GasPayer        string
	FeeCap          txclient.Coin
}

func NewProtocolTxAdapters(cfg ProtocolTxAdapterConfig) *ProtocolTxAdapters {
	if cfg.Tx == nil {
		return nil
	}
	return &ProtocolTxAdapters{
		tx:              cfg.Tx,
		operatorAddress: cfg.OperatorAddress, serviceAddress: cfg.ServiceAddress,
		gasPayer: cfg.GasPayer, feeCap: cfg.FeeCap,
	}
}

func (a *ProtocolTxAdapters) Settlement(cfg verifier.SettlementConfig) *verifier.SettlementManager {
	if a == nil {
		return nil
	}
	cfg.Tx = a.tx
	if cfg.VerifierAddress == "" {
		cfg.VerifierAddress = a.operatorAddress
	}
	if cfg.WorkerAddress == "" {
		cfg.WorkerAddress = a.operatorAddress
	}
	if cfg.GasPayer == "" {
		cfg.GasPayer = a.gasPayer
	}
	if cfg.SubmitterAddress == "" {
		cfg.SubmitterAddress = a.serviceAddress
	}
	if cfg.FeeCap == (txclient.Coin{}) {
		cfg.FeeCap = a.feeCap
	}
	return verifier.NewSettlementManager(cfg)
}
