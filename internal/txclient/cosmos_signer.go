package txclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/signer"
)

type CosmosSigningClient interface {
	SignCosmosTx(context.Context, signer.CosmosTxRequest) ([]byte, error)
}

type CosmosSignerConfig struct {
	Client        CosmosSigningClient
	KeyRef        string
	SignerAddress string
}

type CosmosSigner struct{ cfg CosmosSignerConfig }

func NewCosmosSigner(cfg CosmosSignerConfig) *CosmosSigner { return &CosmosSigner{cfg: cfg} }

func (s *CosmosSigner) Address(context.Context, Kind) (string, error) {
	if s == nil || strings.TrimSpace(s.cfg.SignerAddress) == "" {
		return "", fmt.Errorf("Cosmos signer address is required")
	}
	return s.cfg.SignerAddress, nil
}

func (s *CosmosSigner) Sign(ctx context.Context, req SignRequest) ([]byte, error) {
	if s == nil || s.cfg.Client == nil {
		return nil, fmt.Errorf("Cosmos signing client is required")
	}
	if err := ValidateMessagePayload(req.Kind, req.Payload); err != nil {
		return nil, err
	}
	return s.cfg.Client.SignCosmosTx(ctx, signer.CosmosTxRequest{
		KeyRef: s.cfg.KeyRef, ExpectedSignerAddress: s.cfg.SignerAddress,
		ChainID: req.ChainID, AccountNumber: req.AccountNumber, Sequence: req.AccountSequence,
		GasLimit: req.GasLimit, FeeAmount: req.Fee.Amount, FeeDenom: req.Fee.Denom, FeePayer: req.GasPayer, FeeGranter: req.FeeGrant,
		Memo: req.Memo, TimeoutHeight: req.DeadlineHeight,
		Messages: []signer.CosmosMessage{{TypeURL: req.Kind.String(), Value: json.RawMessage(append([]byte(nil), req.Payload...))}},
	})
}
