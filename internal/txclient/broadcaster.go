package txclient

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	signerclient "github.com/TrueOpen/cortex/internal/signer"
)

const (
	CodeOK                uint32 = 0
	CodeWrongSequence     uint32 = 32
	CodeMempoolRejected   uint32 = 33
	CodeInsufficientFunds uint32 = 34
)

type Signer interface {
	Address(context.Context, Kind) (string, error)
	Sign(context.Context, SignRequest) ([]byte, error)
}

type RPC interface {
	Account(context.Context, string) (Account, error)
	BroadcastTx(context.Context, []byte) (BroadcastResult, error)
	Tx(context.Context, string) (InclusionResult, error)
}

type Account struct {
	Address       string
	AccountNumber uint64
	Sequence      uint64
}

type InclusionResult struct {
	Code   uint32
	Height uint64
	TxHash string
	Log    string
}

type Confirmer interface {
	Confirm(context.Context, Request, InclusionResult) (bool, error)
}

type ConfirmFunc func(context.Context, Request, InclusionResult) (bool, error)

func (f ConfirmFunc) Confirm(ctx context.Context, req Request, included InclusionResult) (bool, error) {
	return f(ctx, req, included)
}

type LifecycleState string

const (
	LifecycleBroadcast       LifecycleState = "BROADCAST"
	LifecycleIncluded        LifecycleState = "INCLUDED"
	LifecycleKeeperConfirmed LifecycleState = "KEEPER_CONFIRMED"
	LifecycleRejected        LifecycleState = "REJECTED"
)

type LifecycleRecord struct {
	TaskID         string
	Kind           Kind
	TxHash         string
	State          LifecycleState
	Height         uint64
	Reason         string
	PayloadDigest  codec.Hash
	MaterialDigest codec.Hash
}

type LifecycleRecorder interface {
	RecordTxLifecycle(context.Context, LifecycleRecord) error
}

type BroadcastResult struct {
	Code   uint32
	TxHash string
	Log    string
}

type SignRequest struct {
	ChainID         string
	TaskID          string
	Kind            Kind
	Payload         []byte
	GasPayer        string
	Fee             Coin
	FeeGrant        string
	Memo            string
	AccountSequence uint64
	AccountNumber   uint64
	GasLimit        uint64
	DeadlineHeight  uint64
	MaterialDigest  codec.Hash
	PayloadDigest   codec.Hash
}

type BroadcasterConfig struct {
	ChainID      string
	GasPayer     string
	MaxFeeAmount uint64
	FeeDenom     string
	MaxAttempts  int
	PollAttempts int
	PollInterval time.Duration
	GasLimit     uint64
	Signer       Signer
	RPC          RPC
	Confirmer    Confirmer
	Lifecycle    LifecycleRecorder
}

type Broadcaster struct {
	cfg BroadcasterConfig
}

func NewBroadcaster(cfg BroadcasterConfig) *Broadcaster {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.PollAttempts <= 0 {
		cfg.PollAttempts = 20
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 100 * time.Millisecond
	}
	return &Broadcaster{cfg: cfg}
}

// Probe performs a read-only account query to verify the broadcaster's node
// dependency. It never signs or broadcasts a transaction.
func (b *Broadcaster) Probe(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if b == nil {
		return fmt.Errorf("tx broadcaster is required")
	}
	if err := b.validateConfig(); err != nil {
		return err
	}
	gasPayer := strings.TrimSpace(b.cfg.GasPayer)
	if gasPayer == "" {
		return fmt.Errorf("gas payer is required")
	}
	account, err := b.cfg.RPC.Account(ctx, gasPayer)
	if err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(account.Address), gasPayer) {
		return fmt.Errorf("gas payer account address mismatch")
	}
	return nil
}

func (b *Broadcaster) Submit(ctx context.Context, req Request) (Observation, error) {
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	if b == nil {
		return Observation{}, fmt.Errorf("tx broadcaster is required")
	}
	if err := ValidateRequest(req); err != nil {
		return Observation{}, err
	}
	if err := b.validateConfig(); err != nil {
		return Observation{}, err
	}
	gasPayer := strings.TrimSpace(req.GasPayer)
	if gasPayer == "" {
		gasPayer = strings.TrimSpace(b.cfg.GasPayer)
	}
	if gasPayer == "" {
		return Observation{}, fmt.Errorf("gas payer is required")
	}
	fee := req.FeeCap
	if fee.Denom == "" {
		fee.Denom = b.cfg.FeeDenom
	}
	if err := b.validateFee(fee); err != nil {
		return Observation{}, err
	}
	address, err := b.cfg.Signer.Address(ctx, req.Kind)
	if err != nil {
		return Observation{}, err
	}
	if strings.TrimSpace(address) == "" {
		return Observation{}, fmt.Errorf("signer address is required")
	}
	if !strings.EqualFold(strings.TrimSpace(address), gasPayer) {
		return Observation{}, fmt.Errorf("gas payer must equal the current service signer address")
	}

	payloadDigest := codec.HashWithDomain("TRUEOPEN_TXCLIENT_REQUEST_V1", []byte(req.TaskID), []byte(req.Kind), req.Payload)
	sequence := uint64(0)
	requestedSequence := req.AccountSequence
	useRequestedSequence := requestedSequence != 0
	var accountNumber uint64
	var lastRejected Observation
	for attempt := 0; attempt < b.cfg.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return Observation{}, err
		}
		if sequence == 0 || attempt > 0 {
			account, err := b.cfg.RPC.Account(ctx, address)
			if err != nil {
				if retryableDependencyError(err) && attempt+1 < b.cfg.MaxAttempts {
					if err := waitPoll(ctx, b.cfg.PollInterval); err != nil {
						return Observation{}, err
					}
					continue
				}
				return Observation{}, err
			}
			sequence = account.Sequence
			accountNumber = account.AccountNumber
			if useRequestedSequence {
				sequence = requestedSequence
				useRequestedSequence = false
			}
		}
		signReq := SignRequest{
			ChainID:         b.cfg.ChainID,
			TaskID:          req.TaskID,
			Kind:            req.Kind,
			Payload:         append([]byte(nil), req.Payload...),
			GasPayer:        gasPayer,
			Fee:             fee,
			FeeGrant:        req.FeeGrant,
			Memo:            req.Memo,
			AccountSequence: sequence,
			AccountNumber:   accountNumber,
			GasLimit:        b.cfg.GasLimit,
			DeadlineHeight:  req.DeadlineHeight,
			MaterialDigest:  req.MaterialDigest,
			PayloadDigest:   payloadDigest,
		}
		signed, err := b.cfg.Signer.Sign(ctx, signReq)
		if err != nil {
			if retryableDependencyError(err) && attempt+1 < b.cfg.MaxAttempts {
				if err := waitPoll(ctx, b.cfg.PollInterval); err != nil {
					return Observation{}, err
				}
				continue
			}
			return Observation{}, err
		}
		result, err := b.broadcastSigned(ctx, signed)
		if err != nil {
			return Observation{}, err
		}
		obs := Observation{
			TaskID:          req.TaskID,
			Kind:            req.Kind,
			TxHash:          result.TxHash,
			RejectReason:    result.Log,
			PayloadDigest:   payloadDigest,
			AccountSequence: sequence,
			Fee:             fee,
			GasPayer:        gasPayer,
			DeadlineHeight:  req.DeadlineHeight,
			MaterialDigest:  req.MaterialDigest,
		}
		switch {
		case result.Code == CodeOK:
			if strings.TrimSpace(obs.TxHash) == "" {
				return Observation{}, fmt.Errorf("BroadcastTx response transaction hash is required")
			}
			obs.Status = LifecycleBroadcast
			if err := b.record(ctx, req, obs, LifecycleBroadcast, 0, ""); err != nil {
				return obs, err
			}
			return b.waitForInclusionAndConfirmation(ctx, req, obs)
		case retryableBroadcastCode(result.Code):
			lastRejected = obs
			sequence = 0
			continue
		default:
			obs.Rejected = true
			obs.Status = LifecycleRejected
			if err := b.record(ctx, req, obs, LifecycleRejected, 0, result.Log); err != nil {
				return obs, err
			}
			return obs, nil
		}
	}
	if lastRejected.RejectReason == "" {
		lastRejected.RejectReason = "tx broadcast retry attempts exhausted"
	}
	lastRejected.Rejected = true
	lastRejected.Status = LifecycleRejected
	if err := b.record(ctx, req, lastRejected, LifecycleRejected, 0, lastRejected.RejectReason); err != nil {
		return lastRejected, err
	}
	return lastRejected, nil
}

func (b *Broadcaster) broadcastSigned(ctx context.Context, signed []byte) (BroadcastResult, error) {
	expectedHash := cosmosTxHash(signed)
	var lastErr error
	for attempt := 0; attempt < b.cfg.MaxAttempts; attempt++ {
		result, err := b.cfg.RPC.BroadcastTx(ctx, signed)
		if err == nil {
			return result, nil
		}
		if !retryableDependencyError(err) {
			return BroadcastResult{}, err
		}
		lastErr = err

		// A transport failure can occur after the node accepted the bytes. Query
		// the deterministic TxRaw hash before rebroadcasting the identical tx.
		included, txErr := b.cfg.RPC.Tx(ctx, expectedHash)
		if txErr == nil {
			if !strings.EqualFold(strings.TrimSpace(included.TxHash), expectedHash) {
				return BroadcastResult{}, fmt.Errorf("included transaction hash mismatch")
			}
			return BroadcastResult{Code: CodeOK, TxHash: expectedHash}, nil
		}
		if !errors.Is(txErr, ErrTxNotFound) && !retryableDependencyError(txErr) {
			return BroadcastResult{}, txErr
		}
		if attempt+1 < b.cfg.MaxAttempts {
			if err := waitPoll(ctx, b.cfg.PollInterval); err != nil {
				return BroadcastResult{}, err
			}
		}
	}
	return BroadcastResult{}, lastErr
}

func (b *Broadcaster) waitForInclusionAndConfirmation(ctx context.Context, req Request, obs Observation) (Observation, error) {
	var included InclusionResult
	for attempt := 0; attempt < b.cfg.PollAttempts; attempt++ {
		result, err := b.cfg.RPC.Tx(ctx, obs.TxHash)
		if err == nil {
			included = result
			break
		}
		if !errors.Is(err, ErrTxNotFound) && !retryableDependencyError(err) {
			return obs, err
		}
		if err := waitPoll(ctx, b.cfg.PollInterval); err != nil {
			return obs, err
		}
	}
	if included.Height == 0 {
		return obs, fmt.Errorf("transaction inclusion timeout for %s", obs.TxHash)
	}
	if !strings.EqualFold(strings.TrimSpace(included.TxHash), strings.TrimSpace(obs.TxHash)) {
		return obs, fmt.Errorf("included transaction hash mismatch")
	}
	obs.IncludedHeight = included.Height
	if included.Code != CodeOK {
		obs.Rejected = true
		obs.RejectReason = included.Log
		obs.Status = LifecycleRejected
		if err := b.record(ctx, req, obs, LifecycleRejected, included.Height, included.Log); err != nil {
			return obs, err
		}
		return obs, nil
	}
	obs.Status = LifecycleIncluded
	if err := b.record(ctx, req, obs, LifecycleIncluded, included.Height, ""); err != nil {
		return obs, err
	}
	for attempt := 0; attempt < b.cfg.PollAttempts; attempt++ {
		confirmed, err := b.cfg.Confirmer.Confirm(ctx, req, included)
		if err != nil {
			if !retryableDependencyError(err) {
				return obs, err
			}
			confirmed = false
		}
		if confirmed {
			obs.Accepted = true
			obs.Status = LifecycleKeeperConfirmed
			if err := b.record(ctx, req, obs, LifecycleKeeperConfirmed, included.Height, ""); err != nil {
				return obs, err
			}
			return obs, nil
		}
		if err := waitPoll(ctx, b.cfg.PollInterval); err != nil {
			return obs, err
		}
	}
	return obs, fmt.Errorf("Keeper confirmation timeout for %s", obs.TxHash)
}

func (b *Broadcaster) record(ctx context.Context, req Request, obs Observation, state LifecycleState, height uint64, reason string) error {
	if b.cfg.Lifecycle == nil {
		return nil
	}
	return b.cfg.Lifecycle.RecordTxLifecycle(ctx, LifecycleRecord{TaskID: req.TaskID, Kind: req.Kind, TxHash: obs.TxHash, State: state, Height: height, Reason: reason, PayloadDigest: obs.PayloadDigest, MaterialDigest: req.MaterialDigest})
}

func waitPoll(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (b *Broadcaster) validateConfig() error {
	if strings.TrimSpace(b.cfg.ChainID) == "" {
		return fmt.Errorf("chain id is required")
	}
	if b.cfg.Signer == nil {
		return fmt.Errorf("signer is required")
	}
	if b.cfg.RPC == nil {
		return fmt.Errorf("rpc is required")
	}
	if b.cfg.Confirmer == nil {
		return fmt.Errorf("Keeper confirmer is required")
	}
	if b.cfg.GasLimit == 0 {
		return fmt.Errorf("gas limit is required")
	}
	if strings.TrimSpace(b.cfg.FeeDenom) == "" {
		return fmt.Errorf("fee denom is required")
	}
	if b.cfg.MaxFeeAmount == 0 {
		return fmt.Errorf("max fee amount is required")
	}
	return nil
}

func (b *Broadcaster) validateFee(fee Coin) error {
	if fee.Amount == 0 {
		return fmt.Errorf("fee cap is required")
	}
	if strings.TrimSpace(fee.Denom) == "" {
		return fmt.Errorf("fee denom is required")
	}
	if fee.Denom != b.cfg.FeeDenom {
		return fmt.Errorf("fee denom %q does not match configured denom %q", fee.Denom, b.cfg.FeeDenom)
	}
	if fee.Amount > b.cfg.MaxFeeAmount {
		return fmt.Errorf("fee cap exceeded: %d > %d %s", fee.Amount, b.cfg.MaxFeeAmount, b.cfg.FeeDenom)
	}
	return nil
}

func retryableBroadcastCode(code uint32) bool {
	return code == CodeWrongSequence || code == CodeMempoolRejected
}

func retryableDependencyError(err error) bool {
	return errors.Is(err, ErrRetryableCosmos) || errors.Is(err, signerclient.ErrRetryable) || chainclient.IsRetryable(err)
}
