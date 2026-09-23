package txclient

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/codec"
)

func TestBroadcasterAcceptsTxAfterSequenceRetry(t *testing.T) {
	ctx := context.Background()
	signer := &recordingSigner{address: "cortex1operator", signedTx: []byte("signed-tx")}
	rpc := &scriptedRPC{
		account: Account{Address: "cortex1operator", Sequence: 7},
		results: []BroadcastResult{
			{Code: CodeWrongSequence, Log: "account sequence mismatch"},
			{Code: CodeOK, TxHash: "0xaccepted"},
		},
	}
	b := NewBroadcaster(BroadcasterConfig{
		ChainID:      "trueopen-devnet-1",
		GasPayer:     "cortex1operator",
		MaxFeeAmount: 500,
		FeeDenom:     "uctx",
		GasLimit:     200000,
		Signer:       signer,
		RPC:          rpc,
		Confirmer:    confirmAlways(),
	})

	obs, err := b.Submit(ctx, Request{
		TaskID:         "task-1",
		Kind:           MsgDeclareModelSupport,
		Payload:        validPayload(t, MsgDeclareModelSupport),
		GasPayer:       "cortex1operator",
		FeeCap:         Coin{Amount: 250, Denom: "uctx"},
		MaterialDigest: digest("material-1"),
	})
	if err != nil {
		t.Fatalf("Submit returned error: %v", err)
	}
	if !obs.Accepted || obs.TxHash != "0xaccepted" || obs.AccountSequence != 8 {
		t.Fatalf("observation = %#v, want accepted retry with refreshed sequence", obs)
	}
	if len(rpc.broadcasts) != 2 {
		t.Fatalf("broadcast attempts = %d, want 2", len(rpc.broadcasts))
	}
	if got := signer.requests[1].AccountSequence; got != 8 {
		t.Fatalf("second signed sequence = %d, want 8", got)
	}
	if signer.requests[1].AccountNumber != 0 || signer.requests[1].GasLimit != 200000 {
		t.Fatalf("second sign request account/gas = %#v", signer.requests[1])
	}
}

func TestBroadcasterProbeOnlyQueriesGasPayerAccount(t *testing.T) {
	rpc := &scriptedRPC{account: Account{Address: "cortex1operator", Sequence: 7}}
	b := NewBroadcaster(BroadcasterConfig{
		ChainID: "chain-1", GasPayer: "cortex1operator", MaxFeeAmount: 10, FeeDenom: "utrueopen", GasLimit: 200000,
		Signer: &recordingSigner{address: "cortex1operator"}, RPC: rpc, Confirmer: confirmAlways(),
	})
	if err := b.Probe(context.Background()); err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(rpc.broadcasts) != 0 {
		t.Fatalf("Probe() broadcast %d transactions, want 0", len(rpc.broadcasts))
	}
}

func TestBroadcasterProbeRejectsAccountMismatchAndCancellation(t *testing.T) {
	b := NewBroadcaster(BroadcasterConfig{
		ChainID: "chain-1", GasPayer: "cortex1operator", MaxFeeAmount: 10, FeeDenom: "utrueopen", GasLimit: 200000,
		Signer: &recordingSigner{}, RPC: &scriptedRPC{account: Account{Address: "cortex1other"}}, Confirmer: confirmAlways(),
	})
	if err := b.Probe(context.Background()); err == nil || !strings.Contains(err.Error(), "address mismatch") {
		t.Fatalf("Probe() error = %v, want account mismatch", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.Probe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Probe(canceled) error = %v, want context.Canceled", err)
	}
}

func TestBroadcasterAlwaysLoadsAccountNumberWhenSequenceIsProvided(t *testing.T) {
	signer := &recordingSigner{address: "cortex1operator", signedTx: []byte("signed-tx")}
	rpc := &scriptedRPC{
		account: Account{Address: "cortex1operator", AccountNumber: 42, Sequence: 7},
		results: []BroadcastResult{{Code: CodeOK, TxHash: "ABC"}},
	}
	b := NewBroadcaster(BroadcasterConfig{
		ChainID: "chain-1", GasPayer: "cortex1operator", MaxFeeAmount: 10, FeeDenom: "utrueopen", GasLimit: 200000,
		Signer: signer, RPC: rpc, Confirmer: confirmAlways(),
	})

	_, err := b.Submit(context.Background(), Request{
		TaskID: "task-1", Kind: MsgSubmitVerifyCommit, Payload: validPayload(t, MsgSubmitVerifyCommit),
		FeeCap: Coin{Amount: 1, Denom: "utrueopen"}, AccountSequence: 6,
	})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if len(signer.requests) != 1 || signer.requests[0].AccountNumber != 42 || signer.requests[0].AccountSequence != 6 {
		t.Fatalf("sign requests = %#v, want account number 42 and requested sequence 6", signer.requests)
	}
}

func TestBroadcasterSeparatesBroadcastInclusionAndKeeperConfirmation(t *testing.T) {
	rpc := &scriptedRPC{account: Account{Address: "cortex1operator", AccountNumber: 7, Sequence: 1}, results: []BroadcastResult{{Code: CodeOK, TxHash: "ABC"}}, inclusions: []InclusionResult{{Code: CodeOK, Height: 123, TxHash: "ABC"}}}
	confirmCalls := 0
	recorder := &recordingLifecycle{}
	b := NewBroadcaster(BroadcasterConfig{ChainID: "chain-1", GasPayer: "cortex1operator", MaxFeeAmount: 10, FeeDenom: "utrueopen", GasLimit: 200000, PollAttempts: 3, PollInterval: time.Nanosecond, Signer: &recordingSigner{address: "cortex1operator", signedTx: []byte("tx")}, RPC: rpc, Lifecycle: recorder, Confirmer: ConfirmFunc(func(context.Context, Request, InclusionResult) (bool, error) {
		confirmCalls++
		return confirmCalls == 2, nil
	})})
	obs, err := b.Submit(context.Background(), Request{TaskID: "task-1", Kind: MsgSubmitVerifyCommit, Payload: validPayload(t, MsgSubmitVerifyCommit), FeeCap: Coin{Amount: 1, Denom: "utrueopen"}})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if !obs.Accepted || obs.Status != LifecycleKeeperConfirmed || obs.IncludedHeight != 123 || confirmCalls != 2 {
		t.Fatalf("observation = %#v calls=%d", obs, confirmCalls)
	}
	want := []LifecycleState{LifecycleBroadcast, LifecycleIncluded, LifecycleKeeperConfirmed}
	if len(recorder.records) != len(want) {
		t.Fatalf("lifecycle = %#v", recorder.records)
	}
	for i, state := range want {
		if recorder.records[i].State != state {
			t.Fatalf("lifecycle[%d] = %s, want %s", i, recorder.records[i].State, state)
		}
	}
}

func TestBroadcasterRejectsMissingBroadcastHash(t *testing.T) {
	rpc := &scriptedRPC{account: Account{Address: "cortex1operator", Sequence: 1}, results: []BroadcastResult{{Code: CodeOK}}}
	b := NewBroadcaster(BroadcasterConfig{ChainID: "chain-1", GasPayer: "cortex1operator", MaxFeeAmount: 10, FeeDenom: "utrueopen", GasLimit: 200000, Signer: &recordingSigner{address: "cortex1operator", signedTx: []byte("tx")}, RPC: rpc, Confirmer: confirmAlways()})

	_, err := b.Submit(context.Background(), Request{TaskID: "task-1", Kind: MsgSubmitVerifyCommit, Payload: validPayload(t, MsgSubmitVerifyCommit), FeeCap: Coin{Amount: 1, Denom: "utrueopen"}})
	if err == nil || !strings.Contains(err.Error(), "transaction hash") {
		t.Fatalf("Submit() error = %v, want missing transaction hash error", err)
	}
}

func TestBroadcasterPreservesIncludedTransactionOnConfirmationError(t *testing.T) {
	queryErr := errors.New("Keeper query unavailable")
	rpc := &scriptedRPC{
		account:    Account{Address: "cortex1operator", Sequence: 1},
		results:    []BroadcastResult{{Code: CodeOK, TxHash: "ABC"}},
		inclusions: []InclusionResult{{Code: CodeOK, Height: 123, TxHash: "ABC"}},
	}
	b := NewBroadcaster(BroadcasterConfig{
		ChainID: "chain-1", GasPayer: "cortex1operator", MaxFeeAmount: 10, FeeDenom: "utrueopen", GasLimit: 200000,
		Signer: &recordingSigner{address: "cortex1operator", signedTx: []byte("tx")}, RPC: rpc,
		Confirmer: ConfirmFunc(func(context.Context, Request, InclusionResult) (bool, error) { return false, queryErr }),
	})
	obs, err := b.Submit(context.Background(), Request{
		TaskID: "task-1", Kind: MsgSettleTask, Payload: validPayload(t, MsgSettleTask), FeeCap: Coin{Amount: 1, Denom: "utrueopen"},
	})
	if !errors.Is(err, queryErr) || obs.TxHash != "ABC" || obs.IncludedHeight != 123 || obs.Status != LifecycleIncluded || obs.Accepted || obs.Rejected {
		t.Fatalf("observation=%#v error=%v, want the included hash without claiming confirmation or rejection", obs, err)
	}
}

func TestBroadcasterRejectsMismatchedInclusionHash(t *testing.T) {
	rpc := &scriptedRPC{account: Account{Address: "cortex1operator", Sequence: 1}, results: []BroadcastResult{{Code: CodeOK, TxHash: "ABC"}}, inclusions: []InclusionResult{{Code: CodeOK, Height: 123, TxHash: "DEF"}}}
	b := NewBroadcaster(BroadcasterConfig{ChainID: "chain-1", GasPayer: "cortex1operator", MaxFeeAmount: 10, FeeDenom: "utrueopen", GasLimit: 200000, Signer: &recordingSigner{address: "cortex1operator", signedTx: []byte("tx")}, RPC: rpc, Confirmer: confirmAlways()})

	_, err := b.Submit(context.Background(), Request{TaskID: "task-1", Kind: MsgSubmitVerifyCommit, Payload: validPayload(t, MsgSubmitVerifyCommit), FeeCap: Coin{Amount: 1, Denom: "utrueopen"}})
	if err == nil || !strings.Contains(err.Error(), "transaction hash mismatch") {
		t.Fatalf("Submit() error = %v, want inclusion transaction hash mismatch", err)
	}
}

func TestBroadcasterRejectsDeliverTxFailure(t *testing.T) {
	rpc := &scriptedRPC{account: Account{Address: "cortex1operator", Sequence: 1}, results: []BroadcastResult{{Code: CodeOK, TxHash: "ABC"}}, inclusions: []InclusionResult{{Code: 42, Height: 123, TxHash: "ABC", Log: "Keeper rejected"}}}
	b := NewBroadcaster(BroadcasterConfig{ChainID: "chain-1", GasPayer: "cortex1operator", MaxFeeAmount: 10, FeeDenom: "utrueopen", GasLimit: 200000, Signer: &recordingSigner{address: "cortex1operator", signedTx: []byte("tx")}, RPC: rpc, Confirmer: confirmAlways()})
	obs, err := b.Submit(context.Background(), Request{TaskID: "task-1", Kind: MsgSubmitVerifyCommit, Payload: validPayload(t, MsgSubmitVerifyCommit), FeeCap: Coin{Amount: 1, Denom: "utrueopen"}})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if !obs.Rejected || obs.Accepted || obs.Status != LifecycleRejected || obs.RejectReason != "Keeper rejected" {
		t.Fatalf("observation = %#v", obs)
	}
}

func TestBroadcasterTimesOutWaitingForInclusion(t *testing.T) {
	rpc := &scriptedRPC{account: Account{Address: "cortex1operator", Sequence: 1}, results: []BroadcastResult{{Code: CodeOK, TxHash: "ABC"}}, txErrs: []error{ErrTxNotFound, ErrTxNotFound}}
	b := NewBroadcaster(BroadcasterConfig{ChainID: "chain-1", GasPayer: "cortex1operator", MaxFeeAmount: 10, FeeDenom: "utrueopen", GasLimit: 200000, PollAttempts: 2, PollInterval: time.Nanosecond, Signer: &recordingSigner{address: "cortex1operator", signedTx: []byte("tx")}, RPC: rpc, Confirmer: confirmAlways()})
	_, err := b.Submit(context.Background(), Request{TaskID: "task-1", Kind: MsgSubmitVerifyCommit, Payload: validPayload(t, MsgSubmitVerifyCommit), FeeCap: Coin{Amount: 1, Denom: "utrueopen"}})
	if err == nil || !strings.Contains(err.Error(), "inclusion timeout") {
		t.Fatalf("Submit() error = %v", err)
	}
}

func TestBroadcasterRetriesTemporaryAccountInclusionAndConfirmationFailures(t *testing.T) {
	rpc := &scriptedRPC{
		account:     Account{Address: "cortex1operator", Sequence: 1},
		accountErrs: []error{fmt.Errorf("%w: auth unavailable", ErrRetryableCosmos)},
		results:     []BroadcastResult{{Code: CodeOK, TxHash: "ABC"}},
		txErrs:      []error{fmt.Errorf("%w: tx index unavailable", ErrRetryableCosmos)},
		inclusions:  []InclusionResult{{Code: CodeOK, Height: 123, TxHash: "ABC"}},
	}
	confirmationCalls := 0
	b := NewBroadcaster(BroadcasterConfig{
		ChainID: "chain-1", GasPayer: "cortex1operator", MaxFeeAmount: 10, FeeDenom: "utrueopen", GasLimit: 200000,
		MaxAttempts: 4, PollAttempts: 4, PollInterval: time.Nanosecond,
		Signer: &recordingSigner{address: "cortex1operator", signedTx: []byte("tx")}, RPC: rpc,
		Confirmer: ConfirmFunc(func(context.Context, Request, InclusionResult) (bool, error) {
			confirmationCalls++
			if confirmationCalls == 1 {
				return false, fmt.Errorf("%w: Keeper unavailable", ErrRetryableCosmos)
			}
			return true, nil
		}),
	})

	obs, err := b.Submit(context.Background(), Request{TaskID: "task-1", Kind: MsgSubmitVerifyCommit, Payload: validPayload(t, MsgSubmitVerifyCommit), FeeCap: Coin{Amount: 1, Denom: "utrueopen"}})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if !obs.Accepted || confirmationCalls != 2 {
		t.Fatalf("observation = %#v confirmation calls = %d", obs, confirmationCalls)
	}
}

func TestBroadcasterRetriesAmbiguousBroadcastWithSameSignedTx(t *testing.T) {
	signer := &recordingSigner{address: "cortex1operator", signedTx: []byte("same-signed-tx")}
	rpc := &scriptedRPC{
		account:       Account{Address: "cortex1operator", Sequence: 1},
		broadcastErrs: []error{fmt.Errorf("%w: gateway unavailable", ErrRetryableCosmos)},
		results:       []BroadcastResult{{Code: CodeOK, TxHash: cosmosTxHash([]byte("same-signed-tx"))}},
		txErrs:        []error{ErrTxNotFound},
	}
	b := NewBroadcaster(BroadcasterConfig{
		ChainID: "chain-1", GasPayer: "cortex1operator", MaxFeeAmount: 10, FeeDenom: "utrueopen", GasLimit: 200000,
		MaxAttempts: 3, PollAttempts: 3, PollInterval: time.Nanosecond,
		Signer: signer, RPC: rpc, Confirmer: confirmAlways(),
	})

	obs, err := b.Submit(context.Background(), Request{TaskID: "task-1", Kind: MsgSubmitVerifyCommit, Payload: validPayload(t, MsgSubmitVerifyCommit), FeeCap: Coin{Amount: 1, Denom: "utrueopen"}})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if !obs.Accepted || len(rpc.broadcasts) != 2 || len(signer.requests) != 1 || string(rpc.broadcasts[0]) != string(rpc.broadcasts[1]) {
		t.Fatalf("observation = %#v broadcasts = %q signer requests = %d", obs, rpc.broadcasts, len(signer.requests))
	}
}

func TestBroadcasterRetriesMempoolTemporaryFailure(t *testing.T) {
	ctx := context.Background()
	signer := &recordingSigner{address: "cortex1operator", signedTx: []byte("signed-tx")}
	rpc := &scriptedRPC{
		account: Account{Address: "cortex1operator", Sequence: 1},
		results: []BroadcastResult{
			{Code: CodeMempoolRejected, Log: "mempool full"},
			{Code: CodeOK, TxHash: "0xmempool"},
		},
	}
	b := NewBroadcaster(BroadcasterConfig{
		ChainID:      "trueopen-devnet-1",
		GasPayer:     "cortex1operator",
		MaxFeeAmount: 500,
		FeeDenom:     "uctx",
		GasLimit:     200000,
		Signer:       signer,
		RPC:          rpc,
		Confirmer:    confirmAlways(),
	})

	obs, err := b.Submit(ctx, Request{
		TaskID:   "task-1",
		Kind:     MsgSettleTask,
		Payload:  validPayload(t, MsgSettleTask),
		FeeCap:   Coin{Amount: 200, Denom: "uctx"},
		GasPayer: "cortex1operator",
	})
	if err != nil {
		t.Fatalf("Submit returned error: %v", err)
	}
	if !obs.Accepted || obs.TxHash != "0xmempool" {
		t.Fatalf("observation = %#v, want accepted after mempool retry", obs)
	}
	if len(rpc.broadcasts) != 2 {
		t.Fatalf("broadcast attempts = %d, want 2", len(rpc.broadcasts))
	}
}

func TestBroadcasterRejectsFeeCapExceededBeforeSigning(t *testing.T) {
	signer := &recordingSigner{address: "cortex1operator", signedTx: []byte("signed-tx")}
	rpc := &scriptedRPC{account: Account{Address: "cortex1operator", Sequence: 1}}
	b := NewBroadcaster(BroadcasterConfig{
		ChainID:      "trueopen-devnet-1",
		GasPayer:     "cortex1operator",
		MaxFeeAmount: 100,
		FeeDenom:     "uctx",
		GasLimit:     200000,
		Signer:       signer,
		RPC:          rpc,
		Confirmer:    confirmAlways(),
	})

	_, err := b.Submit(context.Background(), Request{
		TaskID:   "task-1",
		Kind:     MsgDeclareModelSupport,
		Payload:  validPayload(t, MsgDeclareModelSupport),
		FeeCap:   Coin{Amount: 101, Denom: "uctx"},
		GasPayer: "cortex1operator",
	})
	if err == nil || !strings.Contains(err.Error(), "fee cap exceeded") {
		t.Fatalf("Submit error = %v, want fee cap exceeded", err)
	}
	if len(signer.requests) != 0 || len(rpc.broadcasts) != 0 {
		t.Fatalf("signer requests=%d broadcasts=%d, want no side effects", len(signer.requests), len(rpc.broadcasts))
	}
}

func TestBroadcasterRejectsGasPayerDifferentFromCurrentServiceSigner(t *testing.T) {
	signer := &recordingSigner{address: "trueopen1service", signedTx: []byte("signed-tx")}
	b := NewBroadcaster(BroadcasterConfig{
		ChainID: "trueopen-devnet-1", GasPayer: "trueopen1operator", MaxFeeAmount: 500,
		FeeDenom: "utrueopen", GasLimit: 200000, Signer: signer,
		RPC: &scriptedRPC{account: Account{Address: "trueopen1service", Sequence: 1}}, Confirmer: confirmAlways(),
	})

	_, err := b.Submit(context.Background(), Request{
		TaskID: "task-1", Kind: MsgSubmitVerifyCommit, Payload: validPayload(t, MsgSubmitVerifyCommit),
		FeeCap: Coin{Amount: 100, Denom: "utrueopen"},
	})
	if err == nil || !strings.Contains(err.Error(), "current service signer") {
		t.Fatalf("Submit error = %v, want gas payer/service signer mismatch rejection", err)
	}
}

func TestBroadcasterReturnsRejectedObservationForInsufficientFundsAndRejectedCode(t *testing.T) {
	for name, result := range map[string]BroadcastResult{
		"insufficient funds": {Code: CodeInsufficientFunds, Log: "insufficient funds"},
		"rejected":           {Code: 42, Log: "keeper rejected tx"},
	} {
		t.Run(name, func(t *testing.T) {
			signer := &recordingSigner{address: "cortex1operator", signedTx: []byte("signed-tx")}
			rpc := &scriptedRPC{
				account: Account{Address: "cortex1operator", Sequence: 1},
				results: []BroadcastResult{result},
			}
			b := NewBroadcaster(BroadcasterConfig{
				ChainID:      "trueopen-devnet-1",
				GasPayer:     "cortex1operator",
				MaxFeeAmount: 500,
				FeeDenom:     "uctx",
				GasLimit:     200000,
				Signer:       signer,
				RPC:          rpc,
				Confirmer:    confirmAlways(),
			})

			obs, err := b.Submit(context.Background(), Request{
				TaskID:   "task-1",
				Kind:     MsgBatchConfirmModelSupport,
				Payload:  validPayload(t, MsgBatchConfirmModelSupport),
				FeeCap:   Coin{Amount: 200, Denom: "uctx"},
				GasPayer: "cortex1operator",
			})
			if err != nil {
				t.Fatalf("Submit returned error: %v", err)
			}
			if !obs.Rejected || obs.Accepted || obs.RejectReason != result.Log {
				t.Fatalf("observation = %#v, want rejected reason %q", obs, result.Log)
			}
		})
	}
}

func TestBroadcasterHonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b := NewBroadcaster(BroadcasterConfig{
		ChainID:      "trueopen-devnet-1",
		GasPayer:     "cortex1operator",
		MaxFeeAmount: 500,
		FeeDenom:     "uctx",
		GasLimit:     200000,
		Signer:       &recordingSigner{address: "cortex1operator", signedTx: []byte("signed-tx")},
		RPC:          &scriptedRPC{account: Account{Address: "cortex1operator", Sequence: 1}},
		Confirmer:    confirmAlways(),
	})

	_, err := b.Submit(ctx, Request{
		TaskID:   "task-1",
		Kind:     MsgSubmitVerifyResult,
		Payload:  validPayload(t, MsgSubmitVerifyResult),
		FeeCap:   Coin{Amount: 200, Denom: "uctx"},
		GasPayer: "cortex1operator",
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Submit error = %v, want context canceled", err)
	}
}

func TestRequestValidationCoversProductionFieldsAndKinds(t *testing.T) {
	for _, kind := range []Kind{
		MsgDeclareModelSupport,
		MsgBatchConfirmModelSupport,
		MsgSubmitInferReceipt,
		MsgSubmitVerifyCommit,
		MsgSubmitVerifyResult,
		MsgSettleTask,
		MsgSweepDeadline,
	} {
		if !kind.Valid() {
			t.Fatalf("%s should be valid", kind)
		}
	}
	err := ValidateRequest(Request{
		TaskID:          "task-1",
		Kind:            MsgDeclareModelSupport,
		Payload:         validPayload(t, MsgDeclareModelSupport),
		GasPayer:        "cortex1operator",
		FeeCap:          Coin{Amount: 1, Denom: "uctx"},
		AccountSequence: 12,
		DeadlineHeight:  123,
		MaterialDigest:  digest("material-1"),
	})
	if err != nil {
		t.Fatalf("ValidateRequest returned error: %v", err)
	}
	if err := ValidateRequest(Request{TaskID: "task-1", Kind: Kind("MsgUnknownTx"), Payload: []byte("payload")}); err == nil {
		t.Fatalf("unsupported kind accepted")
	}
	// Every task.v1 name the frozen tx.proto de-registers must stay
	// unbroadcastable. These are the thirteen URLs Cortex used before the freeze
	// plus the four fault/fraud proof labels no Keeper ever registered.
	for _, unsupported := range []Kind{
		"/task.v1.MsgInferReceiptCommitOnly",
		"/task.v1.MsgCommit",
		"/task.v1.MsgBatchCommit",
		"/task.v1.MsgResult",
		"/task.v1.MsgBatchResult",
		"/task.v1.MsgWorkerReveal",
		"/task.v1.MsgSettle",
		"/task.v1.MsgSweepExpiredTask",
		"/task.v1.MsgSessionSweep",
		"/task.v1.MsgAssign",
		"/task.v1.MsgOpenVerify",
		"/task.v1.MsgUserChallenge",
		"/task.v1.MsgChallengeCommit",
		"/task.v1.MsgChallengeResult",
		"/task.v1.MsgSubmitChallengeFullResultReveal",
		"/task.v1.MsgOutputHashMismatchProof",
		"/task.v1.MsgSubmitFraudProof",
		"/task.v1.MsgSubmitFaultProof",
		"/task.v1.MsgSubmitVerdictFraudProof",
		"/task.v1.MsgUpdateTimeoutBucket",
	} {
		if unsupported.Valid() {
			t.Fatalf("de-registered Keeper kind %s accepted", unsupported)
		}
	}
}

func digest(value string) codec.Hash {
	return codec.HashWithDomain("TEST_DIGEST_V1", []byte(value))
}

func confirmAlways() Confirmer {
	return ConfirmFunc(func(context.Context, Request, InclusionResult) (bool, error) { return true, nil })
}

type recordingSigner struct {
	address  string
	signedTx []byte
	requests []SignRequest
}

func (s *recordingSigner) Address(context.Context, Kind) (string, error) {
	return s.address, nil
}

func (s *recordingSigner) Sign(_ context.Context, req SignRequest) ([]byte, error) {
	s.requests = append(s.requests, req)
	return append([]byte(nil), s.signedTx...), nil
}

type scriptedRPC struct {
	account       Account
	accountErrs   []error
	results       []BroadcastResult
	broadcastErrs []error
	broadcasts    [][]byte
	inclusions    []InclusionResult
	txErrs        []error
}

func (r *scriptedRPC) Account(context.Context, string) (Account, error) {
	if len(r.accountErrs) > 0 {
		err := r.accountErrs[0]
		r.accountErrs = r.accountErrs[1:]
		return Account{}, err
	}
	account := r.account
	r.account.Sequence++
	return account, nil
}

func (r *scriptedRPC) BroadcastTx(_ context.Context, tx []byte) (BroadcastResult, error) {
	r.broadcasts = append(r.broadcasts, append([]byte(nil), tx...))
	if len(r.broadcastErrs) > 0 {
		err := r.broadcastErrs[0]
		r.broadcastErrs = r.broadcastErrs[1:]
		return BroadcastResult{}, err
	}
	if len(r.results) == 0 {
		return BroadcastResult{Code: CodeOK, TxHash: "0xdefault"}, nil
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result, nil
}

func (r *scriptedRPC) Tx(_ context.Context, txHash string) (InclusionResult, error) {
	if len(r.txErrs) > 0 {
		err := r.txErrs[0]
		r.txErrs = r.txErrs[1:]
		return InclusionResult{}, err
	}
	if len(r.inclusions) > 0 {
		result := r.inclusions[0]
		r.inclusions = r.inclusions[1:]
		return result, nil
	}
	return InclusionResult{Code: CodeOK, Height: 123, TxHash: txHash}, nil
}

type recordingLifecycle struct{ records []LifecycleRecord }

func (r *recordingLifecycle) RecordTxLifecycle(_ context.Context, record LifecycleRecord) error {
	r.records = append(r.records, record)
	return nil
}
