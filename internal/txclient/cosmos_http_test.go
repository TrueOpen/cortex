package txclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/signer"
)

func TestCosmosBroadcasterUsesDeliverTxInclusionForCommitWithoutQuery(t *testing.T) {
	txHash := cosmosTxHash([]byte("signed-tx"))
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cosmos/auth/v1beta1/accounts/trueopen1service":
			_, _ = w.Write([]byte(`{"account":{"@type":"/cosmos.auth.v1beta1.BaseAccount","address":"trueopen1service","account_number":"7","sequence":"9"}}`))
		case "/cosmos/tx/v1beta1/txs":
			_, _ = w.Write([]byte(`{"tx_response":{"code":0,"txhash":"` + txHash + `","raw_log":""}}`))
		case "/cosmos/tx/v1beta1/txs/" + txHash:
			_, _ = w.Write([]byte(`{"tx_response":{"height":"42","code":0,"txhash":"` + txHash + `","raw_log":""}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	signerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sign/cosmos-tx" {
			http.NotFound(w, r)
			return
		}
		var request signer.CosmosTxRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode signer request: %v", err)
		}
		if request.ExpectedSignerAddress != "trueopen1service" || request.AccountNumber != 7 || request.Sequence != 9 || request.FeePayer != "trueopen1service" || request.Messages[0].TypeURL != MsgSubmitVerifyCommit.String() {
			t.Fatalf("signer request = %#v", request)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"tx_raw": base64.StdEncoding.EncodeToString([]byte("signed-tx")), "signer_address": "trueopen1service"})
	}))
	defer signerServer.Close()

	lifecycle := &recordingLifecycle{}
	signingClient := signer.NewClient(signer.ClientConfig{Endpoint: signerServer.URL})
	broadcaster := NewBroadcaster(BroadcasterConfig{
		ChainID: "chain-1", GasPayer: "trueopen1service", MaxFeeAmount: 100, FeeDenom: "utrueopen", MaxAttempts: 2,
		PollAttempts: 2, PollInterval: time.Nanosecond, GasLimit: 250000,
		Signer: NewCosmosSigner(CosmosSignerConfig{Client: signingClient, KeyRef: "kms://service", SignerAddress: "trueopen1service"}),
		RPC:    NewCosmosHTTPClient(CosmosHTTPConfig{Endpoint: api.URL}), Confirmer: NewKeeperConfirmer(chainclient.NewKeeperABCIClient(api.URL)), Lifecycle: lifecycle,
	})
	obs, err := broadcaster.Submit(context.Background(), Request{TaskID: "task-1", Kind: MsgSubmitVerifyCommit, Payload: validPayload(t, MsgSubmitVerifyCommit), FeeCap: Coin{Amount: 10, Denom: "utrueopen"}, MaterialDigest: digest("material")})
	if err != nil {
		t.Fatalf("Submit returned error: %v", err)
	}
	if !obs.Accepted || obs.Status != LifecycleKeeperConfirmed || obs.IncludedHeight != 42 || obs.TxHash != txHash {
		t.Fatalf("observation = %#v", obs)
	}
	if len(lifecycle.records) != 3 || lifecycle.records[0].State != LifecycleBroadcast || lifecycle.records[1].State != LifecycleIncluded || lifecycle.records[2].State != LifecycleKeeperConfirmed {
		t.Fatalf("lifecycle = %#v", lifecycle.records)
	}
}

func TestCosmosHTTPAccountBroadcastAndInclusion(t *testing.T) {
	txRaw := []byte("signed tx raw")
	txHash := cosmosTxHash(txRaw)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cosmos/auth/v1beta1/accounts/trueopen1operator":
			_ = json.NewEncoder(w).Encode(map[string]any{"account": map[string]any{"@type": "/cosmos.auth.v1beta1.BaseAccount", "address": "trueopen1operator", "account_number": "7", "sequence": "9"}})
		case "/cosmos/tx/v1beta1/txs":
			if r.Method != http.MethodPost {
				t.Fatalf("broadcast method = %s", r.Method)
			}
			var req map[string]string
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode broadcast: %v", err)
			}
			if req["tx_bytes"] != base64.StdEncoding.EncodeToString(txRaw) || req["mode"] != "BROADCAST_MODE_SYNC" {
				t.Fatalf("broadcast request = %#v", req)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"tx_response": map[string]any{"code": 0, "txhash": txHash, "raw_log": ""}})
		case "/cosmos/tx/v1beta1/txs/" + txHash:
			_ = json.NewEncoder(w).Encode(map[string]any{"tx_response": map[string]any{"height": "123", "code": 0, "txhash": txHash, "raw_log": ""}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewCosmosHTTPClient(CosmosHTTPConfig{Endpoint: server.URL})
	account, err := client.Account(context.Background(), "trueopen1operator")
	if err != nil || account.Address != "trueopen1operator" || account.AccountNumber != 7 || account.Sequence != 9 {
		t.Fatalf("account = %#v err=%v", account, err)
	}
	broadcast, err := client.BroadcastTx(context.Background(), txRaw)
	if err != nil || broadcast.Code != 0 || broadcast.TxHash != txHash {
		t.Fatalf("broadcast = %#v err=%v", broadcast, err)
	}
	inclusion, err := client.Tx(context.Background(), txHash)
	if err != nil || inclusion.Code != 0 || inclusion.Height != 123 {
		t.Fatalf("inclusion = %#v err=%v", inclusion, err)
	}
}

func TestCosmosSignerBuildsExactSignerEnvelope(t *testing.T) {
	client := &capturingCosmosSigner{raw: []byte("tx-raw")}
	adapter := NewCosmosSigner(CosmosSignerConfig{Client: client, KeyRef: "kms://operator", SignerAddress: "trueopen1operator"})
	raw, err := adapter.Sign(context.Background(), SignRequest{ChainID: "chain-1", Kind: MsgSubmitVerifyCommit, Payload: validPayload(t, MsgSubmitVerifyCommit), GasPayer: "trueopen1payer", AccountNumber: 7, AccountSequence: 9, GasLimit: 200000, Fee: Coin{Amount: 10, Denom: "uusdc"}, FeeGrant: "trueopen1granter", Memo: "memo", DeadlineHeight: 123})
	if err != nil || string(raw) != "tx-raw" {
		t.Fatalf("Sign() raw=%q err=%v", raw, err)
	}
	req := client.req
	if req.AccountNumber != 7 || req.Sequence != 9 || req.GasLimit != 200000 || req.FeeDenom != "uusdc" || req.FeeAmount != 10 || req.FeePayer != "trueopen1payer" || req.FeeGranter != "trueopen1granter" || req.TimeoutHeight != 123 || len(req.Messages) != 1 || req.Messages[0].TypeURL != MsgSubmitVerifyCommit.String() {
		t.Fatalf("signer request = %#v", req)
	}
}

func TestCosmosServiceSignerSubmitsSelfRescueForOperatorIdentity(t *testing.T) {
	client := &capturingCosmosSigner{raw: []byte("service-signed")}
	service := NewCosmosSigner(CosmosSignerConfig{Client: client, KeyRef: "service.json", SignerAddress: "trueopen1service"})
	// worker_operator_address inside the receipt is the stable operator, not the Tx signer.
	payload := validPayload(t, MsgSubmitInferReceipt)
	if _, err := service.Sign(context.Background(), SignRequest{ChainID: "chain-1", Kind: MsgSubmitInferReceipt, Payload: payload}); err != nil {
		t.Fatalf("service self-rescue Sign() error = %v", err)
	}
	if client.req.ExpectedSignerAddress != "trueopen1service" || client.req.KeyRef != "service.json" {
		t.Fatalf("self-rescue signer request = %#v", client.req)
	}
}

type capturingCosmosSigner struct {
	req signer.CosmosTxRequest
	raw []byte
}

func (c *capturingCosmosSigner) SignCosmosTx(_ context.Context, req signer.CosmosTxRequest) ([]byte, error) {
	c.req = req
	return append([]byte(nil), c.raw...), nil
}

func TestCosmosHTTPClassifiesMissingTxAsPending(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	client := NewCosmosHTTPClient(CosmosHTTPConfig{Endpoint: server.URL})
	if _, err := client.Tx(context.Background(), "ABC123"); err != ErrTxNotFound {
		t.Fatalf("Tx() error = %v, want ErrTxNotFound", err)
	}
}

func TestCosmosHTTPClassifiesRateLimitsServerAndTransportFailuresAsRetryable(t *testing.T) {
	for name, status := range map[string]int{
		"rate limit":     http.StatusTooManyRequests,
		"server failure": http.StatusServiceUnavailable,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			defer server.Close()

			client := NewCosmosHTTPClient(CosmosHTTPConfig{Endpoint: server.URL})
			_, err := client.Account(context.Background(), "trueopen1operator")
			if !errors.Is(err, ErrRetryableCosmos) {
				t.Fatalf("Account() error = %v, want ErrRetryableCosmos", err)
			}
		})
	}

	client := NewCosmosHTTPClient(CosmosHTTPConfig{
		Endpoint: "http://cosmos.invalid",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("temporary transport failure")
		})},
	})
	_, err := client.Account(context.Background(), "trueopen1operator")
	if !errors.Is(err, ErrRetryableCosmos) {
		t.Fatalf("Account() transport error = %v, want ErrRetryableCosmos", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
