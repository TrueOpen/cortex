package modelregistry

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/keepercontract"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/txclient"
	"github.com/TrueOpen/cortex/internal/wirevectors"
	hubv1 "github.com/TrueOpen/cortex/proto/hub/v1"
)

const (
	relayOperator = "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc"
	relayModelA   = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
	relayModelB   = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
)

type relayCall struct {
	epoch        uint64
	confirmation []byte
	digest       codec.Hash
}

type recordingSupportRelay struct {
	calls []relayCall
	err   error
}

func (r *recordingSupportRelay) RelaySupportConfirmation(_ context.Context, epoch uint64, confirmation []byte, digest codec.Hash) error {
	r.calls = append(r.calls, relayCall{epoch: epoch, confirmation: append([]byte(nil), confirmation...), digest: digest})
	return r.err
}

// relayOnlyConfirmer is a file:// keystore node: no tx client ever, a relay, and
// an activated service address.
func relayOnlyConfirmer(relay SupportRelay, digestSigner signer.DigestSigner, address func() string) SupportConfirmer {
	return NewTxSupportConfirmer(nil, TxSupportConfirmerOptions{
		ChainID: "chain-1", OperatorAddress: relayOperator,
		Signer: digestSigner, ServiceKeyRef: "kms://service",
		ServiceIdentity:     func(context.Context) (uint64, uint64, uint64, uint64, error) { return 3, 100, 1, 199, nil },
		SupportedModels:     []string{relayModelB, relayModelA},
		Workload:            func() (txclient.Client, string) { return nil, "" },
		TxUnavailable:       func() string { return "the configured signer cannot sign Cosmos transactions" },
		Relay:               relay,
		RelayServiceAddress: address,
	})
}

func dailyMaterial(model string) SupportMaterial {
	return SupportMaterial{ModelID: model, ProfileVersion: "1", SupportMode: SupportModeDaily, Supported: true}
}

func TestTxSupportConfirmerRelaysWhenItCannotSubmit(t *testing.T) {
	relay := &recordingSupportRelay{}
	signedAs := ""
	digestSigner := signer.DigestSignerFunc(func(_ context.Context, req signer.DigestRequest) ([]byte, error) {
		signedAs = req.ExpectedSignerAddress
		return []byte(strings.Repeat("s", 64)), nil
	})
	confirmer := relayOnlyConfirmer(relay, digestSigner, func() string { return "trueopen1service" })
	if _, err := confirmer.ConfirmSupport(context.Background(), dailyMaterial(relayModelB)); err != nil {
		t.Fatalf("ConfirmSupport: %v", err)
	}
	if len(relay.calls) != 1 {
		t.Fatalf("relay calls = %d, want 1", len(relay.calls))
	}
	call := relay.calls[0]
	wantDigest, err := keepercontract.DailySupportConfirmation("chain-1", relayOperator, 1, 3, 199, []string{relayModelA, relayModelB})
	if err != nil {
		t.Fatal(err)
	}
	if call.epoch != 1 || call.digest != wantDigest || signedAs != "trueopen1service" {
		t.Fatalf("epoch=%d digest=%x signedAs=%q", call.epoch, call.digest, signedAs)
	}
	var got hubv1.ModelSupportConfirmationV1
	if err := proto.Unmarshal(call.confirmation, &got); err != nil {
		t.Fatal(err)
	}
	if got.OperatorAddress != relayOperator || got.ServiceAuthorizationNonce != 3 || got.ExpiryHeight != 199 ||
		!bytes.Equal(got.ServiceSignature, []byte(strings.Repeat("s", 64))) || len(got.SupportedModels) != 2 ||
		hex.EncodeToString(got.SupportedModels[0]) != relayModelA || hex.EncodeToString(got.SupportedModels[1]) != relayModelB {
		t.Fatalf("confirmation = %v", &got)
	}
}

// Retries within an epoch resend the material already signed, never a fresh
// signature: different signed material for the same operator/epoch conflicts.
func TestTxSupportConfirmerRelayRetryReusesTheSignedMaterial(t *testing.T) {
	relay := &recordingSupportRelay{}
	signatures := 0
	digestSigner := signer.DigestSignerFunc(func(context.Context, signer.DigestRequest) ([]byte, error) {
		signatures++
		return bytes.Repeat([]byte{byte(signatures)}, 64), nil
	})
	confirmer := relayOnlyConfirmer(relay, digestSigner, func() string { return "trueopen1service" })
	for range 3 {
		if _, err := confirmer.ConfirmSupport(context.Background(), dailyMaterial(relayModelA)); err != nil {
			t.Fatal(err)
		}
	}
	if signatures != 1 || len(relay.calls) != 3 {
		t.Fatalf("signatures = %d, relay calls = %d; want 1 and 3", signatures, len(relay.calls))
	}
	for _, call := range relay.calls[1:] {
		if !bytes.Equal(call.confirmation, relay.calls[0].confirmation) {
			t.Fatal("a retry relayed different signed material")
		}
	}
}

func TestTxSupportConfirmerPrefersItsOwnTransaction(t *testing.T) {
	relay := &recordingSupportRelay{}
	tx := &recordingTxClient{obs: txclient.Observation{Accepted: true, Status: txclient.LifecycleKeeperConfirmed, TxHash: "tx-support"}}
	confirmer := NewTxSupportConfirmer(nil, TxSupportConfirmerOptions{
		ChainID: "chain-1", OperatorAddress: relayOperator,
		Signer: signer.DigestSignerFunc(func(context.Context, signer.DigestRequest) ([]byte, error) {
			return []byte(strings.Repeat("s", 64)), nil
		}),
		ServiceIdentity:     func(context.Context) (uint64, uint64, uint64, uint64, error) { return 3, 100, 1, 199, nil },
		SupportedModels:     []string{relayModelA},
		Workload:            func() (txclient.Client, string) { return tx, "trueopen1service" },
		Relay:               relay,
		RelayServiceAddress: func() string { return "trueopen1service" },
	})
	if _, err := confirmer.ConfirmSupport(context.Background(), dailyMaterial(relayModelA)); err != nil {
		t.Fatal(err)
	}
	if len(tx.requests) != 1 || len(relay.calls) != 0 {
		t.Fatalf("tx requests = %d, relay calls = %d; want the node's own transaction only", len(tx.requests), len(relay.calls))
	}
}

func TestTxSupportConfirmerRelayNeedsAnActiveServiceKey(t *testing.T) {
	relay := &recordingSupportRelay{}
	confirmer := relayOnlyConfirmer(relay, signer.DigestSignerFunc(func(context.Context, signer.DigestRequest) ([]byte, error) {
		return []byte(strings.Repeat("s", 64)), nil
	}), func() string { return "" })
	_, err := confirmer.ConfirmSupport(context.Background(), dailyMaterial(relayModelA))
	if err == nil || !strings.Contains(err.Error(), "workload is not active") || len(relay.calls) != 0 {
		t.Fatalf("err = %v, relay calls = %d", err, len(relay.calls))
	}
}

func TestTxSupportConfirmerReportsARelayFailure(t *testing.T) {
	relay := &recordingSupportRelay{err: errors.New("every Builder refused")}
	confirmer := relayOnlyConfirmer(relay, signer.DigestSignerFunc(func(context.Context, signer.DigestRequest) ([]byte, error) {
		return []byte(strings.Repeat("s", 64)), nil
	}), func() string { return "trueopen1service" })
	if _, err := confirmer.ConfirmSupport(context.Background(), dailyMaterial(relayModelA)); err == nil || !strings.Contains(err.Error(), "every Builder refused") {
		t.Fatalf("err = %v", err)
	}
}

// The relayed bytes are wire's published confirmation encoding.
func TestSupportConfirmationBytesMatchWireVector(t *testing.T) {
	raw, err := wirevectors.File("hub/model_support_relay_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Confirmation struct {
			OperatorAddress           string   `json:"operator_address"`
			SupportedModelsHex        []string `json:"supported_models_hex"`
			ServiceAuthorizationNonce uint64   `json:"service_authorization_nonce,string"`
			ExpiryHeight              uint64   `json:"expiry_height,string"`
			ServiceSignatureHex       string   `json:"service_signature_hex"`
		} `json:"confirmation"`
		ConfirmationProtobufHex string `json:"confirmation_protobuf_hex"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	signature, _ := hex.DecodeString(v.Confirmation.ServiceSignatureHex)
	got, err := supportConfirmationBytes(v.Confirmation.OperatorAddress, v.Confirmation.SupportedModelsHex,
		v.Confirmation.ServiceAuthorizationNonce, v.Confirmation.ExpiryHeight, signature)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != v.ConfirmationProtobufHex {
		t.Fatalf("confirmation bytes = %x, want %s", got, v.ConfirmationProtobufHex)
	}
}
