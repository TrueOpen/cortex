package signer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
)

func TestClientSignDigestBindsCurrentKeyRefAddressAndDigest(t *testing.T) {
	digest := codec.HashBytes([]byte("keeper payload"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sign/digest" || r.Method != http.MethodPost {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		var req DigestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if req.KeyRef != "kms://service/key" || req.ExpectedSignerAddress != "trueopen1service" || req.Digest != digest {
			t.Fatalf("request = %#v", req)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"signature":      strings.Repeat("ab", 64),
			"signer_address": "trueopen1service",
		})
	}))
	defer server.Close()

	client := NewClient(ClientConfig{Endpoint: server.URL})
	signature, err := client.SignDigest(context.Background(), DigestRequest{
		KeyRef: "kms://service/key", ExpectedSignerAddress: "trueopen1service", Digest: digest,
	})
	if err != nil {
		t.Fatalf("SignDigest() error = %v", err)
	}
	if len(signature) != 64 {
		t.Fatalf("signature length = %d, want 64", len(signature))
	}
}

func TestClientSignDigestRejectsNonCanonicalResponses(t *testing.T) {
	tests := []struct {
		name     string
		response map[string]any
		want     string
	}{
		{name: "short signature", response: map[string]any{"signature": strings.Repeat("ab", 32), "signer_address": "trueopen1service"}, want: "signature"},
		{name: "uppercase signature", response: map[string]any{"signature": strings.Repeat("AB", 64), "signer_address": "trueopen1service"}, want: "signature"},
		{name: "prefixed signature", response: map[string]any{"signature": "0x" + strings.Repeat("ab", 64), "signer_address": "trueopen1service"}, want: "signature"},
		{name: "zero signature", response: map[string]any{"signature": strings.Repeat("00", 64), "signer_address": "trueopen1service"}, want: "signature"},
		{name: "wrong signer", response: map[string]any{"signature": strings.Repeat("ab", 64), "signer_address": "trueopen1other"}, want: "signer address"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()
			client := NewClient(ClientConfig{Endpoint: server.URL})
			_, err := client.SignDigest(context.Background(), DigestRequest{
				KeyRef: "kms://service/key", ExpectedSignerAddress: "trueopen1service", Digest: codec.HashBytes([]byte("payload")),
			})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("SignDigest() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestClientSignDigestRejectsNonCanonicalRecoverableSignature(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"signature": strings.Repeat("ab", 65), "signer_address": "trueopen1service",
		})
	}))
	defer server.Close()
	client := NewClient(ClientConfig{Endpoint: server.URL})

	_, err := client.SignDigest(context.Background(), DigestRequest{
		KeyRef: "kms://service/key", ExpectedSignerAddress: "trueopen1service", Digest: codec.HashBytes([]byte("payload")),
	})
	if err == nil || !strings.Contains(err.Error(), "64-byte") {
		t.Fatalf("SignDigest() error = %v, want non-canonical signature rejection", err)
	}
}

func TestClientSignCosmosTxReturnsRawBytes(t *testing.T) {
	for _, denom := range []string{"uusdc", "utrueopen", "hyperlane/0x4444444444444444444444444444444444444444"} {
		t.Run(denom, func(t *testing.T) { testClientSignCosmosTxReturnsRawBytes(t, denom) })
	}
}

func testClientSignCosmosTxReturnsRawBytes(t *testing.T, denom string) {
	t.Helper()
	want := []byte("signed tx raw")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sign/cosmos-tx" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		var req CosmosTxRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if req.KeyRef != "kms://operator/key" || req.FeePayer != "trueopen1operator" || req.FeeDenom != denom || req.FeeAmount != 1000 || len(req.Messages) != 1 || req.Messages[0].TypeURL != "/hub.v1.MsgDeclareModelSupport" {
			t.Fatalf("request = %#v", req)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tx_raw":         base64.StdEncoding.EncodeToString(want),
			"signer_address": "trueopen1operator",
		})
	}))
	defer server.Close()

	client := NewClient(ClientConfig{Endpoint: server.URL})
	got, err := client.SignCosmosTx(context.Background(), CosmosTxRequest{
		KeyRef: "kms://operator/key", ExpectedSignerAddress: "trueopen1operator", ChainID: "trueopen-mainnet-1",
		AccountNumber: 4, Sequence: 5, GasLimit: 200000, FeeAmount: 1000, FeeDenom: denom, FeePayer: "trueopen1operator",
		Messages: []CosmosMessage{{TypeURL: "/hub.v1.MsgDeclareModelSupport", Value: json.RawMessage(`{"operator_address":"trueopen1operator"}`)}},
	})
	if err != nil {
		t.Fatalf("SignCosmosTx() error = %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("tx raw = %q, want %q", got, want)
	}
}

func TestClientSignCosmosTxRejectsInvalidFeeDenomBeforeSending(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, "unexpected signer request", http.StatusInternalServerError)
	}))
	defer server.Close()
	client := NewClient(ClientConfig{Endpoint: server.URL})
	for _, denom := range []string{"", " uusdc", "uusdc ", "u usdc", "12coin", "us", strings.Repeat("u", 129)} {
		_, err := client.SignCosmosTx(context.Background(), CosmosTxRequest{
			KeyRef: "service", ExpectedSignerAddress: "trueopen1service", ChainID: "chain-1",
			GasLimit: 200000, FeeAmount: 10, FeeDenom: denom, FeePayer: "trueopen1service",
			Messages: []CosmosMessage{{TypeURL: "/task.v1.MsgSweepDeadline", Value: json.RawMessage(`{}`)}},
		})
		if err == nil {
			t.Fatalf("accepted invalid fee denom %q", denom)
		}
	}
	if requests != 0 {
		t.Fatalf("sent %d invalid requests to signer", requests)
	}
}

func TestClientClassifiesHTTPFailuresWithoutLeakingMaterial(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   error
	}{
		{name: "rate limited", status: http.StatusTooManyRequests, want: ErrRetryable},
		{name: "server error", status: http.StatusServiceUnavailable, want: ErrRetryable},
		{name: "rejected", status: http.StatusBadRequest, want: ErrRejected},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte("secret-key-ref kms://service/key digest deadbeef"))
			}))
			defer server.Close()
			client := NewClient(ClientConfig{Endpoint: server.URL})
			_, err := client.SignDigest(context.Background(), DigestRequest{
				KeyRef: "kms://service/key", ExpectedSignerAddress: "trueopen1service", Digest: codec.HashBytes([]byte("deadbeef")),
			})
			if !errors.Is(err, tt.want) {
				t.Fatalf("SignDigest() error = %v, want %v", err, tt.want)
			}
			if strings.Contains(err.Error(), "kms://") || strings.Contains(err.Error(), "deadbeef") || strings.Contains(err.Error(), "secret-key-ref") {
				t.Fatalf("error leaks signed material: %q", err)
			}
		})
	}
}
