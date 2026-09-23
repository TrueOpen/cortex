package taskdataauth

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/signer"
)

const (
	authTestChainID  = "trueopen-devnet-1"
	authTestBuilder  = "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man"
	authTestOperator = "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"
	authTestKeyRef   = "service-key"
)

type authTestServiceKeys struct {
	binding chainclient.ServiceKeySnapshot
	// served is the height Keeper answers the committed read at: the height the
	// binding was read from, and the only height the authenticator may bind to.
	served uint64
	err    error
	reads  int
}

func (s *authTestServiceKeys) CommittedCurrentServiceKey(_ context.Context, participantType, operatorAddress string) (chainclient.ServiceKeySnapshot, uint64, error) {
	s.reads++
	if s.err != nil {
		return chainclient.ServiceKeySnapshot{}, 0, s.err
	}
	if participantType != chainclient.ParticipantTypeCortexNode || operatorAddress != authTestOperator {
		return chainclient.ServiceKeySnapshot{}, 0, errors.New("unexpected current service-key query")
	}
	return s.binding, s.served, nil
}

type authTestSigner struct {
	private *secp256k1.PrivateKey
	address string
	err     error
}

func (s authTestSigner) SignDigest(_ context.Context, request signer.DigestRequest) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	if request.KeyRef != authTestKeyRef || request.ExpectedSignerAddress != s.address {
		return nil, errors.New("unexpected signer identity")
	}
	signature := ecdsa.Sign(s.private, request.Digest[:])
	r, scalar := signature.R(), signature.S()
	result := make([]byte, 64)
	rBytes, sBytes := r.Bytes(), scalar.Bytes()
	copy(result[:32], rBytes[:])
	copy(result[32:], sBytes[:])
	return result, nil
}

func (authTestSigner) SignCosmosTx(context.Context, signer.CosmosTxRequest) ([]byte, error) {
	return nil, errors.New("not supported")
}

func (authTestSigner) CanSignCosmosTx() bool { return false }

func newAuthTestConfig(t *testing.T) (Config, *authTestServiceKeys) {
	t.Helper()
	private := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{0x31}, 32))
	public := private.PubKey().SerializeCompressed()
	address, err := signer.AddressFromCompressedPublicKey("trueopen", public)
	if err != nil {
		t.Fatalf("derive service address: %v", err)
	}
	binding := chainclient.ServiceKeySnapshot{
		ParticipantType:    chainclient.ParticipantTypeCortexNode,
		OperatorAddress:    authTestOperator,
		ServiceAddress:     address,
		ServicePubkey:      hex.EncodeToString(public),
		AuthorizationNonce: chainclient.NewUint64String(7),
		Status:             "ACTIVE",
	}
	keys := &authTestServiceKeys{binding: binding, served: 100}
	return Config{
		ServiceKeys: keys,
		Signer:      authTestSigner{private: private, address: address},
		ChainID:     authTestChainID, OperatorAddress: authTestOperator,
		ServiceAddress: address, ServicePubkey: binding.ServicePubkey,
		ServiceKeyRef: authTestKeyRef, ExpiryBlocks: 12,
	}, keys
}

func authObjectKey() builderclient.TaskDataKey {
	return builderclient.TaskDataKey{TaskHash: strings.Repeat("11", 32), SessionID: strings.Repeat("22", 32), TaskID: strings.Repeat("33", 32), ContentHash: strings.Repeat("44", 32), Kind: builderclient.DataKindInput}
}

func TestAuthenticatorAcceptsEthereumServiceBindingAndRejectsCosmosAddress(t *testing.T) {
	cfg, _ := newAuthTestConfig(t)
	cfg.ServicePubkey = "0298c2da175fd3063bd2e8156303b98a0f77df43c5ca078eaa08dc2533e829f507"
	cfg.OperatorAddress = "trueopen1j5me037hs26kmqz7xy6s5f0y224trsphlqjfd2"
	cfg.ServiceAddress = cfg.OperatorAddress
	if _, err := New(cfg); err != nil {
		t.Fatalf("rejected Node Ethereum service binding: %v", err)
	}
	cfg.ServiceAddress = "trueopen1nv0w37e5azv9qyvc9qhsjpkraqga30w98v708f"
	if _, err := New(cfg); err == nil {
		t.Fatal("accepted retired Cosmos address for the same public key")
	}
}
func authTestBody(t *testing.T) codec.Hash {
	t.Helper()
	digest, err := builderclient.TaskDataMetadataBodyDigest(authObjectKey())
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestAuthenticatorSignsFixedOutputStreamProjection(t *testing.T) {
	cfg, _ := newAuthTestConfig(t)
	auth, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	key := authObjectKey()
	key.Kind = builderclient.DataKindOutput
	key.ContentHash = (codec.Hash{}).String()
	body, err := builderclient.TaskDataOutputStreamBodyDigest(key.TaskHash, key.SessionID, key.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	request, err := auth.SignRequest(context.Background(), "UploadTaskOutputStream", key, authTestBuilder, body)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := builderclient.TaskDataRequestSigningHash(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.VerifyDigestSignature(cfg.ServicePubkey, digest, request.Signature); err != nil {
		t.Fatal(err)
	}
	key.TaskHash = strings.Repeat("55", 32)
	if _, err := auth.SignRequest(context.Background(), "UploadTaskOutputStream", key, authTestBuilder, body); err == nil {
		t.Fatal("signed changed stream identity")
	}
	key.Kind = builderclient.DataKindInput
	if _, err := auth.SignRequest(context.Background(), "UploadTaskOutputStream", key, authTestBuilder, body); err == nil {
		t.Fatal("signed input as output stream")
	}
}
func TestAuthenticatorSignsHeightBoundRequestAndFetch(t *testing.T) {
	cfg, keys := newAuthTestConfig(t)
	auth, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	key := authObjectKey()
	request, err := auth.SignRequest(context.Background(), "GetTaskDataMetadata", key, authTestBuilder, authTestBody(t))
	if err != nil {
		t.Fatal(err)
	}
	if request.SchemaVersion != 1 || request.RequesterKind != builderclient.TaskDataRequesterCortexService || request.Requester != cfg.OperatorAddress || request.ServiceAuthorizationNonce != 7 || request.BuilderAddress != authTestBuilder || request.Method != builderclient.TaskDataProcedure("GetTaskDataMetadata") {
		t.Fatalf("auth projection: %+v", request)
	}
	if len(request.RequestNonce) != 32 || request.ExpiresAtHeight != 112 {
		t.Fatalf("nonce and expiry: %+v", request)
	}
	digest, err := builderclient.TaskDataRequestSigningHash(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.VerifyDigestSignature(cfg.ServicePubkey, digest, request.Signature); err != nil {
		t.Fatal(err)
	}
	bounds := &builderclient.TaskDataRange{Offset: 9, Length: 17}
	fetch, err := auth.SignFetch(context.Background(), key, authTestBuilder, bounds)
	if err != nil {
		t.Fatal(err)
	}
	body, err := builderclient.TaskDataFetchBodyDigest(key, bounds)
	if err != nil {
		t.Fatal(err)
	}
	if fetch.BodyDigest != body || fetch.Method != builderclient.TaskDataProcedure("FetchTaskData") || fetch.Requester != cfg.OperatorAddress || fetch.ServiceAuthorizationNonce != 7 {
		t.Fatalf("fetch auth: %+v", fetch)
	}
	if len(fetch.RequestNonce) != 32 || bytes.Equal(fetch.RequestNonce, request.RequestNonce) {
		t.Fatal("fetch reused nonce")
	}
	digest, err = builderclient.TaskDataRequestSigningHash(fetch)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.VerifyDigestSignature(cfg.ServicePubkey, digest, fetch.Signature); err != nil {
		t.Fatal(err)
	}
	if keys.reads != 2 {
		t.Fatalf("reads=%d, want one committed lookup per signature", keys.reads)
	}
}

// The expiry a request commits to must be the served height plus ExpiryBlocks,
// never a height read separately from CometBFT's /status. A served height far from
// any default proves the signed material carries the height the read came from.
func TestAuthenticatorBindsExpiryToTheServedHeight(t *testing.T) {
	cfg, keys := newAuthTestConfig(t)
	keys.served = 4321
	auth, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key := authObjectKey()
	request, err := auth.SignRequest(context.Background(), "GetTaskDataMetadata", key, authTestBuilder, authTestBody(t))
	if err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	if request.ExpiresAtHeight != 4321+cfg.ExpiryBlocks {
		t.Fatalf("ExpiresAtHeight = %d, want served height 4321 + %d", request.ExpiresAtHeight, cfg.ExpiryBlocks)
	}
	rangeRequest, err := auth.SignFetch(context.Background(), key, authTestBuilder, &builderclient.TaskDataRange{Length: 1})
	if err != nil {
		t.Fatalf("SignRange: %v", err)
	}
	if rangeRequest.ExpiresAtHeight != 4321+cfg.ExpiryBlocks {
		t.Fatalf("range ExpiresAtHeight = %d, want served height 4321 + %d", rangeRequest.ExpiresAtHeight, cfg.ExpiryBlocks)
	}
}

// CommittedBusEnvelopeIdentity feeds TRUEOPEN_BUS_ENVELOPE_V1 fields 7 and 14. Field
// 14, source_snapshot_height, is the sender's own chain view: the block Keeper
// served the binding at, and not that height plus the task-data request window
// the very same read also produces. Returning the expiry would overstate the
// sender's view by ExpiryBlocks, which is exactly the slack a receiver's
// freshness bound must not be handed.
func TestCommittedBusEnvelopeIdentityReturnsTheServedHeightNotTheRequestExpiry(t *testing.T) {
	cfg, keys := newAuthTestConfig(t)
	keys.served = 4321
	auth, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	nonce, height, err := auth.CommittedBusEnvelopeIdentity(context.Background())
	if err != nil {
		t.Fatalf("CommittedBusEnvelopeIdentity: %v", err)
	}
	if nonce != keys.binding.AuthorizationNonce.Uint64() {
		t.Fatalf("service_authorization_nonce = %d, want the binding's %d",
			nonce, keys.binding.AuthorizationNonce.Uint64())
	}
	if height != keys.served {
		t.Fatalf("source_snapshot_height = %d, want the served height %d", height, keys.served)
	}
	// Named explicitly so a regression that returns the request expiry cannot be
	// mistaken for a fixture that happened to line up.
	if height == keys.served+cfg.ExpiryBlocks {
		t.Fatalf("source_snapshot_height = %d, want the served height, not served + ExpiryBlocks", height)
	}
	// The signing paths bind their expiry to the same single read; the height the
	// envelope reports must come from that read too, not a second one.
	if keys.reads != 1 {
		t.Fatalf("committed service-key reads = %d, want exactly one", keys.reads)
	}
	request, err := auth.SignRequest(context.Background(), "GetTaskDataMetadata",
		authObjectKey(),
		authTestBuilder, authTestBody(t))
	if err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	if request.ExpiresAtHeight != height+cfg.ExpiryBlocks {
		t.Fatalf("request expiry = %d, want the reported height %d + %d",
			request.ExpiresAtHeight, height, cfg.ExpiryBlocks)
	}
}

// The revocation bound is the served height, so a binding revoked at exactly the
// height it was read at is refused. A revocation one block after the served
// height is still current and must sign.
func TestAuthenticatorRefusesBindingRevokedAtTheServedHeight(t *testing.T) {
	key := authObjectKey()

	cfg, keys := newAuthTestConfig(t)
	keys.served = 4321
	keys.binding.RevokedHeight = chainclient.NewUint64String(4321)
	auth, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = auth.SignRequest(context.Background(), "GetTaskDataMetadata", key, authTestBuilder, authTestBody(t))
	if err == nil || builderclient.IsRetryable(err) || !strings.Contains(err.Error(), "revoked at height 4321") {
		t.Fatalf("SignRequest error = %v, want a permanent refusal for a key revoked at the served height", err)
	}

	cfg, keys = newAuthTestConfig(t)
	keys.served = 4321
	keys.binding.RevokedHeight = chainclient.NewUint64String(4322)
	auth, err = New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	request, err := auth.SignRequest(context.Background(), "GetTaskDataMetadata", key, authTestBuilder, authTestBody(t))
	if err != nil {
		t.Fatalf("SignRequest with a later revocation: %v", err)
	}
	if request.ExpiresAtHeight != 4321+cfg.ExpiryBlocks {
		t.Fatalf("ExpiresAtHeight = %d, want served height 4321 + %d", request.ExpiresAtHeight, cfg.ExpiryBlocks)
	}
}

func TestAuthenticatorRefusesRequestAuthenticationOnReceiptRelays(t *testing.T) {
	cfg, _ := newAuthTestConfig(t)
	auth, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"SubmitInferReceipt", "SubmitVerifyCommit", "SubmitVerifyResult"} {
		if _, err := auth.SignRequest(context.Background(), method, authObjectKey(), authTestBuilder, authTestBody(t)); err == nil {
			t.Fatalf("signed unsupported request auth for %s", method)
		}
	}
}

func TestAuthenticatorRejectsCurrentServiceKeyBindingMismatch(t *testing.T) {
	for name, mutate := range map[string]func(*chainclient.ServiceKeySnapshot){
		"participant": func(binding *chainclient.ServiceKeySnapshot) {
			binding.ParticipantType = chainclient.ParticipantTypeBuilder
		},
		"operator":        func(binding *chainclient.ServiceKeySnapshot) { binding.OperatorAddress = "trueopen1other" },
		"service address": func(binding *chainclient.ServiceKeySnapshot) { binding.ServiceAddress = "trueopen1other" },
		"service public key": func(binding *chainclient.ServiceKeySnapshot) {
			binding.ServicePubkey = "02" + strings.Repeat("11", 32)
		},
		"inactive": func(binding *chainclient.ServiceKeySnapshot) { binding.Status = "REVOKED" },
		"revoked": func(binding *chainclient.ServiceKeySnapshot) {
			binding.RevokedHeight = chainclient.NewUint64String(100)
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, keys := newAuthTestConfig(t)
			mutate(&keys.binding)
			auth, err := New(cfg)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			_, err = auth.SignRequest(context.Background(), "GetTaskDataMetadata", builderclient.TaskDataKey{
				SessionID: "session-1", TaskID: "task-1", Kind: builderclient.DataKindInput,
			}, authTestBuilder, authTestBody(t))
			if err == nil || builderclient.IsRetryable(err) {
				t.Fatalf("SignRequest error = %v, want permanent binding rejection", err)
			}
		})
	}
}

func TestAuthenticatorRejectsHeightOverflowAndBadLocalSignature(t *testing.T) {
	cfg, keys := newAuthTestConfig(t)
	keys.served = ^uint64(0) - 5
	auth, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key := authObjectKey()
	if _, err := auth.SignFetch(context.Background(), key, authTestBuilder, &builderclient.TaskDataRange{Length: 1}); err == nil || builderclient.IsRetryable(err) {
		t.Fatalf("SignRange overflow error = %v, want permanent rejection", err)
	}

	// Keeper answering with no committed height is a refusal, never a signature
	// anchored to height zero.
	cfg, keys = newAuthTestConfig(t)
	keys.served = 0
	auth, err = New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := auth.SignFetch(context.Background(), key, authTestBuilder, &builderclient.TaskDataRange{Length: 1}); err == nil ||
		builderclient.IsRetryable(err) || !strings.Contains(err.Error(), "positive committed chain height") {
		t.Fatalf("SignRange zero-height error = %v, want permanent rejection", err)
	}

	cfg, _ = newAuthTestConfig(t)
	other := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{0x42}, 32))
	cfg.Signer = authTestSigner{private: other, address: cfg.ServiceAddress}
	auth, err = New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := auth.SignFetch(context.Background(), key, authTestBuilder, &builderclient.TaskDataRange{Length: 1}); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("SignRange signature error = %v, want local verification failure", err)
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return decoded
}
