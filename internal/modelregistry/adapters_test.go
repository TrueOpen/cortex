package modelregistry

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/signer"
	"github.com/SingaXYZ/cortex/internal/txclient"
)

func TestRegistrationDigestSignerUsesOperatorIdentity(t *testing.T) {
	var captured signer.DigestRequest
	digestSigner := signer.DigestSignerFunc(func(_ context.Context, req signer.DigestRequest) ([]byte, error) {
		captured = req
		return []byte(strings.Repeat("r", 64)), nil
	})
	sign := NewRegistrationDigestSigner(digestSigner, "kms://operator", "trueopen1operator")
	signature, err := sign(context.Background(), validAdapterRegistrationMaterial())
	if err != nil {
		t.Fatalf("sign returned error: %v", err)
	}
	if signature != strings.Repeat("72", 64) || captured.KeyRef != "kms://operator" || captured.ExpectedSignerAddress != "trueopen1operator" || captured.Digest == (codec.Hash{}) {
		t.Fatalf("signature=%q request=%#v", signature, captured)
	}
}

func TestCurrentRegistrationDigestSignerSignsProvidedNodeDigest(t *testing.T) {
	want := codec.Hash{1, 2, 3}
	var captured signer.DigestRequest
	digestSigner := signer.DigestSignerFunc(func(_ context.Context, req signer.DigestRequest) ([]byte, error) {
		captured = req
		return []byte(strings.Repeat("r", 64)), nil
	})
	sign := NewCurrentRegistrationDigestSigner(digestSigner, "kms://operator", "trueopen1operator")
	signature, err := sign(context.Background(), want)
	if err != nil {
		t.Fatalf("sign returned error: %v", err)
	}
	if signature.Hex() != strings.Repeat("72", 64) || captured.Digest != want || captured.KeyRef != "kms://operator" || captured.ExpectedSignerAddress != "trueopen1operator" {
		t.Fatalf("signature=%q request=%#v", signature, captured)
	}
}

func TestRegistrationDigestSignersRejectRecoveryByte(t *testing.T) {
	digestSigner := signer.DigestSignerFunc(func(context.Context, signer.DigestRequest) ([]byte, error) {
		return make([]byte, 65), nil
	})
	if _, err := NewRegistrationDigestSigner(digestSigner, "kms://service", "trueopen1service")(context.Background(), validAdapterRegistrationMaterial()); err == nil {
		t.Fatal("legacy registration signer accepted a 65-byte recoverable signature")
	}
	if _, err := NewCurrentRegistrationDigestSigner(digestSigner, "kms://service", "trueopen1service")(context.Background(), codec.Hash{1}); err == nil {
		t.Fatal("current registration signer accepted a 65-byte recoverable signature")
	}
}

func TestCurrentRegistrationSubmitterRejectsMissingTxClient(t *testing.T) {
	_, err := NewCurrentRegistrationSubmitter(nil, TxSubmitterOptions{}).SubmitModelProfile(context.Background(), txclient.RegisterModelProfileMessage{})
	if err == nil || !strings.Contains(err.Error(), "tx client is required") {
		t.Fatalf("SubmitModelProfile error = %v, want tx client required", err)
	}
}

func TestRegistrationSubmitterBroadcastsAtomicCurrentMessage(t *testing.T) {
	tx := &recordingTxClient{obs: txclient.Observation{Accepted: true, Status: txclient.LifecycleKeeperConfirmed, TxHash: "tx-confirmed"}}
	submitter := NewCurrentRegistrationSubmitter(tx, TxSubmitterOptions{GasPayer: "trueopen1operator", FeeCap: txclient.Coin{Amount: 100, Denom: "utrueopen"}})
	message := txclient.RegisterModelProfileMessage{
		ProposerAddress: "trueopen1operator", Profile: validCurrentManifestInput().Profile,
	}
	if _, err := submitter.SubmitModelProfile(context.Background(), message); err != nil {
		t.Fatalf("SubmitModelProfile error = %v", err)
	}
	if len(tx.requests) != 1 || tx.requests[0].Kind != txclient.MsgRegisterModelProfile || tx.requests[0].TaskID != "model-profile-registration:hf-qwen3-8b/1" {
		t.Fatalf("registration request = %#v", tx.requests)
	}
}

func TestBuilderRegistrationPublisherReconstructsStableFrame(t *testing.T) {
	builder := builderclient.NewFakeClient()
	publisher := NewBuilderRegistrationPublisher(builder)
	msg := OutboxMessage{Material: validAdapterRegistrationMaterial(), Authorization: BuilderAuthorization{Granter: "trueopen1operator", CoversGas: true}}

	first, err := publisher.WriteRegistration(context.Background(), msg)
	if err != nil {
		t.Fatalf("WriteRegistration error = %v", err)
	}
	second, err := publisher.WriteRegistration(context.Background(), msg)
	if err != nil {
		t.Fatalf("second WriteRegistration error = %v", err)
	}
	if first == "" || second != first || len(builder.Published) != 2 {
		t.Fatalf("digests = %q, %q; publishes = %d", first, second, len(builder.Published))
	}
	if builder.Published[0].Subject != builderclient.NATSModelRegistrationSubject(first) || builder.Published[0].TaskID != "model-registration-"+first ||
		string(builder.Published[0].Payload) != string(builder.Published[1].Payload) {
		t.Fatalf("published frames differ: %#v", builder.Published)
	}
}

func TestBuilderRegistrationPublisherMakesOperatorRetryExplicit(t *testing.T) {
	want := errors.New("nexus unavailable")
	publisher := NewBuilderRegistrationPublisher(failingRegistrationBuilder{err: want})
	_, err := publisher.WriteRegistration(context.Background(), OutboxMessage{Material: validAdapterRegistrationMaterial()})
	if !errors.Is(err, ErrRegistrationPublishRequiresOperatorRetry) || !errors.Is(err, want) {
		t.Fatalf("WriteRegistration error = %v, want typed operator-retry error wrapping %v", err, want)
	}
}

func TestTxSupportConfirmerRefusesOperatorDeclarationAndStillSubmitsDailyConfirmation(t *testing.T) {
	ctx := context.Background()
	tx := &recordingTxClient{obs: txclient.Observation{Accepted: true, Status: txclient.LifecycleKeeperConfirmed, TxHash: "tx-support", IncludedHeight: 55}}
	signCalls := 0
	digestSigner := signer.DigestSignerFunc(func(_ context.Context, req signer.DigestRequest) ([]byte, error) {
		signCalls++
		if req.KeyRef != "kms://service" || req.ExpectedSignerAddress != "trueopen1service" || req.Digest == (codec.Hash{}) {
			t.Fatalf("digest request = %#v", req)
		}
		return []byte(strings.Repeat("s", 64)), nil
	})
	confirmer := NewTxSupportConfirmer(tx, TxSupportConfirmerOptions{
		ChainID: "chain-1", OperatorAddress: "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc",
		Signer: digestSigner, ServiceKeyRef: "kms://service", ServiceAddress: "trueopen1service",
		ServiceIdentity: func(context.Context) (uint64, uint64, uint64, uint64, error) { return 3, 100, 1, 199, nil },
		GasPayer:        "trueopen1service", FeeCap: txclient.Coin{Amount: 25, Denom: "utrueopen"},
	})
	material := SupportMaterial{
		ModelID: "model-a", ProfileVersion: "1", SupporterAddress: "trueopen1node", SupportMode: SupportModeDeclared, Supported: true,
		InferenceCapability: true, VerificationCapability: true,
	}

	if _, err := confirmer.ConfirmSupport(ctx, material); !errors.Is(err, ErrOperatorModelSupportSignatureRequired) {
		t.Fatalf("declared ConfirmSupport error = %v, want operator-signature requirement", err)
	}
	if signCalls != 0 || len(tx.requests) != 0 {
		t.Fatalf("operator declaration used service signer %d times or submitted %#v", signCalls, tx.requests)
	}

	material.SupportMode = SupportModeDaily
	material.EpochIndex = 7
	if _, err := confirmer.ConfirmSupport(ctx, material); err != nil {
		t.Fatalf("daily ConfirmSupport returned error: %v", err)
	}
	if signCalls != 1 || len(tx.requests) != 1 || tx.requests[0].Kind != txclient.MsgBatchConfirmModelSupport {
		t.Fatalf("daily confirmation sign calls = %d, tx requests = %#v", signCalls, tx.requests)
	}
	var batch txclient.BatchConfirmModelSupportMessage
	if err := json.Unmarshal(tx.requests[0].Payload, &batch); err != nil {
		t.Fatalf("decode batch request: %v", err)
	}
	if len(batch.Confirmations) != 1 || batch.Confirmations[0].OperatorAddress != "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc" ||
		batch.Confirmations[0].ServiceAuthorizationNonce != 3 || batch.Confirmations[0].ExpiryHeight != 199 ||
		batch.Confirmations[0].ServiceSignature == "" {
		t.Fatalf("batch confirmation = %#v, want current service identity and signature", batch.Confirmations)
	}
}

func TestTxSupportConfirmerRejectsNonNumericProfileIdentity(t *testing.T) {
	for _, profile := range []string{"", "0", "01", "profile-v1", " 1"} {
		if _, err := canonicalSupportProfileVersion(profile); err == nil {
			t.Fatalf("canonicalSupportProfileVersion(%q) error = nil", profile)
		}
	}
}

func TestTxSupportConfirmerRejectsRecoveryByte(t *testing.T) {
	ctx := context.Background()
	tx := &recordingTxClient{}
	digestSigner := signer.DigestSignerFunc(func(context.Context, signer.DigestRequest) ([]byte, error) {
		return make([]byte, 65), nil
	})
	confirmer := NewTxSupportConfirmer(tx, TxSupportConfirmerOptions{
		ChainID: "chain-1", OperatorAddress: "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc", Signer: digestSigner,
		ServiceKeyRef: "kms://service", ServiceAddress: "trueopen1service",
		ServiceIdentity: func(context.Context) (uint64, uint64, uint64, uint64, error) { return 3, 100, 1, 199, nil },
	})
	_, err := confirmer.ConfirmSupport(ctx, SupportMaterial{
		ModelID: "model-a", ProfileVersion: "1", SupportMode: SupportModeDaily, Supported: true, EpochIndex: 7,
	})
	if err == nil || !strings.Contains(err.Error(), "invalid signature length") {
		t.Fatalf("ConfirmSupport error = %v, want strict 64-byte signature rejection", err)
	}
	if len(tx.requests) != 0 {
		t.Fatalf("invalid signature reached tx client: %#v", tx.requests)
	}
}

func validAdapterRegistrationMaterial() RegistrationMaterial {
	return RegistrationMaterial{
		ManifestHash: "manifest-hash-1", SignedEnvelope: strings.Repeat("ab", 64), FeeDenom: "utrueopen",
		TreasuryDestination: "trueopen1treasury", FeeKind: FeeKindRegistration, FeeAmount: 100, GasLimit: 50,
		Message: txclient.LegacyRegisterModelProfileMessage{
			ModelID: "model-1", ProfileVersion: "profile-1", ManifestHash: strings.Repeat("ab", 32), TokenizerHash: strings.Repeat("bc", 32),
			RuntimeVersion: "runtime-v1", ResourceTier: "STANDARD", MinStake: 500000, ChallengeOpenWindowBlocks: 100,
			VerificationProfile: "verification-v1", PricingProfile: "pricing-v1", EpsilonParams: "epsilon-v1", TimeoutBootstrapProfile: "timeout-v1",
			SchemaHash: strings.Repeat("cd", 32), RegistrationFee: txclient.CoinMessage{Denom: "utrueopen", Amount: 100},
			RegistrantSignature: strings.Repeat("ab", 64), MetadataHash: strings.Repeat("de", 32),
		},
	}
}

type recordingTxClient struct {
	requests      []txclient.Request
	obs           txclient.Observation
	obsConfigured bool
	err           error
}

type failingRegistrationBuilder struct{ err error }

func (f failingRegistrationBuilder) Publish(context.Context, builderclient.PublishRequest) error {
	return f.err
}

func (r *recordingTxClient) Submit(_ context.Context, req txclient.Request) (txclient.Observation, error) {
	r.requests = append(r.requests, txclient.Request{
		TaskID:          req.TaskID,
		Kind:            req.Kind,
		Payload:         append([]byte(nil), req.Payload...),
		GasPayer:        req.GasPayer,
		FeeCap:          req.FeeCap,
		FeeGrant:        req.FeeGrant,
		Memo:            req.Memo,
		AccountSequence: req.AccountSequence,
		DeadlineHeight:  req.DeadlineHeight,
		MaterialDigest:  req.MaterialDigest,
	})
	if r.err != nil {
		return txclient.Observation{}, r.err
	}
	if r.obsConfigured || r.obs.Accepted || r.obs.Rejected || r.obs.TxHash != "" || r.obs.RejectReason != "" {
		return r.obs, nil
	}
	return txclient.Observation{}, errors.New("recording txclient observation not configured")
}
