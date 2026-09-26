package modelregistry

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/TrueOpen/cortex/internal/txclient"
)

func TestManifestGenerationIsStableAndHashesSameInputIdentically(t *testing.T) {
	input := validManifestInput()
	input.Digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	input.Metadata = map[string]string{
		"z": "last",
		"a": "first",
	}

	first, err := GenerateManifest(input)
	if err != nil {
		t.Fatalf("GenerateManifest first returned error: %v", err)
	}
	second, err := GenerateManifest(input)
	if err != nil {
		t.Fatalf("GenerateManifest second returned error: %v", err)
	}
	if first.Hash == "" {
		t.Fatalf("manifest hash is empty")
	}
	if first.Hash != second.Hash {
		t.Fatalf("manifest hash not stable: %q != %q", first.Hash, second.Hash)
	}
	if first.Canonical != second.Canonical {
		t.Fatalf("canonical manifest not stable:\nfirst:  %s\nsecond: %s", first.Canonical, second.Canonical)
	}
}

func TestManifestValidationFailsForMissingRequiredFields(t *testing.T) {
	valid := validManifestInput()
	tests := map[string]ManifestInput{
		"digest":        withManifestField(valid, func(in *ManifestInput) { in.Digest = "" }),
		"tokenizer":     withManifestField(valid, func(in *ManifestInput) { in.Tokenizer = "" }),
		"model service": withManifestField(valid, func(in *ManifestInput) { in.ModelServiceID = "" }),
		"verification":  withManifestField(valid, func(in *ManifestInput) { in.Verification.Method = "" }),
		"pricing":       withManifestField(valid, func(in *ManifestInput) { in.Pricing.Denom = "" }),
	}

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			manifest, err := GenerateManifest(input)
			if err == nil {
				err = ValidateManifest(manifest)
			}
			if err == nil {
				t.Fatalf("missing %s accepted", name)
			}
		})
	}
}

func TestSelfTestFailureDoesNotProduceRegistrationMaterial(t *testing.T) {
	svc := NewRegistry(RegistryConfig{
		SelfTester: SelfTestFunc(func(context.Context, Manifest) (SelfTestResult, error) {
			return SelfTestResult{Passed: false, Error: "model failed readiness"}, nil
		}),
	})
	manifest := mustManifest(t, validManifestInput())

	material, err := svc.SelfTest(context.Background(), manifest)
	if err == nil {
		t.Fatalf("SelfTest error = nil, want failure")
	}
	if material != nil {
		t.Fatalf("SelfTest material = %#v, want nil on failure", material)
	}
}

func TestRegisterBindsQuoteAuthorizationAndEnvelope(t *testing.T) {
	tx := &recordingSubmitter{}
	outbox := &recordingOutbox{}
	svc := NewRegistry(RegistryConfig{
		NowHeight:   func() (uint64, error) { return 100, nil },
		Treasury:    "trueopen1treasury",
		FeeDenom:    "utrueopen",
		Submitter:   tx,
		Outbox:      outbox,
		SelfTester:  passingSelfTest,
		Signer:      fixedSigner,
		FeeGrant:    StaticFeeGrant{Granter: "operator", Amount: 150, GasLimit: 50},
		MinGasGrant: 50,
	})
	manifest := mustManifest(t, validManifestInput())
	quote := FeeQuote{
		Height:              100,
		ExpiresAtHeight:     120,
		Denom:               "utrueopen",
		TreasuryDestination: "trueopen1treasury",
		FeeKind:             FeeKindRegistration,
		Amount:              100,
		GasLimit:            50,
	}

	result, err := svc.Register(context.Background(), RegisterRequest{
		Manifest: manifest,
		Quote:    quote,
		Mode:     SubmitDirect,
	})
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if result.TxID == "" {
		t.Fatalf("TxID is empty")
	}
	if len(tx.submitted) != 1 {
		t.Fatalf("submitted tx count = %d, want 1", len(tx.submitted))
	}
	if len(outbox.writes) != 0 {
		t.Fatalf("outbox writes = %d, want 0 for direct submit", len(outbox.writes))
	}
	material := tx.submitted[0]
	if material.ManifestHash != manifest.Hash {
		t.Fatalf("manifest hash = %q, want %q", material.ManifestHash, manifest.Hash)
	}
	if material.QuoteHeight != quote.Height ||
		material.QuoteExpiresAtHeight != quote.ExpiresAtHeight ||
		material.FeeDenom != quote.Denom ||
		material.TreasuryDestination != quote.TreasuryDestination ||
		material.FeeKind != quote.FeeKind {
		t.Fatalf("material quote binding = %#v, want quote %#v", material, quote)
	}
	if material.SignedEnvelope == "" {
		t.Fatalf("signed envelope is empty")
	}
}

func TestRegisterRejectsBadQuoteAndGrantBeforeSubmit(t *testing.T) {
	tests := map[string]FeeQuote{
		"expired quote": {
			Height: 100, ExpiresAtHeight: 100, Denom: "utrueopen", TreasuryDestination: "trueopen1treasury", FeeKind: FeeKindRegistration, Amount: 100, GasLimit: 50,
		},
		"denom mismatch": {
			Height: 100, ExpiresAtHeight: 120, Denom: "uatom", TreasuryDestination: "trueopen1treasury", FeeKind: FeeKindRegistration, Amount: 100, GasLimit: 50,
		},
		"treasury mismatch": {
			Height: 100, ExpiresAtHeight: 120, Denom: "utrueopen", TreasuryDestination: "trueopen1other", FeeKind: FeeKindRegistration, Amount: 100, GasLimit: 50,
		},
		"insufficient fee grant": {
			Height: 100, ExpiresAtHeight: 120, Denom: "utrueopen", TreasuryDestination: "trueopen1treasury", FeeKind: FeeKindRegistration, Amount: 151, GasLimit: 50,
		},
	}

	for name, quote := range tests {
		t.Run(name, func(t *testing.T) {
			tx := &recordingSubmitter{}
			outbox := &recordingOutbox{}
			svc := NewRegistry(RegistryConfig{
				NowHeight:   func() (uint64, error) { return 101, nil },
				Treasury:    "trueopen1treasury",
				FeeDenom:    "utrueopen",
				Submitter:   tx,
				Outbox:      outbox,
				SelfTester:  passingSelfTest,
				Signer:      fixedSigner,
				FeeGrant:    StaticFeeGrant{Granter: "operator", Amount: 150, GasLimit: 50},
				MinGasGrant: 50,
			})

			_, err := svc.Register(context.Background(), RegisterRequest{
				Manifest: mustManifest(t, validManifestInput()),
				Quote:    quote,
				Mode:     SubmitDirect,
			})
			if err == nil {
				t.Fatalf("Register accepted %s", name)
			}
			if len(tx.submitted) != 0 {
				t.Fatalf("submitted tx count = %d, want 0", len(tx.submitted))
			}
			if len(outbox.writes) != 0 {
				t.Fatalf("outbox writes = %d, want 0", len(outbox.writes))
			}
		})
	}
}

func TestRegisterDryRunDoesNotWriteOutboxOrBroadcast(t *testing.T) {
	tx := &recordingSubmitter{}
	outbox := &recordingOutbox{}
	svc := NewRegistry(RegistryConfig{
		NowHeight:   func() (uint64, error) { return 100, nil },
		Treasury:    "trueopen1treasury",
		FeeDenom:    "utrueopen",
		Submitter:   tx,
		Outbox:      outbox,
		SelfTester:  passingSelfTest,
		Signer:      fixedSigner,
		FeeGrant:    StaticFeeGrant{Granter: "operator", Amount: 200, GasLimit: 50},
		MinGasGrant: 50,
	})

	result, err := svc.Register(context.Background(), RegisterRequest{
		Manifest: mustManifest(t, validManifestInput()),
		Quote: FeeQuote{
			Height:              100,
			ExpiresAtHeight:     120,
			Denom:               "utrueopen",
			TreasuryDestination: "trueopen1treasury",
			FeeKind:             FeeKindRegistration,
			Amount:              100,
			GasLimit:            50,
		},
		Mode:   SubmitViaBuilder,
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("Register dry-run returned error: %v", err)
	}
	if !result.DryRun {
		t.Fatalf("result DryRun = false, want true")
	}
	if len(tx.submitted) != 0 {
		t.Fatalf("submitted tx count = %d, want 0", len(tx.submitted))
	}
	if len(outbox.writes) != 0 {
		t.Fatalf("outbox writes = %d, want 0", len(outbox.writes))
	}
}

func TestOperatorSupportRequiresIntentWhileDailySupportUsesServiceConfirmation(t *testing.T) {
	confirmer := &recordingSupportConfirmer{}
	svc := NewRegistry(RegistryConfig{
		NowHeight:              func() (uint64, error) { return 100, nil },
		SupporterAddress:       "cortex1supporter",
		InferenceCapability:    true,
		VerificationCapability: true,
		SupportConfirmer:       confirmer,
		Signer:                 fixedSigner,
	})
	svc.PutStatus(ModelStatus{ModelID: "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", ProfileVersion: "1"})
	if _, err := svc.Support(context.Background(), SupportRequest{ModelID: "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", Supported: true}); !errors.Is(err, ErrOperatorModelSupportSignatureRequired) {
		t.Fatalf("Support error = %v, want operator-signature requirement", err)
	}
	status, err := svc.DailySupport(context.Background(), DailySupportRequest{ModelID: "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", Enabled: true})
	if err != nil {
		t.Fatalf("DailySupport returned error: %v", err)
	}
	if !status.DailySupportEnabled {
		t.Fatalf("DailySupportEnabled = false, want true")
	}
	if len(confirmer.materials) != 1 || confirmer.materials[0].SupportMode != SupportModeDaily {
		t.Fatalf("support confirmations = %#v, want only daily confirmation", confirmer.materials)
	}
}

func TestPrepareOperatorSupportIntentUsesNodeOperatorOnlyMessage(t *testing.T) {
	svc := NewRegistry(RegistryConfig{
		SupporterAddress:       "trueopen1operator",
		InferenceCapability:    true,
		VerificationCapability: true,
	})
	intent, err := svc.PrepareOperatorSupportIntent(context.Background(), SupportRequest{
		ModelID: "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", ProfileVersion: "7", Supported: true,
	})
	if err != nil {
		t.Fatalf("PrepareOperatorSupportIntent returned error: %v", err)
	}
	if intent.TypeURL != txclient.MsgDeclareModelSupport.String() {
		t.Fatalf("type_url = %q", intent.TypeURL)
	}
	want := txclient.DeclareModelSupportMessage{
		OperatorAddress: "trueopen1operator", ModelID: txclient.ProtoBytes32("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"),
		InferenceCapability: true, VerificationCapability: true,
	}
	if intent.Message != want {
		t.Fatalf("message = %#v, want %#v", intent.Message, want)
	}
	if _, err := svc.Status(context.Background(), StatusRequest{ModelID: "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"}); err == nil {
		t.Fatal("preparing an unsigned operator intent mutated daemon support state")
	}
}

func TestDailySupportFailsClosedWhenConfirmationIsRequired(t *testing.T) {
	svc := NewRegistry(RegistryConfig{
		SupporterAddress:           "cortex1supporter",
		RequireSupportConfirmation: true,
	})
	_, err := svc.DailySupport(context.Background(), DailySupportRequest{ModelID: "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", Enabled: true})
	if err == nil || !strings.Contains(err.Error(), "support confirmation client is required") {
		t.Fatalf("DailySupport() error = %v, want missing confirmation client error", err)
	}
}

func TestRegisterMakesModelVisibleInStatusListAndShow(t *testing.T) {
	svc := NewRegistry(RegistryConfig{
		NowHeight:   func() (uint64, error) { return 100, nil },
		Treasury:    "trueopen1treasury",
		FeeDenom:    "utrueopen",
		Submitter:   &recordingSubmitter{},
		SelfTester:  passingSelfTest,
		Signer:      fixedSigner,
		FeeGrant:    StaticFeeGrant{Granter: "operator", Amount: 200, GasLimit: 50},
		MinGasGrant: 50,
	})
	manifest := mustManifest(t, validManifestInput())

	_, err := svc.Register(context.Background(), RegisterRequest{
		Manifest: manifest,
		Quote: FeeQuote{
			Height:              100,
			ExpiresAtHeight:     120,
			Denom:               "utrueopen",
			TreasuryDestination: "trueopen1treasury",
			FeeKind:             FeeKindRegistration,
			Amount:              100,
			GasLimit:            50,
		},
		Mode: SubmitDirect,
	})
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	status, err := svc.Status(context.Background(), StatusRequest{ModelID: manifest.ModelID})
	if err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
	if status.ManifestHash != manifest.Hash || status.ChainState != "registration_submitted" {
		t.Fatalf("Status = %#v, want submitted status for %s", status, manifest.Hash)
	}
	list, err := svc.List(context.Background(), ListRequest{})
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if len(list) != 1 || list[0].ModelID != manifest.ModelID {
		t.Fatalf("List = %#v", list)
	}
	show, err := svc.Show(context.Background(), ShowRequest{ModelID: manifest.ModelID})
	if err != nil {
		t.Fatalf("Show returned error: %v", err)
	}
	if show.Manifest.Hash != manifest.Hash {
		t.Fatalf("Show manifest hash = %q, want %q", show.Manifest.Hash, manifest.Hash)
	}
}

func TestOperatorSupportIntentUsesManifestProfileVersionNotManifestHash(t *testing.T) {
	svc := NewRegistry(RegistryConfig{
		NowHeight:              func() (uint64, error) { return 42, nil },
		Treasury:               "trueopen1treasury",
		FeeDenom:               "utrueopen",
		Submitter:              &recordingSubmitter{},
		SelfTester:             passingSelfTest,
		Signer:                 fixedSigner,
		FeeGrant:               StaticFeeGrant{Granter: "operator", Amount: 100, GasLimit: 50},
		MinGasGrant:            50,
		SupporterAddress:       "cortex1supporter",
		InferenceCapability:    true,
		VerificationCapability: true,
	})
	manifest := mustManifest(t, validManifestInput())
	if _, err := svc.Register(context.Background(), RegisterRequest{
		Manifest: manifest,
		Quote: FeeQuote{
			Height: 42, ExpiresAtHeight: 100, Denom: "utrueopen", TreasuryDestination: "trueopen1treasury",
			FeeKind: FeeKindRegistration, Amount: 100, GasLimit: 50,
		},
		Mode: SubmitDirect,
	}); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	intent, err := svc.PrepareOperatorSupportIntent(context.Background(), SupportRequest{ModelID: manifest.ModelID, Supported: true})
	if err != nil {
		t.Fatalf("PrepareOperatorSupportIntent returned error: %v", err)
	}
	if intent.Message.ModelID.Hex() != manifest.ModelID {
		t.Fatalf("ModelID = %q, want %q", intent.Message.ModelID, manifest.ModelID)
	}
}

func TestRegistryConcurrentRegisterAndRead(t *testing.T) {
	const modelCount = 16

	svc := NewRegistry(RegistryConfig{
		NowHeight:   func() (uint64, error) { return 100, nil },
		Treasury:    "trueopen1treasury",
		FeeDenom:    "utrueopen",
		Submitter:   &concurrentSubmitter{},
		SelfTester:  passingSelfTest,
		Signer:      fixedSigner,
		FeeGrant:    StaticFeeGrant{Granter: "operator", Amount: 200, GasLimit: 50},
		MinGasGrant: 50,
	})
	manifests := make([]Manifest, 0, modelCount)
	for i := 0; i < modelCount; i++ {
		input := validManifestInput()
		input.ModelID = fmt.Sprintf("llama-text-%02d", i)
		input.Version = fmt.Sprintf("2026-07-%02d", i+1)
		manifests = append(manifests, mustManifest(t, input))
	}
	quote := FeeQuote{
		Height:              100,
		ExpiresAtHeight:     120,
		Denom:               "utrueopen",
		TreasuryDestination: "trueopen1treasury",
		FeeKind:             FeeKindRegistration,
		Amount:              100,
		GasLimit:            50,
	}

	var wg sync.WaitGroup
	errs := make(chan error, modelCount*4)
	for _, manifest := range manifests {
		manifest := manifest
		wg.Add(4)
		go func() {
			defer wg.Done()
			_, err := svc.Register(context.Background(), RegisterRequest{
				Manifest: manifest,
				Quote:    quote,
				Mode:     SubmitDirect,
			})
			if err != nil {
				errs <- fmt.Errorf("register %s: %w", manifest.ModelID, err)
			}
		}()
		go func() {
			defer wg.Done()
			_, _ = svc.Status(context.Background(), StatusRequest{ModelID: manifest.ModelID})
		}()
		go func() {
			defer wg.Done()
			if _, err := svc.List(context.Background(), ListRequest{}); err != nil {
				errs <- fmt.Errorf("list: %w", err)
			}
		}()
		go func() {
			defer wg.Done()
			_, _ = svc.Show(context.Background(), ShowRequest{ModelID: manifest.ModelID})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestRegisterSignsOnlyIntoTheEnvelopeTheOutboxPublishes pins where the
// registration signature is allowed to land. It travels as
// RegistrationMaterial.SignedEnvelope, which the builder outbox frames into the
// published payload and its dedup digest; RegistrationMaterial.Message is only
// the signing preimage, so a signature written back into it would be work no
// reader can observe and would misdescribe what was actually signed.
func TestRegisterSignsOnlyIntoTheEnvelopeTheOutboxPublishes(t *testing.T) {
	outbox := &recordingOutbox{}
	svc := NewRegistry(RegistryConfig{
		NowHeight:   func() (uint64, error) { return 100, nil },
		Treasury:    "trueopen1treasury",
		FeeDenom:    "utrueopen",
		Outbox:      outbox,
		SelfTester:  passingSelfTest,
		Signer:      fixedSigner,
		FeeGrant:    StaticFeeGrant{Granter: "operator", Amount: 200, GasLimit: 50},
		MinGasGrant: 50,
	})

	result, err := svc.Register(context.Background(), RegisterRequest{
		Manifest: mustManifest(t, validManifestInput()),
		Quote: FeeQuote{
			Height: 100, ExpiresAtHeight: 120, Denom: "utrueopen",
			TreasuryDestination: "trueopen1treasury", FeeKind: FeeKindRegistration,
			Amount: 100, GasLimit: 50,
		},
		Mode: SubmitViaBuilder,
	})
	if err != nil {
		t.Fatalf("Register via-builder returned error: %v", err)
	}
	if result.Material.SignedEnvelope == "" {
		t.Fatal("signed envelope is empty: the outbox payload would carry no signature")
	}
	if len(outbox.writes) != 1 || outbox.writes[0].Material.SignedEnvelope != result.Material.SignedEnvelope {
		t.Fatalf("outbox writes = %#v, want the signed envelope to reach the builder frame", outbox.writes)
	}
	if got := result.Material.Message.RegistrantSignature; got != "" {
		t.Fatalf("legacy message registrant_signature = %q, want empty: the message is only the signing preimage", got)
	}
}

func TestViaBuilderWritesOutboxOnlyWithFeeAndGasAuthorization(t *testing.T) {
	outbox := &recordingOutbox{}
	svc := NewRegistry(RegistryConfig{
		NowHeight:   func() (uint64, error) { return 100, nil },
		Treasury:    "trueopen1treasury",
		FeeDenom:    "utrueopen",
		Outbox:      outbox,
		SelfTester:  passingSelfTest,
		Signer:      fixedSigner,
		FeeGrant:    StaticFeeGrant{Granter: "operator", Amount: 200, GasLimit: 50},
		MinGasGrant: 50,
	})

	result, err := svc.Register(context.Background(), RegisterRequest{
		Manifest: mustManifest(t, validManifestInput()),
		Quote: FeeQuote{
			Height:              100,
			ExpiresAtHeight:     120,
			Denom:               "utrueopen",
			TreasuryDestination: "trueopen1treasury",
			FeeKind:             FeeKindRegistration,
			Amount:              100,
			GasLimit:            50,
		},
		Mode: SubmitViaBuilder,
	})
	if err != nil {
		t.Fatalf("Register via-builder returned error: %v", err)
	}
	if result.OutboxID == "" {
		t.Fatalf("OutboxID is empty")
	}
	if len(outbox.writes) != 1 {
		t.Fatalf("outbox writes = %d, want 1", len(outbox.writes))
	}
	if !outbox.writes[0].Authorization.CoversRegistrationFee || !outbox.writes[0].Authorization.CoversGas {
		t.Fatalf("authorization = %#v, want registration fee and gas coverage", outbox.writes[0].Authorization)
	}

	outbox = &recordingOutbox{}
	svc = NewRegistry(RegistryConfig{
		NowHeight:   func() (uint64, error) { return 100, nil },
		Treasury:    "trueopen1treasury",
		FeeDenom:    "utrueopen",
		Outbox:      outbox,
		SelfTester:  passingSelfTest,
		Signer:      fixedSigner,
		FeeGrant:    StaticFeeGrant{Granter: "operator", Amount: 200, GasLimit: 50},
		MinGasGrant: 51,
	})
	_, err = svc.Register(context.Background(), RegisterRequest{
		Manifest: mustManifest(t, validManifestInput()),
		Quote: FeeQuote{
			Height:              100,
			ExpiresAtHeight:     120,
			Denom:               "utrueopen",
			TreasuryDestination: "trueopen1treasury",
			FeeKind:             FeeKindRegistration,
			Amount:              100,
			GasLimit:            50,
		},
		Mode: SubmitViaBuilder,
	})
	if err == nil {
		t.Fatalf("Register via-builder accepted insufficient gas authorization")
	}
	if len(outbox.writes) != 0 {
		t.Fatalf("outbox writes = %d, want 0", len(outbox.writes))
	}
}

func TestViaBuilderRejectsMissingGasAuthorizationEvenWhenQuoteGasLimitIsHigh(t *testing.T) {
	outbox := &recordingOutbox{}
	svc := NewRegistry(RegistryConfig{
		NowHeight:   func() (uint64, error) { return 100, nil },
		Treasury:    "trueopen1treasury",
		FeeDenom:    "utrueopen",
		Outbox:      outbox,
		SelfTester:  passingSelfTest,
		Signer:      fixedSigner,
		FeeGrant:    StaticFeeGrant{Granter: "operator", Amount: 200, GasLimit: 0},
		MinGasGrant: 50,
	})

	_, err := svc.Register(context.Background(), RegisterRequest{
		Manifest: mustManifest(t, validManifestInput()),
		Quote: FeeQuote{
			Height:              100,
			ExpiresAtHeight:     120,
			Denom:               "utrueopen",
			TreasuryDestination: "trueopen1treasury",
			FeeKind:             FeeKindRegistration,
			Amount:              100,
			GasLimit:            10_000,
		},
		Mode: SubmitViaBuilder,
	})
	if err == nil {
		t.Fatalf("Register via-builder accepted missing gas authorization")
	}
	if len(outbox.writes) != 0 {
		t.Fatalf("outbox writes = %d, want 0", len(outbox.writes))
	}
}

func TestViaBuilderRejectsGasAuthorizationBelowQuoteGasLimit(t *testing.T) {
	outbox := &recordingOutbox{}
	svc := NewRegistry(RegistryConfig{
		NowHeight:   func() (uint64, error) { return 100, nil },
		Treasury:    "trueopen1treasury",
		FeeDenom:    "utrueopen",
		Outbox:      outbox,
		SelfTester:  passingSelfTest,
		Signer:      fixedSigner,
		FeeGrant:    StaticFeeGrant{Granter: "operator", Amount: 200, GasLimit: 50},
		MinGasGrant: 10,
	})

	_, err := svc.Register(context.Background(), RegisterRequest{
		Manifest: mustManifest(t, validManifestInput()),
		Quote: FeeQuote{
			Height:              100,
			ExpiresAtHeight:     120,
			Denom:               "utrueopen",
			TreasuryDestination: "trueopen1treasury",
			FeeKind:             FeeKindRegistration,
			Amount:              100,
			GasLimit:            60,
		},
		Mode: SubmitViaBuilder,
	})
	if err == nil {
		t.Fatalf("Register via-builder accepted gas authorization below quote gas limit")
	}
	if len(outbox.writes) != 0 {
		t.Fatalf("outbox writes = %d, want 0", len(outbox.writes))
	}
}

func TestStatusListShowExposeSeparateDisplayFields(t *testing.T) {
	svc := NewRegistry(RegistryConfig{})
	status := ModelStatus{
		ModelID:             "1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b",
		ManifestHash:        "manifest-hash",
		ChainState:          "registered",
		DisplayVisibility:   "public",
		VerificationLabel:   "trace verified",
		RewardState:         "eligible",
		Supported:           true,
		DailySupportEnabled: true,
	}
	svc.PutStatus(status)

	got, err := svc.Status(context.Background(), StatusRequest{ModelID: status.ModelID})
	if err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
	assertStatusDisplayFields(t, got, status)

	list, err := svc.List(context.Background(), ListRequest{})
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("List count = %d, want 1", len(list))
	}
	assertStatusDisplayFields(t, list[0], status)

	show, err := svc.Show(context.Background(), ShowRequest{ModelID: status.ModelID})
	if err != nil {
		t.Fatalf("Show returned error: %v", err)
	}
	assertStatusDisplayFields(t, show.Status, status)
}

func validManifestInput() ManifestInput {
	return ManifestInput{
		ModelID:        "1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b",
		Version:        "2026-07-08",
		Digest:         "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Tokenizer:      "tiktoken-cl100k",
		ModelServiceID: "modelsvc-local",
		Verification: VerificationSpec{
			Method:         "trace_sample_v1",
			ProfileVersion: "1",
		},
		Pricing: PricingSpec{
			Denom:               "utrueopen",
			PromptUnitPrice:     3,
			CompletionUnitPrice: 7,
		},
		TokenizerHash:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RuntimeVersion: "runtime-v1", RuntimeHash: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		QuantHash:         "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		HardwareTierFloor: 1, ResourceTier: "3", MinStake: 500000, ChallengeOpenWindowBlocks: 100,
		EpsilonParams: "epsilon-v1", TimeoutBootstrapProfile: "timeout-v1",
		SchemaHash:   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		MetadataHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
}

func withManifestField(input ManifestInput, change func(*ManifestInput)) ManifestInput {
	change(&input)
	return input
}

func mustManifest(t *testing.T, input ManifestInput) Manifest {
	t.Helper()
	manifest, err := GenerateManifest(input)
	if err != nil {
		t.Fatalf("GenerateManifest returned error: %v", err)
	}
	return manifest
}

func passingSelfTest(_ context.Context, manifest Manifest) (SelfTestResult, error) {
	return SelfTestResult{
		Passed: true,
		RegistrationMaterial: &RegistrationMaterial{
			ManifestHash: manifest.Hash,
		},
	}, nil
}

func fixedSigner(_ context.Context, material RegistrationMaterial) (string, error) {
	if material.ManifestHash == "" {
		return "", errors.New("missing manifest hash")
	}
	return strings.Repeat("ab", 64), nil
}

func assertStatusDisplayFields(t *testing.T, got ModelStatus, want ModelStatus) {
	t.Helper()
	if got.ChainState != want.ChainState ||
		got.DisplayVisibility != want.DisplayVisibility ||
		got.VerificationLabel != want.VerificationLabel ||
		got.RewardState != want.RewardState {
		t.Fatalf("status fields = %#v, want %#v", got, want)
	}
}

type recordingSubmitter struct {
	submitted []RegistrationMaterial
}

func (r *recordingSubmitter) SubmitRegistration(_ context.Context, material RegistrationMaterial) (string, error) {
	r.submitted = append(r.submitted, material)
	return "tx-" + material.ManifestHash, nil
}

type concurrentSubmitter struct{}

func (c *concurrentSubmitter) SubmitRegistration(_ context.Context, material RegistrationMaterial) (string, error) {
	return "tx-" + material.ManifestHash, nil
}

type recordingOutbox struct {
	writes []OutboxMessage
}

func (r *recordingOutbox) WriteRegistration(_ context.Context, msg OutboxMessage) (string, error) {
	r.writes = append(r.writes, msg)
	return "outbox-" + msg.Material.ManifestHash, nil
}

type recordingSupportConfirmer struct {
	materials []SupportMaterial
}

func (r *recordingSupportConfirmer) ConfirmSupport(_ context.Context, material SupportMaterial) (string, error) {
	r.materials = append(r.materials, material)
	return "support-" + material.SupportDigest, nil
}

func TestRegisterFailsClosedWhenCurrentHeightIsUnavailable(t *testing.T) {
	// An unknown chain height must stop registration. Before this was fixed,
	// NowHeight returned 0 on a Keeper failure and every quote whose
	// ExpiresAtHeight was above 0 passed the expiry comparison.
	unavailable := map[string]func() (uint64, error){
		"keeper error": func() (uint64, error) { return 0, errors.New("keeper unreachable") },
		"zero height":  func() (uint64, error) { return 0, nil },
		"unset":        nil,
	}

	for name, nowHeight := range unavailable {
		t.Run(name, func(t *testing.T) {
			tx := &recordingSubmitter{}
			outbox := &recordingOutbox{}
			svc := NewRegistry(RegistryConfig{
				NowHeight:   nowHeight,
				Treasury:    "trueopen1treasury",
				FeeDenom:    "utrueopen",
				Submitter:   tx,
				Outbox:      outbox,
				SelfTester:  passingSelfTest,
				Signer:      fixedSigner,
				FeeGrant:    StaticFeeGrant{Granter: "operator", Amount: 150, GasLimit: 50},
				MinGasGrant: 50,
			})

			_, err := svc.Register(context.Background(), RegisterRequest{
				Manifest: mustManifest(t, validManifestInput()),
				Quote: FeeQuote{
					Height: 100, ExpiresAtHeight: 120, Denom: "utrueopen",
					TreasuryDestination: "trueopen1treasury", FeeKind: FeeKindRegistration,
					Amount: 100, GasLimit: 50,
				},
				Mode: SubmitDirect,
			})
			if err == nil {
				t.Fatalf("Register accepted a quote while the chain height was unavailable")
			}
			if len(tx.submitted) != 0 || len(outbox.writes) != 0 {
				t.Fatalf("submitted=%d outbox=%d, want no side effects", len(tx.submitted), len(outbox.writes))
			}
		})
	}
}

func TestRegisterStillAcceptsUnexpiredQuoteWithKnownHeight(t *testing.T) {
	tx := &recordingSubmitter{}
	outbox := &recordingOutbox{}
	svc := NewRegistry(RegistryConfig{
		NowHeight:   func() (uint64, error) { return 100, nil },
		Treasury:    "trueopen1treasury",
		FeeDenom:    "utrueopen",
		Submitter:   tx,
		Outbox:      outbox,
		SelfTester:  passingSelfTest,
		Signer:      fixedSigner,
		FeeGrant:    StaticFeeGrant{Granter: "operator", Amount: 150, GasLimit: 50},
		MinGasGrant: 50,
	})

	if _, err := svc.Register(context.Background(), RegisterRequest{
		Manifest: mustManifest(t, validManifestInput()),
		Quote: FeeQuote{
			Height: 100, ExpiresAtHeight: 120, Denom: "utrueopen",
			TreasuryDestination: "trueopen1treasury", FeeKind: FeeKindRegistration,
			Amount: 100, GasLimit: 50,
		},
		Mode: SubmitDirect,
	}); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if len(tx.submitted) != 1 {
		t.Fatalf("submitted tx count = %d, want 1", len(tx.submitted))
	}
}

func TestDailySupportFailsClosedWhenCurrentHeightIsUnavailable(t *testing.T) {
	confirmer := &recordingSupportConfirmer{}
	svc := NewRegistry(RegistryConfig{
		NowHeight:              func() (uint64, error) { return 0, errors.New("keeper unreachable") },
		SupporterAddress:       "cortex1supporter",
		InferenceCapability:    true,
		VerificationCapability: true,
		SupportConfirmer:       confirmer,
	})
	svc.PutStatus(ModelStatus{ModelID: "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", ProfileVersion: "1"})
	if _, err := svc.DailySupport(context.Background(), DailySupportRequest{ModelID: "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", Enabled: true}); err == nil {
		t.Fatalf("DailySupport confirmed material while chain height was unavailable")
	}
	if len(confirmer.materials) != 0 {
		t.Fatalf("support confirmations = %d, want 0", len(confirmer.materials))
	}
}
