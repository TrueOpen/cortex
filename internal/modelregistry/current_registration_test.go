package modelregistry

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/keepercontract"
	"github.com/SingaXYZ/cortex/internal/txclient"
)

func TestRegisterCurrentSubmitsWithoutAnInnerRegistrantSignature(t *testing.T) {
	manifest := mustCurrentManifest(t)
	reader := &currentRegistrationReaderStub{err: chainclient.ErrNotFound}
	submitter := &currentRegistrationSubmitterStub{}
	var signed codec.Hash
	registry := newCurrentRegistry(reader, submitter, func(_ context.Context, digest codec.Hash) (txclient.ProtoBytes, error) {
		signed = digest
		return txclient.ProtoBytes(strings.Repeat("cd", 64)), nil
	})

	result, err := registry.RegisterCurrent(context.Background(), CurrentRegisterRequest{Manifest: manifest})
	if err != nil {
		t.Fatalf("RegisterCurrent error = %v", err)
	}
	wantDigest, _, err := keepercontract.ModelRegistrationDigest("trueopen-devnet-1", "trueopen1operator", manifest.Profile)
	if err != nil {
		t.Fatal(err)
	}
	if !signed.IsZero() || result.RegistrationDigest != wantDigestHex(wantDigest) {
		t.Fatalf("signed/result digest = %x/%s, want %x", signed, result.RegistrationDigest, wantDigest)
	}
	if result.Status != RegistrationStageSubmitted || result.TxID != "registration-tx" || len(submitter.messages) != 1 {
		t.Fatalf("result/submissions = %#v/%d", result, len(submitter.messages))
	}
	message := submitter.messages[0]
	if message.ProposerAddress != "trueopen1operator" || message.Profile.ModelID != manifest.Profile.ModelID {
		t.Fatalf("submitted message = %#v", message)
	}
}

func TestRegisterCurrentSkipsExactExistingDigestWithoutSigning(t *testing.T) {
	manifest := mustCurrentManifest(t)
	digest, _, err := keepercontract.ModelRegistrationDigest("trueopen-devnet-1", "trueopen1operator", manifest.Profile)
	if err != nil {
		t.Fatal(err)
	}
	reader := &currentRegistrationReaderStub{state: currentStateForRegistration(manifest.Profile, digest)}
	submitter := &currentRegistrationSubmitterStub{}
	registry := newCurrentRegistry(reader, submitter, func(context.Context, codec.Hash) (txclient.ProtoBytes, error) {
		t.Fatal("signer called for idempotent registration")
		return "", nil
	})

	result, err := registry.RegisterCurrent(context.Background(), CurrentRegisterRequest{Manifest: manifest})
	if err != nil || result.Status != RegistrationStageSkipped || len(submitter.messages) != 0 {
		t.Fatalf("RegisterCurrent = %#v, %v; submissions %d", result, err, len(submitter.messages))
	}
}

func TestRegisterCurrentRejectsExistingDigestConflict(t *testing.T) {
	manifest := mustCurrentManifest(t)
	digest := codec.Hash{1}
	reader := &currentRegistrationReaderStub{state: currentStateForRegistration(manifest.Profile, digest)}
	registry := newCurrentRegistry(reader, &currentRegistrationSubmitterStub{}, nil)

	_, err := registry.RegisterCurrent(context.Background(), CurrentRegisterRequest{Manifest: manifest})
	if err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("RegisterCurrent error = %v, want conflict", err)
	}
}

func TestRegisterCurrentDryRunCalculatesDigestWithoutSigningOrSubmitting(t *testing.T) {
	manifest := mustCurrentManifest(t)
	reader := &currentRegistrationReaderStub{err: chainclient.ErrNotFound}
	submitter := &currentRegistrationSubmitterStub{}
	registry := newCurrentRegistry(reader, submitter, nil)

	result, err := registry.RegisterCurrent(context.Background(), CurrentRegisterRequest{Manifest: manifest, DryRun: true})
	if err != nil || result.Status != RegistrationStagePlanned || result.RegistrationDigest == "" || len(submitter.messages) != 0 {
		t.Fatalf("RegisterCurrent = %#v, %v", result, err)
	}
}

func TestRegisterCurrentReturnsFailedStatusOnAtomicSubmitError(t *testing.T) {
	manifest := mustCurrentManifest(t)
	reader := &currentRegistrationReaderStub{err: chainclient.ErrNotFound}
	submitter := &currentRegistrationSubmitterStub{err: errors.New("rejected")}
	registry := newCurrentRegistry(reader, submitter, func(context.Context, codec.Hash) (txclient.ProtoBytes, error) {
		return txclient.ProtoBytes(strings.Repeat("cd", 64)), nil
	})

	result, err := registry.RegisterCurrent(context.Background(), CurrentRegisterRequest{Manifest: manifest})
	if err == nil || result.Status != RegistrationStageFailed || len(submitter.messages) != 1 {
		t.Fatalf("RegisterCurrent = %#v, %v", result, err)
	}
}

func mustCurrentManifest(t testing.TB) CurrentManifest {
	t.Helper()
	manifest, err := GenerateCurrentManifest(validCurrentManifestInput())
	if err != nil {
		t.Fatalf("GenerateCurrentManifest: %v", err)
	}
	return manifest
}

func newCurrentRegistry(reader CurrentRegistrationReader, submitter CurrentRegistrationSubmitter, sign CurrentRegistrationSigner) *Registry {
	return NewRegistry(RegistryConfig{
		CurrentRegistrationReader: reader, CurrentRegistrationSubmitter: submitter, CurrentRegistrationSigner: sign,
		ChainID: "trueopen-devnet-1", ProposerAddress: "trueopen1operator",
	})
}

func currentStateForRegistration(profile txclient.ModelProfileProjectionMessage, digest codec.Hash) chainclient.CurrentModelProfileSnapshot {
	return chainclient.CurrentModelProfileSnapshot{
		Model: chainclient.CurrentModelSnapshot{ModelID: profile.ModelID, ProposerAddress: "trueopen1operator"},
		Profile: chainclient.CurrentProfileSnapshot{
			ModelID: profile.ModelID, ProfileVersion: chainclient.NewProfileVersion(uint32(profile.ProfileVersion)), ProposerAddress: "trueopen1operator",
			ManifestHash: chainclient.ProtoBytes32(mustDecodeHex(profile.ManifestHash.Hex())), RegistrationDigest: chainclient.ProtoBytes32(digest[:]),
			RegistrationFeePaid: chainclient.NewUint64String(uint64(profile.RegistrationFee.Amount)),
		},
	}
}

func wantDigestHex(digest codec.Hash) string {
	return hex.EncodeToString(digest[:])
}

func mustDecodeHex(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return decoded
}

type currentRegistrationReaderStub struct {
	state chainclient.CurrentModelProfileSnapshot
	err   error
}

func (r *currentRegistrationReaderStub) CurrentModelProfile(context.Context, string, string) (chainclient.CurrentModelProfileSnapshot, error) {
	return r.state, r.err
}

type currentRegistrationSubmitterStub struct {
	messages []txclient.RegisterModelProfileMessage
	err      error
}

func (s *currentRegistrationSubmitterStub) SubmitModelProfile(_ context.Context, message txclient.RegisterModelProfileMessage) (string, error) {
	s.messages = append(s.messages, message)
	return "registration-tx", s.err
}
