package modelregistry

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/txclient"
)

// Declarations only tests use, kept out of the production binary.

func NewRegistrationDigestSigner(client signer.DigestSigner, keyRef string, address string) Signer {
	return func(ctx context.Context, material RegistrationMaterial) (string, error) {
		if client == nil {
			return "", fmt.Errorf("model registration digest signer is required")
		}
		message := material.Message
		message.RegistrantSignature = ""
		canonical, err := json.Marshal(message)
		if err != nil {
			return "", err
		}
		digest := codec.HashBytes(canonical)
		signature, err := client.SignDigest(ctx, signer.DigestRequest{KeyRef: keyRef, ExpectedSignerAddress: address, Digest: digest})
		if err != nil {
			return "", err
		}
		if len(signature) != 64 {
			return "", fmt.Errorf("model registration signer returned an invalid signature length")
		}
		return hex.EncodeToString(signature), nil
	}
}

func NewCurrentRegistrationDigestSigner(client signer.DigestSigner, keyRef string, address string) CurrentRegistrationSigner {
	return func(ctx context.Context, digest codec.Hash) (txclient.ProtoBytes, error) {
		if client == nil {
			return "", fmt.Errorf("model registration digest signer is required")
		}
		signature, err := client.SignDigest(ctx, signer.DigestRequest{KeyRef: keyRef, ExpectedSignerAddress: address, Digest: digest})
		if err != nil {
			return "", err
		}
		if len(signature) != 64 {
			return "", fmt.Errorf("model registration signer returned an invalid signature length")
		}
		return txclient.ProtoBytes(hex.EncodeToString(signature)), nil
	}
}

// NewCurrentRegistrationSubmitter builds the only registration submitter that
// targets a registered Keeper message: MsgRegisterModelProfile. There is
// deliberately no txclient-backed TxSubmitter any more - the Keeper registers no
// model/profile creation message for the legacy flat material, so such a
// submitter could only ever refuse, and every caller had to sign the material
// first to reach that refusal.
func NewCurrentRegistrationSubmitter(tx txclient.Client, options TxSubmitterOptions) CurrentRegistrationSubmitter {
	return txSubmitter{tx: tx, options: options}
}
func (s txSubmitter) SubmitModelProfile(ctx context.Context, message txclient.RegisterModelProfileMessage) (string, error) {
	taskID := "model-profile-registration:" + string(message.Profile.ModelID) + "/" + strconv.FormatUint(uint64(message.Profile.ProfileVersion), 10)
	return s.submitKeeperRegistration(ctx, taskID, txclient.MsgRegisterModelProfile, message)
}

func (s txSubmitter) submitKeeperRegistration(ctx context.Context, taskID string, kind txclient.Kind, message any) (string, error) {
	if s.tx == nil {
		return "", fmt.Errorf("tx client is required")
	}
	payload, err := txclient.MarshalMessage(kind, message)
	if err != nil {
		return "", err
	}
	digest := codec.HashWithDomain("CORTEX_KEEPER_MODEL_REGISTRATION_V2", []byte(kind), payload)
	observation, err := s.tx.Submit(ctx, txclient.Request{
		TaskID: taskID, Kind: kind, Payload: payload, GasPayer: s.options.GasPayer,
		FeeCap: s.options.FeeCap, FeeGrant: s.options.FeeGrant, Memo: s.options.Memo, MaterialDigest: digest,
	})
	if err != nil {
		return "", err
	}
	if observation.Rejected {
		return "", fmt.Errorf("Keeper rejected %s: %s", kind, observation.RejectReason)
	}
	if !observation.Accepted || observation.TxHash == "" {
		return "", fmt.Errorf("Keeper did not confirm %s", kind)
	}
	return observation.TxHash, nil
}
