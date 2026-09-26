package modelregistry

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/keepercontract"
	"github.com/TrueOpen/cortex/internal/txclient"
)

type CurrentRegistrationReader interface {
	CurrentModelProfile(context.Context, string, string) (chainclient.CurrentModelProfileSnapshot, error)
}

type CurrentRegistrationSubmitter interface {
	SubmitModelProfile(context.Context, txclient.RegisterModelProfileMessage) (string, error)
}

type CurrentRegistrationSigner func(context.Context, codec.Hash) (txclient.ProtoBytes, error)

type CurrentRegisterRequest struct {
	Manifest CurrentManifest `json:"manifest"`
	DryRun   bool            `json:"dry_run"`
}

type CurrentRegisterResult struct {
	ManifestHash       string `json:"manifest_hash"`
	RegistrationDigest string `json:"registration_digest"`
	Status             string `json:"status"`
	TxID               string `json:"tx_id,omitempty"`
	DryRun             bool   `json:"dry_run"`
}

func (r *Registry) RegisterCurrent(ctx context.Context, req CurrentRegisterRequest) (CurrentRegisterResult, error) {
	result := CurrentRegisterResult{ManifestHash: req.Manifest.Hash, DryRun: req.DryRun}
	if err := ValidateCurrentManifest(req.Manifest); err != nil {
		return result, err
	}
	if r.chainID == "" || r.proposerAddress == "" {
		return result, fmt.Errorf("current model registration chain_id and proposer_address are required")
	}
	digest, _, err := keepercontract.ModelRegistrationDigest(r.chainID, r.proposerAddress, req.Manifest.Profile)
	if err != nil {
		return result, fmt.Errorf("calculate model registration digest: %w", err)
	}
	result.RegistrationDigest = hex.EncodeToString(digest[:])

	if r.currentRegistrationReader == nil {
		return result, fmt.Errorf("current model registration reader is required")
	}
	state, err := r.currentRegistrationReader.CurrentModelProfile(ctx, string(req.Manifest.Profile.ModelID), fmt.Sprintf("%d", req.Manifest.Profile.ProfileVersion))
	switch {
	case err == nil:
		if !currentRegistrationMatches(state, r.proposerAddress, req.Manifest.Profile, digest) {
			return result, fmt.Errorf("model profile conflict: existing state does not match registration projection and digest")
		}
		result.Status = RegistrationStageSkipped
		return result, nil
	case !errors.Is(err, chainclient.ErrNotFound):
		return result, fmt.Errorf("read current Keeper model profile: %w", err)
	}

	result.Status = RegistrationStagePlanned
	if req.DryRun {
		return result, nil
	}
	message := txclient.RegisterModelProfileMessage{
		ProposerAddress: r.proposerAddress,
		Profile:         req.Manifest.Profile,
	}
	if _, err := txclient.MarshalMessage(txclient.MsgRegisterModelProfile, message); err != nil {
		return result, fmt.Errorf("validate model registration message: %w", err)
	}
	if r.currentRegistrationSubmitter == nil {
		return result, fmt.Errorf("current model registration submitter is required")
	}
	txID, err := r.currentRegistrationSubmitter.SubmitModelProfile(ctx, message)
	if err != nil {
		result.Status = RegistrationStageFailed
		return result, fmt.Errorf("model profile registration: %w", err)
	}
	result.Status = RegistrationStageSubmitted
	result.TxID = txID
	return result, nil
}

func currentRegistrationMatches(state chainclient.CurrentModelProfileSnapshot, proposer string, profile txclient.ModelProfileProjectionMessage, digest codec.Hash) bool {
	return state.Model.ModelID == string(profile.ModelID) &&
		state.Profile.ModelID == string(profile.ModelID) &&
		state.Profile.ProfileVersion.Uint32() == uint32(profile.ProfileVersion) &&
		state.Model.ProposerAddress == proposer &&
		state.Profile.ProposerAddress == proposer &&
		bytes.Equal(state.Profile.RegistrationDigest, digest[:]) &&
		state.Profile.RegistrationFeePaid.Uint64() == uint64(profile.RegistrationFee.Amount) &&
		state.Profile.ManifestHash.Hex() == profile.ManifestHash.Hex()
}
