package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidencebundle"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/tasktrace"
	"github.com/TrueOpen/cortex/internal/verifier"
	"github.com/TrueOpen/cortex/internal/worker"
)

// nexusVerifierEvidencePublisher makes the committed bundle available before a result is relayed.
type nexusVerifierEvidencePublisher struct {
	cfg             TaskRunnerConfig
	builderOperator string
}

func (p nexusVerifierEvidencePublisher) PublishVerifierEvidence(ctx context.Context, state verifier.TaskState, receipt nodewire.ResultReceiptV3, manifestBytes, proof []byte) error {
	if p.cfg.TaskData == nil || p.cfg.TaskDataAuth == nil || p.cfg.ReceivingBuilder == nil || p.cfg.TaskFacts == nil || p.cfg.Evidence == nil {
		return fmt.Errorf("Verifier evidence publication requires task-data, authentication, Builder resolution, task facts and durable evidence")
	}
	manifest, err := evidencebundle.Decode(manifestBytes)
	if err != nil {
		return err
	}
	bundleHash := evidencebundle.Hash(manifestBytes)
	if !bytes.Equal(receipt.VerifierEvidenceBundleHash, bundleHash[:]) || receipt.VerifierEvidenceManifestSizeBytes != uint64(len(manifestBytes)) || manifest.EvidenceKind != evidencebundle.KindVerifierValueOpening || len(manifest.Artifacts) != 1 || manifest.Artifacts[0].ID != "aggregate_proof" {
		return fmt.Errorf("Verifier manifest differs from signed receipt")
	}
	facts, err := p.cfg.TaskFacts.TaskFacts(ctx, state.TaskID)
	if err != nil {
		return err
	}
	if err := facts.Validate(state.TaskID); err != nil {
		return err
	}
	if manifest.ChainID != p.cfg.ChainID || receipt.ChainID != p.cfg.ChainID || manifest.TaskID != state.TaskID || hex.EncodeToString(receipt.TaskID) != state.TaskID || manifest.TaskHash != hex.EncodeToString(facts.AcceptedTaskHash) || manifest.ProducerKind != "VERIFIER" || manifest.ProducerOperator != receipt.VerifierOperatorAddress || receipt.VerifierOperatorAddress != p.cfg.LocalVerifierAddress || uint64(manifest.VerifyRound) != state.VerifyRound || receipt.VerifyRound != manifest.VerifyRound {
		return fmt.Errorf("Verifier bundle task, producer or round mismatch")
	}
	proofHash := codec.HashBytes(proof)
	size, err := manifest.Artifacts[0].SizeBytes()
	if err != nil || size != uint64(len(proof)) || manifest.Artifacts[0].ContentHash != proofHash.String() || !bytes.Equal(receipt.AggregateProofHash, proofHash[:]) {
		return fmt.Errorf("Verifier aggregate proof differs from manifest or receipt")
	}
	bundleKey := builderclient.EvidenceObjectKey(manifest.TaskHash, state.SessionID, state.TaskID, builderclient.DataKindEvidenceManifest, bundleHash.String(), builderclient.EvidenceProducerVerifier, manifest.VerifyRound, manifest.ProducerOperator, nodewire.EvidenceKindVerifierValueOpening)
	taskHash := codec.Hash(facts.AcceptedTaskHash)
	recordKind := fmt.Sprintf("verifier-evidence-confirmation-%d", state.VerifyRound)
	retained, err := p.retainedVerifierConfirmation(ctx, taskHash, recordKind)
	if err != nil {
		return err
	}
	if retained != nil {
		height, err := p.verifierConfirmationHeight(ctx)
		if err != nil {
			return err
		}
		return validateVerifierConfirmation(*retained, p.cfg.ChainID, p.builderOperator, bundleKey, uint64(len(manifestBytes)), uint64(len(proof)), height)
	}
	ref := worker.ReceivingBuilderRef{SessionID: state.SessionID, TaskID: state.TaskID, AssignedBuilderOperator: p.builderOperator}
	endpoint, err := p.cfg.ReceivingBuilder.ResolveReceivingBuilder(ctx, ref)
	if err != nil {
		return err
	}
	if endpoint.OperatorAddress != p.builderOperator || endpoint.AuthorizationNonce == 0 || endpoint.CurrentHeight == 0 {
		return fmt.Errorf("Verifier receiving Builder identity is incomplete")
	}
	ctx = builderclient.WithTLSPubkeyHash(ctx, endpoint.TLSPubkeyHash)
	artifactKey := builderclient.EvidenceObjectKey(manifest.TaskHash, state.SessionID, state.TaskID, builderclient.DataKindEvidenceArtifact, proofHash.String(), builderclient.EvidenceProducerVerifier, manifest.VerifyRound, manifest.ProducerOperator, nodewire.EvidenceKindVerifierValueOpening)
	for _, object := range []struct {
		key  builderclient.TaskDataKey
		data []byte
	}{{artifactKey, proof}, {bundleKey, manifestBytes}} {
		digest, err := builderclient.TaskDataUploadBodyDigest(object.key, uint64(len(object.data)), "")
		if err != nil {
			return err
		}
		auth, err := p.cfg.TaskDataAuth.SignRequest(ctx, "UploadTaskResultObject", object.key, endpoint.OperatorAddress, digest)
		if err != nil {
			return err
		}
		meta, err := p.cfg.TaskData.UploadTaskResultObject(ctx, endpoint.Endpoint, builderclient.UploadTaskResultRequest{Key: object.key, SizeBytes: uint64(len(object.data)), Auth: auth, Data: object.data})
		if err != nil {
			return err
		}
		if meta.Key != object.key || meta.SizeBytes != uint64(len(object.data)) || (meta.Readiness != builderclient.TaskDataStored && meta.Readiness != builderclient.TaskDataReady) {
			return fmt.Errorf("Verifier upload returned mismatched metadata")
		}
	}
	request := builderclient.FinalizeVerifierEvidenceRequest{TaskHash: manifest.TaskHash, SessionID: state.SessionID, TaskID: state.TaskID, VerifyRound: manifest.VerifyRound, VerifierOperator: manifest.ProducerOperator, Receipt: receipt}
	digest, err := builderclient.TaskDataFinalizeVerifierBodyDigest(request)
	if err != nil {
		return err
	}
	request.Auth, err = p.cfg.TaskDataAuth.SignRequest(ctx, "FinalizeVerifierEvidence", bundleKey, endpoint.OperatorAddress, digest)
	if err != nil {
		return err
	}
	response, err := p.cfg.TaskData.FinalizeVerifierEvidence(ctx, endpoint.Endpoint, request)
	if err != nil {
		return err
	}
	current, err := p.cfg.ReceivingBuilder.ResolveReceivingBuilder(ctx, ref)
	if err != nil {
		return err
	}
	if current.OperatorAddress != p.builderOperator || current.AuthorizationNonce == 0 || current.CurrentHeight == 0 {
		return fmt.Errorf("Verifier current receiving Builder identity is incomplete or mismatched")
	}
	confirmation := response.EvidenceBundleConfirmation
	record := verifierEvidenceConfirmation{Version: 1, Confirmation: confirmation, BuilderServicePubkey: current.ServicePubkey, BuilderAuthorizationNonce: current.AuthorizationNonce, VerifiedAtHeight: current.CurrentHeight}
	if err := validateVerifierConfirmation(record, p.cfg.ChainID, p.builderOperator, bundleKey, uint64(len(manifestBytes)), uint64(len(proof)), current.CurrentHeight); err != nil {
		return err
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := writeTaskEvidence(ctx, p.cfg.Evidence, taskHash, state.SessionID, state.TaskID, recordKind, encoded); err != nil {
		return fmt.Errorf("persist verified Verifier bundle confirmation: %w", err)
	}
	p.cfg.Trace.Event("verifier_evidence_finalized", tasktrace.Str("task", state.TaskID), tasktrace.Hash("evidence_bundle_hash", bundleHash), tasktrace.Uint("verify_round", state.VerifyRound))
	return nil
}

// The full confirmation and the identity verified on receipt commit together.
// Later key rotations do not invalidate these already-verified bytes.
type verifierEvidenceConfirmation struct {
	Version                   uint32                            `json:"version"`
	Confirmation              builderclient.StorageConfirmation `json:"confirmation"`
	BuilderServicePubkey      string                            `json:"builder_service_pubkey"`
	BuilderAuthorizationNonce uint64                            `json:"builder_authorization_nonce"`
	VerifiedAtHeight          uint64                            `json:"verified_at_height"`
}

func (p nexusVerifierEvidencePublisher) retainedVerifierConfirmation(ctx context.Context, taskHash codec.Hash, kind string) (*verifierEvidenceConfirmation, error) {
	artifacts, err := p.cfg.Evidence.TaskArtifacts(ctx, taskHash)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	for _, artifact := range artifacts {
		if string(artifact.Kind) != kind {
			continue
		}
		data, err := p.cfg.Evidence.ReadTaskKind(ctx, taskHash, kind)
		if err != nil {
			return nil, fmt.Errorf("read verified Verifier confirmation: %w", err)
		}
		var record verifierEvidenceConfirmation
		if err := json.Unmarshal(data, &record); err != nil {
			return nil, fmt.Errorf("decode verified Verifier confirmation: %w", err)
		}
		return &record, nil
	}
	return nil, nil
}

func (p nexusVerifierEvidencePublisher) verifierConfirmationHeight(ctx context.Context) (uint64, error) {
	if p.cfg.ChainStatus != nil {
		height, chainID, err := p.cfg.ChainStatus.ChainStatus(ctx)
		if err != nil {
			return 0, err
		}
		if height == 0 || chainID != p.cfg.ChainID {
			return 0, fmt.Errorf("Verifier confirmation requires current height on its chain")
		}
		return height, nil
	}
	_, height, err := p.cfg.TaskDataAuth.CommittedBusEnvelopeIdentity(ctx)
	return height, err
}

func validateVerifierConfirmation(record verifierEvidenceConfirmation, chainID, builder string, key builderclient.TaskDataKey, size, artifactSize, height uint64) error {
	c := record.Confirmation
	if record.Version != 1 || height == 0 || record.VerifiedAtHeight == 0 || record.VerifiedAtHeight > height || record.BuilderAuthorizationNonce == 0 || record.BuilderServicePubkey == "" || c.SchemaVersion != 1 || c.ChainID != chainID || c.Key != key || c.BuilderOperator != builder || c.ServiceAuthorizationNonce != record.BuilderAuthorizationNonce || c.SizeBytes != size || c.ArtifactTotalSizeBytes != artifactSize || c.RetentionUntilHeight <= height {
		return fmt.Errorf("Verifier bundle confirmation differs from object or verified Builder binding, or its retention expired")
	}
	digest, err := builderclient.StorageConfirmationSigningHash(c)
	if err != nil {
		return err
	}
	return signer.VerifyDigestSignature(record.BuilderServicePubkey, digest, c.Signature)
}
