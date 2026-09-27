package verifier

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// verifierCommitDeliveryEvidenceKind records that the chain confirmed this
// round's commit, so the commit-key dedup survives a restart.
const verifierCommitDeliveryEvidenceKind = "verifier-commit-delivery"

// randomSalt draws a non-zero 32-byte commit salt from the CSPRNG.
func randomSalt() (codec.Hash, error) {
	var salt codec.Hash
	for salt.IsZero() {
		if _, err := rand.Read(salt[:]); err != nil {
			return codec.Hash{}, fmt.Errorf("draw commit salt: %w", err)
		}
	}
	return salt, nil
}

// persistedCommit restores this round's signed commit from the persisted
// reveal record. ok is false when no commit was persisted yet.
func (v *Verifier) persistedCommit(ctx context.Context, state TaskState) (VerifyResult, bool, error) {
	reader, ok := v.cfg.Persistence.(verifierEvidenceReader)
	if !ok {
		return VerifyResult{}, false, nil
	}
	data, err := reader.ReadVerifierEvidence(ctx, verifierFullResultRevealEvidenceKind)
	if errors.Is(err, evidence.ErrArtifactNotFound) {
		return VerifyResult{}, false, nil
	}
	if err != nil {
		return VerifyResult{}, false, fmt.Errorf("read persisted verify commit: %w", err)
	}
	var record struct {
		TaskID                 string                   `json:"task_id"`
		VerifyRound            uint64                   `json:"verify_round"`
		VerificationSampleSeed codec.Hash               `json:"verification_sample_seed"`
		ResultDigest           codec.Hash               `json:"result_digest"`
		CommitWire             *nodewire.VerifyCommitV1 `json:"commit_wire"`
	}
	if err := json.Unmarshal(data, &record); err != nil {
		return VerifyResult{}, false, fmt.Errorf("decode persisted verify commit: %w", err)
	}
	if record.TaskID != state.TaskID || record.VerifyRound != state.VerifyRound {
		return VerifyResult{}, false, nil
	}
	source, err := v.persistedReveal(ctx, state)
	if err != nil {
		return VerifyResult{}, false, err
	}
	if record.CommitWire == nil || len(record.CommitWire.ServiceSignature) == 0 ||
		!bytes.Equal(record.CommitWire.CommitHash, source.CommitHash[:]) {
		return VerifyResult{}, false, fmt.Errorf("persisted verify commit for task %s round %d is not the signed commit of its commit_hash", state.TaskID, state.VerifyRound)
	}
	return VerifyResult{
		Started: true, VerificationSampleSeed: record.VerificationSampleSeed, ResultDigest: record.ResultDigest,
		ResultReveal: source.ResultReveal, EvidenceManifest: source.EvidenceManifest,
		CommitHash: source.CommitHash, CommitWire: *record.CommitWire, Salt: source.Salt, MetricMaterial: source.MetricMaterial,
	}, true, nil
}

type persistedCommitDelivery struct {
	Scope          string `json:"scope"`
	CommitHash     string `json:"commit_hash"`
	TxHash         string `json:"tx_hash"`
	IncludedHeight uint64 `json:"included_height"`
}

// persistedDelivery reads the durable record of a chain-confirmed commit.
func (v *Verifier) persistedDelivery(ctx context.Context, scope string) (CommitDelivery, bool, error) {
	reader, ok := v.cfg.Persistence.(verifierEvidenceReader)
	if !ok {
		return CommitDelivery{}, false, nil
	}
	data, err := reader.ReadVerifierEvidence(ctx, verifierCommitDeliveryEvidenceKind)
	if errors.Is(err, evidence.ErrArtifactNotFound) {
		return CommitDelivery{}, false, nil
	}
	if err != nil {
		return CommitDelivery{}, false, fmt.Errorf("read persisted commit delivery: %w", err)
	}
	var record persistedCommitDelivery
	if err := json.Unmarshal(data, &record); err != nil {
		return CommitDelivery{}, false, fmt.Errorf("decode persisted commit delivery: %w", err)
	}
	if record.Scope != scope {
		return CommitDelivery{}, false, nil
	}
	return CommitDelivery{Reason: CommitExitRelayChannelAbsent, SelfSubmitted: true, ChainAccepted: true, Duplicate: true,
		TxHash: record.TxHash, IncludedHeight: record.IncludedHeight}, true, nil
}

// recordDelivery makes a chain-confirmed commit durable for the dedup.
func (v *Verifier) recordDelivery(ctx context.Context, state TaskState, scope string, result VerifyResult, delivery CommitDelivery) error {
	if v.cfg.Persistence == nil {
		return nil
	}
	data, err := json.Marshal(persistedCommitDelivery{Scope: scope, CommitHash: hex.EncodeToString(result.CommitHash[:]),
		TxHash: delivery.TxHash, IncludedHeight: delivery.IncludedHeight})
	if err != nil {
		return err
	}
	return v.cfg.Persistence.WriteEvidence(ctx, EvidenceRecord{TaskID: state.TaskID, Kind: verifierCommitDeliveryEvidenceKind, Data: data, Ref: evidenceRef(data)})
}
