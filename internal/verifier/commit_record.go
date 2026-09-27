package verifier

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TrueOpen/cortex/internal/tasktrace"
	"reflect"
	"slices"

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

// HasPersistedCommit reports whether this round's verify record is persisted,
// so a caller can re-deliver the signed commit before fetching anything.
func HasPersistedCommit(ctx context.Context, persistence Persistence) (bool, error) {
	reader, ok := persistence.(verifierEvidenceReader)
	if !ok {
		return false, nil
	}
	_, err := reader.ReadVerifierEvidence(ctx, verifierFullResultRevealEvidenceKind)
	if errors.Is(err, evidence.ErrArtifactNotFound) {
		return false, nil
	}
	return err == nil, err
}

// ResumePersistedCommit re-delivers this round's already-signed commit when
// one is persisted, before any evidence fetch or model call, so a commit can
// reach the chain while Builders are unavailable. ok is false when there is
// nothing persisted and the caller must verify from the start.
//
// The commit_hash, salt and verifier_value_root are never changed. If the
// persisted signature was made under a service_authorization_nonce or expiry
// that no longer matches what this node would sign now (a key rotation), the
// same commit_hash is re-signed with the current key; the re-signed body is
// kept in memory, because the persisted record is write-once.
func (v *Verifier) ResumePersistedCommit(ctx context.Context, state TaskState) (VerifyResult, bool, error) {
	if !state.OpenVerifyAccepted || !slices.Contains(state.AssignedVerifiers, v.cfg.VerifierAddress) {
		return VerifyResult{}, false, nil
	}
	result, ok, err := v.persistedCommit(ctx, state)
	if err != nil || !ok {
		return VerifyResult{}, false, err
	}
	if result.CommitWire, err = v.currentCommitWire(ctx, state, result.CommitWire); err != nil {
		return VerifyResult{}, false, err
	}
	delivery, err := v.deliverCommit(ctx, state, result)
	result.CommitDelivery = delivery
	return result, true, err
}

// currentCommitWire returns persisted when it is what this node would sign
// now, and otherwise the same commit_hash signed under the current binding.
func (v *Verifier) currentCommitWire(ctx context.Context, state TaskState, persisted nodewire.VerifyCommitV1) (nodewire.VerifyCommitV1, error) {
	current, err := verifyCommitWire(v.cfg, state, codec.Hash(persisted.CommitHash))
	if err != nil {
		return nodewire.VerifyCommitV1{}, err
	}
	current.ServiceSignature = persisted.ServiceSignature
	if reflect.DeepEqual(current, persisted) {
		return persisted, nil
	}
	digest, err := nodewire.VerifyCommitSigningDigest(current)
	if err != nil {
		return nodewire.VerifyCommitV1{}, err
	}
	if current.ServiceSignature, err = v.signDigest(ctx, digest); err != nil {
		return nodewire.VerifyCommitV1{}, err
	}
	v.cfg.Trace.Event("verify_commit_resigned", tasktrace.Str("task", state.TaskID), tasktrace.Uint("verify_round", state.VerifyRound),
		tasktrace.Hex("commit_hash", hex.EncodeToString(current.CommitHash)),
		tasktrace.Uint("persisted_nonce", persisted.ServiceAuthorizationNonce), tasktrace.Uint("current_nonce", current.ServiceAuthorizationNonce))
	return current, nil
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
	if record.CommitWire == nil {
		return VerifyResult{}, false, fmt.Errorf("persisted verify record for task %s round %d carries no signed commit (written by an "+
			"earlier build); clear this task's local verifier record before retrying it", state.TaskID, state.VerifyRound)
	}
	if len(record.CommitWire.ServiceSignature) == 0 || !bytes.Equal(record.CommitWire.CommitHash, source.CommitHash[:]) {
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
