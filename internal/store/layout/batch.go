package layout

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store"
)

var (
	// ErrConflict is returned when a merge would overwrite an immutable or
	// already-set field with a different non-empty value.
	ErrConflict = errors.New("record conflict")

	// ErrInvalidStage is returned when a role record carries a RoleStage outside
	// the declared constants.
	ErrInvalidStage = errors.New("invalid role stage")

	// ErrInvalidArtifactKind is returned when a record references an unknown
	// ArtifactKind.
	ErrInvalidArtifactKind = errors.New("invalid artifact kind")

	// ErrInvalidFinishReason is returned when an infer record references an
	// unknown FinishReasonV1.
	ErrInvalidFinishReason = errors.New("invalid finish reason")

	// ErrStaleCandidateReplacement is returned when a candidate replacement does
	// not advance the publish time.
	ErrStaleCandidateReplacement = errors.New("candidate replacement does not advance publish time")
)

// MergeTask merges an authoritative Keeper task record into the store. Every
// field is compared against the stored value and a conflicting non-empty value
// fails. This makes concurrent creation by infer and verify paths safe.
func MergeTask(ctx context.Context, s *store.Store, taskHash StoredHash, record TaskRecord) error {
	record.SchemaVersion = defaultSchemaVersion(record.SchemaVersion)
	return s.ApplyBatch(ctx, func(b *store.Batch) error {
		existing, err := taskRecordFromBatch(b, taskHash)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		merged, err := mergeTaskRecords(existing, record)
		if err != nil {
			return err
		}
		return putBatchJSON(b, TaskKey(taskHash), merged)
	})
}

// MergeInfer merges an infer role record with read-modify-write semantics. It
// refuses a Stage outside the declared constants and permits only scheduling
// transitions plus the one-shot FinishReason write.
func MergeInfer(ctx context.Context, s *store.Store, taskHash StoredHash, record InferRecord) error {
	if err := validateStage(record.Stage); err != nil {
		return err
	}
	if record.FinishReason != "" {
		if err := validateFinishReason(record.FinishReason); err != nil {
			return err
		}
	}
	record.SchemaVersion = defaultSchemaVersion(record.SchemaVersion)
	return s.ApplyBatch(ctx, func(b *store.Batch) error {
		existing, err := inferRecordFromBatch(b, taskHash)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		merged, err := mergeInferRecords(existing, record)
		if err != nil {
			return err
		}
		if merged.TaskID != "" {
			if err := b.Set(TaskIDInferKey(merged.TaskID), taskHash[:]); err != nil {
				return err
			}
		}
		return putBatchJSON(b, InferKey(taskHash), merged)
	})
}

// MergeVerify merges a verify role record with read-modify-write semantics. It
// applies the same immutable-field, stage-validation and write-once-late checks
// as MergeInfer.
func MergeVerify(ctx context.Context, s *store.Store, taskHash StoredHash, record VerifyRecord) error {
	if err := validateStage(record.Stage); err != nil {
		return err
	}
	record.SchemaVersion = defaultSchemaVersion(record.SchemaVersion)
	return s.ApplyBatch(ctx, func(b *store.Batch) error {
		existing, err := verifyRecordFromBatch(b, taskHash)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		merged, err := mergeVerifyRecords(existing, record)
		if err != nil {
			return err
		}
		if merged.TaskID != "" {
			if err := b.Set(TaskIDVerifyKey(merged.TaskID), taskHash[:]); err != nil {
				return err
			}
		}
		return putBatchJSON(b, VerifyKey(taskHash), merged)
	})
}

// MergeEvidence merges an evidence manifest row. Artifact writes are idempotent
// by (Kind, Digest); singleton kinds reject a different digest once one is
// committed.
func MergeEvidence(ctx context.Context, s *store.Store, taskHash StoredHash, record Evidence) error {
	record.SchemaVersion = defaultSchemaVersion(record.SchemaVersion)
	return s.ApplyBatch(ctx, func(b *store.Batch) error {
		existing, err := evidenceRecordFromBatch(b, taskHash)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		merged, err := mergeEvidenceRecords(existing, record)
		if err != nil {
			return err
		}
		return putBatchJSON(b, EvidenceKey(taskHash), merged)
	})
}

// MergeEvidenceFn atomically reads, mutates, validates, and durably writes one
// task's evidence record while excluding all other Store operations.
func MergeEvidenceFn(ctx context.Context, s *store.Store, taskHash StoredHash, mutate func(Evidence, bool) (Evidence, error)) (Evidence, error) {
	var updated Evidence
	err := s.ApplyBatch(ctx, func(b *store.Batch) error {
		existing, err := evidenceRecordFromBatch(b, taskHash)
		exists := err == nil
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		updated, err = mutate(existing, exists)
		if err != nil {
			return err
		}
		updated.SchemaVersion = defaultSchemaVersion(updated.SchemaVersion)
		merged, err := mergeEvidenceRecords(existing, updated)
		if err != nil {
			return err
		}
		return putBatchJSON(b, EvidenceKey(taskHash), merged)
	})
	return updated, err
}

// MergeInferWithEvidence atomically commits an infer role record update and the
// evidence manifest for the same task. This keeps the executor checkpoint and the
// durable evidence manifest consistent across a crash.
func MergeInferWithEvidence(ctx context.Context, s *store.Store, taskHash StoredHash, infer InferRecord, ev Evidence) error {
	if err := validateStage(infer.Stage); err != nil {
		return err
	}
	if infer.FinishReason != "" {
		if err := validateFinishReason(infer.FinishReason); err != nil {
			return err
		}
	}
	infer.SchemaVersion = defaultSchemaVersion(infer.SchemaVersion)
	ev.SchemaVersion = defaultSchemaVersion(ev.SchemaVersion)
	return s.ApplyBatch(ctx, func(b *store.Batch) error {
		// Merge infer record.
		existingInfer, err := inferRecordFromBatch(b, taskHash)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		mergedInfer, err := mergeInferRecords(existingInfer, infer)
		if err != nil {
			return err
		}
		if mergedInfer.TaskID != "" {
			if err := b.Set(TaskIDInferKey(mergedInfer.TaskID), taskHash[:]); err != nil {
				return err
			}
		}
		if err := putBatchJSON(b, InferKey(taskHash), mergedInfer); err != nil {
			return err
		}
		// Merge evidence manifest.
		existingEvidence, err := evidenceRecordFromBatch(b, taskHash)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		mergedEvidence, err := mergeEvidenceRecords(existingEvidence, ev)
		if err != nil {
			return err
		}
		return putBatchJSON(b, EvidenceKey(taskHash), mergedEvidence)
	})
}

// UpsertChallenge opens or closes a challenge lifecycle record. Updates compare
// LastPosition, so an older open cannot overwrite a newer close.
func UpsertChallenge(ctx context.Context, s *store.Store, taskHash StoredHash, challengeID string, record ChallengeLifecycle) error {
	if isZeroPosition(record.LastPosition) {
		return fmt.Errorf("challenge last_position must be set")
	}
	record.SchemaVersion = defaultSchemaVersion(record.SchemaVersion)
	return s.ApplyBatch(ctx, func(b *store.Batch) error {
		existing, err := challengeLifecycleFromBatch(b, taskHash, challengeID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err == nil {
			if positionLess(record.LastPosition, existing.LastPosition) {
				return nil // older position, ignore
			}
			if positionLess(existing.LastPosition, record.LastPosition) {
				// update
			} else {
				// equal position: identical replay, keep existing
				record = existing
			}
		}
		return putBatchJSON(b, ChallengeKey(taskHash, challengeID), record)
	})
}

// PutDelivery stores a Builder storage confirmation for one data kind. It is
// idempotent by (taskHash, dataKind).
func PutDelivery(ctx context.Context, s *store.Store, taskHash StoredHash, dataKind string, confirmation StorageConfirmation) error {
	key := DeliveryKey(taskHash, dataKind)
	confirmation.SchemaVersion = defaultSchemaVersion(confirmation.SchemaVersion)
	encoded, err := json.Marshal(confirmation)
	if err != nil {
		return fmt.Errorf("encode delivery: %w", err)
	}
	return s.PutRaw(ctx, key, encoded)
}

// PutDeliveryWithSelector stores a Builder storage confirmation for one evidence
// selector. It is idempotent by (taskHash, dataKind, selector).
func PutDeliveryWithSelector(ctx context.Context, s *store.Store, taskHash StoredHash, dataKind, selector string, confirmation StorageConfirmation) error {
	key := DeliveryKey(taskHash, dataKind, selector)
	confirmation.SchemaVersion = defaultSchemaVersion(confirmation.SchemaVersion)
	encoded, err := json.Marshal(confirmation)
	if err != nil {
		return fmt.Errorf("encode delivery: %w", err)
	}
	return s.PutRaw(ctx, key, encoded)
}

// AdmissionBatch atomically commits candidate creation or replacement, plus any
// superseded-candidate deletion.
func AdmissionBatch(ctx context.Context, s *store.Store, sessionID string, orderSequence uint64, taskHash StoredHash, admission CandidateAdmission) error {
	admission.SchemaVersion = defaultSchemaVersion(admission.SchemaVersion)
	if admission.SchemaVersion > CandidateAdmissionSchemaVersion {
		return fmt.Errorf("candidate admission schema_version %d is newer than supported %d", admission.SchemaVersion, CandidateAdmissionSchemaVersion)
	}
	locatorKey := CandidateCurrentKey(sessionID, orderSequence)
	candidateKey := CandidateKey(taskHash)
	encoded, err := json.Marshal(admission)
	if err != nil {
		return fmt.Errorf("encode candidate admission: %w", err)
	}

	return s.ApplyBatch(ctx, func(b *store.Batch) error {
		locatorValue, err := b.Get(locatorKey)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("read locator: %w", err)
		}

		// Validate the locator value is well-formed.
		if len(locatorValue) != 0 && len(locatorValue) != len(taskHash) {
			return fmt.Errorf("candidate locator is corrupt")
		}

		if len(locatorValue) == len(taskHash) && bytes.Equal(locatorValue, taskHash[:]) {
			// Same taskHash already at this locator. Accept only identical replay; a
			// different order for the same hash must advance PublishTS.
			existing, err := candidateAdmissionFromBatch(b, taskHash)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("read candidate: %w", err)
			}
			if err == nil {
				if candidateAdmissionsEqual(existing, admission) {
					// Identical replay: leave locator and candidate untouched.
					return nil
				}
				if existing.SchemaVersion < admission.SchemaVersion {
					if !candidateAdmissionUpgradeCompatible(existing, admission) {
						return fmt.Errorf("%w: candidate schema upgrade changes stable identity", ErrConflict)
					}
					if err := b.Set(candidateKey, encoded); err != nil {
						return fmt.Errorf("set schema-upgraded candidate: %w", err)
					}
					return nil
				}
				if existing.PublishTS != 0 && admission.PublishTS <= existing.PublishTS {
					return ErrStaleCandidateReplacement
				}
			}
			if err := b.Set(candidateKey, encoded); err != nil {
				return fmt.Errorf("set candidate: %w", err)
			}
			return nil
		}

		// If the locator points at a different task hash, require PublishTS advance.
		if len(locatorValue) == len(taskHash) {
			prevHash := StoredHash(locatorValue)
			prevAdmission, err := candidateAdmissionFromBatch(b, prevHash)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("read superseded candidate: %w", err)
			}
			if err == nil {
				if admission.PublishTS <= prevAdmission.PublishTS {
					return ErrStaleCandidateReplacement
				}
			}
			if err := b.Delete(CandidateKey(prevHash)); err != nil {
				return fmt.Errorf("delete superseded candidate: %w", err)
			}
		}

		if err := b.Set(candidateKey, encoded); err != nil {
			return fmt.Errorf("set candidate: %w", err)
		}
		if err := b.Set(locatorKey, taskHash[:]); err != nil {
			return fmt.Errorf("set locator: %w", err)
		}
		return nil
	})
}

// ReleaseCandidateAdmission drops the candidate rows of an order this node is
// no longer obliged to serve — the chain finalized the assignment to another
// Worker.
//
// It is the counterpart AdmissionBatch never had. The candidate row exists so a
// restart mid-handraise can still publish the signed document it already
// committed to; once the winner is decided that obligation is discharged, and
// this store holds restart obligations and nothing else. Without a release,
// every order a node bids on and loses leaves a permanent row.
//
// The locator is only removed while it still points at this task hash: a newer
// candidate may already have replaced this one at the same (session, order),
// and taking its locator would orphan a live obligation. Both deletes land in
// one batch, and releasing an already-released candidate is a no-op, because a
// redelivered notification arrives at exactly that state.
func ReleaseCandidateAdmission(ctx context.Context, s *store.Store, sessionID string, orderSequence uint64, taskHash StoredHash) error {
	locatorKey := CandidateCurrentKey(sessionID, orderSequence)
	return s.ApplyBatch(ctx, func(b *store.Batch) error {
		if err := b.Delete(CandidateKey(taskHash)); err != nil {
			return fmt.Errorf("delete candidate: %w", err)
		}
		locatorValue, err := b.Get(locatorKey)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil
			}
			return fmt.Errorf("read locator: %w", err)
		}
		if len(locatorValue) != len(taskHash) || !bytes.Equal(locatorValue, taskHash[:]) {
			return nil
		}
		if err := b.Delete(locatorKey); err != nil {
			return fmt.Errorf("delete locator: %w", err)
		}
		return nil
	})
}

// VerifyAdmissionBatch writes a verifier pre-assignment handraise for one
// verify round, idempotent by (taskHash, verifyRound). It is used to prevent
// duplicate output fetches and repeated handraises on a duplicate
// OUTPUT_AVAILABLE hint. It reports true only when a *completed* claim already
// exists, which is the one case where the work must not be redone. A conflicting
// existing record returns an error.
//
// An existing *incomplete* claim means an earlier delivery took the claim and
// then failed or crashed before finishing. Suppressing on that would strand the
// task with no confirmation and no handraise, so it reports false and the caller
// redoes the work. That is why the row records completion rather than attempt.
//
// The read and the write share one ApplyBatch closure. Only ApplyBatch holds the
// store lock across the callback, so two concurrent first deliveries cannot both
// observe an absent row and both proceed - which a GetRaw/PutRaw pair allows.
func VerifyAdmissionBatch(ctx context.Context, s *store.Store, taskHash StoredHash, verifyRound uint64, admission VerifierAdmission) (bool, error) {
	admission.SchemaVersion = defaultSchemaVersion(admission.SchemaVersion)
	if admission.SchemaVersion > VerifierAdmissionSchemaVersion {
		return false, fmt.Errorf("verifier admission schema_version %d is newer than supported %d", admission.SchemaVersion, VerifierAdmissionSchemaVersion)
	}
	// A claim is taken before Keeper reconciliation and handraise signing. Keep
	// only its stable attempt identity here; authenticated sender and receipt facts
	// become durable through CompleteVerifyAdmission after validation succeeds.
	admission.InferReceiptHash = StoredHash{}
	admission.DataReadyBuilderOperator = ""
	admission.HandraisePayload = nil
	admission.HandraiseDigest = StoredHash{}
	admission.ExpiryHeight = 0
	admission.Completed = false
	key := VerifyCandidateKey(taskHash, verifyRound)
	encoded, err := json.Marshal(admission)
	if err != nil {
		return false, fmt.Errorf("encode verifier admission: %w", err)
	}
	alreadyCompleted := false
	err = s.ApplyBatch(ctx, func(b *store.Batch) error {
		existingRaw, err := b.Get(key)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("read verifier admission: %w", err)
		}
		if err == nil {
			var existing VerifierAdmission
			if unmarshalErr := json.Unmarshal(existingRaw, &existing); unmarshalErr != nil {
				return fmt.Errorf("decode existing verifier admission: %w", unmarshalErr)
			}
			if existing.SchemaVersion < admission.SchemaVersion {
				if !verifierAdmissionUpgradeCompatible(existing, admission) {
					return fmt.Errorf("%w: verifier admission schema upgrade changes stable identity", ErrConflict)
				}
				upgraded := admission
				if existing.DataReadyBuilderOperator != "" {
					upgraded.DataReadyBuilderOperator = existing.DataReadyBuilderOperator
				}
				upgraded.InferReceiptHash = existing.InferReceiptHash
				upgraded.Completed = false
				return putBatchJSON(b, key, upgraded)
			}
			if !verifierAdmissionsEqual(existing, admission) {
				return fmt.Errorf("%w: verify-candidate already exists with different content", ErrConflict)
			}
			alreadyCompleted = existing.Completed
			return nil
		}
		return b.Set(key, encoded)
	})
	if err != nil {
		return false, err
	}
	return alreadyCompleted, nil
}

// CompleteVerifyAdmission enriches and finishes a verify-candidate claim. Until
// it is called the claim suppresses nothing, so authenticated sender and receipt
// facts are accepted here only after Keeper reconciliation and handraise success.
func CompleteVerifyAdmission(ctx context.Context, s *store.Store, taskHash StoredHash, verifyRound uint64, facts VerifierAdmission) error {
	facts.SchemaVersion = defaultSchemaVersion(facts.SchemaVersion)
	if facts.SchemaVersion > VerifierAdmissionSchemaVersion {
		return fmt.Errorf("verifier admission schema_version %d is newer than supported %d", facts.SchemaVersion, VerifierAdmissionSchemaVersion)
	}
	key := VerifyCandidateKey(taskHash, verifyRound)
	return s.ApplyBatch(ctx, func(b *store.Batch) error {
		raw, err := b.Get(key)
		if errors.Is(err, store.ErrNotFound) {
			// A task-terminal effect deletes every verify-candidate row, and it
			// can land while the handraise this completes was in flight. There is
			// nothing left to suppress and the handraise already succeeded, so
			// failing here would report an error after an externally visible
			// success and send the frame back for a redelivery that can only fail
			// again - the verify record is gone too.
			return nil
		}
		if err != nil {
			return fmt.Errorf("read verifier admission to complete: %w", err)
		}
		var admission VerifierAdmission
		if err := json.Unmarshal(raw, &admission); err != nil {
			return fmt.Errorf("decode verifier admission to complete: %w", err)
		}
		if admission.OutputHash != facts.OutputHash || !storedHashesCompatible(admission.InferReceiptHash, facts.InferReceiptHash) {
			return fmt.Errorf("%w: completed verifier admission changes stable identity", ErrConflict)
		}
		if admission.SchemaVersion > VerifierAdmissionSchemaVersion {
			return fmt.Errorf("verifier admission schema_version %d is newer than supported %d", admission.SchemaVersion, VerifierAdmissionSchemaVersion)
		}
		if facts.DataReadyBuilderOperator != "" && strings.TrimSpace(facts.DataReadyBuilderOperator) != facts.DataReadyBuilderOperator {
			return fmt.Errorf("data-ready Builder operator must be canonical")
		}
		if admission.InferReceiptHash.IsZero() {
			admission.InferReceiptHash = facts.InferReceiptHash
		}
		if admission.DataReadyBuilderOperator == "" {
			admission.DataReadyBuilderOperator = facts.DataReadyBuilderOperator
		}
		if len(facts.HandraisePayload) > 0 {
			if len(admission.HandraisePayload) > 0 && !bytes.Equal(admission.HandraisePayload, facts.HandraisePayload) {
				return fmt.Errorf("%w: completed verifier admission changes handraise payload", ErrConflict)
			}
			admission.HandraisePayload = append([]byte(nil), facts.HandraisePayload...)
		}
		if !facts.HandraiseDigest.IsZero() {
			if !storedHashesCompatible(admission.HandraiseDigest, facts.HandraiseDigest) {
				return fmt.Errorf("%w: completed verifier admission changes handraise digest", ErrConflict)
			}
			admission.HandraiseDigest = facts.HandraiseDigest
		}
		if facts.ExpiryHeight != 0 {
			if admission.ExpiryHeight != 0 && admission.ExpiryHeight != facts.ExpiryHeight {
				return fmt.Errorf("%w: completed verifier admission changes expiry height", ErrConflict)
			}
			admission.ExpiryHeight = facts.ExpiryHeight
		}
		if facts.SchemaVersion > admission.SchemaVersion {
			admission.SchemaVersion = facts.SchemaVersion
		}
		admission.Completed = true
		if err := putBatchJSON(b, key, admission); err != nil {
			return fmt.Errorf("write completed verifier admission: %w", err)
		}
		return backfillTaskBuilderFromVerifierAdmission(b, taskHash, admission)
	})
}

func verifierAdmissionsEqual(a, b VerifierAdmission) bool {
	// VerifyAdmissionBatch compares attempt identity only. Completion facts are
	// checked and merged by CompleteVerifyAdmission after Keeper reconciliation.
	return a.SchemaVersion == b.SchemaVersion &&
		a.OutputHash == b.OutputHash &&
		storedHashesCompatible(a.InferReceiptHash, b.InferReceiptHash)
}

// GetVerifierAdmission returns the durable pre-assignment facts for one round.
func GetVerifierAdmission(ctx context.Context, s *store.Store, taskHash StoredHash, verifyRound uint64) (VerifierAdmission, error) {
	var admission VerifierAdmission
	err := getJSON(ctx, s, VerifyCandidateKey(taskHash, verifyRound), &admission)
	return admission, err
}

func verifierAdmissionUpgradeCompatible(a, b VerifierAdmission) bool {
	return a.OutputHash == b.OutputHash
}

func storedHashesCompatible(a, b StoredHash) bool {
	return a.IsZero() || b.IsZero() || a == b
}

// inferRecordsEqual compares two InferRecord values for idempotency.
func candidateAdmissionsEqual(a, b CandidateAdmission) bool {
	return a.PublishTS == b.PublishTS &&
		a.SchemaVersion == b.SchemaVersion &&
		string(a.SignedOrder) == string(b.SignedOrder) &&
		string(a.HandraisePayload) == string(b.HandraisePayload) &&
		a.HandraiseDigest == b.HandraiseDigest &&
		a.InputSizeBytes == b.InputSizeBytes &&
		a.DedupID == b.DedupID
}

func candidateAdmissionUpgradeCompatible(a, b CandidateAdmission) bool {
	inputSizeCompatible := a.InputSizeBytes == 0 || a.InputSizeBytes == b.InputSizeBytes
	return a.PublishTS == b.PublishTS &&
		string(a.SignedOrder) == string(b.SignedOrder) &&
		inputSizeCompatible &&
		a.DedupID == b.DedupID
}

// InferAssignmentBatch atomically creates task/ and infer/ for a Worker assignment.
// Candidate admission is left intact; it is deleted by TaskTerminalBatch. Replays
// with identical records are idempotent; a conflicting existing record returns an error.
func InferAssignmentBatch(ctx context.Context, s *store.Store, taskHash StoredHash, task TaskRecord, infer InferRecord) error {
	task.SchemaVersion = defaultSchemaVersion(task.SchemaVersion)
	infer.SchemaVersion = defaultSchemaVersion(infer.SchemaVersion)
	if err := validateStage(infer.Stage); err != nil {
		return err
	}
	if infer.FinishReason != "" {
		if err := validateFinishReason(infer.FinishReason); err != nil {
			return err
		}
	}

	return s.ApplyBatch(ctx, func(b *store.Batch) error {
		existingTask, err := taskRecordFromBatch(b, taskHash)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("read task: %w", err)
		}
		mergedTask, err := mergeTaskRecords(existingTask, task)
		if err != nil {
			return err
		}

		existingInfer, err := inferRecordFromBatch(b, taskHash)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("read infer: %w", err)
		}
		if err == nil {
			mergedInfer, err := mergeInferRecords(existingInfer, infer)
			if err != nil {
				return err
			}
			if err := putBatchJSON(b, InferKey(taskHash), mergedInfer); err != nil {
				return fmt.Errorf("set infer: %w", err)
			}
		} else {
			if err := putBatchJSON(b, InferKey(taskHash), infer); err != nil {
				return fmt.Errorf("set infer: %w", err)
			}
		}
		if infer.TaskID != "" {
			if err := b.Set(TaskIDInferKey(infer.TaskID), taskHash[:]); err != nil {
				return err
			}
		}

		if err := putBatchJSON(b, TaskKey(taskHash), mergedTask); err != nil {
			return fmt.Errorf("set task: %w", err)
		}
		return nil
	})
}

// VerifyAssignmentBatch atomically creates task/ and verify/ for a Verifier assignment.
// Verify-candidate admission is left intact; it is deleted by TaskTerminalBatch. Replays
// with identical records are idempotent; a conflicting existing record returns an error.
func VerifyAssignmentBatch(ctx context.Context, s *store.Store, taskHash StoredHash, task TaskRecord, verify VerifyRecord) error {
	task.SchemaVersion = defaultSchemaVersion(task.SchemaVersion)
	verify.SchemaVersion = defaultSchemaVersion(verify.SchemaVersion)
	if err := validateStage(verify.Stage); err != nil {
		return err
	}

	return s.ApplyBatch(ctx, func(b *store.Batch) error {
		admission, err := verifierAdmissionFromBatch(b, taskHash, verify.VerifyRound)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("read verifier admission: %w", err)
		}
		if err == nil && task.BuilderOperatorAddress == "" {
			builder, err := dataReadyBuilderForVerify(admission, verify)
			if err != nil {
				return err
			}
			task.BuilderOperatorAddress = builder
		}

		existingTask, err := taskRecordFromBatch(b, taskHash)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("read task: %w", err)
		}
		mergedTask, err := mergeTaskRecords(existingTask, task)
		if err != nil {
			return err
		}

		existingVerify, err := verifyRecordFromBatch(b, taskHash)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("read verify: %w", err)
		}
		if err == nil {
			mergedVerify, err := mergeVerifyRecords(existingVerify, verify)
			if err != nil {
				return err
			}
			if err := putBatchJSON(b, VerifyKey(taskHash), mergedVerify); err != nil {
				return fmt.Errorf("set verify: %w", err)
			}
		} else {
			if err := putBatchJSON(b, VerifyKey(taskHash), verify); err != nil {
				return fmt.Errorf("set verify: %w", err)
			}
		}
		if verify.TaskID != "" {
			if err := b.Set(TaskIDVerifyKey(verify.TaskID), taskHash[:]); err != nil {
				return err
			}
		}

		if err := putBatchJSON(b, TaskKey(taskHash), mergedTask); err != nil {
			return fmt.Errorf("set task: %w", err)
		}
		return nil
	})
}

// TaskTerminalBatch atomically upserts the evidence lifecycle row and deletes
// task/, infer/, verify/, delivery/ and admission records for a task.
func TaskTerminalBatch(ctx context.Context, s *store.Store, taskHash StoredHash, evidence Evidence) error {
	evidence.SchemaVersion = defaultSchemaVersion(evidence.SchemaVersion)
	return s.ApplyBatch(ctx, func(b *store.Batch) error {
		existingEvidence, err := evidenceRecordFromBatch(b, taskHash)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("read evidence: %w", err)
		}
		mergedEvidence, err := mergeEvidenceRecords(existingEvidence, evidence)
		if err != nil {
			return err
		}

		if err := putBatchJSON(b, EvidenceKey(taskHash), mergedEvidence); err != nil {
			return fmt.Errorf("set evidence: %w", err)
		}
		if err := b.Delete(TaskKey(taskHash)); err != nil {
			return err
		}
		inferRec, _ := inferRecordFromBatch(b, taskHash)
		verifyRec, _ := verifyRecordFromBatch(b, taskHash)
		if err := b.Delete(InferKey(taskHash)); err != nil {
			return err
		}
		if err := b.Delete(VerifyKey(taskHash)); err != nil {
			return err
		}
		if inferRec.TaskID != "" {
			if err := b.Delete(TaskIDInferKey(inferRec.TaskID)); err != nil {
				return err
			}
		}
		if verifyRec.TaskID != "" {
			if err := b.Delete(TaskIDVerifyKey(verifyRec.TaskID)); err != nil {
				return err
			}
		}
		if err := b.Delete(CandidateKey(taskHash)); err != nil {
			return err
		}

		// Delete every new-layout candidate-current locator that points to this
		// task hash. This scans only the v2 candidate-current prefix, so it does
		// not touch legacy locators.
		if err := deleteLocatorForTaskHash(b, taskHash); err != nil {
			return fmt.Errorf("delete candidate-current locators: %w", err)
		}
		if err := deletePrefixedKeysInBatch(b, []byte(verifyCandidatePrefixForTask(taskHash))); err != nil {
			return fmt.Errorf("delete verify-candidate: %w", err)
		}
		if err := deletePrefixedKeysInBatch(b, []byte(deliveryPrefixForTask(taskHash))); err != nil {
			return fmt.Errorf("delete delivery: %w", err)
		}
		return nil
	})
}

// CleanupBatch atomically deletes evidence/ and challenge/ rows for a task
// once retention has matured.
func CleanupBatch(ctx context.Context, s *store.Store, taskHash StoredHash) error {
	return s.ApplyBatch(ctx, func(b *store.Batch) error {
		if err := deletePrefixedKeysInBatch(b, []byte(challengePrefixForTask(taskHash))); err != nil {
			return fmt.Errorf("delete challenge rows: %w", err)
		}
		if err := b.Delete(EvidenceKey(taskHash)); err != nil {
			return err
		}
		return nil
	})
}

// --- helpers ---

func defaultSchemaVersion(v uint16) uint16 {
	if v == 0 {
		return 1
	}
	return v
}

func validateStage(stage RoleStage) error {
	switch stage {
	case StageQueued, StageCommitted, StageFailed, StageSucceeded:
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrInvalidStage, stage)
	}
}

func validateFinishReason(reason FinishReasonV1) error {
	switch reason {
	case FinishReasonEOS, FinishReasonStopSequence, FinishReasonMaxOutputTokens,
		FinishReasonMaxOutputDuration, FinishReasonUnknown:
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrInvalidFinishReason, reason)
	}
}

func isSingletonKind(kind ArtifactKind) bool {
	switch kind {
	case ArtifactTaskInput, ArtifactWorkerOutput, ArtifactWorkerTrace,
		ArtifactWorkerCheckpoint, ArtifactWorkerBatchLog, ArtifactInferReceipt:
		return true
	default:
		return false
	}
}

func validateArtifactKind(kind ArtifactKind) error {
	if kind == "" {
		return fmt.Errorf("%w: empty kind", ErrInvalidArtifactKind)
	}
	switch kind {
	case ArtifactTaskInput, ArtifactWorkerOutput, ArtifactWorkerTrace,
		ArtifactWorkerCheckpoint, ArtifactWorkerBatchLog, ArtifactInferReceipt,
		ArtifactWorkerOutputDescriptor, ArtifactWorkerResult:
		return nil
	}
	// Other evidence kinds are allowed per the design doc, but they must not
	// be aliases of the singleton set. Since the only declared local kinds are
	// the seven above, any other non-empty string is accepted as a multi-digest
	// kind. A future profile-driven registry can tighten this.
	return nil
}

func putBatchJSON(b *store.Batch, key []byte, v interface{}) error {
	encoded, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode record: %w", err)
	}
	return b.Set(key, encoded)
}

func taskRecordFromBatch(b *store.Batch, taskHash StoredHash) (TaskRecord, error) {
	var record TaskRecord
	err := getBatchJSON(b, TaskKey(taskHash), &record)
	return record, err
}

func inferRecordFromBatch(b *store.Batch, taskHash StoredHash) (InferRecord, error) {
	var record InferRecord
	err := getBatchJSON(b, InferKey(taskHash), &record)
	return record, err
}

func verifyRecordFromBatch(b *store.Batch, taskHash StoredHash) (VerifyRecord, error) {
	var record VerifyRecord
	err := getBatchJSON(b, VerifyKey(taskHash), &record)
	return record, err
}

func evidenceRecordFromBatch(b *store.Batch, taskHash StoredHash) (Evidence, error) {
	var record Evidence
	err := getBatchJSON(b, EvidenceKey(taskHash), &record)
	return record, err
}

func candidateAdmissionFromBatch(b *store.Batch, taskHash StoredHash) (CandidateAdmission, error) {
	var record CandidateAdmission
	err := getBatchJSON(b, CandidateKey(taskHash), &record)
	return record, err
}

func verifierAdmissionFromBatch(b *store.Batch, taskHash StoredHash, verifyRound uint64) (VerifierAdmission, error) {
	var record VerifierAdmission
	err := getBatchJSON(b, VerifyCandidateKey(taskHash, verifyRound), &record)
	return record, err
}

func dataReadyBuilderForVerify(admission VerifierAdmission, verify VerifyRecord) (string, error) {
	if admission.SchemaVersion > VerifierAdmissionSchemaVersion {
		return "", fmt.Errorf("verifier admission schema_version %d is newer than supported %d", admission.SchemaVersion, VerifierAdmissionSchemaVersion)
	}
	if admission.SchemaVersion < VerifierAdmissionSchemaVersion || !admission.Completed ||
		admission.DataReadyBuilderOperator == "" || admission.OutputHash.IsZero() || admission.InferReceiptHash.IsZero() ||
		admission.OutputHash != verify.OutputDigest || admission.InferReceiptHash != verify.InferReceiptDigest {
		return "", nil
	}
	if strings.TrimSpace(admission.DataReadyBuilderOperator) != admission.DataReadyBuilderOperator {
		return "", fmt.Errorf("data-ready Builder operator must be canonical")
	}
	return admission.DataReadyBuilderOperator, nil
}

func backfillTaskBuilderFromVerifierAdmission(b *store.Batch, taskHash StoredHash, admission VerifierAdmission) error {
	verify, err := verifyRecordFromBatch(b, taskHash)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read verify responsibility for Builder backfill: %w", err)
	}
	builder, err := dataReadyBuilderForVerify(admission, verify)
	if err != nil || builder == "" {
		return err
	}
	task, err := taskRecordFromBatch(b, taskHash)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read task for Builder backfill: %w", err)
	}
	if task.BuilderOperatorAddress != "" {
		return nil
	}
	task.BuilderOperatorAddress = builder
	if err := putBatchJSON(b, TaskKey(taskHash), task); err != nil {
		return fmt.Errorf("set task Builder backfill: %w", err)
	}
	return nil
}

func challengeLifecycleFromBatch(b *store.Batch, taskHash StoredHash, challengeID string) (ChallengeLifecycle, error) {
	var record ChallengeLifecycle
	err := getBatchJSON(b, ChallengeKey(taskHash, challengeID), &record)
	return record, err
}

func getBatchJSON(b *store.Batch, key []byte, dest interface{}) error {
	value, err := b.Get(key)
	if err != nil {
		return err
	}
	return json.Unmarshal(value, dest)
}

func getJSON(ctx context.Context, s *store.Store, key []byte, dest interface{}) error {
	value, err := s.GetRaw(ctx, key)
	if err != nil {
		return err
	}
	return json.Unmarshal(value, dest)
}

// Exported read helpers for tests and diagnostics.

func GetTaskRecord(ctx context.Context, s *store.Store, taskHash StoredHash) (TaskRecord, error) {
	var record TaskRecord
	err := getJSON(ctx, s, TaskKey(taskHash), &record)
	return record, err
}

func GetInferRecord(ctx context.Context, s *store.Store, taskHash StoredHash) (InferRecord, error) {
	var record InferRecord
	err := getJSON(ctx, s, InferKey(taskHash), &record)
	return record, err
}

func GetVerifyRecord(ctx context.Context, s *store.Store, taskHash StoredHash) (VerifyRecord, error) {
	var record VerifyRecord
	err := getJSON(ctx, s, VerifyKey(taskHash), &record)
	return record, err
}

func GetEvidenceRecord(ctx context.Context, s *store.Store, taskHash StoredHash) (Evidence, error) {
	var record Evidence
	err := getJSON(ctx, s, EvidenceKey(taskHash), &record)
	return record, err
}

// ListEvidence returns all evidence records under the evidence prefix.
func ListEvidence(ctx context.Context, s *store.Store) ([]EvidenceEntry, error) {
	var result []EvidenceEntry
	err := s.ScanPrefix(ctx, []byte(evidencePrefix), func(key, value []byte) error {
		var rec Evidence
		if err := json.Unmarshal(value, &rec); err != nil {
			return err
		}
		var h StoredHash
		copy(h[:], key[len(evidencePrefix):])
		result = append(result, EvidenceEntry{TaskHash: codec.Hash(h), Evidence: rec})
		return nil
	})
	return result, err
}

// DeleteEvidence removes the evidence record for a task.
func DeleteEvidence(ctx context.Context, s *store.Store, taskHash StoredHash) error {
	return s.ApplyBatch(ctx, func(b *store.Batch) error {
		return b.Delete(EvidenceKey(taskHash))
	})
}

func GetCandidateAdmission(ctx context.Context, s *store.Store, taskHash StoredHash) (CandidateAdmission, error) {
	var record CandidateAdmission
	err := getJSON(ctx, s, CandidateKey(taskHash), &record)
	return record, err
}

// ListChallenges returns the challenge IDs that are currently open for a task.
// DeleteChallenges removes all challenge lifecycle rows for a task.
func DeleteChallenges(ctx context.Context, s *store.Store, taskHash StoredHash) error {
	return s.ApplyBatch(ctx, func(b *store.Batch) error {
		return deletePrefixedKeysInBatch(b, []byte(challengePrefixForTask(taskHash)))
	})
}

// ListChallenges returns the challenge IDs that are currently open for a task.
func ListChallenges(ctx context.Context, s *store.Store, taskHash StoredHash) ([]string, error) {
	prefix := []byte(challengePrefixForTask(taskHash))
	var ids []string
	err := s.ScanPrefix(ctx, prefix, func(key, value []byte) error {
		parts := bytes.Split(key, []byte("/"))
		if len(parts) == 0 {
			return nil
		}
		id := string(parts[len(parts)-1])
		if id == "" {
			return nil
		}
		var record ChallengeLifecycle
		if err := json.Unmarshal(value, &record); err != nil {
			return err
		}
		if record.Open {
			ids = append(ids, id)
		}
		return nil
	})
	return ids, err
}

// ClearInferAutoHalt and ClearVerifyAutoHalt release an auto-halt, and they are
// a read-modify-write rather than a merge because mergeAutoHalt cannot express
// a clear: the flag is monotonic there precisely so that no routine merge can
// drop it. An operator asking for the task to run again is the only thing that
// may, and it says so by calling one of these.
//
// A record that is not halted is left untouched rather than rewritten, so
// calling this on a healthy responsibility is a no-op and not a stage change.
func ClearInferAutoHalt(ctx context.Context, s *store.Store, taskHash StoredHash) error {
	return s.ApplyBatch(ctx, func(b *store.Batch) error {
		rec, err := inferRecordFromBatch(b, taskHash)
		if err != nil {
			return err
		}
		if !rec.AutoHalted {
			return nil
		}
		rec.AutoHalt = AutoHalt{}
		return putBatchJSON(b, InferKey(taskHash), rec)
	})
}

func ClearVerifyAutoHalt(ctx context.Context, s *store.Store, taskHash StoredHash) error {
	return s.ApplyBatch(ctx, func(b *store.Batch) error {
		rec, err := verifyRecordFromBatch(b, taskHash)
		if err != nil {
			return err
		}
		if !rec.AutoHalted {
			return nil
		}
		rec.AutoHalt = AutoHalt{}
		return putBatchJSON(b, VerifyKey(taskHash), rec)
	})
}

// DeleteInferRecord removes the infer role record for a task.
func DeleteInferRecord(ctx context.Context, s *store.Store, taskHash StoredHash) error {
	return s.ApplyBatch(ctx, func(b *store.Batch) error {
		rec, err := inferRecordFromBatch(b, taskHash)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err := b.Delete(InferKey(taskHash)); err != nil {
			return err
		}
		if rec.TaskID != "" {
			if err := b.Delete(TaskIDInferKey(rec.TaskID)); err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteVerifyRecord removes the verify role record for a task.
func DeleteVerifyRecord(ctx context.Context, s *store.Store, taskHash StoredHash) error {
	return s.ApplyBatch(ctx, func(b *store.Batch) error {
		rec, err := verifyRecordFromBatch(b, taskHash)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err := b.Delete(VerifyKey(taskHash)); err != nil {
			return err
		}
		if rec.TaskID != "" {
			if err := b.Delete(TaskIDVerifyKey(rec.TaskID)); err != nil {
				return err
			}
		}
		return nil
	})
}

// ListInferRecords scans all infer role records and returns their hashes and records.
func ListInferRecords(ctx context.Context, s *store.Store) ([]StoredHash, []InferRecord, error) {
	return listRoleRecords(ctx, s, []byte(inferPrefix), func(data []byte) (InferRecord, error) {
		var record InferRecord
		err := json.Unmarshal(data, &record)
		return record, err
	})
}

// ListVerifyRecords scans all verify role records and returns their hashes and records.
func ListVerifyRecords(ctx context.Context, s *store.Store) ([]StoredHash, []VerifyRecord, error) {
	return listRoleRecords(ctx, s, []byte(verifyPrefix), func(data []byte) (VerifyRecord, error) {
		var record VerifyRecord
		err := json.Unmarshal(data, &record)
		return record, err
	})
}

func listRoleRecords[T any](ctx context.Context, s *store.Store, prefix []byte, decodeFn func([]byte) (T, error)) ([]StoredHash, []T, error) {
	var hashes []StoredHash
	var records []T
	if err := s.ScanPrefix(ctx, prefix, func(key, value []byte) error {
		if len(key) != len(prefix)+32 {
			return nil
		}
		var hash StoredHash
		copy(hash[:], key[len(prefix):])
		record, err := decodeFn(value)
		if err != nil {
			return err
		}
		hashes = append(hashes, hash)
		records = append(records, record)
		return nil
	}); err != nil {
		return nil, nil, err
	}
	return hashes, records, nil
}

func GetChallengeLifecycle(ctx context.Context, s *store.Store, taskHash StoredHash, challengeID string) (ChallengeLifecycle, error) {
	var record ChallengeLifecycle
	err := getJSON(ctx, s, ChallengeKey(taskHash, challengeID), &record)
	return record, err
}

func deleteLocatorForTaskHash(b *store.Batch, taskHash StoredHash) error {
	iter, err := b.NewIter([]byte(candidateCurrentPrefix))
	if err != nil {
		return err
	}
	defer iter.Close()
	for iter.First(); iter.Valid(); iter.Next() {
		if bytes.Equal(iter.Value(), taskHash[:]) {
			if err := b.Delete(append([]byte(nil), iter.Key()...)); err != nil {
				return err
			}
		}
	}
	return iter.Close()
}

func deletePrefixedKeysInBatch(b *store.Batch, prefix []byte) error {
	iter, err := b.NewIter(prefix)
	if err != nil {
		return err
	}
	defer iter.Close()
	for iter.First(); iter.Valid(); iter.Next() {
		if err := b.Delete(append([]byte(nil), iter.Key()...)); err != nil {
			return err
		}
	}
	return iter.Close()
}

func mergeTaskRecords(existing, new TaskRecord) (TaskRecord, error) {
	merged := existing
	if conflict := mergeString(&merged.SessionID, new.SessionID); conflict {
		return TaskRecord{}, fmt.Errorf("%w: task.SessionID", ErrConflict)
	}
	if new.OrderSequence != 0 && merged.OrderSequence != 0 && new.OrderSequence != merged.OrderSequence {
		return TaskRecord{}, fmt.Errorf("%w: task.OrderSequence", ErrConflict)
	}
	if merged.OrderSequence == 0 {
		merged.OrderSequence = new.OrderSequence
	}
	if conflict := mergeString(&merged.ModelID, new.ModelID); conflict {
		return TaskRecord{}, fmt.Errorf("%w: task.ModelID", ErrConflict)
	}
	if new.ProfileVersion != 0 && merged.ProfileVersion != 0 && new.ProfileVersion != merged.ProfileVersion {
		return TaskRecord{}, fmt.Errorf("%w: task.ProfileVersion", ErrConflict)
	}
	if merged.ProfileVersion == 0 {
		merged.ProfileVersion = new.ProfileVersion
	}
	if conflict := mergeStoredHash(&merged.AssignmentOrderDigest, new.AssignmentOrderDigest); conflict {
		return TaskRecord{}, fmt.Errorf("%w: task.AssignmentOrderDigest", ErrConflict)
	}
	if conflict := mergeStoredHash(&merged.AssignmentDigest, new.AssignmentDigest); conflict {
		return TaskRecord{}, fmt.Errorf("%w: task.AssignmentDigest", ErrConflict)
	}
	if conflict := mergeStoredHash(&merged.AcceptedInputHash, new.AcceptedInputHash); conflict {
		return TaskRecord{}, fmt.Errorf("%w: task.AcceptedInputHash", ErrConflict)
	}
	if conflict := mergeString(&merged.WorkerAddress, new.WorkerAddress); conflict {
		return TaskRecord{}, fmt.Errorf("%w: task.WorkerAddress", ErrConflict)
	}
	if conflict := mergeString(&merged.BuilderOperatorAddress, new.BuilderOperatorAddress); conflict {
		return TaskRecord{}, fmt.Errorf("%w: task.BuilderOperatorAddress", ErrConflict)
	}
	// Late fields: first non-empty value wins; identical replay allowed.
	if conflict := mergeString(&merged.TaskBuilderSetID, new.TaskBuilderSetID); conflict {
		return TaskRecord{}, fmt.Errorf("%w: task.TaskBuilderSetID", ErrConflict)
	}
	if len(new.TaskBuilderSetHash) != 0 {
		if len(merged.TaskBuilderSetHash) != 0 && !bytes.Equal(merged.TaskBuilderSetHash, new.TaskBuilderSetHash) {
			return TaskRecord{}, fmt.Errorf("%w: task.TaskBuilderSetHash", ErrConflict)
		}
		merged.TaskBuilderSetHash = new.TaskBuilderSetHash
	}
	if new.InputSizeBytes != 0 {
		if merged.InputSizeBytes != 0 && merged.InputSizeBytes != new.InputSizeBytes {
			return TaskRecord{}, fmt.Errorf("%w: task.InputSizeBytes", ErrConflict)
		}
		merged.InputSizeBytes = new.InputSizeBytes
	}
	if new.InputCID != "" {
		if merged.InputCID != "" && merged.InputCID != new.InputCID {
			return TaskRecord{}, fmt.Errorf("%w: task.InputCID", ErrConflict)
		}
		merged.InputCID = new.InputCID
	}
	if conflict := mergeStoredHash(&merged.InputDigest, new.InputDigest); conflict {
		return TaskRecord{}, fmt.Errorf("%w: task.InputDigest", ErrConflict)
	}
	merged.SchemaVersion = maxSchemaVersion(merged.SchemaVersion, new.SchemaVersion)
	return merged, nil
}

func maxSchemaVersion(a, b uint16) uint16 {
	if a > b {
		return a
	}
	return b
}

func mergeInferRecords(existing, new InferRecord) (InferRecord, error) {
	merged := existing
	if conflict := mergeString(&merged.TaskID, new.TaskID); conflict {
		return InferRecord{}, fmt.Errorf("%w: infer.TaskID", ErrConflict)
	}
	if conflict := mergeStoredHash(&merged.GenerationParamsDigest, new.GenerationParamsDigest); conflict {
		return InferRecord{}, fmt.Errorf("%w: infer.GenerationParamsDigest", ErrConflict)
	}
	if new.WinnerConfirmHeight != 0 && merged.WinnerConfirmHeight != 0 && new.WinnerConfirmHeight != merged.WinnerConfirmHeight {
		return InferRecord{}, fmt.Errorf("%w: infer.WinnerConfirmHeight", ErrConflict)
	}
	if merged.WinnerConfirmHeight == 0 {
		merged.WinnerConfirmHeight = new.WinnerConfirmHeight
	}
	if new.InferDeadlineHeight != 0 && merged.InferDeadlineHeight != 0 && new.InferDeadlineHeight != merged.InferDeadlineHeight {
		return InferRecord{}, fmt.Errorf("%w: infer.InferDeadlineHeight", ErrConflict)
	}
	if merged.InferDeadlineHeight == 0 {
		merged.InferDeadlineHeight = new.InferDeadlineHeight
	}

	// FinishReason is one-shot.
	if new.FinishReason != "" {
		if merged.FinishReason != "" && merged.FinishReason != new.FinishReason {
			return InferRecord{}, fmt.Errorf("%w: infer.FinishReason", ErrConflict)
		}
		merged.FinishReason = new.FinishReason
	}

	// Scheduling fields are mutable.
	if new.Stage != "" {
		merged.Stage = new.Stage
	}
	if new.RetryCount != 0 {
		merged.RetryCount = new.RetryCount
	}
	if new.RetryAtUnixMilli != 0 {
		merged.RetryAtUnixMilli = new.RetryAtUnixMilli
	}
	if new.RetryAtHeight != 0 {
		merged.RetryAtHeight = new.RetryAtHeight
	}
	if new.DeadlineHeight != 0 {
		merged.DeadlineHeight = new.DeadlineHeight
	}
	if new.LastError != "" {
		merged.LastError = new.LastError
	}
	mergeAutoHalt(&merged.AutoHalt, new.AutoHalt)
	if new.OutputCID != "" {
		if merged.OutputCID != "" && merged.OutputCID != new.OutputCID {
			return InferRecord{}, fmt.Errorf("%w: infer.OutputCID", ErrConflict)
		}
		merged.OutputCID = new.OutputCID
	}
	if conflict := mergeStoredHash(&merged.OutputDigest, new.OutputDigest); conflict {
		return InferRecord{}, fmt.Errorf("%w: infer.OutputDigest", ErrConflict)
	}
	if new.ReceiptCID != "" {
		if merged.ReceiptCID != "" && merged.ReceiptCID != new.ReceiptCID {
			return InferRecord{}, fmt.Errorf("%w: infer.ReceiptCID", ErrConflict)
		}
		merged.ReceiptCID = new.ReceiptCID
	}
	if conflict := mergeStoredHash(&merged.ReceiptDigest, new.ReceiptDigest); conflict {
		return InferRecord{}, fmt.Errorf("%w: infer.ReceiptDigest", ErrConflict)
	}
	merged.SchemaVersion = maxSchemaVersion(merged.SchemaVersion, new.SchemaVersion)
	return merged, nil
}

func mergeVerifyRecords(existing, new VerifyRecord) (VerifyRecord, error) {
	merged := existing
	if conflict := mergeString(&merged.TaskID, new.TaskID); conflict {
		return VerifyRecord{}, fmt.Errorf("%w: verify.TaskID", ErrConflict)
	}
	immutableUint := func(name string, existingPtr *uint64, newV uint64) error {
		if newV != 0 && *existingPtr != 0 && newV != *existingPtr {
			return fmt.Errorf("%w: verify.%s", ErrConflict, name)
		}
		if *existingPtr == 0 {
			*existingPtr = newV
		}
		return nil
	}
	if err := immutableUint("VerifyRound", &merged.VerifyRound, new.VerifyRound); err != nil {
		return VerifyRecord{}, err
	}
	if err := immutableUint("OpenVerifyHeight", &merged.OpenVerifyHeight, new.OpenVerifyHeight); err != nil {
		return VerifyRecord{}, err
	}
	if err := immutableUint("SampleSeedReadyHeight", &merged.SampleSeedReadyHeight, new.SampleSeedReadyHeight); err != nil {
		return VerifyRecord{}, err
	}
	if err := immutableUint("CommitDeadlineHeight", &merged.CommitDeadlineHeight, new.CommitDeadlineHeight); err != nil {
		return VerifyRecord{}, err
	}
	if err := immutableUint("WorkerRevealDeadlineHeight", &merged.WorkerRevealDeadlineHeight, new.WorkerRevealDeadlineHeight); err != nil {
		return VerifyRecord{}, err
	}
	if err := immutableUint("RevealDeadlineHeight", &merged.RevealDeadlineHeight, new.RevealDeadlineHeight); err != nil {
		return VerifyRecord{}, err
	}
	if conflict := mergeStoredHash(&merged.VerificationSampleSeed, new.VerificationSampleSeed); conflict {
		return VerifyRecord{}, fmt.Errorf("%w: verify.VerificationSampleSeed", ErrConflict)
	}
	if new.AssignedVerifiers != nil {
		if merged.AssignedVerifiers != nil && !slicesEqual(merged.AssignedVerifiers, new.AssignedVerifiers) {
			return VerifyRecord{}, fmt.Errorf("%w: verify.AssignedVerifiers", ErrConflict)
		}
		merged.AssignedVerifiers = new.AssignedVerifiers
	}
	if conflict := mergeStoredHash(&merged.InferReceiptDigest, new.InferReceiptDigest); conflict {
		return VerifyRecord{}, fmt.Errorf("%w: verify.InferReceiptDigest", ErrConflict)
	}
	if conflict := mergeStoredHash(&merged.PackageDigest, new.PackageDigest); conflict {
		return VerifyRecord{}, fmt.Errorf("%w: verify.PackageDigest", ErrConflict)
	}

	if new.Stage != "" {
		merged.Stage = new.Stage
	}
	if new.RetryCount != 0 {
		merged.RetryCount = new.RetryCount
	}
	if new.RetryAtUnixMilli != 0 {
		merged.RetryAtUnixMilli = new.RetryAtUnixMilli
	}
	if new.RetryAtHeight != 0 {
		merged.RetryAtHeight = new.RetryAtHeight
	}
	if new.DeadlineHeight != 0 {
		merged.DeadlineHeight = new.DeadlineHeight
	}
	if new.LastError != "" {
		merged.LastError = new.LastError
	}
	mergeAutoHalt(&merged.AutoHalt, new.AutoHalt)
	if conflict := mergeStoredHash(&merged.OutputDigest, new.OutputDigest); conflict {
		return VerifyRecord{}, fmt.Errorf("%w: verify.OutputDigest", ErrConflict)
	}
	if new.ReceiptCID != "" {
		if merged.ReceiptCID != "" && merged.ReceiptCID != new.ReceiptCID {
			return VerifyRecord{}, fmt.Errorf("%w: verify.ReceiptCID", ErrConflict)
		}
		merged.ReceiptCID = new.ReceiptCID
	}
	if conflict := mergeStoredHash(&merged.ReceiptDigest, new.ReceiptDigest); conflict {
		return VerifyRecord{}, fmt.Errorf("%w: verify.ReceiptDigest", ErrConflict)
	}
	if new.OutputCID != "" {
		if merged.OutputCID != "" && merged.OutputCID != new.OutputCID {
			return VerifyRecord{}, fmt.Errorf("%w: verify.OutputCID", ErrConflict)
		}
		merged.OutputCID = new.OutputCID
	}
	if new.KeeperReceiptJSON != "" {
		if merged.KeeperReceiptJSON != "" && merged.KeeperReceiptJSON != new.KeeperReceiptJSON {
			return VerifyRecord{}, fmt.Errorf("%w: verify.KeeperReceiptJSON", ErrConflict)
		}
		merged.KeeperReceiptJSON = new.KeeperReceiptJSON
	}
	merged.SchemaVersion = maxSchemaVersion(merged.SchemaVersion, new.SchemaVersion)
	return merged, nil
}

// mergeAutoHalt is the one merge rule that is deliberately monotonic rather
// than last-writer-wins, and the asymmetry is the whole point.
//
// Every other scheduling field on a role record is mutable because a later
// writer knows more. An auto-halt is the opposite: the writer that set it read
// the model's answer, and every writer after it is a Keeper event replaying an
// assignment, a checkpoint mirroring an execution, or an admission arriving a
// second time -- none of which know anything about the fault, and all of which
// carry the zero value. Last-writer-wins would let any one of them silently
// clear the stop and hand the task back to the model. (InferAssignmentBatch
// makes that concrete: it merges a fresh record whose Stage is StageQueued.)
//
// So the flag only ever goes false -> true here, and the code and reason are
// attached with it. Clearing is an explicit operator act on its own path --
// ClearInferAutoHalt / ClearVerifyAutoHalt -- because "an operator decided to
// try again" is a different event from "a record was merged".
func mergeAutoHalt(merged *AutoHalt, new AutoHalt) {
	if !new.AutoHalted {
		return
	}
	merged.AutoHalted = true
	if new.HaltCode != "" {
		merged.HaltCode = new.HaltCode
	}
	if new.HaltReason != "" {
		merged.HaltReason = new.HaltReason
	}
}

func mergeEvidenceRecords(existing, new Evidence) (Evidence, error) {
	merged := existing
	if conflict := mergeString(&merged.SessionID, new.SessionID); conflict {
		return Evidence{}, fmt.Errorf("%w: evidence.SessionID", ErrConflict)
	}
	if conflict := mergeString(&merged.TaskID, new.TaskID); conflict {
		return Evidence{}, fmt.Errorf("%w: evidence.TaskID", ErrConflict)
	}

	mergedArtifacts, err := mergeArtifacts(merged.Artifacts, new.Artifacts)
	if err != nil {
		return Evidence{}, err
	}
	merged.Artifacts = mergedArtifacts

	// Digest and Size are derived from the artifact set; the callback is the
	// authoritative producer, so accept an updated non-zero value.
	if !new.Digest.IsZero() {
		merged.Digest = new.Digest
	}
	if new.Size != 0 {
		merged.Size = new.Size
	}

	if new.FinalityHeight != 0 && new.FinalityHeight > merged.FinalityHeight {
		merged.FinalityHeight = new.FinalityHeight
	}
	if new.RetentionStartHeight != 0 && new.RetentionStartHeight > merged.RetentionStartHeight {
		merged.RetentionStartHeight = new.RetentionStartHeight
	}
	// "A later finality advances both FinalityHeight and RetentionStartHeight"
	// (docs/specs/task-storage-layout.md). The authoritative finality height is
	// by definition a valid retention start, so a finality that arrives without
	// one carries the clock forward on its own. Without this a row whose only
	// height is a finality would never become eligible for cleanup.
	if merged.FinalityHeight > merged.RetentionStartHeight {
		merged.RetentionStartHeight = merged.FinalityHeight
	}
	if new.CleanupHeight != 0 && new.CleanupHeight > merged.CleanupHeight {
		merged.CleanupHeight = new.CleanupHeight
	}
	if new.TerminalOrSettled {
		merged.TerminalOrSettled = true
	}
	merged.SchemaVersion = maxSchemaVersion(merged.SchemaVersion, new.SchemaVersion)
	return merged, nil
}

func mergeArtifacts(existing, new []EvidenceArtifact) ([]EvidenceArtifact, error) {

	byKey := make(map[string]EvidenceArtifact)

	for _, a := range existing {

		byKey[artifactKey(a)] = a

	}

	for _, a := range new {

		if err := validateArtifactKind(a.Kind); err != nil {

			return nil, err

		}

		key := artifactKey(a)

		if _, ok := byKey[key]; ok {

			continue

		}

		if isSingletonKind(a.Kind) {

			for k := range byKey {

				if byKey[k].Kind == a.Kind {

					return nil, fmt.Errorf("%w: duplicate singleton evidence kind %s", ErrConflict, a.Kind)

				}

			}

		}

		byKey[key] = a

	}

	merged := make([]EvidenceArtifact, 0, len(byKey))

	for _, a := range byKey {

		merged = append(merged, a)

	}

	sort.Slice(merged, func(i, j int) bool {
		if merged[i].Kind != merged[j].Kind {

			return merged[i].Kind < merged[j].Kind
		}
		return merged[i].Digest.String() < merged[j].Digest.String()

	})

	return merged, nil

}

func artifactKey(a EvidenceArtifact) string {
	return string(a.Kind) + "\x00" + a.Digest.String()
}

func mergeString(dst *string, src string) bool {
	if src == "" {
		return false
	}
	if *dst != "" && *dst != src {
		return true
	}
	*dst = src
	return false
}

func mergeStoredHash(dst *StoredHash, src StoredHash) bool {
	if src.IsZero() {
		return false
	}
	if !dst.IsZero() && *dst != src {
		return true
	}
	*dst = src
	return false
}

func positionLess(a, b Position) bool {
	if a.Height != b.Height {
		return a.Height < b.Height
	}
	if a.TxIndex != b.TxIndex {
		return a.TxIndex < b.TxIndex
	}
	if a.MsgIndex != b.MsgIndex {
		return a.MsgIndex < b.MsgIndex
	}
	return a.EventIndex < b.EventIndex
}

func isZeroPosition(p Position) bool {
	return p.Height == 0 && p.TxIndex == 0 && p.MsgIndex == 0 && p.EventIndex == 0
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// FindInferRecordByTaskID looks up an infer record by its TaskID using the
// task-id secondary index.
func FindInferRecordByTaskID(ctx context.Context, s *store.Store, taskID string) (StoredHash, InferRecord, error) {
	var h StoredHash
	idx, err := s.GetRaw(ctx, TaskIDInferKey(taskID))
	if err != nil {
		return h, InferRecord{}, err
	}
	copy(h[:], idx)
	rec, err := GetInferRecord(ctx, s, h)
	return h, rec, err
}

// FindVerifyRecordByTaskID looks up a verify record by its TaskID using the
// task-id secondary index.
func FindVerifyRecordByTaskID(ctx context.Context, s *store.Store, taskID string) (StoredHash, VerifyRecord, error) {
	var h StoredHash
	idx, err := s.GetRaw(ctx, TaskIDVerifyKey(taskID))
	if err != nil {
		return h, VerifyRecord{}, err
	}
	copy(h[:], idx)
	rec, err := GetVerifyRecord(ctx, s, h)
	return h, rec, err
}
