package builderclient

// The two Worker evidence commitments of wire v0.3.0: the A-level
// TRUEOPEN_WORKER_TOKEN_COMMITMENT_V1 over the token-id artifacts, output and
// finish reason, and the B-level TRUEOPEN_WORKER_VALUE_COMMITMENT_V3 over the
// Merkle root of the per-position values. Wire owns their field order and
// domains; internal/nodewire encodes them.

import (
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// InferEvidenceRequirement is one element of the locked Verification Profile's
// evidence_schema.required_infer_evidence, served by
// hub.v1.Query/Profile as
// profile.verification_profile.evidence_schema.required_infer_evidence.
type InferEvidenceRequirement struct {
	EvidenceKind            nodewire.EvidenceKind
	CommitmentSchemaVersion uint32
	MaxEncodedSizeBytes     uint64
}

// WorkerEvidenceRequirementsV3 is the requirement SHAPE every v0.3.0 profile
// must carry: the B-level value opening (kind 1, commitment schema 3) and the
// A-level token opening (kind 4, commitment schema 1), in ascending kind order.
// What is NOT derivable is max_encoded_size_bytes: that is per-Profile data,
// so this fills it with the contract-wide ceiling, which bounds the wire but is
// NOT the locked Profile's bound.
//
// It is consequently not usable for building a receipt: BuildInferReceipt
// requires the real requirement set and refuses without it, because a
// commitment inside the ceiling but outside the Profile's bound is a signature
// over a body the Keeper rejects on size. Its honest uses are checks with no
// Profile read available and no signature to produce, such as the Worker's
// recovery boundary re-establishing a persisted receipt's shape.
func WorkerEvidenceRequirementsV3() []InferEvidenceRequirement {
	return []InferEvidenceRequirement{
		{EvidenceKind: nodewire.EvidenceKindWorkerValueOpening, CommitmentSchemaVersion: nodewire.WorkerValueCommitmentSchemaVersionV3, MaxEncodedSizeBytes: nodewire.MaxEvidenceEncodedSizeBytesV1},
		{EvidenceKind: nodewire.EvidenceKindWorkerTokenOpening, CommitmentSchemaVersion: nodewire.WorkerTokenCommitmentSchemaVersionV1, MaxEncodedSizeBytes: nodewire.MaxEvidenceEncodedSizeBytesV1},
	}
}

// ValidateWorkerEvidenceRequirementsV3 requires the locked Profile's
// required_infer_evidence to be exactly the wire v0.3.0 Worker shape: the value
// opening at schema 3, then the token opening at schema 1, each with a positive
// size bound. Code that indexes the two Worker commitments checks this first.
func ValidateWorkerEvidenceRequirementsV3(requirements []InferEvidenceRequirement) error {
	want := WorkerEvidenceRequirementsV3()
	if len(requirements) != len(want) {
		return fmt.Errorf("locked profile must require exactly the Worker value and token openings, got %d requirements", len(requirements))
	}
	for i, requirement := range requirements {
		if requirement.EvidenceKind != want[i].EvidenceKind || requirement.CommitmentSchemaVersion != want[i].CommitmentSchemaVersion ||
			requirement.MaxEncodedSizeBytes == 0 {
			return fmt.Errorf("locked profile must require the Worker value opening (schema 3) then the token opening (schema 1), each with a size bound")
		}
	}
	return nil
}

// WorkerEvidenceFacts are the inputs of both Worker evidence commitments. The
// split between hex strings and codec.Hash is the same one InferReceiptFacts
// makes: a consensus read arrives as text so "unset" and "32 zero bytes" stay
// tellable apart, and a value Cortex computed itself arrives already typed.
type WorkerEvidenceFacts struct {
	ChainID string
	// TaskID is the canonical lowercase 64-hex Keeper task id.
	TaskID string
	// AcceptedTaskHash is TaskCoreState.accepted_task_hash, canonical lowercase
	// 64-hex, and must be the same value the receipt carries as task_hash.
	AcceptedTaskHash string
	// WorkerOperatorAddress is canonical Bech32; the preimages frame its address
	// codec bytes, never the text.
	WorkerOperatorAddress string
	// GenerationParamsDigest is TaskAssignmentState.generation_params_digest,
	// canonical lowercase 64-hex.
	GenerationParamsDigest string
	// EvidenceSchemaHash is the locked Profile's
	// verification_profile.evidence_schema_hash, canonical lowercase 64-hex.
	EvidenceSchemaHash         string
	OutputHash                 codec.Hash
	OutputSizeBytes            uint64
	OutputLeafCount            uint64
	GeneratedTokenCount        uint64
	InputTokenIDsHash          codec.Hash
	GeneratedTokenIDsHash      codec.Hash
	InputTokenIDsSizeBytes     uint64
	GeneratedTokenIDsSizeBytes uint64
	// FinishReason is the Worker's successful termination outcome. There is no
	// "unknown" value: an unsuccessful finish cannot produce an accepted receipt.
	FinishReason nodewire.FinishReasonV1
	// WorkerValueRoot is the Merkle root of the worker_values leaves, and
	// WorkerValuesEncodedSizeBytes the exact size of that artifact.
	WorkerValueRoot              codec.Hash
	WorkerValuesEncodedSizeBytes uint64
}

// inferReceiptHashUnavailable treats an unset field and an all-zero hash as the
// same condition. The wire frames a Hash32 unconditionally and gives it no
// "absent" encoding, so a caller with no value has only two ways to say so:
// leave the string empty, or write 32 zero bytes. The second one is a positive
// claim about consensus state, and it is the more dangerous of the two because
// it is shape-valid all the way to the signature. Both are refused.
func inferReceiptHashUnavailable(value string) bool {
	return value == "" || isZeroTaskDataHash(value)
}

// WorkerEvidenceCommitments derives the two evidence commitments a V3
// InferReceipt carries, in ascending kind order: value (kind 1), then token
// (kind 4). encoded_size_bytes comes back from the derivations rather than
// being added up here, so a digest and its size are never computed from two
// different sums.
//
// The all-zero refusals are the point of doing this in Cortex at all. The
// handler does not recompute evidence_hash_or_root, so an all-zero consensus
// read folded into a commitment would produce a well-formed 32-byte digest that
// the chain accepts and that means nothing.
func WorkerEvidenceCommitments(facts WorkerEvidenceFacts) ([]EvidenceCommitment, error) {
	value, err := WorkerValueEvidenceCommitment(facts)
	if err != nil {
		return nil, err
	}
	token, err := WorkerTokenEvidenceCommitment(facts)
	if err != nil {
		return nil, err
	}
	return []EvidenceCommitment{value, token}, nil
}

// WorkerValueEvidenceCommitment derives the B-level commitment alone. It reads
// only the scope, the evidence schema hash and the value root.
func WorkerValueEvidenceCommitment(facts WorkerEvidenceFacts) (EvidenceCommitment, error) {
	scope, err := workerEvidenceScope(facts, false)
	if err != nil {
		return EvidenceCommitment{}, err
	}
	if facts.WorkerValueRoot == (codec.Hash{}) {
		return EvidenceCommitment{}, fmt.Errorf("worker evidence commitment worker_value_root must not be 32 zero bytes: " +
			"no artifact hashes to zero, so this is an unhashed artifact rather than a value")
	}
	digest, size, err := nodewire.WorkerValueCommitmentV3Digest(nodewire.WorkerValueCommitmentV3{
		SchemaVersion:                nodewire.WorkerValueCommitmentSchemaVersionV3,
		ChainID:                      facts.ChainID,
		TaskID:                       scope.taskID,
		AcceptedTaskHash:             scope.acceptedTaskHash,
		WorkerOperatorAddress:        facts.WorkerOperatorAddress,
		EvidenceSchemaHash:           scope.evidenceSchemaHash,
		WorkerValueRoot:              facts.WorkerValueRoot[:],
		WorkerValuesEncodedSizeBytes: facts.WorkerValuesEncodedSizeBytes,
	})
	if err != nil {
		return EvidenceCommitment{}, fmt.Errorf("derive worker value commitment: %w", err)
	}
	return EvidenceCommitment{EvidenceKind: nodewire.EvidenceKindWorkerValueOpening, EvidenceHashOrRoot: digest, EncodedSizeBytes: size}, nil
}

// WorkerTokenEvidenceCommitment derives the A-level commitment alone.
func WorkerTokenEvidenceCommitment(facts WorkerEvidenceFacts) (EvidenceCommitment, error) {
	if facts.OutputSizeBytes == 0 && facts.OutputLeafCount != 1 {
		return EvidenceCommitment{}, fmt.Errorf("empty output requires exactly one MMR leaf")
	}
	scope, err := workerEvidenceScope(facts, true)
	if err != nil {
		return EvidenceCommitment{}, err
	}
	// finish_reason is supplied by the model service. The Worker maps the
	// free-text finish reason to a FinishReasonV1 and refuses to sign if the
	// value is unspecified or ambiguous.
	if facts.FinishReason == nodewire.FinishReasonV1Unspecified {
		return EvidenceCommitment{}, fmt.Errorf(
			"%w: worker token commitment finish_reason is unspecified; the model service must report a concrete "+
				"FinishReasonV1 outcome (e.g. EOS_TOKEN, STOP_SEQUENCE, MAX_OUTPUT_TOKENS)",
			ErrInferReceiptInputUnavailable)
	}
	// The artifact commitments. An all-zero hash is not a protocol gap: it means
	// the artifact hashing produced nothing, which is a local bug.
	for _, field := range [...]struct {
		name  string
		value codec.Hash
	}{
		{"output_hash", facts.OutputHash},
		{"input_token_ids_hash", facts.InputTokenIDsHash},
		{"generated_token_ids_hash", facts.GeneratedTokenIDsHash},
	} {
		if field.value == (codec.Hash{}) {
			return EvidenceCommitment{}, fmt.Errorf(
				"worker evidence commitment %s must not be 32 zero bytes: no artifact hashes to zero, "+
					"so this is an unhashed artifact rather than a value", field.name)
		}
	}
	digest, size, err := nodewire.WorkerTokenCommitment(nodewire.WorkerTokenCommitmentV1{
		SchemaVersion:              nodewire.WorkerTokenCommitmentSchemaVersionV1,
		ChainID:                    facts.ChainID,
		TaskID:                     scope.taskID,
		AcceptedTaskHash:           scope.acceptedTaskHash,
		WorkerOperatorAddress:      facts.WorkerOperatorAddress,
		GenerationParamsDigest:     scope.generationParamsDigest,
		EvidenceSchemaHash:         scope.evidenceSchemaHash,
		OutputHash:                 facts.OutputHash[:],
		OutputSizeBytes:            facts.OutputSizeBytes,
		OutputLeafCount:            facts.OutputLeafCount,
		FinishReason:               facts.FinishReason,
		GeneratedTokenCount:        facts.GeneratedTokenCount,
		InputTokenIDsHash:          facts.InputTokenIDsHash[:],
		GeneratedTokenIDsHash:      facts.GeneratedTokenIDsHash[:],
		InputTokenIDsSizeBytes:     facts.InputTokenIDsSizeBytes,
		GeneratedTokenIDsSizeBytes: facts.GeneratedTokenIDsSizeBytes,
	})
	if err != nil {
		return EvidenceCommitment{}, fmt.Errorf("derive worker token commitment: %w", err)
	}
	return EvidenceCommitment{EvidenceKind: nodewire.EvidenceKindWorkerTokenOpening, EvidenceHashOrRoot: digest, EncodedSizeBytes: size}, nil
}

type workerEvidenceScopeBytes struct {
	taskID, acceptedTaskHash, generationParamsDigest, evidenceSchemaHash []byte
}

// workerEvidenceScope decodes the consensus reads both commitments share.
// Their unavailability is a protocol gap, not caller error, so it wraps the
// same sentinel the receipt refusals use and every refusal names the query the
// value comes from. generation_params_digest enters only the token commitment.
func workerEvidenceScope(facts WorkerEvidenceFacts, needGeneration bool) (workerEvidenceScopeBytes, error) {
	var scope workerEvidenceScopeBytes
	fields := []struct {
		name   string
		source string
		value  string
		into   *[]byte
	}{
		{"task_id", "the canonical Keeper task id", facts.TaskID, &scope.taskID},
		{"accepted_task_hash", "TaskCoreState.accepted_task_hash from task.v1.Query/Task (TaskViewV1.active.core)", facts.AcceptedTaskHash, &scope.acceptedTaskHash},
		{"evidence_schema_hash", "the locked Profile's verification_profile.evidence_schema_hash from hub.v1.Query/Profile", facts.EvidenceSchemaHash, &scope.evidenceSchemaHash},
	}
	if needGeneration {
		fields = append(fields, struct {
			name   string
			source string
			value  string
			into   *[]byte
		}{"generation_params_digest", "TaskAssignmentState.generation_params_digest from task.v1.Query/TaskAssignment", facts.GenerationParamsDigest, &scope.generationParamsDigest})
	}
	for _, field := range fields {
		if inferReceiptHashUnavailable(field.value) {
			return workerEvidenceScopeBytes{}, fmt.Errorf(
				"%w: worker evidence commitment %s requires %s; the handler does not recompute "+
					"evidence_hash_or_root, so zeros here would produce a well-formed commitment that commits nothing",
				ErrInferReceiptInputUnavailable, field.name, field.source)
		}
		raw, ok := decodeCanonicalTaskDataHash(field.value)
		if !ok {
			return workerEvidenceScopeBytes{}, fmt.Errorf("worker evidence commitment %s must be lowercase 32-byte hex", field.name)
		}
		*field.into = raw
	}
	return scope, nil
}

// ConfirmWorkerValueEvidence proves that downloaded worker_values bytes are the
// ones a signed receipt's value commitment covers. The commitment does not
// depend on finish_reason, so a mismatch is final.
func ConfirmWorkerValueEvidence(facts WorkerEvidenceFacts, committed EvidenceCommitment) error {
	if committed.EvidenceKind != nodewire.EvidenceKindWorkerValueOpening || committed.EvidenceHashOrRoot == (codec.Hash{}) {
		return fmt.Errorf("worker value confirmation requires a set WORKER_VALUE_OPENING commitment")
	}
	derived, err := WorkerValueEvidenceCommitment(facts)
	if err != nil {
		return err
	}
	if derived.EvidenceHashOrRoot != committed.EvidenceHashOrRoot {
		return fmt.Errorf("downloaded worker_values do not reproduce the committed value commitment %s: worker_value_root=%s (%d bytes)",
			committed.EvidenceHashOrRoot, facts.WorkerValueRoot, facts.WorkerValuesEncodedSizeBytes)
	}
	// encoded_size_bytes is not inside the digest, so it is compared
	// separately. It is also the value the Keeper bounded against the locked
	// Profile, which makes it a size statement that is not the Builder's.
	if derived.EncodedSizeBytes != committed.EncodedSizeBytes {
		return fmt.Errorf("worker_values reproduce the committed digest but encoded_size_bytes is %d, not the committed %d",
			derived.EncodedSizeBytes, committed.EncodedSizeBytes)
	}
	return nil
}

// ConfirmWorkerTokenEvidence proves that downloaded token-id artifacts are the
// ones a signed receipt's token commitment covers, and returns the
// finish_reason that reproduction resolved to.
//
// FINISH_REASON IS SEARCHED, NOT ASSUMED. It is a token-commitment preimage
// field with no Verifier-readable source: it is not a receipt field, and
// task.v1.InferReceiptState has no column for it. Its domain is the closed
// four-member set nodewire.SuccessfulFinishReasonsV1 returns, so each candidate
// is derived and exactly one must reproduce the committed digest. A match pins
// every other field, the artifact hashes included, and no match is a refusal
// rather than a fallback.
func ConfirmWorkerTokenEvidence(facts WorkerEvidenceFacts, committed EvidenceCommitment) (nodewire.FinishReasonV1, error) {
	if committed.EvidenceKind != nodewire.EvidenceKindWorkerTokenOpening || committed.EvidenceHashOrRoot == (codec.Hash{}) {
		return nodewire.FinishReasonV1Unspecified, fmt.Errorf("worker token confirmation requires a set WORKER_TOKEN_OPENING commitment")
	}
	for _, candidate := range nodewire.SuccessfulFinishReasonsV1() {
		attempt := facts
		attempt.FinishReason = candidate
		derived, err := WorkerTokenEvidenceCommitment(attempt)
		if err != nil {
			return nodewire.FinishReasonV1Unspecified, err
		}
		if derived.EvidenceHashOrRoot != committed.EvidenceHashOrRoot {
			continue
		}
		if derived.EncodedSizeBytes != committed.EncodedSizeBytes {
			return nodewire.FinishReasonV1Unspecified, fmt.Errorf(
				"token-id artifacts reproduce the committed digest but encoded_size_bytes is %d, not the committed %d",
				derived.EncodedSizeBytes, committed.EncodedSizeBytes)
		}
		return candidate, nil
	}
	return nodewire.FinishReasonV1Unspecified, fmt.Errorf(
		"downloaded token-id artifacts do not reproduce the committed token commitment %s under any successful finish_reason",
		committed.EvidenceHashOrRoot)
}

// ConfirmWorkerEvidence confirms both commitments of a V3 receipt, value then
// token, and returns the resolved finish_reason.
func ConfirmWorkerEvidence(facts WorkerEvidenceFacts, committed []EvidenceCommitment) (nodewire.FinishReasonV1, error) {
	if len(committed) != 2 || committed[0].EvidenceKind != nodewire.EvidenceKindWorkerValueOpening || committed[1].EvidenceKind != nodewire.EvidenceKindWorkerTokenOpening {
		return nodewire.FinishReasonV1Unspecified, fmt.Errorf("worker evidence confirmation requires the WORKER_VALUE_OPENING and WORKER_TOKEN_OPENING commitments, in that order")
	}
	if err := ConfirmWorkerValueEvidence(facts, committed[0]); err != nil {
		return nodewire.FinishReasonV1Unspecified, err
	}
	return ConfirmWorkerTokenEvidence(facts, committed[1])
}

// ValidateProfileEvidenceCommitments reproduces every precondition the
// SubmitInferReceipt handler applies to required_evidence_commitments, so a
// receipt the chain will reject is refused before it is signed rather than after
// it is broadcast:
//
//   - the element count equals the locked Profile's requirement count;
//   - commitments[i].evidence_kind == requirements[i].evidence_kind, index by
//     index, not as sets;
//   - each requirement names a commitment schema Cortex produces: value
//     opening at schema 3, token opening at schema 1;
//   - 0 < encoded_size_bytes <= requirement.max_encoded_size_bytes;
//   - the list is strictly ascending with unique kinds and every
//     evidence_hash_or_root is a set 32-byte value.
func ValidateProfileEvidenceCommitments(requirements []InferEvidenceRequirement, commitments []EvidenceCommitment) error {
	if len(requirements) == 0 {
		return fmt.Errorf(
			"the locked Profile's required_infer_evidence must be non-empty: no Profile requires the empty set")
	}
	if len(commitments) != len(requirements) {
		return fmt.Errorf(
			"required_evidence_commitments must exactly match the locked Profile requirement count: got %d, want %d",
			len(commitments), len(requirements))
	}
	for index, requirement := range requirements {
		commitment := commitments[index]
		if commitment.EvidenceKind != requirement.EvidenceKind {
			return fmt.Errorf(
				"required_evidence_commitments[%d] kind %d does not match the locked Profile kind %d",
				index, commitment.EvidenceKind, requirement.EvidenceKind)
		}
		supported := requirement.EvidenceKind == nodewire.EvidenceKindWorkerValueOpening && requirement.CommitmentSchemaVersion == nodewire.WorkerValueCommitmentSchemaVersionV3 ||
			requirement.EvidenceKind == nodewire.EvidenceKindWorkerTokenOpening && requirement.CommitmentSchemaVersion == nodewire.WorkerTokenCommitmentSchemaVersionV1
		if !supported {
			return fmt.Errorf(
				"required_evidence_commitments[%d] uses an unsupported commitment schema %d for evidence_kind %d: "+
					"wire v0.3.0 defines WORKER_VALUE_OPENING at schema %d and WORKER_TOKEN_OPENING at schema %d",
				index, requirement.CommitmentSchemaVersion, requirement.EvidenceKind,
				nodewire.WorkerValueCommitmentSchemaVersionV3, nodewire.WorkerTokenCommitmentSchemaVersionV1)
		}
		if commitment.EncodedSizeBytes == 0 || commitment.EncodedSizeBytes > requirement.MaxEncodedSizeBytes {
			return fmt.Errorf(
				"required_evidence_commitments[%d] encoded_size_bytes %d is outside the locked Profile's 1..%d",
				index, commitment.EncodedSizeBytes, requirement.MaxEncodedSizeBytes)
		}
		if commitment.EvidenceHashOrRoot == (codec.Hash{}) {
			return fmt.Errorf(
				"required_evidence_commitments[%d] evidence_hash_or_root must not be 32 zero bytes", index)
		}
		if index > 0 && commitments[index-1].EvidenceKind >= commitment.EvidenceKind {
			return fmt.Errorf(
				"required_evidence_commitments must be strictly ascending by evidence_kind with unique kinds: "+
					"element %d has kind %d after kind %d",
				index, commitment.EvidenceKind, commitments[index-1].EvidenceKind)
		}
	}
	return nil
}
