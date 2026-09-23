package builderclient

// WorkerValueCommitmentV2 binds the output MMR and all four required evidence
// artifacts. Wire v0.4.1 owns its field order and domains; monorepo 05afeeaf
// Task data-plane section 2.1 specifies the typed manifest locator.

import (
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// InferEvidenceRequirement is one element of the locked Verification Profile's
// evidence_schema.required_infer_evidence, served by
// hub.v1.Query/Profile as
// profile.verification_profile.evidence_schema.required_infer_evidence.
//
// It is declared here rather than in internal/chainclient because nothing reads
// it off the chain yet: the receipt path is the only consumer, and this is the
// shape a reader must produce. A chainclient snapshot type should map into this,
// not duplicate it.
type InferEvidenceRequirement struct {
	EvidenceKind            nodewire.EvidenceKind
	CommitmentSchemaVersion uint32
	MaxEncodedSizeBytes     uint64
}

// WorkerValueEvidenceRequirementsV2 is the requirement SHAPE every V1 profile
// must carry, derived from the frozen handler rather than assumed:
//
//   - msg_server_receipt.go:303-306 rejects the receipt unless EVERY requirement
//     has commitment_schema_version == 2 and evidence_kind ==
//     EVIDENCE_KIND_WORKER_VALUE_OPENING, so no other kind can appear;
//   - ValidateEvidenceSchemaV1 (evidence.go:23-48) requires the list to be
//     non-empty and strictly ascending with unique kinds, so WORKER_VALUE_OPENING
//     can appear at most once.
//
// Exactly one element, therefore, for every profile the chain will accept a V1
// receipt against. What is NOT derivable is max_encoded_size_bytes: that is
// per-Profile data that ValidateEvidenceSchemaV1 only confines to
// 1..MaxEvidenceEncodedSizeBytesV1, and the handler compares
// encoded_size_bytes against the locked Profile's own value. This function
// therefore fills that slot with the contract-wide ceiling, which bounds the
// wire but is NOT the locked Profile's bound.
//
// It is consequently not usable for building a receipt: BuildInferReceipt
// requires the real requirement set and refuses without it, because a
// commitment inside the ceiling but outside the Profile's bound is a signature
// over a body the Keeper rejects on size. Its honest uses are checks with no
// Profile read available and no signature to produce: the Worker's recovery
// boundary re-establishing a persisted receipt's V1 shape
// (internal/worker/recovery.go), and the tests that pin the shape itself.
func WorkerValueEvidenceRequirementsV2() []InferEvidenceRequirement {
	return []InferEvidenceRequirement{{
		EvidenceKind:            nodewire.EvidenceKindWorkerValueOpening,
		CommitmentSchemaVersion: nodewire.WorkerValueCommitmentSchemaVersionV2,
		MaxEncodedSizeBytes:     nodewire.MaxEvidenceEncodedSizeBytesV1,
	}}
}

// WorkerValueEvidenceFacts are the inputs of the single WORKER_VALUE_OPENING
// commitment. The split between hex strings and codec.Hash is the same one
// InferReceiptFacts makes: a consensus read arrives as text so "unset" and "32
// zero bytes" stay tellable apart, and a value Cortex computed itself arrives
// already typed.
type WorkerValueEvidenceFacts struct {
	ChainID string
	// TaskID is the canonical lowercase 64-hex Keeper task id.
	TaskID string
	// AcceptedTaskHash is TaskCoreState.accepted_task_hash, canonical lowercase
	// 64-hex, and must be the same value the receipt carries as task_hash.
	AcceptedTaskHash string
	// WorkerOperatorAddress is canonical Bech32; the preimage frames its address
	// codec bytes, never the text.
	WorkerOperatorAddress string
	// GenerationParamsDigest is TaskAssignmentState.generation_params_digest,
	// canonical lowercase 64-hex.
	GenerationParamsDigest string
	// EvidenceSchemaHash is the locked Profile's
	// verification_profile.evidence_schema_hash, canonical lowercase 64-hex. The
	// handler independently requires it to equal
	// TaskAssignmentState.evidence_schema_hash, so a Worker that reads a
	// different profile version commits the wrong value here.
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
	// TraceRoot and CheckpointRoot are the two Hash32 commitments the Worker
	// already produces. They occupy one evidence kind together, which is what
	// makes a single WORKER_VALUE_OPENING requirement satisfiable.
	TraceRoot                  codec.Hash
	TraceEncodedSizeBytes      uint64
	CheckpointRoot             codec.Hash
	CheckpointEncodedSizeBytes uint64
}

// inferReceiptHashUnavailable treats an unset field and an all-zero hash as the
// same condition. The frozen wire frames a Hash32 unconditionally and gives it
// no "absent" encoding, so a caller with no value has only two ways to say so:
// leave the string empty, or write 32 zero bytes. The second one is a positive
// claim about consensus state, and it is the more dangerous of the two because
// it is shape-valid all the way to the signature. Both are refused.
func inferReceiptHashUnavailable(value string) bool {
	return value == "" || isZeroTaskDataHash(value)
}

// WorkerValueEvidenceCommitment derives the single evidence commitment a V1
// InferReceipt carries. encoded_size_bytes comes back from the derivation rather
// than being added up here, so the digest and the size can never be computed
// from two different sums.
//
// The all-zero refusals are the point of doing this in Cortex at all. The frozen
// handler does not recompute evidence_hash_or_root, so an all-zero
// accepted_task_hash, generation_params_digest or evidence_schema_hash folded
// into the commitment would produce a perfectly well-formed 32-byte digest that
// the chain accepts and that means nothing. The frozen Hash32 has no absent
// encoding, so zeros are a positive claim about consensus state, and they are
// refused here for the same reason InferReceiptSigningDigest refuses them in
// the receipt itself.
func WorkerValueEvidenceCommitment(facts WorkerValueEvidenceFacts) (EvidenceCommitment, error) {
	if facts.OutputSizeBytes == 0 && facts.OutputLeafCount != 1 {
		return EvidenceCommitment{}, fmt.Errorf("empty output requires exactly one MMR leaf")
	}
	// The four consensus reads. Their unavailability is a protocol gap, not
	// caller error, so it wraps the same sentinel the receipt refusals use and
	// every refusal names the query the value comes from: an operator reading
	// "commitment input unavailable" cannot otherwise tell which read Cortex is
	// waiting on.
	var taskID, acceptedTaskHash, generationParamsDigest, evidenceSchemaHash []byte
	for _, field := range [...]struct {
		name   string
		source string
		value  string
		into   *[]byte
	}{
		{"task_id", "the canonical Keeper task id", facts.TaskID, &taskID},
		{
			"accepted_task_hash",
			"TaskCoreState.accepted_task_hash from task.v1.Query/Task (TaskViewV1.active.core); " +
				"order_digest is not a substitute because it commits the order envelope, not canonical TaskOrderV1",
			facts.AcceptedTaskHash, &acceptedTaskHash,
		},
		{
			"generation_params_digest",
			"TaskAssignmentState.generation_params_digest from task.v1.Query/TaskAssignment",
			facts.GenerationParamsDigest, &generationParamsDigest,
		},
		{
			"evidence_schema_hash",
			"the locked Profile's verification_profile.evidence_schema_hash from hub.v1.Query/Profile",
			facts.EvidenceSchemaHash, &evidenceSchemaHash,
		},
	} {
		if inferReceiptHashUnavailable(field.value) {
			return EvidenceCommitment{}, fmt.Errorf(
				"%w: worker value commitment %s requires %s; the frozen handler does not recompute "+
					"evidence_hash_or_root, so zeros here would produce a well-formed commitment that commits nothing",
				ErrInferReceiptInputUnavailable, field.name, field.source)
		}
		raw, ok := decodeCanonicalTaskDataHash(field.value)
		if !ok {
			return EvidenceCommitment{}, fmt.Errorf(
				"worker value commitment %s must be lowercase 32-byte hex", field.name)
		}
		*field.into = raw
	}
	// finish_reason is supplied by the model service. The Worker maps the free-text
	// finish reason to a FinishReasonV1 and refuses to sign if the value is
	// unspecified or ambiguous.
	if facts.FinishReason == nodewire.FinishReasonV1Unspecified {
		return EvidenceCommitment{}, fmt.Errorf(
			"%w: worker value commitment finish_reason is unspecified; the model service must report a concrete "+
				"FinishReasonV1 outcome (e.g. EOS_TOKEN, STOP_SEQUENCE, MAX_OUTPUT_TOKENS)",
			ErrInferReceiptInputUnavailable)
	}
	// The artifact commitments. An all-zero root is not a protocol gap: it means
	// the artifact hashing produced nothing, which is a local bug.
	for _, field := range [...]struct {
		name  string
		value codec.Hash
	}{
		{"output_hash", facts.OutputHash},
		{"trace_root", facts.TraceRoot},
		{"checkpoint_root", facts.CheckpointRoot},
		{"input_token_ids_hash", facts.InputTokenIDsHash},
		{"generated_token_ids_hash", facts.GeneratedTokenIDsHash},
	} {
		if field.value == (codec.Hash{}) {
			return EvidenceCommitment{}, fmt.Errorf(
				"worker value commitment %s must not be 32 zero bytes: no artifact hashes to zero, "+
					"so this is an unhashed artifact rather than a value", field.name)
		}
	}
	digest, encodedSizeBytes, err := nodewire.WorkerValueCommitment(nodewire.WorkerValueCommitmentV2{
		SchemaVersion:              nodewire.WorkerValueCommitmentSchemaVersionV2,
		ChainID:                    facts.ChainID,
		TaskID:                     taskID,
		AcceptedTaskHash:           acceptedTaskHash,
		WorkerOperatorAddress:      facts.WorkerOperatorAddress,
		GenerationParamsDigest:     generationParamsDigest,
		EvidenceSchemaHash:         evidenceSchemaHash,
		OutputHash:                 facts.OutputHash[:],
		OutputSizeBytes:            facts.OutputSizeBytes,
		OutputLeafCount:            facts.OutputLeafCount,
		GeneratedTokenCount:        facts.GeneratedTokenCount,
		InputTokenIDsHash:          facts.InputTokenIDsHash[:],
		GeneratedTokenIDsHash:      facts.GeneratedTokenIDsHash[:],
		InputTokenIDsSizeBytes:     facts.InputTokenIDsSizeBytes,
		GeneratedTokenIDsSizeBytes: facts.GeneratedTokenIDsSizeBytes,
		FinishReason:               facts.FinishReason,
		TraceRoot:                  facts.TraceRoot[:],
		TraceEncodedSizeBytes:      facts.TraceEncodedSizeBytes,
		CheckpointRoot:             facts.CheckpointRoot[:],
		CheckpointEncodedSizeBytes: facts.CheckpointEncodedSizeBytes,
	})
	if err != nil {
		return EvidenceCommitment{}, fmt.Errorf("derive worker value commitment: %w", err)
	}
	return EvidenceCommitment{
		EvidenceKind:       nodewire.EvidenceKindWorkerValueOpening,
		EvidenceHashOrRoot: digest,
		EncodedSizeBytes:   encodedSizeBytes,
	}, nil
}

// ConfirmWorkerValueEvidence proves that downloaded trace and checkpoint bytes
// are the ones a signed receipt's WORKER_VALUE_OPENING commitment covers, and
// returns the finish_reason that reproduction resolved to.
//
// It is the Verifier's half of WorkerValueEvidenceCommitment and takes the same
// facts, with two of them supplied by the downloaded artifacts rather than by
// the local model service. The check matters because everything else about an
// evidence object is Builder-asserted: the object exists, it is this many bytes,
// it hashes to this. Only re-deriving the commitment binds the bytes to
// something the chain settled on -- the receipt's evidence_hash_or_root, reached
// through the infer_receipt_hash Keeper accepted.
//
// FINISH_REASON IS SEARCHED, NOT ASSUMED. It is one of the twenty preimage
// fields and the only one with no Verifier-readable source: it is not a receipt
// field, and task.v1.InferReceiptState has no column for it. Its value
// domain is the closed four-member set nodewire.SuccessfulFinishReasonsV1
// returns, so each candidate is derived and exactly one must reproduce the
// committed digest. That is a preimage confirmation over a four-value unknown,
// not a guess: a match pins the other nineteen fields, all artifact commitments
// included, and no match is a refusal rather than a fallback. Nothing here may
// be relaxed into "skip the check when finish_reason is unknown" -- unknown is
// the normal case, and skipping would leave the Verifier re-verifying whatever
// blob the Builder chose to serve.
func ConfirmWorkerValueEvidence(
	facts WorkerValueEvidenceFacts,
	committed EvidenceCommitment,
) (nodewire.FinishReasonV1, error) {
	if committed.EvidenceKind != nodewire.EvidenceKindWorkerValueOpening {
		return nodewire.FinishReasonV1Unspecified, fmt.Errorf(
			"worker value evidence confirmation requires the WORKER_VALUE_OPENING commitment, got evidence_kind %d",
			committed.EvidenceKind)
	}
	if committed.EvidenceHashOrRoot == (codec.Hash{}) {
		return nodewire.FinishReasonV1Unspecified, fmt.Errorf(
			"committed worker value evidence_hash_or_root is 32 zero bytes: there is nothing to confirm against")
	}
	// encoded_size_bytes is not inside the digest -- WorkerValueCommitment returns
	// it as the checked sum -- so it is compared separately. It is also the value
	// the Keeper bounded against the locked Profile, which makes it the one size
	// statement about the pair that is not the Builder's.
	for _, candidate := range nodewire.SuccessfulFinishReasonsV1() {
		attempt := facts
		attempt.FinishReason = candidate
		commitment, err := WorkerValueEvidenceCommitment(attempt)
		if err != nil {
			return nodewire.FinishReasonV1Unspecified, err
		}
		if commitment.EvidenceHashOrRoot != committed.EvidenceHashOrRoot {
			continue
		}
		if commitment.EncodedSizeBytes != committed.EncodedSizeBytes {
			return nodewire.FinishReasonV1Unspecified, fmt.Errorf(
				"worker value evidence reproduces the committed digest but encoded_size_bytes is %d, not the committed %d",
				commitment.EncodedSizeBytes, committed.EncodedSizeBytes)
		}
		return candidate, nil
	}
	return nodewire.FinishReasonV1Unspecified, fmt.Errorf(
		"downloaded worker value evidence does not reproduce the committed evidence_hash_or_root %s under any "+
			"successful finish_reason: trace_root=%s (%d bytes) checkpoint_root=%s (%d bytes)",
		committed.EvidenceHashOrRoot, facts.TraceRoot, facts.TraceEncodedSizeBytes,
		facts.CheckpointRoot, facts.CheckpointEncodedSizeBytes)
}

// ValidateProfileEvidenceCommitments reproduces every precondition the frozen
// SubmitInferReceipt handler applies to required_evidence_commitments, so a
// receipt the chain will reject is refused before it is signed rather than after
// it is broadcast:
//
//   - the element count equals the locked Profile's requirement count
//     (msg_server_receipt.go:296-298);
//   - commitments[i].evidence_kind == requirements[i].evidence_kind, index by
//     index, not as sets (:300-302);
//   - the requirement uses commitment_schema_version == 2 and
//     kind == WORKER_VALUE_OPENING;
//   - 0 < encoded_size_bytes <= requirement.max_encoded_size_bytes (:307-309);
//   - the list is strictly ascending with unique kinds and every
//     evidence_hash_or_root is a set 32-byte value (evidence_commitments.go:105-111
//     and :50), which the handler enforces indirectly by re-deriving
//     evidence_commitments_hash over the list.
//
// The two bounds it cannot check are the chain params ceilings
// (max_infer_evidence_commitments_per_receipt and
// max_infer_receipt_commitment_bytes). Both are upper bounds on a list this
// function already pins to one element, so nothing is guessed by leaving them
// to the handler.
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
		if requirement.CommitmentSchemaVersion != nodewire.WorkerValueCommitmentSchemaVersionV2 ||
			requirement.EvidenceKind != nodewire.EvidenceKindWorkerValueOpening {
			return fmt.Errorf(
				"required_evidence_commitments[%d] uses an unsupported commitment schema: "+
					"wire v0.4.1 supports only commitment_schema_version %d with EVIDENCE_KIND_WORKER_VALUE_OPENING",
				index, nodewire.WorkerValueCommitmentSchemaVersionV2)
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
