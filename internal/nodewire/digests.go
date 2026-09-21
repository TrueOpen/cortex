package nodewire

import (
	"crypto/sha256"
	"fmt"
	"math"
	"unicode/utf8"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/hfields"
)

// EvidenceCommitmentsPreimage returns the ordered
// TRUEOPEN_INFER_EVIDENCE_COMMITMENTS_V1 preimage:
//
//	u64_be(35) || "TRUEOPEN_INFER_EVIDENCE_COMMITMENTS_V1"
//	u64_be(4)  || uint32_be(count)
//	u64_be(n)  || commitments frame
//
// The domain frames exactly TWO fields. The second is a single nested frame over
// the whole repeated field - u64_be(4)||uint32_be(element_count) followed by one
// frame per element - and not one top-level field per element.
//
// This repository used to flatten the elements into the outer field list, which
// produced a different preimage for every non-trivial list and, for the empty
// list, omitted the second field entirely. The frozen vectors published in
// github.com/TrueOpen/wire (testdata/v1/task/task_domains_v1.json, the four
// infer_evidence_commitments_v1_* vectors) settle the shape: the empty list is
// u64_be(12)||u64_be(4)||uint32_be(0), which the flattened form could not emit.
// Do not re-flatten it; evidence_commitments_hash feeds InferReceiptV2, so the
// difference reaches a digest this node signs and submits on chain.
//
// The element frame is the nested FieldFrameV1 of EvidenceCommitmentV1 with no
// domain prefix and its three fields in schema field-number order. The preimage
// carries no chain_id and no task_id: it is a pure content commitment, and the
// outer receipt digest binds the task and the worker.
//
// An empty list stays fully defined as uint32_be(0) plus a commitments frame
// whose own element_count is 0. It is never 32 zero bytes, never an empty byte
// string and never a skipped field, and a nil slice and an empty slice give the
// same bytes.
//
// Ordering is not the caller's choice: the list is frozen as strictly ascending
// by evidence_kind with unique kinds, and a reordered or duplicated list is
// rejected here rather than silently re-sorted.
func EvidenceCommitmentsPreimage(items []EvidenceCommitmentV1) ([]byte, error) {
	fields, err := evidenceCommitmentsFields(items)
	if err != nil {
		return nil, err
	}
	return hfields.Preimage(DomainInferEvidenceCommitmentsV1, fields...)
}

// EvidenceCommitmentsHash derives InferReceiptV2.evidence_commitments_hash, the
// tenth field of the receipt preimage. It is Keeper-derived and is never a
// caller-submitted wire field.
func EvidenceCommitmentsHash(items []EvidenceCommitmentV1) (codec.Hash, error) {
	return digestOf(EvidenceCommitmentsPreimage(items))
}

func evidenceCommitmentsFields(items []EvidenceCommitmentV1) ([]hfields.Field, error) {
	if uint64(len(items)) > uint64(math.MaxUint32) {
		return nil, fmt.Errorf("evidence commitment count %d overflows uint32", len(items))
	}
	// The repeated field is framed once, as a single nested frame whose own
	// first field repeats the count. Building it separately from the outer list
	// is what keeps the two counts from drifting apart.
	elements := make([]hfields.Field, 0, len(items)+1)
	elements = append(elements, hfields.Uint32(uint32(len(items))))
	for index, item := range items {
		if index > 0 && items[index-1].EvidenceKind >= item.EvidenceKind {
			return nil, fmt.Errorf(
				"required_evidence_commitments must be strictly ascending by evidence_kind with unique kinds: "+
					"element %d has kind %d after kind %d",
				index, item.EvidenceKind, items[index-1].EvidenceKind,
			)
		}
		frame, err := evidenceCommitmentFrame(item)
		if err != nil {
			return nil, fmt.Errorf("required_evidence_commitments[%d]: %w", index, err)
		}
		elements = append(elements, frame)
	}
	return []hfields.Field{
		hfields.Uint32(uint32(len(items))),
		hfields.Frame(elements...),
	}, nil
}

func evidenceCommitmentFrame(item EvidenceCommitmentV1) (hfields.Field, error) {
	kind, err := canonicalEvidenceKind(item.EvidenceKind)
	if err != nil {
		return hfields.Field{}, err
	}
	hashOrRoot, err := canonicalHash32("evidence_hash_or_root", item.EvidenceHashOrRoot)
	if err != nil {
		return hfields.Field{}, err
	}
	return hfields.Frame(
		hfields.Uint32(kind),
		hfields.Bytes(hashOrRoot),
		hfields.Uint64(item.EncodedSizeBytes),
	), nil
}

// InferReceiptSigningPreimage frames the receipt fields in schema order,
// excluding service_signature. The typed evidence list enters through its hash;
// generated_token_count and output_leaf_count follow expiry_height.
func InferReceiptSigningPreimage(receipt InferReceiptV2) ([]byte, error) {
	if receipt.SchemaVersion != InferReceiptSchemaVersionV2 {
		return nil, fmt.Errorf("infer receipt schema_version must be %d", InferReceiptSchemaVersionV2)
	}
	chainID, err := canonicalUTF8Field("chain_id", receipt.ChainID)
	if err != nil {
		return nil, err
	}
	taskID, err := canonicalHash32("task_id", receipt.TaskID)
	if err != nil {
		return nil, err
	}
	taskHash, err := canonicalHash32("task_hash", receipt.TaskHash)
	if err != nil {
		return nil, err
	}
	worker, err := CanonicalOperatorAddressBytes("worker_operator_address", receipt.WorkerOperatorAddress)
	if err != nil {
		return nil, err
	}
	generationParamsDigest, err := canonicalHash32("generation_params_digest", receipt.GenerationParamsDigest)
	if err != nil {
		return nil, err
	}
	outputHash, err := canonicalHash32("output_hash", receipt.OutputHash)
	if err != nil {
		return nil, err
	}
	evidenceCommitmentsHash, err := EvidenceCommitmentsHash(receipt.RequiredEvidenceCommitments)
	if err != nil {
		return nil, err
	}
	return hfields.Preimage(
		DomainInferReceiptV2,
		hfields.Uint32(receipt.SchemaVersion),
		hfields.String(chainID),
		hfields.Bytes(taskID),
		hfields.Bytes(taskHash),
		hfields.Bytes(worker),
		hfields.Uint64(receipt.ServiceAuthorizationNonce),
		hfields.Bytes(generationParamsDigest),
		hfields.Bytes(outputHash),
		hfields.Uint64(receipt.OutputSizeBytes),
		hfields.Hash(evidenceCommitmentsHash),
		hfields.Uint64(receipt.ExpiryHeight),
		hfields.Uint64(receipt.GeneratedTokenCount),
		hfields.Uint64(receipt.OutputLeafCount),
	)
}

// InferReceiptSigningDigest is the frozen receipt digest. It is both the value a
// Worker signs and the receipt's own identity on chain.
func InferReceiptSigningDigest(receipt InferReceiptV2) (codec.Hash, error) {
	return digestOf(InferReceiptSigningPreimage(receipt))
}

// VerifyCommitSigningPreimage returns the frozen verifier commit preimage:
//
//	H_FIELDS_V1("TRUEOPEN_COMMIT_V1",
//	  schema_version, chain_id, task_id, verify_round,
//	  verifier_operator_address, service_authorization_nonce,
//	  commit_hash, expiry_height)
//
// Eight fields; service_signature is excluded. verify_round is uint32_be, never
// decimal text. commit_hash must be the canonical result-commitment value, and
// the 32-byte check here is the structural half of the rule that forbids a
// non-empty placeholder.
func VerifyCommitSigningPreimage(commit VerifyCommitV1) ([]byte, error) {
	chainID, err := canonicalUTF8Field("chain_id", commit.ChainID)
	if err != nil {
		return nil, err
	}
	taskID, err := canonicalHash32("task_id", commit.TaskID)
	if err != nil {
		return nil, err
	}
	verifier, err := CanonicalOperatorAddressBytes("verifier_operator_address", commit.VerifierOperatorAddress)
	if err != nil {
		return nil, err
	}
	commitHash, err := canonicalHash32("commit_hash", commit.CommitHash)
	if err != nil {
		return nil, err
	}
	return hfields.Preimage(
		DomainVerifyCommitV1,
		hfields.Uint32(commit.SchemaVersion),
		hfields.String(chainID),
		hfields.Bytes(taskID),
		hfields.Uint32(commit.VerifyRound),
		hfields.Bytes(verifier),
		hfields.Uint64(commit.ServiceAuthorizationNonce),
		hfields.Bytes(commitHash),
		hfields.Uint64(commit.ExpiryHeight),
	)
}

// VerifyCommitSigningDigest is the frozen verifier commit digest.
func VerifyCommitSigningDigest(commit VerifyCommitV1) (codec.Hash, error) {
	return digestOf(VerifyCommitSigningPreimage(commit))
}

// WorkerHandraiseSigningPreimage returns the frozen worker handraise preimage
// with its ten fields in order:
//
//	schema_version, chain_id, task_id, task_hash, model_id, profile_version,
//	member, duty, service_authorization_nonce, expiry_height
//
// member is a required nested message and is framed recursively; duty is framed
// as uint32_be. duty = WORKER for this wire is an admission check and is left to
// the handler so the derivation stays total, exactly as for schema_version.
func WorkerHandraiseSigningPreimage(handraise WorkerHandraiseV1) ([]byte, error) {
	chainID, err := canonicalUTF8Field("chain_id", handraise.ChainID)
	if err != nil {
		return nil, err
	}
	taskID, err := canonicalHash32("task_id", handraise.TaskID)
	if err != nil {
		return nil, err
	}
	taskHash, err := canonicalHash32("task_hash", handraise.TaskHash)
	if err != nil {
		return nil, err
	}
	modelID, err := canonicalUTF8Field("model_id", handraise.ModelID)
	if err != nil {
		return nil, err
	}
	member, err := candidateMemberRefFrame(handraise.Member)
	if err != nil {
		return nil, err
	}
	duty, err := canonicalDuty(handraise.Duty)
	if err != nil {
		return nil, err
	}
	return hfields.Preimage(
		DomainWorkerHandraiseV1,
		hfields.Uint32(handraise.SchemaVersion),
		hfields.String(chainID),
		hfields.Bytes(taskID),
		hfields.Bytes(taskHash),
		hfields.String(modelID),
		hfields.Uint32(handraise.ProfileVersion),
		member,
		hfields.Uint32(duty),
		hfields.Uint64(handraise.ServiceAuthorizationNonce),
		hfields.Uint64(handraise.ExpiryHeight),
	)
}

// WorkerHandraiseSigningDigest is the frozen worker handraise digest.
func WorkerHandraiseSigningDigest(handraise WorkerHandraiseV1) (codec.Hash, error) {
	return digestOf(WorkerHandraiseSigningPreimage(handraise))
}

// VerifierHandraiseSigningPreimage returns the frozen verifier handraise
// preimage with its twelve fields in order:
//
//	schema_version, chain_id, task_id, verify_round, infer_receipt_hash,
//	output_hash, model_id, profile_version, member, duty,
//	service_authorization_nonce, expiry_height
//
// Same framing rules as the worker handraise; duty = VERIFIER for this wire is
// likewise an admission check.
func VerifierHandraiseSigningPreimage(handraise VerifierHandraiseV1) ([]byte, error) {
	chainID, err := canonicalUTF8Field("chain_id", handraise.ChainID)
	if err != nil {
		return nil, err
	}
	taskID, err := canonicalHash32("task_id", handraise.TaskID)
	if err != nil {
		return nil, err
	}
	inferReceiptHash, err := canonicalHash32("infer_receipt_hash", handraise.InferReceiptHash)
	if err != nil {
		return nil, err
	}
	outputHash, err := canonicalHash32("output_hash", handraise.OutputHash)
	if err != nil {
		return nil, err
	}
	modelID, err := canonicalUTF8Field("model_id", handraise.ModelID)
	if err != nil {
		return nil, err
	}
	member, err := candidateMemberRefFrame(handraise.Member)
	if err != nil {
		return nil, err
	}
	duty, err := canonicalDuty(handraise.Duty)
	if err != nil {
		return nil, err
	}
	return hfields.Preimage(
		DomainVerifierHandraiseV1,
		hfields.Uint32(handraise.SchemaVersion),
		hfields.String(chainID),
		hfields.Bytes(taskID),
		hfields.Uint32(handraise.VerifyRound),
		hfields.Bytes(inferReceiptHash),
		hfields.Bytes(outputHash),
		hfields.String(modelID),
		hfields.Uint32(handraise.ProfileVersion),
		member,
		hfields.Uint32(duty),
		hfields.Uint64(handraise.ServiceAuthorizationNonce),
		hfields.Uint64(handraise.ExpiryHeight),
	)
}

// VerifierHandraiseSigningDigest is the frozen verifier handraise digest.
func VerifierHandraiseSigningDigest(handraise VerifierHandraiseV1) (codec.Hash, error) {
	return digestOf(VerifierHandraiseSigningPreimage(handraise))
}

// SettlementBillLeafPreimage returns the frozen settlement bill leaf preimage:
//
//	H_FIELDS_V1("TRUEOPEN_SETTLEMENT_BILL_LEAF_V1",
//	  worker_operator_address, infer_receipt_ref, fee_rule_version,
//	  generated_token_count, work_unit)
//
// The five fields carry no schema_version: the leaf is a structure-only freeze
// and is not one of the schema-versioned stage wires.
func SettlementBillLeafPreimage(leaf TaskSettlementBillLeafV1) ([]byte, error) {
	worker, err := CanonicalOperatorAddressBytes("worker_operator_address", leaf.WorkerOperatorAddress)
	if err != nil {
		return nil, err
	}
	inferReceiptRef, err := canonicalHash32("infer_receipt_ref", leaf.InferReceiptRef)
	if err != nil {
		return nil, err
	}
	return hfields.Preimage(
		DomainSettlementBillLeafV1,
		hfields.Bytes(worker),
		hfields.Bytes(inferReceiptRef),
		hfields.Uint64(leaf.FeeRuleVersion),
		hfields.Uint64(leaf.GeneratedTokenCount),
		hfields.Uint64(leaf.WorkUnit),
	)
}

// SettlementBillLeafHash is the 32-byte leaf_hash handed to the single task
// evidence Merkle leaf rule. Nothing may write it on chain yet.
func SettlementBillLeafHash(leaf TaskSettlementBillLeafV1) (codec.Hash, error) {
	return digestOf(SettlementBillLeafPreimage(leaf))
}

// candidateMemberRefFrame encodes the required nested member
// reference as a FieldFrameV1 with no domain prefix and its four fields in
// ascending schema field-number order:
//
//	u64_be(32) || candidate_pool_snapshot_id
//	u64_be(4)  || uint32_be(slot)
//	u64_be(8)  || uint64_be(slot_version)
//	u64_be(n)  || operator_address codec bytes
func candidateMemberRefFrame(member CandidateMemberRefV1) (hfields.Field, error) {
	snapshotID, err := canonicalHash32("member.candidate_pool_snapshot_id", member.CandidatePoolSnapshotID)
	if err != nil {
		return hfields.Field{}, err
	}
	operator, err := CanonicalOperatorAddressBytes("member.operator_address", member.OperatorAddress)
	if err != nil {
		return hfields.Field{}, err
	}
	return hfields.Frame(
		hfields.Bytes(snapshotID),
		hfields.Uint32(member.Slot),
		hfields.Uint64(member.SlotVersion),
		hfields.Bytes(operator),
	), nil
}

// digestOf hashes an already-built preimage. Every digest in this package is
// SHA-256 over the exact bytes its preimage function returns, so the two can
// never drift apart.
func digestOf(preimage []byte, err error) (codec.Hash, error) {
	if err != nil {
		return codec.Hash{}, err
	}
	return codec.HashBytes(preimage), nil
}

// canonicalEvidenceKind rejects the unspecified and unknown enum values the
// frozen framing requires to be rejected rather than framed.
func canonicalEvidenceKind(kind EvidenceKind) (uint32, error) {
	switch kind {
	case EvidenceKindWorkerValueOpening, EvidenceKindVerifierValueOpening, EvidenceKindSettlementRootOpening:
		return uint32(kind), nil
	case EvidenceKindUnspecified:
		return 0, fmt.Errorf("evidence_kind must not be EVIDENCE_KIND_UNSPECIFIED")
	default:
		return 0, fmt.Errorf("evidence_kind %d is not a registered EvidenceKind value", int32(kind))
	}
}

// canonicalDuty rejects the unspecified and unknown Duty values. It does not
// enforce which live duty belongs to which wire.
func canonicalDuty(duty Duty) (uint32, error) {
	switch duty {
	case DutyWorker, DutyVerifier:
		return uint32(duty), nil
	case DutyUnspecified:
		return 0, fmt.Errorf("duty must not be DUTY_UNSPECIFIED")
	default:
		return 0, fmt.Errorf("duty %d is not a registered Duty value", int32(duty))
	}
}

// canonicalHash32 enforces the Hash32 shape: inside a consensus preimage a
// Hash32 is raw 32 bytes, never hex text and never a shorter placeholder.
func canonicalHash32(field string, value []byte) ([]byte, error) {
	if len(value) != sha256.Size {
		return nil, fmt.Errorf("%s must be exactly %d raw bytes, got %d", field, sha256.Size, len(value))
	}
	return value, nil
}

// canonicalUTF8Field applies the string rule: validate strict UTF-8, then frame
// the bytes as they are. No trimming, no case folding, no normalisation - the
// bytes the caller signed are the bytes that are framed. The check is explicit
// rather than left to hfields.String so the error names the field.
func canonicalUTF8Field(field, value string) (string, error) {
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("%s must be strict UTF-8", field)
	}
	return value, nil
}
