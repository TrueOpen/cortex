// Package nodewire implements the canonical signing and commitment contracts
// consumed by Cortex from wire v0.4.1. Typed field framing is shared with
// internal/hfields. Published fixture inconsistencies are recorded explicitly
// in conformance tests, with current schema formulas checked independently.
package nodewire

// Frozen H_FIELDS_V1 domain separators. Changing any literal is a breaking
// protocol change; the §1.4 registry rows live upstream, and
// TRUEOPEN_SETTLEMENT_BILL_LEAF_V1 is the ruling-32 structure-only freeze that the
// registry deliberately does not carry yet.
const (
	DomainInferEvidenceCommitmentsV1 = "TRUEOPEN_INFER_EVIDENCE_COMMITMENTS_V1"
	DomainVerifyCommitV1             = "TRUEOPEN_COMMIT_V1"
	DomainWorkerHandraiseV1          = "TRUEOPEN_WORKER_HANDRAISE_V1"
	DomainVerifierHandraiseV1        = "TRUEOPEN_VERIFIER_HANDRAISE_V1"
	DomainSettlementBillLeafV1       = "TRUEOPEN_SETTLEMENT_BILL_LEAF_V1"
)

// Each signing contract carries its own published schema version.
const (
	VerifyCommitSchemaVersionV1      uint32 = 1
	WorkerHandraiseSchemaVersionV1   uint32 = 1
	VerifierHandraiseSchemaVersionV1 uint32 = 1
)

// EvidenceKind is the closed set of evidence opening payload kinds. The numbers
// are the frozen task/v1/evidence.proto values and are what the preimage
// frames; UNSPECIFIED is never written and is rejected before hashing.
type EvidenceKind int32

const (
	EvidenceKindUnspecified           EvidenceKind = 0
	EvidenceKindWorkerValueOpening    EvidenceKind = 1
	EvidenceKindVerifierValueOpening  EvidenceKind = 2
	EvidenceKindSettlementRootOpening EvidenceKind = 3
	// EvidenceKindWorkerTokenOpening is the A-level Worker evidence: the token
	// ids a Verifier teacher-forces over.
	EvidenceKindWorkerTokenOpening EvidenceKind = 4
)

// Duty is the frozen hub/v1/common.proto duty enum. Which of the two live
// duties belongs to which handraise wire is an admission check and is not
// enforced by the derivations.
type Duty int32

const (
	DutyUnspecified Duty = 0
	DutyWorker      Duty = 1
	DutyVerifier    Duty = 2
)

// EvidenceCommitmentV1 is one worker-authored evidence commitment carried by
// InferReceiptV3. Fields are in schema field-number order, which is also the
// order the nested element frame writes them.
type EvidenceCommitmentV1 struct {
	EvidenceKind       EvidenceKind
	EvidenceHashOrRoot []byte // Hash32: exactly 32 raw bytes, never hex text
	EncodedSizeBytes   uint64
}

// VerifyCommitV1 is the frozen verifier commit wire. ServiceSignature is wire
// field 9 and is outside the preimage.
type VerifyCommitV1 struct {
	SchemaVersion             uint32
	ChainID                   string
	TaskID                    []byte // Hash32
	VerifyRound               uint32
	VerifierOperatorAddress   string
	ServiceAuthorizationNonce uint64
	CommitHash                []byte // Hash32, the canonical result commitment
	ExpiryHeight              uint64
	ServiceSignature          []byte // excluded from the preimage
}

// CandidateMemberRefV1 is the required nested member reference both handraise
// wires carry. It holds the pool snapshot id only: the snapshot id already
// commits to the pool hash, so an asserted copy is forbidden.
type CandidateMemberRefV1 struct {
	CandidatePoolSnapshotID []byte // Hash32
	Slot                    uint32
	SlotVersion             uint64
	OperatorAddress         string
}

// TaskSettlementBillLeafV1 is the structure-only frozen settlement bill leaf.
// It carries no amount: the fee rule stays with the budget state's
// fee_rule_version. Freezing the structure does not license producing the leaf
// on chain, so this exists to compute and pin the value only.
type TaskSettlementBillLeafV1 struct {
	WorkerOperatorAddress string
	InferReceiptRef       []byte // Hash32: the accepted receipt's digest
	FeeRuleVersion        uint64
	GeneratedTokenCount   uint64
	WorkUnit              uint64
}
