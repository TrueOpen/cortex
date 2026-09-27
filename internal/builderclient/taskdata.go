package builderclient

import (
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// DataKind is the released TaskDataObjectKind closed set.
type DataKind uint32

const (
	DataKindInput DataKind = iota + 1
	DataKindOutput
	DataKindEvidenceManifest
	DataKindEvidenceArtifact
)

func (kind DataKind) String() string {
	switch kind {
	case DataKindInput:
		return "INPUT"
	case DataKindOutput:
		return "OUTPUT"
	case DataKindEvidenceManifest:
		return "EVIDENCE_MANIFEST"
	case DataKindEvidenceArtifact:
		return "EVIDENCE_ARTIFACT"
	default:
		return ""
	}
}

type EvidenceProducerKind uint32

const (
	EvidenceProducerUnspecified EvidenceProducerKind = iota
	EvidenceProducerWorker
	EvidenceProducerVerifier
)

type TaskDataRequesterKind uint32

const TaskDataRequesterCortexService TaskDataRequesterKind = 2

// Artifact names belong to manifest entries, never to transport object refs.
const (
	EvidenceArtifactInputTokenIDs     = "input_token_ids"
	EvidenceArtifactGeneratedTokenIDs = "generated_token_ids"
	EvidenceArtifactWorkerValues      = "worker_values"
	EvidenceArtifactGenerationParams  = "generation_params"
	EvidenceArtifactAggregateProof    = "aggregate_proof"
)

// TaskDataKey is the complete TaskDataObjectRefV1. Empty ProducerOperator means
// absent; non-evidence objects must carry an absent producer, zero round and
// EVIDENCE_KIND_UNSPECIFIED. EvidenceKind names which bundle an evidence
// object belongs to: a Worker round has two, the A-level token bundle and the
// B-level value bundle.
type TaskDataKey struct {
	TaskHash             string
	SessionID            string
	TaskID               string
	Kind                 DataKind
	ContentHash          string
	EvidenceProducerKind EvidenceProducerKind
	VerifyRound          uint32
	ProducerOperator     string
	EvidenceKind         nodewire.EvidenceKind
}

// EvidenceObjectKey addresses manifest or artifact bytes within a producer's
// bundle. The content hash distinguishes artifacts; their IDs stay in manifests.
func EvidenceObjectKey(taskHash, sessionID, taskID string, kind DataKind, contentHash string, producer EvidenceProducerKind, round uint32, operator string, evidenceKind nodewire.EvidenceKind) TaskDataKey {
	return TaskDataKey{TaskHash: taskHash, SessionID: sessionID, TaskID: taskID, Kind: kind, ContentHash: contentHash, EvidenceProducerKind: producer, VerifyRound: round, ProducerOperator: operator, EvidenceKind: evidenceKind}
}

// TaskDataRequestAuth is the eleven-field CORTEX_SERVICE authentication wire.
// Method is the full "/nexus.v1.IngressAPI/<Method>" procedure.
type TaskDataRequestAuth struct {
	SchemaVersion             uint32
	ChainID                   string
	BuilderAddress            string
	Method                    string
	BodyDigest                codec.Hash
	RequesterKind             TaskDataRequesterKind
	Requester                 string
	ServiceAuthorizationNonce uint64
	RequestNonce              []byte
	ExpiresAtHeight           uint64
	Signature                 []byte
}

// TaskDataRange is present only for a bounded fetch; nil authorizes a full read.
type TaskDataRange struct {
	Offset uint64
	Length uint64
}

// SignedInferReceipt carries the task.v1.InferReceiptV3 facts. Its four
// ADR-0024 key slots are not carried: only PLAINTEXT is accepted, so they are
// ZERO32 by rule, written on conversion and refused if a peer sends otherwise.
// Cortex uses canonical lowercase hex for its hash and signature fields;
// protobuf conversion decodes them into the released raw byte fields.
//
// There is no infer_receipt_hash field. §5.14 writes infer_receipt_hash and
// infer_receipt_signing_digest as the same value, so it is derived by
// InferReceiptSigningDigest and never carried as a self-asserted copy.
type SignedInferReceipt struct {
	SchemaVersion               uint32
	ChainID                     string
	TaskID                      string
	TaskHash                    string
	WorkerOperatorAddress       string
	ServiceAuthorizationNonce   uint64
	GenerationParamsDigest      string
	OutputHash                  string
	OutputSizeBytes             uint64
	OutputLeafCount             uint64
	GeneratedTokenCount         uint64
	RequiredEvidenceCommitments []EvidenceCommitment
	ExpiryHeight                uint64
	ServiceSignature            string
}

// EvidenceCommitment is one frozen required_evidence_commitments[] element.
// EvidenceHashOrRoot is the raw Hash32 the proto carries as bytes, not hex
// text; the list is strictly ascending by EvidenceKind with unique kinds.
type EvidenceCommitment struct {
	EvidenceKind       nodewire.EvidenceKind
	EvidenceHashOrRoot codec.Hash
	EncodedSizeBytes   uint64
}
