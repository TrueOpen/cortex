package builderclient

// The wire v0.3.0 task-data plane (TrueOpen/wire#14, task/task_data_auth_v1.json
// and task/builder_confirmation_v1.json). TaskDataObjectRefV1 gains a ninth
// field, evidence_kind, because a Worker round now has two evidence bundles;
// the five body domains and the storage confirmation move to _V2 with it.
// Added beside the V1 derivations; nothing calls them yet.
//
// The evidence kind is passed beside TaskDataKey rather than added to it, so
// the V1 derivations and their callers stay untouched until the upgrade.

import (
	"fmt"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

const storageConfirmationDomainV2 = "TRUEOPEN_BUILDER_STORAGE_CONFIRMATION_V2"

// taskDataObjectFrameV2 is the nine-field object ref: the V1 projection plus
// evidence_kind. INPUT and OUTPUT carry UNSPECIFIED; a Worker bundle carries
// its A-level or B-level kind; a Verifier bundle carries VERIFIER_VALUE_OPENING.
func taskDataObjectFrameV2(key TaskDataKey, kind nodewire.EvidenceKind) (hfields.Field, error) {
	if err := ValidateTaskDataKey(key); err != nil {
		return hfields.Field{}, err
	}
	var hashes [4][]byte
	for i, value := range []string{key.TaskHash, key.SessionID, key.TaskID, key.ContentHash} {
		hashes[i], _ = decodeCanonicalTaskDataHash(value)
	}
	evidence := key.Kind == DataKindEvidenceManifest || key.Kind == DataKindEvidenceArtifact
	var operator []byte
	switch {
	case !evidence:
		if kind != nodewire.EvidenceKindUnspecified {
			return hfields.Field{}, fmt.Errorf("non-evidence object must use EVIDENCE_KIND_UNSPECIFIED")
		}
	case key.EvidenceProducerKind == EvidenceProducerWorker:
		if kind != nodewire.EvidenceKindWorkerValueOpening && kind != nodewire.EvidenceKindWorkerTokenOpening {
			return hfields.Field{}, fmt.Errorf("Worker evidence must be WORKER_VALUE_OPENING or WORKER_TOKEN_OPENING")
		}
	default:
		if kind != nodewire.EvidenceKindVerifierValueOpening {
			return hfields.Field{}, fmt.Errorf("Verifier evidence must be VERIFIER_VALUE_OPENING")
		}
	}
	if evidence {
		operator, _ = nodewire.CanonicalOperatorAddressBytes("producer_operator", key.ProducerOperator)
	}
	return hfields.Frame(
		hfields.Bytes(hashes[0]), hfields.Bytes(hashes[1]), hfields.Bytes(hashes[2]), hfields.Uint32(uint32(key.Kind)),
		hfields.Bytes(hashes[3]), hfields.Uint32(uint32(key.EvidenceProducerKind)), hfields.Uint32(key.VerifyRound),
		hfields.Optional(evidence, hfields.Bytes(operator)), hfields.Uint32(uint32(kind)),
	), nil
}

func TaskDataMetadataBodyDigestV2(key TaskDataKey, kind nodewire.EvidenceKind) (codec.Hash, error) {
	frame, err := taskDataObjectFrameV2(key, kind)
	if err != nil {
		return codec.Hash{}, err
	}
	return hfields.Digest("TRUEOPEN_TASK_DATA_METADATA_BODY_V2", frame)
}

func TaskDataFetchBodyDigestV2(key TaskDataKey, kind nodewire.EvidenceKind, bounds *TaskDataRange) (codec.Hash, error) {
	frame, err := taskDataObjectFrameV2(key, kind)
	if err != nil {
		return codec.Hash{}, err
	}
	var offset, length uint64
	if bounds != nil {
		offset, length = bounds.Offset, bounds.Length
		if length == 0 || offset > ^uint64(0)-length {
			return codec.Hash{}, fmt.Errorf("task data range is empty or overflows")
		}
	}
	return hfields.Digest("TRUEOPEN_TASK_DATA_FETCH_BODY_V2", frame, hfields.Optional(bounds != nil, hfields.Frame(hfields.Uint64(offset), hfields.Uint64(length))))
}

// TaskDataUploadBodyDigestV2 applies the V1 upload rules (no INPUT upload,
// no media type on artifacts, canonical media type) to the V2 object ref.
func TaskDataUploadBodyDigestV2(key TaskDataKey, kind nodewire.EvidenceKind, size uint64, mediaType string) (codec.Hash, error) {
	if _, err := TaskDataUploadBodyDigest(key, size, mediaType); err != nil {
		return codec.Hash{}, err
	}
	frame, err := taskDataObjectFrameV2(key, kind)
	if err != nil {
		return codec.Hash{}, err
	}
	return hfields.Digest("TRUEOPEN_TASK_DATA_UPLOAD_BODY_V2", frame, hfields.Uint64(size), hfields.String(mediaType))
}

// TaskDataFinalizeResultBodyDigestV2 finalizes one Worker bundle, so the body
// authenticates which of the two kinds it closes.
func TaskDataFinalizeResultBodyDigestV2(taskHash, sessionID, taskID string, receiptDigest, signatureDigest codec.Hash, kind nodewire.EvidenceKind) (codec.Hash, error) {
	if kind != nodewire.EvidenceKindWorkerValueOpening && kind != nodewire.EvidenceKindWorkerTokenOpening {
		return codec.Hash{}, fmt.Errorf("a result finalize must name one Worker evidence kind")
	}
	scope, err := finalizeScope(taskHash, sessionID, taskID)
	if err != nil {
		return codec.Hash{}, err
	}
	return hfields.Digest("TRUEOPEN_TASK_DATA_FINALIZE_RESULT_BODY_V2",
		append(scope, hfields.Hash(receiptDigest), hfields.Hash(signatureDigest), hfields.Uint32(uint32(kind)))...)
}

// TaskDataFinalizeVerifierBodyDigestV2 keeps the V1 field list under the V2
// domain.
func TaskDataFinalizeVerifierBodyDigestV2(taskHash, sessionID, taskID string, round uint32, verifierOperator string, receiptDigest, signatureDigest codec.Hash) (codec.Hash, error) {
	scope, err := finalizeScope(taskHash, sessionID, taskID)
	if err != nil {
		return codec.Hash{}, err
	}
	operator, err := nodewire.CanonicalOperatorAddressBytes("verifier_operator", verifierOperator)
	if err != nil {
		return codec.Hash{}, err
	}
	return hfields.Digest("TRUEOPEN_TASK_DATA_FINALIZE_VERIFIER_BODY_V2",
		append(scope, hfields.Uint32(round), hfields.Bytes(operator), hfields.Hash(receiptDigest), hfields.Hash(signatureDigest))...)
}

// StorageConfirmationSigningHashV2 applies the V1 confirmation rules to the
// nine-field object ref.
func StorageConfirmationSigningHashV2(c StorageConfirmation, kind nodewire.EvidenceKind) (codec.Hash, error) {
	if _, err := StorageConfirmationSigningHash(c); err != nil {
		return codec.Hash{}, err
	}
	frame, err := taskDataObjectFrameV2(c.Key, kind)
	if err != nil {
		return codec.Hash{}, err
	}
	operator, _ := nodewire.CanonicalOperatorAddressBytes("builder_operator_address", c.BuilderOperator)
	return hfields.Digest(storageConfirmationDomainV2, hfields.Uint32(c.SchemaVersion), hfields.String(c.ChainID), hfields.Bytes(operator),
		hfields.Uint64(c.ServiceAuthorizationNonce), frame, hfields.Uint64(c.SizeBytes), hfields.Uint64(c.ArtifactTotalSizeBytes), hfields.Uint64(c.RetentionUntilHeight))
}
