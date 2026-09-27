package builderclient

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	taskDataCompactSignatureLen = 64
	storageConfirmationDomain   = "TRUEOPEN_BUILDER_STORAGE_CONFIRMATION_V2"
	taskDataProcedurePrefix     = "/nexus.v1.IngressAPI/"
)

// TaskDataProcedure returns the exact signed RPC procedure.
func TaskDataProcedure(method string) string {
	if strings.HasPrefix(method, taskDataProcedurePrefix) {
		return method
	}
	return taskDataProcedurePrefix + method
}

func validTaskDataMethod(method string) bool {
	switch method {
	case TaskDataProcedure("UploadTaskResultObject"), TaskDataProcedure("GetTaskDataMetadata"),
		TaskDataProcedure("FetchTaskData"), TaskDataProcedure("FinalizeTaskResult"), TaskDataProcedure("FinalizeVerifierEvidence"), TaskDataProcedure("UploadTaskOutputStream"):
		return true
	default:
		return false
	}
}

func taskDataHash(field, value string) ([]byte, error) {
	raw, ok := decodeCanonicalTaskDataHash(value)
	if !ok || isZeroTaskDataHash(value) {
		return nil, fmt.Errorf("%s must be canonical nonzero Hash32", field)
	}
	return raw, nil
}

// ValidateTaskDataKey enforces the released object-ref projection.
func ValidateTaskDataKey(key TaskDataKey) error {
	_, err := taskDataObjectFrame(key)
	return err
}

// taskDataObjectFrame is the nine-field TaskDataObjectRefV1 of wire v0.3.0.
// INPUT and OUTPUT carry EVIDENCE_KIND_UNSPECIFIED; a Worker bundle carries
// its A-level or B-level kind; a Verifier bundle carries VERIFIER_VALUE_OPENING.
func taskDataObjectFrame(key TaskDataKey) (hfields.Field, error) {
	var hashes [4][]byte
	for i, f := range []struct{ name, value string }{{"task_hash", key.TaskHash}, {"session_id", key.SessionID}, {"task_id", key.TaskID}, {"content_hash", key.ContentHash}} {
		raw, err := taskDataHash(f.name, f.value)
		if err != nil {
			return hfields.Field{}, err
		}
		hashes[i] = raw
	}
	if key.Kind.String() == "" {
		return hfields.Field{}, fmt.Errorf("task data object kind is invalid")
	}
	evidence := key.Kind == DataKindEvidenceManifest || key.Kind == DataKindEvidenceArtifact
	var operator []byte
	if evidence {
		if key.EvidenceProducerKind != EvidenceProducerWorker && key.EvidenceProducerKind != EvidenceProducerVerifier {
			return hfields.Field{}, fmt.Errorf("evidence producer kind is required")
		}
		if key.VerifyRound == 0 || key.VerifyRound > 2 || (key.EvidenceProducerKind == EvidenceProducerWorker && key.VerifyRound != 1) {
			return hfields.Field{}, fmt.Errorf("evidence verify round does not match producer")
		}
		switch key.EvidenceProducerKind {
		case EvidenceProducerWorker:
			if key.EvidenceKind != nodewire.EvidenceKindWorkerValueOpening && key.EvidenceKind != nodewire.EvidenceKindWorkerTokenOpening {
				return hfields.Field{}, fmt.Errorf("Worker evidence must be WORKER_VALUE_OPENING or WORKER_TOKEN_OPENING")
			}
		default:
			if key.EvidenceKind != nodewire.EvidenceKindVerifierValueOpening {
				return hfields.Field{}, fmt.Errorf("Verifier evidence must be VERIFIER_VALUE_OPENING")
			}
		}
		var err error
		operator, err = nodewire.CanonicalOperatorAddressBytes("producer_operator", key.ProducerOperator)
		if err != nil {
			return hfields.Field{}, err
		}
	} else if key.EvidenceProducerKind != EvidenceProducerUnspecified || key.VerifyRound != 0 || key.ProducerOperator != "" || key.EvidenceKind != nodewire.EvidenceKindUnspecified {
		return hfields.Field{}, fmt.Errorf("non-evidence object must omit producer, verify round and evidence kind")
	}
	return hfields.Frame(
		hfields.Bytes(hashes[0]), hfields.Bytes(hashes[1]), hfields.Bytes(hashes[2]), hfields.Uint32(uint32(key.Kind)),
		hfields.Bytes(hashes[3]), hfields.Uint32(uint32(key.EvidenceProducerKind)), hfields.Uint32(key.VerifyRound),
		hfields.Optional(evidence, hfields.Bytes(operator)), hfields.Uint32(uint32(key.EvidenceKind)),
	), nil
}

func TaskDataRequestSigningHash(auth TaskDataRequestAuth) (codec.Hash, error) {
	if auth.SchemaVersion != 1 || auth.RequesterKind != TaskDataRequesterCortexService {
		return codec.Hash{}, fmt.Errorf("task data authentication requires schema 1 and CORTEX_SERVICE")
	}
	if !canonicalTaskDataText(auth.ChainID) || !validTaskDataMethod(auth.Method) {
		return codec.Hash{}, fmt.Errorf("task data authentication chain or RPC method is invalid")
	}
	if auth.BodyDigest.IsZero() || auth.ServiceAuthorizationNonce == 0 || auth.ExpiresAtHeight == 0 || len(auth.RequestNonce) != 32 {
		return codec.Hash{}, fmt.Errorf("task data authentication requires body digest, current service nonce, 32-byte request nonce and expiry")
	}
	builder, err := nodewire.CanonicalOperatorAddressBytes("builder_operator_address", auth.BuilderAddress)
	if err != nil {
		return codec.Hash{}, err
	}
	requester, err := nodewire.CanonicalOperatorAddressBytes("requester_address", auth.Requester)
	if err != nil {
		return codec.Hash{}, err
	}
	return hfields.Digest("TRUEOPEN_TASK_DATA_REQUEST_V1", hfields.Uint32(auth.SchemaVersion), hfields.String(auth.ChainID), hfields.Bytes(builder), hfields.String(auth.Method), hfields.Hash(auth.BodyDigest), hfields.Uint32(uint32(auth.RequesterKind)), hfields.Bytes(requester), hfields.Uint64(auth.ServiceAuthorizationNonce), hfields.Bytes(auth.RequestNonce), hfields.Uint64(auth.ExpiresAtHeight))
}

func TaskDataMetadataBodyDigest(key TaskDataKey) (codec.Hash, error) {
	frame, err := taskDataObjectFrame(key)
	if err != nil {
		return codec.Hash{}, err
	}
	return hfields.Digest("TRUEOPEN_TASK_DATA_METADATA_BODY_V2", frame)
}

func TaskDataFetchBodyDigest(key TaskDataKey, bounds *TaskDataRange) (codec.Hash, error) {
	frame, err := taskDataObjectFrame(key)
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

func TaskDataUploadBodyDigest(key TaskDataKey, size uint64, mediaType string) (codec.Hash, error) {
	if key.Kind == DataKindInput {
		return codec.Hash{}, fmt.Errorf("INPUT uploads require OpenTask")
	}
	frame, err := taskDataObjectFrame(key)
	if err != nil {
		return codec.Hash{}, err
	}
	if key.Kind == DataKindEvidenceArtifact && mediaType != "" {
		return codec.Hash{}, fmt.Errorf("evidence artifacts must omit media_type")
	}
	if strings.TrimSpace(mediaType) != mediaType || strings.ContainsRune(mediaType, '\x00') {
		return codec.Hash{}, fmt.Errorf("media_type is not canonical")
	}
	return hfields.Digest("TRUEOPEN_TASK_DATA_UPLOAD_BODY_V2", frame, hfields.Uint64(size), hfields.String(mediaType))
}

func finalizeScope(taskHash, sessionID, taskID string) ([]hfields.Field, error) {
	out := make([]hfields.Field, 0, 3)
	for _, f := range []struct{ name, value string }{{"task_hash", taskHash}, {"session_id", sessionID}, {"task_id", taskID}} {
		raw, err := taskDataHash(f.name, f.value)
		if err != nil {
			return nil, err
		}
		out = append(out, hfields.Bytes(raw))
	}
	return out, nil
}

func TaskDataFinalizeResultBodyDigest(request FinalizeTaskResultRequest) (codec.Hash, error) {
	fields, err := finalizeScope(request.TaskHash, request.SessionID, request.TaskID)
	if err != nil {
		return codec.Hash{}, err
	}
	if request.Receipt.TaskHash != request.TaskHash || request.Receipt.TaskID != request.TaskID {
		return codec.Hash{}, fmt.Errorf("finalize receipt task identity mismatch")
	}
	if request.EvidenceKind != nodewire.EvidenceKindWorkerValueOpening && request.EvidenceKind != nodewire.EvidenceKindWorkerTokenOpening {
		return codec.Hash{}, fmt.Errorf("a result finalize must name one Worker evidence kind")
	}
	if err := validateSignedInferReceipt(request.Receipt); err != nil {
		return codec.Hash{}, err
	}
	digest, err := InferReceiptSigningDigest(request.Receipt)
	if err != nil {
		return codec.Hash{}, err
	}
	signature, _ := hex.DecodeString(request.Receipt.ServiceSignature)
	signatureDigest := codec.HashBytes(signature)
	return taskDataFinalizeResultDigest(fields, digest, signatureDigest, request.EvidenceKind)
}

// taskDataFinalizeResultDigest finalizes one Worker bundle, so the body
// authenticates which of the two kinds it closes.
func taskDataFinalizeResultDigest(scope []hfields.Field, receiptDigest, signatureDigest codec.Hash, kind nodewire.EvidenceKind) (codec.Hash, error) {
	return hfields.Digest("TRUEOPEN_TASK_DATA_FINALIZE_RESULT_BODY_V2", append(scope, hfields.Hash(receiptDigest), hfields.Hash(signatureDigest), hfields.Uint32(uint32(kind)))...)
}

func TaskDataFinalizeVerifierBodyDigest(request FinalizeVerifierEvidenceRequest) (codec.Hash, error) {
	fields, err := finalizeScope(request.TaskHash, request.SessionID, request.TaskID)
	if err != nil {
		return codec.Hash{}, err
	}
	if hex.EncodeToString(request.Receipt.TaskID) != request.TaskID || request.Receipt.VerifyRound != request.VerifyRound || request.Receipt.VerifierOperatorAddress != request.VerifierOperator {
		return codec.Hash{}, fmt.Errorf("finalize verifier receipt scope mismatch")
	}
	if err := validateCompactSignature(request.Receipt.ServiceSignature); err != nil {
		return codec.Hash{}, err
	}
	operator, err := nodewire.CanonicalOperatorAddressBytes("verifier_operator", request.VerifierOperator)
	if err != nil {
		return codec.Hash{}, err
	}
	digest, err := nodewire.ResultReceiptSigningDigest(request.Receipt)
	if err != nil {
		return codec.Hash{}, err
	}
	return taskDataFinalizeVerifierDigest(fields, request.VerifyRound, operator, digest, codec.HashBytes(request.Receipt.ServiceSignature))
}

func taskDataFinalizeVerifierDigest(scope []hfields.Field, round uint32, operator []byte, receiptDigest, signatureDigest codec.Hash) (codec.Hash, error) {
	return hfields.Digest("TRUEOPEN_TASK_DATA_FINALIZE_VERIFIER_BODY_V2", append(scope, hfields.Uint32(round), hfields.Bytes(operator), hfields.Hash(receiptDigest), hfields.Hash(signatureDigest))...)
}

func StorageConfirmationSigningHash(c StorageConfirmation) (codec.Hash, error) {
	if c.SchemaVersion != 1 || !canonicalTaskDataText(c.ChainID) || c.ServiceAuthorizationNonce == 0 || c.RetentionUntilHeight == 0 {
		return codec.Hash{}, fmt.Errorf("storage confirmation identity is incomplete")
	}
	if c.Key.Kind == DataKindEvidenceArtifact {
		return codec.Hash{}, fmt.Errorf("artifacts cannot carry storage confirmations")
	}
	if c.Key.Kind != DataKindEvidenceManifest && c.ArtifactTotalSizeBytes != 0 {
		return codec.Hash{}, fmt.Errorf("non-bundle confirmation must have zero artifact total")
	}
	frame, err := taskDataObjectFrame(c.Key)
	if err != nil {
		return codec.Hash{}, err
	}
	operator, err := nodewire.CanonicalOperatorAddressBytes("builder_operator_address", c.BuilderOperator)
	if err != nil {
		return codec.Hash{}, err
	}
	return hfields.Digest(storageConfirmationDomain, hfields.Uint32(c.SchemaVersion), hfields.String(c.ChainID), hfields.Bytes(operator), hfields.Uint64(c.ServiceAuthorizationNonce), frame, hfields.Uint64(c.SizeBytes), hfields.Uint64(c.ArtifactTotalSizeBytes), hfields.Uint64(c.RetentionUntilHeight))
}

func validateCompactSignature(signature []byte) error {
	if len(signature) != 64 {
		return fmt.Errorf("service signature must be raw64")
	}
	var r, s secp256k1.ModNScalar
	if r.SetByteSlice(signature[:32]) || r.IsZero() || s.SetByteSlice(signature[32:]) || s.IsZero() || s.IsOverHalfOrder() {
		return fmt.Errorf("service signature requires nonzero canonical low-S scalars")
	}
	return nil
}

func ValidateSignedVerifyCommit(commit nodewire.VerifyCommitV1) error {
	if commit.SchemaVersion != 1 {
		return fmt.Errorf("verify commit schema_version must be 1, got %d", commit.SchemaVersion)
	}
	if !canonicalTaskDataText(commit.ChainID) || !canonicalTaskDataText(commit.VerifierOperatorAddress) {
		return fmt.Errorf("verify commit chain id and verifier operator address must be canonical text")
	}
	if len(commit.TaskID) != sha256.Size || len(commit.CommitHash) != sha256.Size {
		return fmt.Errorf("verify commit task_id and commit_hash must be 32 raw bytes")
	}
	if commit.VerifyRound == 0 || commit.ServiceAuthorizationNonce == 0 || commit.ExpiryHeight == 0 {
		return fmt.Errorf("verify commit verify_round, service_authorization_nonce, and expiry_height are required")
	}
	if len(commit.ServiceSignature) != taskDataCompactSignatureLen {
		return fmt.Errorf("verify commit service_signature must be 64 raw bytes: the frozen body was never signed")
	}
	return validateCompactSignature(commit.ServiceSignature)
}

// InferReceiptSigningDigest is the frozen §5.14 receipt digest. It is both the
// value the Worker's current service key signs and the receipt's own identity on
// chain: the contract writes infer_receipt_hash and infer_receipt_signing_digest
// as one value, so there is no second "business hash" to derive.
//
// The framing is not reimplemented here. internal/nodewire owns it, pinned
// byte-for-byte to Node's published H_FIELDS_V1 vectors; this only turns the
// wire's hex text into the typed input those derivations take.
func InferReceiptSigningDigest(receipt SignedInferReceipt) (codec.Hash, error) {
	wire, err := inferReceiptWire(receipt)
	if err != nil {
		return codec.Hash{}, err
	}
	return nodewire.InferReceiptSigningDigest(wire)
}

func inferReceiptWire(receipt SignedInferReceipt) (nodewire.InferReceiptV3, error) {
	if err := validateInferReceiptFacts(receipt); err != nil {
		return nodewire.InferReceiptV3{}, err
	}
	taskID, _ := decodeCanonicalTaskDataHash(receipt.TaskID)
	taskHash, _ := decodeCanonicalTaskDataHash(receipt.TaskHash)
	generationParamsDigest, _ := decodeCanonicalTaskDataHash(receipt.GenerationParamsDigest)
	outputHash, _ := decodeCanonicalTaskDataHash(receipt.OutputHash)
	commitments := make([]nodewire.EvidenceCommitmentV1, len(receipt.RequiredEvidenceCommitments))
	for index, commitment := range receipt.RequiredEvidenceCommitments {
		hashOrRoot := commitment.EvidenceHashOrRoot
		commitments[index] = nodewire.EvidenceCommitmentV1{
			EvidenceKind:       commitment.EvidenceKind,
			EvidenceHashOrRoot: hashOrRoot[:],
			EncodedSizeBytes:   commitment.EncodedSizeBytes,
		}
	}
	zero := make([]byte, 32)
	return nodewire.InferReceiptV3{
		SchemaVersion:               receipt.SchemaVersion,
		ChainID:                     receipt.ChainID,
		TaskID:                      taskID,
		TaskHash:                    taskHash,
		WorkerOperatorAddress:       receipt.WorkerOperatorAddress,
		ServiceAuthorizationNonce:   receipt.ServiceAuthorizationNonce,
		GenerationParamsDigest:      generationParamsDigest,
		OutputHash:                  outputHash,
		OutputSizeBytes:             receipt.OutputSizeBytes,
		OutputLeafCount:             receipt.OutputLeafCount,
		RequiredEvidenceCommitments: commitments,
		ExpiryHeight:                receipt.ExpiryHeight,
		GeneratedTokenCount:         receipt.GeneratedTokenCount,
		OutputKeyCommitment:         zero,
		WorkerTokenKeyCommitment:    zero,
		WorkerValueKeyCommitment:    zero,
		CiphertextOutputRoot:        zero,
	}, nil
}

func validateSignedInferReceipt(receipt SignedInferReceipt) error {
	if err := validateInferReceiptFacts(receipt); err != nil {
		return err
	}
	signature, ok := decodeCanonicalTaskDataSignature(receipt.ServiceSignature)
	if !ok {
		return fmt.Errorf("infer receipt service signature must be lowercase 64-byte hex")
	}
	return validateCompactSignature(signature)
}

// validateInferReceiptFacts rejects a receipt whose signed facts are not the
// frozen shape. schema_version is checked for equality rather than presence:
// nodewire keeps its derivations total on purpose, so a receipt carrying any
// other version would hash fine here and be refused by both Nexus admission and
// the Keeper handler.
func validateInferReceiptFacts(receipt SignedInferReceipt) error {
	if receipt.SchemaVersion != nodewire.InferReceiptSchemaVersionV3 {
		return fmt.Errorf("infer receipt schema_version must be %d, got %d",
			nodewire.InferReceiptSchemaVersionV3, receipt.SchemaVersion)
	}
	if !canonicalTaskDataText(receipt.ChainID) || !canonicalTaskDataText(receipt.WorkerOperatorAddress) {
		return fmt.Errorf("infer receipt chain id and worker operator address must be canonical text")
	}
	for _, field := range [...]struct{ name, value string }{
		{"task_id", receipt.TaskID},
		{"task_hash", receipt.TaskHash},
		{"generation_params_digest", receipt.GenerationParamsDigest},
		{"output_hash", receipt.OutputHash},
	} {
		if !canonicalTaskDataHash(field.value) {
			return fmt.Errorf("infer receipt %s must be lowercase 32-byte hex", field.name)
		}
	}
	// task_hash and generation_params_digest are consensus reads Cortex cannot
	// perform yet. The frozen wire gives a Hash32 no "absent" encoding, so 32
	// zero bytes is not a gap marker: it is a positive claim about
	// TaskCoreState.accepted_task_hash and
	// TaskAssignmentState.generation_params_digest, signed into a receipt the
	// Keeper can only reject. Zero is refused exactly where the empty string is,
	// which is what the evidence element check below already does for a root.
	for _, field := range [...]struct{ name, value string }{
		{"task_hash", receipt.TaskHash},
		{"generation_params_digest", receipt.GenerationParamsDigest},
	} {
		if isZeroTaskDataHash(field.value) {
			return fmt.Errorf(
				"infer receipt %s must not be 32 zero bytes: the frozen Hash32 has no absent encoding, "+
					"so zeros are a claim about consensus state rather than a missing value",
				field.name)
		}
	}
	if receipt.OutputLeafCount == 0 || receipt.ServiceAuthorizationNonce == 0 || receipt.ExpiryHeight == 0 {
		return fmt.Errorf("infer receipt output_leaf_count, service_authorization_nonce, and expiry_height are required")
	}
	if receipt.OutputSizeBytes == 0 && receipt.OutputLeafCount != 1 {
		return fmt.Errorf("empty output requires exactly one MMR leaf")
	}
	// A submittable receipt must commit at least one evidence commitment.
	// nodewire.EvidenceCommitmentsHash stays total for the empty list on purpose
	// -- Node publishes that digest so a consumer can verify its own derivation
	// -- but a receipt that signs it asserts the locked Verification Profile
	// requires no evidence at all, which no Profile does. BuildInferReceipt
	// already refuses the empty list; refusing it here too means a caller that
	// skips the constructor still cannot produce a signable or relayable receipt.
	if len(receipt.RequiredEvidenceCommitments) == 0 {
		return fmt.Errorf(
			"infer receipt required_evidence_commitments must not be empty: it has to equal the locked " +
				"Verification Profile's required EvidenceKind set, and no Profile requires the empty set")
	}
	for index, commitment := range receipt.RequiredEvidenceCommitments {
		if commitment.EvidenceKind == nodewire.EvidenceKindUnspecified {
			return fmt.Errorf("infer receipt required_evidence_commitments[%d] evidence_kind is unspecified", index)
		}
		if commitment.EvidenceHashOrRoot == (codec.Hash{}) || commitment.EncodedSizeBytes == 0 {
			return fmt.Errorf("infer receipt required_evidence_commitments[%d] is incomplete", index)
		}
		if index > 0 && receipt.RequiredEvidenceCommitments[index-1].EvidenceKind >= commitment.EvidenceKind {
			return fmt.Errorf(
				"infer receipt required_evidence_commitments must be strictly ascending by evidence_kind with unique kinds: "+
					"element %d has kind %d after kind %d",
				index, commitment.EvidenceKind, receipt.RequiredEvidenceCommitments[index-1].EvidenceKind,
			)
		}
	}
	return nil
}

func canonicalTaskDataText(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && !strings.ContainsRune(value, '\x00')
}

func canonicalTaskDataHash(value string) bool {
	_, ok := decodeCanonicalTaskDataHash(value)
	return ok
}

// isZeroTaskDataHash reports whether value is a canonical hash whose 32 bytes
// are all zero. It answers "the caller had nothing to put here" for a field the
// frozen wire always frames, so it is true only for the shape-valid all-zero
// hex; a malformed value is a different failure and is reported as such.
func isZeroTaskDataHash(value string) bool {
	decoded, ok := decodeCanonicalTaskDataHash(value)
	if !ok {
		return false
	}
	for _, b := range decoded {
		if b != 0 {
			return false
		}
	}
	return true
}

func decodeCanonicalTaskDataHash(value string) ([]byte, bool) {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return nil, false
	}
	decoded, err := hex.DecodeString(value)
	return decoded, err == nil && len(decoded) == sha256.Size
}

func decodeCanonicalTaskDataSignature(value string) ([]byte, bool) {
	if len(value) != taskDataCompactSignatureLen*2 || value != strings.ToLower(value) {
		return nil, false
	}
	decoded, err := hex.DecodeString(value)
	return decoded, err == nil && len(decoded) == taskDataCompactSignatureLen
}
