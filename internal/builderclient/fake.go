package builderclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"github.com/TrueOpen/cortex/internal/nodewire"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidencebundle"
)

type FakeClient struct {
	RejectPackageValidation   bool
	ValidatedPackages         []OutputPackage
	OutputPackages            map[string]OutputPackage
	TaskData                  map[TaskDataKey][]byte
	TaskDataMetadata          map[TaskDataKey]TaskDataMetadata
	UploadedTaskResults       []UploadTaskResultRequest
	UploadedOutputStreams     []OutputStreamRequest
	UploadedOutputFins        []OutputFin
	outputStreams             map[string][]OutputChunk
	SubmittedInferReceipts    []SubmitInferReceiptRequest
	SubmittedVerifyCommits    []SubmitVerifyCommitRequest
	SubmittedVerifyResults    []SubmitVerifyResultRequest
	FinalizedTaskResults      []FinalizeTaskResultRequest
	FinalizedVerifierEvidence []FinalizeVerifierEvidenceRequest
	finalizedTaskResults      map[string]FinalizeTaskResultResponse
	finalizedVerifierEvidence map[string]FinalizeVerifierEvidenceResponse
	finalizedDigests          map[string]codec.Hash
	Published                 []PublishRequest
	Events                    *[]string
}

func NewFakeClient() *FakeClient {
	return &FakeClient{
		OutputPackages:   map[string]OutputPackage{},
		TaskData:         map[TaskDataKey][]byte{},
		TaskDataMetadata: map[TaskDataKey]TaskDataMetadata{},
	}
}

func (f *FakeClient) ValidateOutputPackage(_ context.Context, pkg OutputPackage) error {
	if f.RejectPackageValidation {
		return fmt.Errorf("output package validation rejected")
	}
	if pkg.TaskID == "" || pkg.OutputRef == "" {
		return fmt.Errorf("output package missing required fields")
	}
	expected := codecPackageHash(pkg.TaskID, pkg.OutputRef, pkg.TokenIDsRef, pkg.PositionValuesRef, pkg.OutputHash)
	if pkg.SessionID != "" {
		var err error
		expected, err = CanonicalOutputPackageHash(pkg)
		if err != nil {
			return err
		}
	}
	if !bytes.Equal(pkg.PackageHash[:], expected[:]) {
		return fmt.Errorf("output package hash mismatch")
	}
	material, err := DecodeInferReceiptMaterial(pkg.ReceiptPayload)
	if err != nil {
		return err
	}
	// The same field set NexusClient.ValidateOutputPackage compares. Skipping
	// output_hash / package_hash would let "the receipt material describes a different
	// inference's package" stay green all the way through the tests while a real
	// Builder refuses it every time.
	if material.TaskID != pkg.TaskID || material.OutputRef != pkg.OutputRef ||
		material.OutputHash != pkg.OutputHash || material.PackageHash != pkg.PackageHash {
		return fmt.Errorf("receipt material does not match output package")
	}
	if material.ReceiptResultHash != pkg.ReceiptHash {
		return fmt.Errorf("receipt material hash does not match package receipt hash")
	}
	f.ValidatedPackages = append(f.ValidatedPackages, pkg)
	f.PutOutputPackageForTest(pkg.OutputRef, pkg)
	f.record("validate")
	return nil
}

// LoadOutputPackage serves the packages recorded by PutOutputPackageForTest and
// by ValidateOutputPackage, so one fake can stand in for both the Worker's
// produce side and the Verifier's output-confirmation loader.
func (f *FakeClient) LoadOutputPackage(_ context.Context, cid string, expected codec.Hash) (OutputPackage, error) {
	pkg, ok := f.OutputPackages[outputPackageKey(cid, expected)]
	if !ok {
		return OutputPackage{}, fmt.Errorf("output package %q not found", cid)
	}
	f.record("load-output-package")
	return pkg, nil
}

// PutOutputPackageForTest stores pkg under the reference a caller will present.
func (f *FakeClient) PutOutputPackageForTest(cid string, pkg OutputPackage) {
	if f.OutputPackages == nil {
		f.OutputPackages = map[string]OutputPackage{}
	}
	f.OutputPackages[outputPackageKey(cid, pkg.PackageHash)] = pkg
}

func (f *FakeClient) GetTaskDataMetadata(_ context.Context, _ string, req GetTaskDataMetadataRequest) (TaskDataMetadata, error) {
	metadata, ok := f.TaskDataMetadata[req.Key]
	if !ok {
		return TaskDataMetadata{}, fmt.Errorf("task data not found")
	}
	metadata.ChunkLengths = append([]uint32(nil), metadata.ChunkLengths...)
	if metadata.Readiness != TaskDataReady {
		metadata.ChunkLengths = nil
		metadata.OutputLeafCount = 0
	}
	if req.Key.Kind == DataKindEvidenceManifest {
		manifest, _, err := f.fakeBundle(req.Key, req.Auth.ChainID)
		if err != nil {
			return TaskDataMetadata{}, err
		}
		metadata.EvidenceBundle = &EvidenceBundleSummary{EvidenceManifestHash: evidencebundle.Hash(f.TaskData[req.Key]).String(), EvidenceSchemaHash: manifest.EvidenceSchemaHash, ArtifactCount: uint32(len(manifest.Artifacts)), ArtifactTotalSizeBytes: manifest.TotalSize(), ManifestSizeBytes: uint64(len(f.TaskData[req.Key]))}
	}
	return metadata, nil
}

func (f *FakeClient) FetchTaskData(_ context.Context, _ string, req FetchTaskDataRequest, receive func(TaskDataChunk) error) error {
	if receive == nil {
		return fmt.Errorf("fetch task data callback is required")
	}
	data, ok := f.TaskData[req.Key]
	if !ok {
		return fmt.Errorf("task data not found")
	}
	if metadata, ok := f.TaskDataMetadata[req.Key]; ok && metadata.Readiness != TaskDataReady {
		return fmt.Errorf("task data is not READY")
	}
	offset, length := uint64(0), uint64(len(data))
	if req.Range != nil {
		offset, length = req.Range.Offset, req.Range.Length
		if length == 0 {
			return fmt.Errorf("task data range is empty")
		}
	}
	if offset > uint64(len(data)) || length > uint64(len(data))-offset {
		return fmt.Errorf("task data range is invalid")
	}
	return receive(TaskDataChunk{Offset: offset, Data: append([]byte(nil), data[offset:offset+length]...), EOF: true})
}

func (f *FakeClient) UploadTaskResultObject(_ context.Context, _ string, req UploadTaskResultRequest) (TaskDataMetadata, error) {
	if _, err := validateUploadTaskResultRequest(req); err != nil {
		return TaskDataMetadata{}, err
	}
	if f.TaskData == nil {
		f.TaskData = map[TaskDataKey][]byte{}
	}
	if f.TaskDataMetadata == nil {
		f.TaskDataMetadata = map[TaskDataKey]TaskDataMetadata{}
	}
	if old, ok := f.TaskData[req.Key]; ok && !bytes.Equal(old, req.Data) {
		return TaskDataMetadata{}, fmt.Errorf("task object conflict")
	}
	metadata := TaskDataMetadata{Key: req.Key, SizeBytes: req.SizeBytes, MediaType: req.MediaType, Readiness: TaskDataStored}
	f.TaskData[req.Key] = append([]byte(nil), req.Data...)
	if existing, ok := f.TaskDataMetadata[req.Key]; !ok || existing.Readiness != TaskDataReady {
		f.TaskDataMetadata[req.Key] = metadata
	}
	f.UploadedTaskResults = append(f.UploadedTaskResults, req)
	f.record("upload_task_result_object")
	return metadata, nil
}

func (f *FakeClient) fakeConfirmation(key TaskDataKey, auth TaskDataRequestAuth) (StorageConfirmation, error) {
	metadata, ok := f.TaskDataMetadata[key]
	data, present := f.TaskData[key]
	if !ok || !present || metadata.Key != key || metadata.SizeBytes != uint64(len(data)) || metadata.Readiness != TaskDataStored && metadata.Readiness != TaskDataReady {
		return StorageConfirmation{}, fmt.Errorf("finalize object is not stored")
	}
	if key.Kind == DataKindOutput {
		var chunks [][]byte
		var offset uint64
		for _, length := range metadata.ChunkLengths {
			if uint64(length) > uint64(len(data))-offset {
				return StorageConfirmation{}, fmt.Errorf("stored output chunk boundaries exceed bytes")
			}
			chunks = append(chunks, data[offset:offset+uint64(length)])
			offset += uint64(length)
		}
		root, err := codec.OutputMMRRoot(chunks)
		if err != nil || offset != uint64(len(data)) || uint64(len(chunks)) != metadata.OutputLeafCount || root.String() != key.ContentHash {
			return StorageConfirmation{}, fmt.Errorf("stored output content MMR mismatch")
		}
	}
	confirmation := StorageConfirmation{SchemaVersion: 1, ChainID: auth.ChainID, BuilderOperator: auth.BuilderAddress, ServiceAuthorizationNonce: 1, Key: key, SizeBytes: metadata.SizeBytes, RetentionUntilHeight: auth.ExpiresAtHeight, Signature: bytes.Repeat([]byte{1}, 64)}
	if key.Kind == DataKindEvidenceManifest {
		manifest, _, err := f.fakeBundle(key, auth.ChainID)
		if err != nil {
			return StorageConfirmation{}, err
		}
		confirmation.ArtifactTotalSizeBytes = manifest.TotalSize()
	}
	return confirmation, nil
}

func (f *FakeClient) fakeBundle(key TaskDataKey, chainID string) (evidencebundle.Manifest, []TaskDataKey, error) {
	manifest, err := evidencebundle.Decode(f.TaskData[key])
	if err != nil {
		return evidencebundle.Manifest{}, nil, err
	}
	producer := EvidenceProducerWorker
	if manifest.ProducerKind == "VERIFIER" {
		producer = EvidenceProducerVerifier
	}
	if manifest.ChainID != chainID || manifest.TaskID != key.TaskID || manifest.TaskHash != key.TaskHash || manifest.ProducerOperator != key.ProducerOperator || manifest.VerifyRound != key.VerifyRound || producer != key.EvidenceProducerKind || manifest.EvidenceKind != evidencebundle.KindToken(key.EvidenceKind) || (producer != EvidenceProducerWorker && evidencebundle.Hash(f.TaskData[key]).String() != key.ContentHash) {
		return evidencebundle.Manifest{}, nil, fmt.Errorf("manifest scope does not match object")
	}
	keys := []TaskDataKey{key}
	for _, artifact := range manifest.Artifacts {
		artifactKey := key
		artifactKey.Kind = DataKindEvidenceArtifact
		artifactKey.ContentHash = artifact.ContentHash
		data, ok := f.TaskData[artifactKey]
		metadata, stored := f.TaskDataMetadata[artifactKey]
		size, err := artifact.SizeBytes()
		if !ok || !stored || metadata.Key != artifactKey || metadata.SizeBytes != uint64(len(data)) || metadata.Readiness != TaskDataStored && metadata.Readiness != TaskDataReady || err != nil || uint64(len(data)) != size || codec.HashBytes(data).String() != artifact.ContentHash {
			return evidencebundle.Manifest{}, nil, fmt.Errorf("manifest artifact %s is not stored correctly", artifact.ID)
		}
		keys = append(keys, artifactKey)
	}
	return manifest, keys, nil
}

func (f *FakeClient) fakeMarkReady(keys []TaskDataKey) {
	for _, key := range keys {
		metadata := f.TaskDataMetadata[key]
		metadata.Key = key
		metadata.SizeBytes = uint64(len(f.TaskData[key]))
		metadata.Readiness = TaskDataReady
		f.TaskDataMetadata[key] = metadata
	}
}

func (f *FakeClient) FinalizeTaskResult(_ context.Context, _ string, req FinalizeTaskResultRequest) (FinalizeTaskResultResponse, error) {
	digest, err := TaskDataFinalizeResultBodyDigest(req)
	if err != nil {
		return FinalizeTaskResultResponse{}, err
	}
	if err := validateSignedTaskDataRequest(req.Auth, "FinalizeTaskResult", digest); err != nil {
		return FinalizeTaskResultResponse{}, err
	}
	if req.Auth.Requester != req.Receipt.WorkerOperatorAddress || req.Auth.ChainID != req.Receipt.ChainID {
		return FinalizeTaskResultResponse{}, fmt.Errorf("finalize requester does not match worker receipt")
	}
	scope := fmt.Sprintf("%s|%s|worker|%s|%d", req.Auth.BuilderAddress, req.Receipt.ChainID, req.TaskHash, req.EvidenceKind)
	if previous, ok := f.finalizedDigests[scope]; ok {
		if previous != digest {
			return FinalizeTaskResultResponse{}, fmt.Errorf("finalize material conflict")
		}
		result := cloneFakeFinalization(f.finalizedTaskResults[scope])
		result.Idempotent = true
		return result, nil
	}
	key := TaskDataKey{TaskHash: req.TaskHash, SessionID: req.SessionID, TaskID: req.TaskID, Kind: DataKindOutput, ContentHash: req.Receipt.OutputHash}
	output, err := f.fakeConfirmation(key, req.Auth)
	if err != nil {
		return FinalizeTaskResultResponse{}, err
	}
	if output.SizeBytes != req.Receipt.OutputSizeBytes || f.TaskDataMetadata[key].OutputLeafCount != req.Receipt.OutputLeafCount {
		return FinalizeTaskResultResponse{}, fmt.Errorf("output size or leaf count does not match receipt")
	}
	result := FinalizeTaskResultResponse{OutputConfirmation: output, Idempotent: f.TaskDataMetadata[key].Readiness == TaskDataReady}
	keys := []TaskDataKey{key}
	var commitment *EvidenceCommitment
	for i := range req.Receipt.RequiredEvidenceCommitments {
		if req.Receipt.RequiredEvidenceCommitments[i].EvidenceKind == req.EvidenceKind {
			commitment = &req.Receipt.RequiredEvidenceCommitments[i]
		}
	}
	if commitment == nil {
		return FinalizeTaskResultResponse{}, fmt.Errorf("receipt commits no evidence of kind %d", req.EvidenceKind)
	}
	bundleKey := EvidenceObjectKey(req.TaskHash, req.SessionID, req.TaskID, DataKindEvidenceManifest, hex.EncodeToString(commitment.EvidenceHashOrRoot[:]), EvidenceProducerWorker, 1, req.Receipt.WorkerOperatorAddress, commitment.EvidenceKind)
	confirmation, err := f.fakeConfirmation(bundleKey, req.Auth)
	if err != nil {
		return FinalizeTaskResultResponse{}, err
	}
	if confirmation.ArtifactTotalSizeBytes != commitment.EncodedSizeBytes {
		return FinalizeTaskResultResponse{}, fmt.Errorf("artifact total does not match receipt")
	}
	manifest, bundleKeys, err := f.fakeBundle(bundleKey, req.Receipt.ChainID)
	if err != nil {
		return FinalizeTaskResultResponse{}, err
	}
	if err := f.fakeConfirmWorkerCommitment(req.Receipt, manifest, bundleKeys, *commitment); err != nil {
		return FinalizeTaskResultResponse{}, err
	}
	result.EvidenceBundleConfirmations = append(result.EvidenceBundleConfirmations, confirmation)
	keys = append(keys, bundleKeys...)
	f.fakeMarkReady(keys)
	metadata := f.TaskDataMetadata[key]
	receipt := req.Receipt
	metadata.SignedInferReceipt = &receipt
	f.TaskDataMetadata[key] = metadata
	if f.finalizedDigests == nil {
		f.finalizedDigests = map[string]codec.Hash{}
	}
	if f.finalizedTaskResults == nil {
		f.finalizedTaskResults = map[string]FinalizeTaskResultResponse{}
	}
	f.finalizedDigests[scope] = digest
	f.finalizedTaskResults[scope] = cloneFakeFinalization(result)
	f.FinalizedTaskResults = append(f.FinalizedTaskResults, req)
	f.record("finalize_task_result")
	return result, nil
}

// fakeConfirmWorkerCommitment re-derives the one commitment this bundle's kind
// carries from its stored artifacts, as Nexus does before confirming it.
func (f *FakeClient) fakeConfirmWorkerCommitment(receipt SignedInferReceipt, manifest evidencebundle.Manifest, keys []TaskDataKey, commitment EvidenceCommitment) error {
	artifacts := map[string][]byte{}
	for i, artifact := range manifest.Artifacts {
		artifacts[artifact.ID] = f.TaskData[keys[i+1]]
	}
	output, err := taskDataHash("output_hash", receipt.OutputHash)
	if err != nil {
		return err
	}
	facts := WorkerEvidenceFacts{
		ChainID: receipt.ChainID, TaskID: receipt.TaskID, AcceptedTaskHash: receipt.TaskHash,
		WorkerOperatorAddress: receipt.WorkerOperatorAddress, GenerationParamsDigest: receipt.GenerationParamsDigest,
		EvidenceSchemaHash: manifest.EvidenceSchemaHash, OutputSizeBytes: receipt.OutputSizeBytes,
		OutputLeafCount: receipt.OutputLeafCount, GeneratedTokenCount: receipt.GeneratedTokenCount,
	}
	copy(facts.OutputHash[:], output)
	switch commitment.EvidenceKind {
	case nodewire.EvidenceKindWorkerTokenOpening:
		input, err := nodewire.DecodeTokenIDs(artifacts[EvidenceArtifactInputTokenIDs])
		if err != nil {
			return fmt.Errorf("Worker input token IDs: %w", err)
		}
		generated, err := nodewire.DecodeTokenIDs(artifacts[EvidenceArtifactGeneratedTokenIDs])
		if err != nil {
			return fmt.Errorf("Worker generated token IDs: %w", err)
		}
		if uint64(len(generated)) != receipt.GeneratedTokenCount {
			return fmt.Errorf("Worker generated token IDs count differs from receipt")
		}
		if facts.InputTokenIDsHash, err = nodewire.InputTokenIDsHash(input); err != nil {
			return err
		}
		if facts.GeneratedTokenIDsHash, err = nodewire.GeneratedTokenIDsHash(generated); err != nil {
			return err
		}
		facts.InputTokenIDsSizeBytes = uint64(len(artifacts[EvidenceArtifactInputTokenIDs]))
		facts.GeneratedTokenIDsSizeBytes = uint64(len(artifacts[EvidenceArtifactGeneratedTokenIDs]))
		_, err = ConfirmWorkerTokenEvidence(facts, commitment)
		return err
	case nodewire.EvidenceKindWorkerValueOpening:
		raw := artifacts[EvidenceArtifactWorkerValues]
		requiredTopK, err := nodewire.WorkerValuesTopK(raw)
		if err != nil {
			return err
		}
		binding := nodewire.WorkerValueBindingV1{
			ChainID: receipt.ChainID, WorkerOperatorAddress: receipt.WorkerOperatorAddress, RequiredTopK: requiredTopK,
		}
		if binding.TaskID, err = taskDataHash("task_id", receipt.TaskID); err != nil {
			return err
		}
		if binding.AcceptedTaskHash, err = taskDataHash("task_hash", receipt.TaskHash); err != nil {
			return err
		}
		values, err := nodewire.DecodeWorkerValues(binding, raw)
		if err != nil {
			return fmt.Errorf("Worker values: %w", err)
		}
		if uint64(len(values)) != receipt.GeneratedTokenCount {
			return fmt.Errorf("Worker values count differs from receipt")
		}
		if facts.WorkerValueRoot, err = nodewire.WorkerValueRoot(binding, values); err != nil {
			return err
		}
		facts.WorkerValuesEncodedSizeBytes = uint64(len(raw))
		return ConfirmWorkerValueEvidence(facts, commitment)
	default:
		return fmt.Errorf("evidence kind %d is not a Worker bundle", commitment.EvidenceKind)
	}
}

func (f *FakeClient) FinalizeVerifierEvidence(_ context.Context, _ string, req FinalizeVerifierEvidenceRequest) (FinalizeVerifierEvidenceResponse, error) {
	digest, err := TaskDataFinalizeVerifierBodyDigest(req)
	if err != nil {
		return FinalizeVerifierEvidenceResponse{}, err
	}
	if err := validateSignedTaskDataRequest(req.Auth, "FinalizeVerifierEvidence", digest); err != nil {
		return FinalizeVerifierEvidenceResponse{}, err
	}
	if req.Auth.Requester != req.VerifierOperator || req.Auth.ChainID != req.Receipt.ChainID {
		return FinalizeVerifierEvidenceResponse{}, fmt.Errorf("finalize requester does not match verifier receipt")
	}
	scope := fmt.Sprintf("%s|%s|verifier|%s|%d|%s", req.Auth.BuilderAddress, req.Receipt.ChainID, req.TaskHash, req.VerifyRound, req.VerifierOperator)
	if previous, ok := f.finalizedDigests[scope]; ok {
		if previous != digest {
			return FinalizeVerifierEvidenceResponse{}, fmt.Errorf("finalize material conflict")
		}
		result := f.finalizedVerifierEvidence[scope]
		result.EvidenceBundleConfirmation.Signature = append([]byte(nil), result.EvidenceBundleConfirmation.Signature...)
		result.Idempotent = true
		return result, nil
	}
	key := EvidenceObjectKey(req.TaskHash, req.SessionID, req.TaskID, DataKindEvidenceManifest, hex.EncodeToString(req.Receipt.VerifierEvidenceBundleHash), EvidenceProducerVerifier, req.VerifyRound, req.VerifierOperator, nodewire.EvidenceKindVerifierValueOpening)
	confirmation, err := f.fakeConfirmation(key, req.Auth)
	if err != nil {
		return FinalizeVerifierEvidenceResponse{}, err
	}
	if confirmation.SizeBytes != req.Receipt.VerifierEvidenceManifestSizeBytes {
		return FinalizeVerifierEvidenceResponse{}, fmt.Errorf("manifest size does not match receipt")
	}
	_, keys, err := f.fakeBundle(key, req.Receipt.ChainID)
	if err != nil {
		return FinalizeVerifierEvidenceResponse{}, err
	}
	f.fakeMarkReady(keys)
	result := FinalizeVerifierEvidenceResponse{EvidenceBundleConfirmation: confirmation}
	if f.finalizedDigests == nil {
		f.finalizedDigests = map[string]codec.Hash{}
	}
	if f.finalizedVerifierEvidence == nil {
		f.finalizedVerifierEvidence = map[string]FinalizeVerifierEvidenceResponse{}
	}
	f.finalizedDigests[scope] = digest
	stored := result
	stored.EvidenceBundleConfirmation.Signature = append([]byte(nil), result.EvidenceBundleConfirmation.Signature...)
	f.finalizedVerifierEvidence[scope] = stored
	f.FinalizedVerifierEvidence = append(f.FinalizedVerifierEvidence, req)
	f.record("finalize_verifier_evidence")
	return result, nil
}

func (f *FakeClient) SubmitVerifyCommit(_ context.Context, _ string, req SubmitVerifyCommitRequest) (VerifyRelayAck, error) {
	if err := ValidateSignedVerifyCommit(req.Commit); err != nil {
		return VerifyRelayAck{}, err
	}
	digest, err := nodewire.VerifyCommitSigningDigest(req.Commit)
	if err != nil {
		return VerifyRelayAck{}, err
	}
	key, err := nodewire.VerifyCommitKey(req.Commit.ChainID, req.Commit.TaskID, req.Commit.VerifyRound, req.Commit.VerifierOperatorAddress)
	if err != nil {
		return VerifyRelayAck{}, err
	}
	f.SubmittedVerifyCommits = append(f.SubmittedVerifyCommits, req)
	f.record("submit_verify_commit")
	return VerifyRelayAck{CommitKey: key, SigningDigest: digest}, nil
}

func cloneFakeFinalization(result FinalizeTaskResultResponse) FinalizeTaskResultResponse {
	result.OutputConfirmation.Signature = append([]byte(nil), result.OutputConfirmation.Signature...)
	result.EvidenceBundleConfirmations = append([]StorageConfirmation(nil), result.EvidenceBundleConfirmations...)
	for i := range result.EvidenceBundleConfirmations {
		result.EvidenceBundleConfirmations[i].Signature = append([]byte(nil), result.EvidenceBundleConfirmations[i].Signature...)
	}
	return result
}

func (f *FakeClient) SubmitInferReceipt(_ context.Context, _ string, req SubmitInferReceiptRequest) error {
	if err := validateSubmitInferReceiptRequest(req); err != nil {
		return err
	}
	f.SubmittedInferReceipts = append(f.SubmittedInferReceipts, req)
	f.record("submit_infer_receipt")
	return nil
}

func (f *FakeClient) SubmitVerifyResult(_ context.Context, _ string, req SubmitVerifyResultRequest) (VerifyRelayAck, error) {
	if _, err := ResultReceiptProto(req.Receipt); err != nil {
		return VerifyRelayAck{}, err
	}
	digest, err := nodewire.ResultReceiptSigningDigest(req.Receipt)
	if err != nil {
		return VerifyRelayAck{}, err
	}
	f.SubmittedVerifyResults = append(f.SubmittedVerifyResults, req)
	f.record("submit_verify_result")
	return VerifyRelayAck{SigningDigest: digest}, nil
}

func (f *FakeClient) Publish(_ context.Context, req PublishRequest) error {
	if req.Subject == "" || req.TaskID == "" {
		return fmt.Errorf("publish missing required fields")
	}
	f.Published = append(f.Published, req)
	f.record("publish")
	return nil
}

func (f *FakeClient) record(event string) {
	if f.Events != nil {
		*f.Events = append(*f.Events, "builder:"+event)
	}
}

func codecPackageHash(taskID, outputRef, tokenIDsRef, positionValuesRef string, outputHash [32]byte) [32]byte {
	return codec.HashWithDomain(
		"TRUEOPEN_OUTPUT_PACKAGE_V1",
		[]byte(taskID),
		[]byte(outputRef),
		[]byte(tokenIDsRef),
		[]byte(positionValuesRef),
		outputHash[:],
	)
}

func outputPackageKey(cid string, packageHash codec.Hash) string {
	return cid + ":" + fmt.Sprintf("%x", packageHash[:])
}
