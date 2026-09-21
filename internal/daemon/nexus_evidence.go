package daemon

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/evidencebundle"
	"github.com/SingaXYZ/cortex/internal/modelservice"
	"github.com/SingaXYZ/cortex/internal/nodewire"
	"github.com/SingaXYZ/cortex/internal/taskdataauth"
	"github.com/SingaXYZ/cortex/internal/tasktrace"
)

// EvidenceCommitments comes from the chain-checked receipt and locked profile.
type EvidenceCommitments struct {
	SessionID, TaskID, BuilderOperatorAddress string
	Receipt                                   builderclient.SignedInferReceipt
	EvidenceSchemaHash                        string
	Output                                    []byte
	OutputChunkLengths                        []uint64
	MaxEncodedSizeBytes                       uint64
}

type WorkerValueEvidence struct {
	Trace, Checkpoint                []byte
	InputTokenIDs, GeneratedTokenIDs []byte
	FinishReason                     nodewire.FinishReasonV1
}

type EvidenceConfirmer interface {
	ConfirmWorkerValueEvidence(context.Context, EvidenceCommitments) (WorkerValueEvidence, error)
}

type NexusEvidenceConfirmerConfig struct {
	TaskData  builderclient.TaskDataClient
	Endpoints BuilderEndpointResolver
	Auth      *taskdataauth.Authenticator
	ChainID   string
	Trace     *tasktrace.Trace
}

type NexusEvidenceConfirmer struct{ cfg NexusEvidenceConfirmerConfig }

func NewNexusEvidenceConfirmer(cfg NexusEvidenceConfirmerConfig) (*NexusEvidenceConfirmer, error) {
	if cfg.TaskData == nil || cfg.Endpoints == nil || cfg.Auth == nil || strings.TrimSpace(cfg.ChainID) == "" {
		return nil, fmt.Errorf("Nexus evidence confirmer requires task-data, endpoints, authentication and chain id")
	}
	return &NexusEvidenceConfirmer{cfg: cfg}, nil
}

func (c *NexusEvidenceConfirmer) ConfirmWorkerValueEvidence(ctx context.Context, commitments EvidenceCommitments) (WorkerValueEvidence, error) {
	if _, err := builderclient.InferReceiptSigningDigest(commitments.Receipt); err != nil {
		return WorkerValueEvidence{}, fmt.Errorf("Worker receipt: %w", err)
	}
	committed, err := workerValueCommitment(commitments)
	if err != nil {
		return WorkerValueEvidence{}, err
	}
	if commitments.Receipt.ChainID != c.cfg.ChainID || commitments.Receipt.TaskID != commitments.TaskID {
		return WorkerValueEvidence{}, fmt.Errorf("Worker receipt task or chain mismatch")
	}
	if committed.EncodedSizeBytes == 0 || committed.EncodedSizeBytes > 256<<20 || commitments.MaxEncodedSizeBytes == 0 || committed.EncodedSizeBytes > commitments.MaxEncodedSizeBytes {
		return WorkerValueEvidence{}, fmt.Errorf("Worker evidence exceeds the locked profile or local size bound")
	}
	var result WorkerValueEvidence
	err = dialBuilder(ctx, c.cfg.Endpoints, commitments.BuilderOperatorAddress, func(ctx context.Context, endpoint BuilderEndpoint) error {
		var err error
		result, err = c.confirmFrom(ctx, commitments, committed, endpoint)
		return err
	})
	return result, err
}

func (c *NexusEvidenceConfirmer) confirmFrom(ctx context.Context, facts EvidenceCommitments, committed builderclient.EvidenceCommitment, endpoint BuilderEndpoint) (WorkerValueEvidence, error) {
	receipt := facts.Receipt
	key := builderclient.EvidenceObjectKey(receipt.TaskHash, facts.SessionID, facts.TaskID, builderclient.DataKindEvidenceManifest, committed.EvidenceHashOrRoot.String(), builderclient.EvidenceProducerWorker, 1, receipt.WorkerOperatorAddress)
	metadata, err := c.evidenceMetadata(ctx, facts, endpoint.Endpoint, key)
	if err != nil {
		return WorkerValueEvidence{}, err
	}
	summary := metadata.EvidenceBundle
	if summary == nil || summary.ManifestSizeBytes == 0 || summary.ManifestSizeBytes > evidencebundle.MaxManifestBytes ||
		metadata.SizeBytes != summary.ManifestSizeBytes || summary.EvidenceSchemaHash != facts.EvidenceSchemaHash ||
		summary.ArtifactCount != 4 || summary.ArtifactTotalSizeBytes != committed.EncodedSizeBytes {
		return WorkerValueEvidence{}, fmt.Errorf("Worker evidence bundle summary differs from receipt, profile or manifest bounds")
	}
	if _, err := decodeCanonicalHash(summary.EvidenceBundleHash, "evidence_bundle_hash"); err != nil {
		return WorkerValueEvidence{}, err
	}
	manifestBytes, err := c.fetchEvidenceBytes(ctx, facts, endpoint.Endpoint, key, metadata.SizeBytes, summary.EvidenceBundleHash)
	if err != nil {
		return WorkerValueEvidence{}, err
	}
	manifest, err := evidencebundle.Decode(manifestBytes)
	if err != nil {
		return WorkerValueEvidence{}, err
	}
	if manifest.ChainID != receipt.ChainID || manifest.TaskID != receipt.TaskID || manifest.TaskHash != receipt.TaskHash || manifest.ProducerKind != "WORKER" || manifest.ProducerOperator != receipt.WorkerOperatorAddress || manifest.VerifyRound != 1 || manifest.EvidenceSchemaHash != facts.EvidenceSchemaHash {
		return WorkerValueEvidence{}, fmt.Errorf("Worker manifest scope differs from the receipt or locked profile")
	}
	if len(manifest.Artifacts) != 4 || manifest.TotalSize() != committed.EncodedSizeBytes {
		return WorkerValueEvidence{}, fmt.Errorf("unsupported Worker opening artifact set or size")
	}
	var result WorkerValueEvidence
	for _, artifact := range manifest.Artifacts {
		size, err := artifact.SizeBytes()
		if err != nil {
			return WorkerValueEvidence{}, err
		}
		artifactKey := builderclient.EvidenceObjectKey(receipt.TaskHash, facts.SessionID, facts.TaskID, builderclient.DataKindEvidenceArtifact, artifact.ContentHash, builderclient.EvidenceProducerWorker, 1, receipt.WorkerOperatorAddress)
		data, err := c.fetchEvidence(ctx, facts, endpoint.Endpoint, artifactKey, size)
		if err != nil {
			return WorkerValueEvidence{}, err
		}
		switch artifact.ID {
		case "trace":
			result.Trace = data
		case "checkpoint":
			result.Checkpoint = data
		case "input_token_ids":
			result.InputTokenIDs = data
		case "generated_token_ids":
			result.GeneratedTokenIDs = data
		}
	}
	if len(result.Trace) == 0 || len(result.Checkpoint) == 0 {
		return WorkerValueEvidence{}, fmt.Errorf("Worker manifest must contain trace and checkpoint")
	}
	generation, err := modelservice.GenerationContextFromTrace(result.Trace)
	if err != nil {
		return WorkerValueEvidence{}, err
	}
	digest, err := decodeCanonicalHash(receipt.GenerationParamsDigest, "generation_params_digest")
	if err != nil {
		return WorkerValueEvidence{}, err
	}
	outputRoot, err := codec.OutputMMRRootFromLengths(facts.Output, facts.OutputChunkLengths)
	if err != nil || outputRoot.String() != receipt.OutputHash || uint64(len(facts.Output)) != receipt.OutputSizeBytes || uint64(len(facts.OutputChunkLengths)) != receipt.OutputLeafCount {
		return WorkerValueEvidence{}, fmt.Errorf("Worker output differs from signed receipt")
	}
	count, reason, err := modelservice.ValidateGenerationEvidence(generation, digest[:], facts.Output, result.Trace, result.Checkpoint)
	if err != nil {
		return WorkerValueEvidence{}, err
	}
	if count != receipt.GeneratedTokenCount {
		return WorkerValueEvidence{}, fmt.Errorf("Worker evidence generated_token_count differs from signed receipt")
	}
	if err := modelservice.ValidateTokenIDArtifacts(result.Trace, result.Checkpoint, result.InputTokenIDs, result.GeneratedTokenIDs); err != nil {
		return WorkerValueEvidence{}, fmt.Errorf("Worker token artifacts: %w", err)
	}
	inputIDs, err := nodewire.DecodeTokenIDs(result.InputTokenIDs)
	if err != nil {
		return WorkerValueEvidence{}, err
	}
	generatedIDs, err := nodewire.DecodeTokenIDs(result.GeneratedTokenIDs)
	if err != nil {
		return WorkerValueEvidence{}, err
	}
	inputHash, err := nodewire.InputTokenIDsHash(inputIDs)
	if err != nil {
		return WorkerValueEvidence{}, err
	}
	generatedHash, err := nodewire.GeneratedTokenIDsHash(generatedIDs)
	if err != nil {
		return WorkerValueEvidence{}, err
	}
	confirmedReason, err := builderclient.ConfirmWorkerValueEvidence(builderclient.WorkerValueEvidenceFacts{
		ChainID: receipt.ChainID, TaskID: receipt.TaskID, AcceptedTaskHash: receipt.TaskHash,
		WorkerOperatorAddress: receipt.WorkerOperatorAddress, GenerationParamsDigest: receipt.GenerationParamsDigest,
		EvidenceSchemaHash: facts.EvidenceSchemaHash, OutputHash: outputRoot, OutputSizeBytes: receipt.OutputSizeBytes,
		OutputLeafCount: receipt.OutputLeafCount, GeneratedTokenCount: receipt.GeneratedTokenCount,
		TraceRoot: codec.HashBytes(result.Trace), TraceEncodedSizeBytes: uint64(len(result.Trace)),
		CheckpointRoot: codec.HashBytes(result.Checkpoint), CheckpointEncodedSizeBytes: uint64(len(result.Checkpoint)),
		InputTokenIDsHash: inputHash, GeneratedTokenIDsHash: generatedHash,
		InputTokenIDsSizeBytes: uint64(len(result.InputTokenIDs)), GeneratedTokenIDsSizeBytes: uint64(len(result.GeneratedTokenIDs)),
	}, committed)
	if err != nil {
		return WorkerValueEvidence{}, err
	}
	if confirmedReason != reason {
		return WorkerValueEvidence{}, fmt.Errorf("Worker finish reason differs from typed commitment")
	}
	result.FinishReason = confirmedReason
	c.cfg.Trace.Event("evidence_confirmed", tasktrace.Str("task", facts.TaskID), tasktrace.Hash("worker_value_commitment", committed.EvidenceHashOrRoot), tasktrace.Uint("generated_token_count", count))
	return result, nil
}

func (c *NexusEvidenceConfirmer) fetchEvidence(ctx context.Context, facts EvidenceCommitments, endpoint string, key builderclient.TaskDataKey, size uint64) ([]byte, error) {
	metadata, err := c.evidenceMetadata(ctx, facts, endpoint, key)
	if err != nil {
		return nil, err
	}
	if metadata.SizeBytes != size {
		return nil, fmt.Errorf("evidence metadata differs from the committed object size")
	}
	return c.fetchEvidenceBytes(ctx, facts, endpoint, key, size, key.ContentHash)
}

func (c *NexusEvidenceConfirmer) evidenceMetadata(ctx context.Context, facts EvidenceCommitments, endpoint string, key builderclient.TaskDataKey) (builderclient.TaskDataMetadata, error) {
	digest, err := builderclient.TaskDataMetadataBodyDigest(key)
	if err != nil {
		return builderclient.TaskDataMetadata{}, err
	}
	auth, err := c.cfg.Auth.SignRequest(ctx, "GetTaskDataMetadata", key, facts.BuilderOperatorAddress, digest)
	if err != nil {
		return builderclient.TaskDataMetadata{}, err
	}
	metadata, err := c.cfg.TaskData.GetTaskDataMetadata(ctx, endpoint, builderclient.GetTaskDataMetadataRequest{Key: key, Auth: auth})
	if err != nil {
		return builderclient.TaskDataMetadata{}, err
	}
	if metadata.Key != key || metadata.Readiness != builderclient.TaskDataReady {
		return builderclient.TaskDataMetadata{}, fmt.Errorf("evidence metadata differs from the committed object or is not READY")
	}
	return metadata, nil
}

func (c *NexusEvidenceConfirmer) fetchEvidenceBytes(ctx context.Context, facts EvidenceCommitments, endpoint string, key builderclient.TaskDataKey, size uint64, expectedHash string) ([]byte, error) {
	auth, err := c.cfg.Auth.SignFetch(ctx, key, facts.BuilderOperatorAddress, nil)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, size)
	ended := false
	err = c.cfg.TaskData.FetchTaskData(ctx, endpoint, builderclient.FetchTaskDataRequest{Key: key, Auth: auth}, func(chunk builderclient.TaskDataChunk) error {
		if ended || chunk.Offset != uint64(len(data)) || uint64(len(chunk.Data)) > size-uint64(len(data)) {
			return fmt.Errorf("evidence stream offset, size or EOF mismatch")
		}
		data = append(data, chunk.Data...)
		ended = chunk.EOF
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !ended || uint64(len(data)) != size {
		return nil, fmt.Errorf("incomplete evidence stream")
	}
	hash := codec.HashBytes(data)
	if key.Kind == builderclient.DataKindEvidenceManifest {
		hash = evidencebundle.Hash(data)
	}
	if hash.String() != expectedHash {
		return nil, fmt.Errorf("evidence content hash differs from committed object reference")
	}
	return data, nil
}

func workerValueCommitment(facts EvidenceCommitments) (builderclient.EvidenceCommitment, error) {
	if len(facts.Receipt.RequiredEvidenceCommitments) != 1 || facts.Receipt.RequiredEvidenceCommitments[0].EvidenceKind != nodewire.EvidenceKindWorkerValueOpening {
		return builderclient.EvidenceCommitment{}, fmt.Errorf("signed infer receipt requires exactly one Worker opening bundle")
	}
	return facts.Receipt.RequiredEvidenceCommitments[0], nil
}

func decodeCanonicalHash(value, field string) (codec.Hash, error) {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 || value != strings.ToLower(value) {
		return codec.Hash{}, fmt.Errorf("%s must be lowercase 32-byte hex", field)
	}
	var hash codec.Hash
	copy(hash[:], raw)
	return hash, nil
}
