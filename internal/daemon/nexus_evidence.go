package daemon

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidencebundle"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/taskdataauth"
	"github.com/TrueOpen/cortex/internal/tasktrace"
)

// EvidenceCommitments comes from the chain-checked receipt and locked profile.
type EvidenceCommitments struct {
	SessionID, TaskID, BuilderOperatorAddress string
	Receipt                                   builderclient.SignedInferReceipt
	EvidenceSchemaHash                        string
	Output                                    []byte
	OutputChunkLengths                        []uint64
	// MaxEncodedSizeBytes is the locked Profile's bound per Worker evidence kind.
	MaxEncodedSizeBytes map[nodewire.EvidenceKind]uint64
	// RequiredTopK is the locked Profile's; worker_values are framed under it.
	RequiredTopK uint32
}

// WorkerEvidence is the confirmed content of the Worker's two bundles.
type WorkerEvidence struct {
	InputTokenIDs, GeneratedTokenIDs []byte
	WorkerValues                     []byte
	FinishReason                     nodewire.FinishReasonV1
}

type EvidenceConfirmer interface {
	ConfirmWorkerEvidence(context.Context, EvidenceCommitments) (WorkerEvidence, error)
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

// ConfirmWorkerEvidence downloads the Worker's token and value bundles and
// proves that they reproduce both typed commitments of the signed receipt.
func (c *NexusEvidenceConfirmer) ConfirmWorkerEvidence(ctx context.Context, commitments EvidenceCommitments) (WorkerEvidence, error) {
	receipt := commitments.Receipt
	if _, err := builderclient.InferReceiptSigningDigest(receipt); err != nil {
		return WorkerEvidence{}, fmt.Errorf("Worker receipt: %w", err)
	}
	if receipt.ChainID != c.cfg.ChainID || receipt.TaskID != commitments.TaskID {
		return WorkerEvidence{}, fmt.Errorf("Worker receipt task or chain mismatch")
	}
	if len(receipt.RequiredEvidenceCommitments) != 2 || receipt.RequiredEvidenceCommitments[0].EvidenceKind != nodewire.EvidenceKindWorkerValueOpening ||
		receipt.RequiredEvidenceCommitments[1].EvidenceKind != nodewire.EvidenceKindWorkerTokenOpening {
		return WorkerEvidence{}, fmt.Errorf("signed infer receipt must commit the Worker value and token bundles, in that order")
	}
	for _, committed := range receipt.RequiredEvidenceCommitments {
		limit := commitments.MaxEncodedSizeBytes[committed.EvidenceKind]
		if committed.EncodedSizeBytes == 0 || committed.EncodedSizeBytes > 256<<20 || limit == 0 || committed.EncodedSizeBytes > limit {
			return WorkerEvidence{}, fmt.Errorf("Worker evidence of kind %d exceeds the locked profile or local size bound", committed.EvidenceKind)
		}
	}
	if commitments.RequiredTopK == 0 {
		return WorkerEvidence{}, fmt.Errorf("locked profile required_top_k is required to confirm worker_values")
	}
	var result WorkerEvidence
	err := dialBuilder(ctx, c.cfg.Endpoints, commitments.BuilderOperatorAddress, func(ctx context.Context, endpoint BuilderEndpoint) error {
		var err error
		result, err = c.confirmFrom(ctx, commitments, endpoint)
		return err
	})
	return result, err
}

func (c *NexusEvidenceConfirmer) confirmFrom(ctx context.Context, facts EvidenceCommitments, endpoint BuilderEndpoint) (WorkerEvidence, error) {
	receipt := facts.Receipt
	artifacts := map[string][]byte{}
	for _, committed := range receipt.RequiredEvidenceCommitments {
		bundle, err := c.fetchBundle(ctx, facts, endpoint.Endpoint, committed)
		if err != nil {
			return WorkerEvidence{}, err
		}
		for id, data := range bundle {
			artifacts[id] = data
		}
	}
	result := WorkerEvidence{
		InputTokenIDs:     artifacts[builderclient.EvidenceArtifactInputTokenIDs],
		GeneratedTokenIDs: artifacts[builderclient.EvidenceArtifactGeneratedTokenIDs],
		WorkerValues:      artifacts[builderclient.EvidenceArtifactWorkerValues],
	}
	outputRoot, err := codec.OutputMMRRootFromLengths(facts.Output, facts.OutputChunkLengths)
	if err != nil || outputRoot.String() != receipt.OutputHash || uint64(len(facts.Output)) != receipt.OutputSizeBytes || uint64(len(facts.OutputChunkLengths)) != receipt.OutputLeafCount {
		return WorkerEvidence{}, fmt.Errorf("Worker output differs from signed receipt")
	}
	inputIDs, err := nodewire.DecodeTokenIDs(result.InputTokenIDs)
	if err != nil {
		return WorkerEvidence{}, err
	}
	generatedIDs, err := nodewire.DecodeTokenIDs(result.GeneratedTokenIDs)
	if err != nil {
		return WorkerEvidence{}, err
	}
	if uint64(len(generatedIDs)) != receipt.GeneratedTokenCount {
		return WorkerEvidence{}, fmt.Errorf("Worker generated_token_ids length differs from signed generated_token_count")
	}
	inputHash, err := nodewire.InputTokenIDsHash(inputIDs)
	if err != nil {
		return WorkerEvidence{}, err
	}
	generatedHash, err := nodewire.GeneratedTokenIDsHash(generatedIDs)
	if err != nil {
		return WorkerEvidence{}, err
	}
	taskID, err := decodeCanonicalHash(receipt.TaskID, "task_id")
	if err != nil {
		return WorkerEvidence{}, err
	}
	taskHash, err := decodeCanonicalHash(receipt.TaskHash, "task_hash")
	if err != nil {
		return WorkerEvidence{}, err
	}
	binding := nodewire.WorkerValueBindingV1{
		ChainID: receipt.ChainID, TaskID: taskID[:], AcceptedTaskHash: taskHash[:],
		WorkerOperatorAddress: receipt.WorkerOperatorAddress, RequiredTopK: facts.RequiredTopK,
	}
	leaves, err := nodewire.DecodeWorkerValues(binding, result.WorkerValues)
	if err != nil {
		return WorkerEvidence{}, fmt.Errorf("Worker values: %w", err)
	}
	if uint64(len(leaves)) != receipt.GeneratedTokenCount {
		return WorkerEvidence{}, fmt.Errorf("Worker values cover %d positions, not the signed generated_token_count", len(leaves))
	}
	for i, leaf := range leaves {
		if leaf.TokenID != generatedIDs[i] {
			return WorkerEvidence{}, fmt.Errorf("Worker value at position %d names token %d, not the generated token %d", i, leaf.TokenID, generatedIDs[i])
		}
	}
	valueRoot, err := nodewire.WorkerValueRoot(binding, leaves)
	if err != nil {
		return WorkerEvidence{}, err
	}
	result.FinishReason, err = builderclient.ConfirmWorkerEvidence(builderclient.WorkerEvidenceFacts{
		ChainID: receipt.ChainID, TaskID: receipt.TaskID, AcceptedTaskHash: receipt.TaskHash,
		WorkerOperatorAddress: receipt.WorkerOperatorAddress, GenerationParamsDigest: receipt.GenerationParamsDigest,
		EvidenceSchemaHash: facts.EvidenceSchemaHash, OutputHash: outputRoot, OutputSizeBytes: receipt.OutputSizeBytes,
		OutputLeafCount: receipt.OutputLeafCount, GeneratedTokenCount: receipt.GeneratedTokenCount,
		InputTokenIDsHash: inputHash, GeneratedTokenIDsHash: generatedHash,
		InputTokenIDsSizeBytes: uint64(len(result.InputTokenIDs)), GeneratedTokenIDsSizeBytes: uint64(len(result.GeneratedTokenIDs)),
		WorkerValueRoot: valueRoot, WorkerValuesEncodedSizeBytes: uint64(len(result.WorkerValues)),
	}, receipt.RequiredEvidenceCommitments)
	if err != nil {
		return WorkerEvidence{}, err
	}
	c.cfg.Trace.Event("evidence_confirmed", tasktrace.Str("task", facts.TaskID),
		tasktrace.Hash("worker_value_commitment", receipt.RequiredEvidenceCommitments[0].EvidenceHashOrRoot),
		tasktrace.Hash("worker_token_commitment", receipt.RequiredEvidenceCommitments[1].EvidenceHashOrRoot),
		tasktrace.Hash("worker_value_root", valueRoot), tasktrace.Uint("generated_token_count", receipt.GeneratedTokenCount))
	return result, nil
}

// fetchBundle downloads one Worker bundle: its manifest, addressed by the
// kind's typed commitment, then each artifact the manifest names. It binds the
// bytes to the manifest only; the caller binds them to the commitment.
func (c *NexusEvidenceConfirmer) fetchBundle(ctx context.Context, facts EvidenceCommitments, endpoint string, committed builderclient.EvidenceCommitment) (map[string][]byte, error) {
	receipt := facts.Receipt
	kind := committed.EvidenceKind
	key := builderclient.EvidenceObjectKey(receipt.TaskHash, facts.SessionID, facts.TaskID, builderclient.DataKindEvidenceManifest, committed.EvidenceHashOrRoot.String(), builderclient.EvidenceProducerWorker, 1, receipt.WorkerOperatorAddress, kind)
	metadata, err := c.evidenceMetadata(ctx, facts, endpoint, key)
	if err != nil {
		return nil, err
	}
	wantArtifacts := uint32(1)
	if kind == nodewire.EvidenceKindWorkerTokenOpening {
		wantArtifacts = 2
	}
	summary := metadata.EvidenceBundle
	if summary == nil || summary.ManifestSizeBytes == 0 || summary.ManifestSizeBytes > evidencebundle.MaxManifestBytes ||
		metadata.SizeBytes != summary.ManifestSizeBytes || summary.EvidenceSchemaHash != facts.EvidenceSchemaHash ||
		summary.ArtifactCount != wantArtifacts || summary.ArtifactTotalSizeBytes != committed.EncodedSizeBytes {
		return nil, fmt.Errorf("Worker %s bundle summary differs from receipt, profile or manifest bounds", evidencebundle.KindToken(kind))
	}
	// evidence_manifest_hash is Builder metadata, not a commitment: it only
	// guards the transfer. The artifacts are bound to the receipt below.
	if _, err := decodeCanonicalHash(summary.EvidenceManifestHash, "evidence_manifest_hash"); err != nil {
		return nil, err
	}
	manifestBytes, err := c.fetchEvidenceBytes(ctx, facts, endpoint, key, metadata.SizeBytes, summary.EvidenceManifestHash)
	if err != nil {
		return nil, err
	}
	manifest, err := evidencebundle.Decode(manifestBytes)
	if err != nil {
		return nil, err
	}
	if manifest.ChainID != receipt.ChainID || manifest.TaskID != receipt.TaskID || manifest.TaskHash != receipt.TaskHash ||
		manifest.ProducerKind != "WORKER" || manifest.ProducerOperator != receipt.WorkerOperatorAddress || manifest.VerifyRound != 1 ||
		manifest.EvidenceSchemaHash != facts.EvidenceSchemaHash || manifest.EvidenceKind != evidencebundle.KindToken(kind) {
		return nil, fmt.Errorf("Worker %s manifest scope differs from the receipt or locked profile", manifest.EvidenceKind)
	}
	if manifest.TotalSize() != committed.EncodedSizeBytes {
		return nil, fmt.Errorf("Worker %s manifest size differs from the committed encoded_size_bytes", manifest.EvidenceKind)
	}
	out := make(map[string][]byte, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		size, err := artifact.SizeBytes()
		if err != nil {
			return nil, err
		}
		artifactKey := builderclient.EvidenceObjectKey(receipt.TaskHash, facts.SessionID, facts.TaskID, builderclient.DataKindEvidenceArtifact, artifact.ContentHash, builderclient.EvidenceProducerWorker, 1, receipt.WorkerOperatorAddress, kind)
		data, err := c.fetchEvidence(ctx, facts, endpoint, artifactKey, size)
		if err != nil {
			return nil, err
		}
		out[artifact.ID] = data
	}
	return out, nil
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

func decodeCanonicalHash(value, field string) (codec.Hash, error) {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 || value != strings.ToLower(value) {
		return codec.Hash{}, fmt.Errorf("%s must be lowercase 32-byte hex", field)
	}
	var hash codec.Hash
	copy(hash[:], raw)
	return hash, nil
}
