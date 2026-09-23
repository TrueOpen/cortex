package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidencebundle"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/taskdataauth"
)

const evidenceTestPin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const evidenceTestSchemaHash = "4444444444444444444444444444444444444444444444444444444444444444"

type evidenceTaskDataClient struct {
	*builderclient.FakeClient
	objects          map[builderclient.TaskDataKey][]byte
	metadataRequests []builderclient.GetTaskDataMetadataRequest
	fetches          []builderclient.FetchTaskDataRequest
	pins             []string
	metadataMutation func(*builderclient.TaskDataMetadata)
	frames           func(builderclient.TaskDataKey, []byte) []builderclient.TaskDataChunk
}

func (c *evidenceTaskDataClient) GetTaskDataMetadata(ctx context.Context, _ string, request builderclient.GetTaskDataMetadataRequest) (builderclient.TaskDataMetadata, error) {
	c.metadataRequests = append(c.metadataRequests, request)
	pin, _ := builderclient.TLSPubkeyHashFromContext(ctx)
	c.pins = append(c.pins, pin)
	data, ok := c.objects[request.Key]
	if !ok {
		return builderclient.TaskDataMetadata{}, fmt.Errorf("evidence object missing")
	}
	metadata := builderclient.TaskDataMetadata{Key: request.Key, SizeBytes: uint64(len(data)), Readiness: builderclient.TaskDataReady}
	if request.Key.Kind == builderclient.DataKindEvidenceManifest {
		manifest, err := evidencebundle.Decode(data)
		if err != nil {
			return builderclient.TaskDataMetadata{}, err
		}
		metadata.EvidenceBundle = &builderclient.EvidenceBundleSummary{EvidenceBundleHash: evidencebundle.Hash(data).String(), EvidenceSchemaHash: manifest.EvidenceSchemaHash,
			ArtifactCount: uint32(len(manifest.Artifacts)), ArtifactTotalSizeBytes: manifest.TotalSize(), ManifestSizeBytes: uint64(len(data))}
	}
	if c.metadataMutation != nil {
		c.metadataMutation(&metadata)
	}
	return metadata, nil
}

func (c *evidenceTaskDataClient) FetchTaskData(ctx context.Context, _ string, request builderclient.FetchTaskDataRequest, receive func(builderclient.TaskDataChunk) error) error {
	c.fetches = append(c.fetches, request)
	pin, _ := builderclient.TLSPubkeyHashFromContext(ctx)
	c.pins = append(c.pins, pin)
	data, ok := c.objects[request.Key]
	if !ok {
		return fmt.Errorf("evidence object missing")
	}
	frames := []builderclient.TaskDataChunk{{Data: data, EOF: true}}
	if c.frames != nil {
		frames = c.frames(request.Key, data)
	}
	for _, frame := range frames {
		if err := receive(frame); err != nil {
			return err
		}
	}
	return nil
}

type evidenceFixture struct {
	Trace, Checkpoint, Manifest      []byte
	InputTokenIDs, GeneratedTokenIDs []byte
	Commitments                      EvidenceCommitments
}

func newEvidenceFixture(t *testing.T) evidenceFixture {
	t.Helper()
	generation := &nodewire.GenerationContext{
		ModelID: "model-a", ProfileVersion: 1, TaskType: 2, OutputBudgetBucket: 4,
		Params: nodewire.GenerationParamsV1{SchemaVersion: 1, MaxOutputTokens: 256, MaxOutputDuration: 30000,
			DecodingParams: nodewire.DecodingParamsV1{SamplingEnabled: true, TemperatureMilli: 700, TopPPPM: 950000, RepetitionPenaltyPPM: 1000000}},
	}
	digest, err := generation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	model := modelservice.NewFakeService()
	result, err := model.Infer(context.Background(), modelservice.InferRequest{ModelID: generation.ModelID, ProfileVersion: "1", Capability: modelservice.CapabilityLLMTextV1,
		Input: []byte("fixture prompt"), Generation: generation, GenerationParamsDigest: digest[:]})
	if err != nil {
		t.Fatal(err)
	}
	artifacts := make([][]byte, 0, 3)
	for _, ref := range []string{result.OutputRef, result.TraceRef, result.CheckpointRef} {
		artifact, err := model.FetchArtifact(context.Background(), modelservice.FetchArtifactRequest{Ref: ref})
		if err != nil {
			t.Fatal(err)
		}
		artifacts = append(artifacts, artifact.Data)
	}
	f := evidenceFixture{Trace: artifacts[1], Checkpoint: artifacts[2], Commitments: EvidenceCommitments{
		SessionID: strings.Repeat("11", 32), TaskID: outputTestTaskID, BuilderOperatorAddress: inputTestBuilder,
		EvidenceSchemaHash: evidenceTestSchemaHash, Output: artifacts[0], OutputChunkLengths: []uint64{uint64(len(artifacts[0]))}, MaxEncodedSizeBytes: 256 << 20,
		Receipt: builderclient.SignedInferReceipt{SchemaVersion: 2, ChainID: outputTestChainID, TaskID: outputTestTaskID,
			TaskHash: codec.HashBytes([]byte("accepted-task")).String(), WorkerOperatorAddress: inputTestOperator,
			ServiceAuthorizationNonce: 1, GenerationParamsDigest: digest.String(),
			OutputSizeBytes: uint64(len(artifacts[0])), OutputLeafCount: 1, GeneratedTokenCount: result.GeneratedTokenCount, ExpiryHeight: 1200},
	}}
	root, err := codec.OutputMMRRootFromLengths(f.Commitments.Output, f.Commitments.OutputChunkLengths)
	if err != nil {
		t.Fatal(err)
	}
	f.Commitments.Receipt.OutputHash = root.String()
	f.InputTokenIDs, f.GeneratedTokenIDs, err = modelservice.TokenIDArtifacts(f.Trace, f.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	f.rebuildManifest(t, nil)
	signing, binding := localInputServiceSigner(t)
	receiptDigest, err := builderclient.InferReceiptSigningDigest(f.Commitments.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signing.SignDigest(context.Background(), signer.DigestRequest{KeyRef: inputTestKeyRef, ExpectedSignerAddress: binding.ServiceAddress, Digest: receiptDigest})
	if err != nil {
		t.Fatal(err)
	}
	f.Commitments.Receipt.ServiceSignature = hex.EncodeToString(signature)
	return f
}

func (f *evidenceFixture) rebuildManifest(t *testing.T, mutate func(*evidencebundle.Manifest)) {
	t.Helper()
	r := f.Commitments.Receipt
	m := evidencebundle.Manifest{Version: 1, ChainID: r.ChainID, TaskID: r.TaskID, TaskHash: r.TaskHash, VerifyRound: 1,
		ProducerKind: "WORKER", ProducerOperator: r.WorkerOperatorAddress, EvidenceSchemaHash: f.Commitments.EvidenceSchemaHash, EvidenceKind: "WORKER_VALUE_OPENING",
		Artifacts: []evidencebundle.Artifact{evidencebundle.NewArtifact("checkpoint", f.Checkpoint), evidencebundle.NewArtifact("generated_token_ids", f.GeneratedTokenIDs), evidencebundle.NewArtifact("input_token_ids", f.InputTokenIDs), evidencebundle.NewArtifact("trace", f.Trace)}}
	if mutate != nil {
		mutate(&m)
	}
	var err error
	f.Manifest, err = m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	input, err := nodewire.DecodeTokenIDs(f.InputTokenIDs)
	if err != nil {
		t.Fatal(err)
	}
	generated, err := nodewire.DecodeTokenIDs(f.GeneratedTokenIDs)
	if err != nil {
		t.Fatal(err)
	}
	inputHash, _ := nodewire.InputTokenIDsHash(input)
	generatedHash, _ := nodewire.GeneratedTokenIDsHash(generated)
	outputHash, err := decodeCanonicalHash(r.OutputHash, "output_hash")
	if err != nil {
		t.Fatal(err)
	}
	generation, err := modelservice.GenerationContextFromTrace(f.Trace)
	if err != nil {
		t.Fatal(err)
	}
	genDigest, _ := decodeCanonicalHash(r.GenerationParamsDigest, "generation_params_digest")
	_, reason, err := modelservice.ValidateGenerationEvidence(generation, genDigest[:], f.Commitments.Output, f.Trace, f.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := builderclient.WorkerValueEvidenceCommitment(builderclient.WorkerValueEvidenceFacts{
		ChainID: r.ChainID, TaskID: r.TaskID, AcceptedTaskHash: r.TaskHash, WorkerOperatorAddress: r.WorkerOperatorAddress,
		GenerationParamsDigest: r.GenerationParamsDigest, EvidenceSchemaHash: f.Commitments.EvidenceSchemaHash,
		OutputHash: outputHash, OutputSizeBytes: r.OutputSizeBytes, OutputLeafCount: r.OutputLeafCount, GeneratedTokenCount: r.GeneratedTokenCount, FinishReason: reason,
		TraceRoot: codec.HashBytes(f.Trace), TraceEncodedSizeBytes: uint64(len(f.Trace)), CheckpointRoot: codec.HashBytes(f.Checkpoint), CheckpointEncodedSizeBytes: uint64(len(f.Checkpoint)),
		InputTokenIDsHash: inputHash, GeneratedTokenIDsHash: generatedHash, InputTokenIDsSizeBytes: uint64(len(f.InputTokenIDs)), GeneratedTokenIDsSizeBytes: uint64(len(f.GeneratedTokenIDs)),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.Commitments.Receipt.RequiredEvidenceCommitments = []builderclient.EvidenceCommitment{commitment}
}

func (f evidenceFixture) keys() []builderclient.TaskDataKey {
	r := f.Commitments.Receipt
	key := func(kind builderclient.DataKind, hash string) builderclient.TaskDataKey {
		return builderclient.EvidenceObjectKey(r.TaskHash, f.Commitments.SessionID, r.TaskID, kind, hash, builderclient.EvidenceProducerWorker, 1, r.WorkerOperatorAddress)
	}
	return []builderclient.TaskDataKey{key(builderclient.DataKindEvidenceManifest, r.RequiredEvidenceCommitments[0].EvidenceHashOrRoot.String()),
		key(builderclient.DataKindEvidenceArtifact, codec.HashBytes(f.Checkpoint).String()),
		key(builderclient.DataKindEvidenceArtifact, codec.HashBytes(f.GeneratedTokenIDs).String()),
		key(builderclient.DataKindEvidenceArtifact, codec.HashBytes(f.InputTokenIDs).String()),
		key(builderclient.DataKindEvidenceArtifact, codec.HashBytes(f.Trace).String())}
}

func (f evidenceFixture) objects() map[builderclient.TaskDataKey][]byte {
	keys := f.keys()
	return map[builderclient.TaskDataKey][]byte{keys[0]: f.Manifest, keys[1]: f.Checkpoint, keys[2]: f.GeneratedTokenIDs, keys[3]: f.InputTokenIDs, keys[4]: f.Trace}
}

func evidenceAuth(t *testing.T) (*taskdataauth.Authenticator, signer.Signer) {
	t.Helper()
	signing, binding := localInputServiceSigner(t)
	auth, err := taskdataauth.New(taskdataauth.Config{ServiceKeys: &inputServiceKeys{binding: binding}, Signer: signing,
		ChainID: outputTestChainID, OperatorAddress: inputTestOperator, ServiceAddress: binding.ServiceAddress, ServicePubkey: binding.ServicePubkey,
		ServiceKeyRef: inputTestKeyRef, ExpiryBlocks: inputTestExpiry})
	if err != nil {
		t.Fatal(err)
	}
	return auth, signing
}

func newEvidenceConfirmer(t *testing.T, client builderclient.TaskDataClient) *NexusEvidenceConfirmer {
	t.Helper()
	auth, _ := evidenceAuth(t)
	confirmer, err := NewNexusEvidenceConfirmer(NexusEvidenceConfirmerConfig{TaskData: client, Auth: auth, ChainID: outputTestChainID,
		Endpoints: staticEndpoints{endpoint: BuilderEndpoint{OperatorAddress: inputTestBuilder, Endpoint: "https://builder.example", Source: BuilderEndpointSourceDescriptor, TLSPubkeyHash: evidenceTestPin}}})
	if err != nil {
		t.Fatal(err)
	}
	return confirmer
}

func TestNexusEvidenceConfirmerFetchesManifestBeforeFullArtifactReferences(t *testing.T) {
	f := newEvidenceFixture(t)
	client := &evidenceTaskDataClient{objects: f.objects()}
	result, err := newEvidenceConfirmer(t, client).ConfirmWorkerValueEvidence(context.Background(), f.Commitments)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.Trace, f.Trace) || !bytes.Equal(result.Checkpoint, f.Checkpoint) || result.FinishReason == nodewire.FinishReasonV1Unspecified {
		t.Fatal("confirmed evidence differs from the manifest")
	}
	keys := f.keys()
	if len(client.metadataRequests) != 5 || len(client.fetches) != 5 {
		t.Fatalf("manifest/artifact requests=%d/%d", len(client.metadataRequests), len(client.fetches))
	}
	if keys[0].ContentHash == evidencebundle.Hash(f.Manifest).String() || keys[0].ContentHash != f.Commitments.Receipt.RequiredEvidenceCommitments[0].EvidenceHashOrRoot.String() {
		t.Fatal("Worker manifest locator must be the typed commitment, independent of manifest hash")
	}
	for i, request := range client.metadataRequests {
		if request.Key != keys[i] || client.fetches[i].Key != keys[i] || client.fetches[i].Range != nil {
			t.Fatalf("object %d lost its full scoped reference", i)
		}
		if !strings.HasSuffix(request.Auth.Method, "/GetTaskDataMetadata") || request.Auth.BuilderAddress != inputTestBuilder || request.Auth.ChainID != outputTestChainID || len(request.Auth.Signature) != 64 || len(client.fetches[i].Auth.Signature) != 64 {
			t.Fatal("unsigned evidence request")
		}
	}
	for _, pin := range client.pins {
		if pin != evidenceTestPin {
			t.Fatalf("evidence request lost TLS pin: %s", pin)
		}
	}
}

func TestNexusEvidenceConfirmerRejectsUnboundManifestAndArtifacts(t *testing.T) {
	for _, name := range []string{"manifest hash", "artifact hash", "missing artifact", "schema", "chain", "task", "task hash", "producer", "count", "output hash", "output size", "generation digest", "missing commitment", "duplicate commitment", "manifest size", "artifact limit"} {
		t.Run(name, func(t *testing.T) {
			f := newEvidenceFixture(t)
			client := &evidenceTaskDataClient{objects: f.objects()}
			switch name {
			case "manifest hash":
				client.objects[f.keys()[0]] = append(append([]byte(nil), f.Manifest...), ' ')
			case "artifact hash":
				data := append([]byte(nil), f.Trace...)
				data[0] ^= 1
				client.objects[f.keys()[4]] = data
			case "missing artifact":
				delete(client.objects, f.keys()[1])
			case "schema", "chain", "task", "task hash", "producer", "artifact limit":
				f.rebuildManifest(t, func(m *evidencebundle.Manifest) {
					switch name {
					case "schema":
						m.EvidenceSchemaHash = strings.Repeat("aa", 32)
					case "chain":
						m.ChainID += "-other"
					case "task":
						m.TaskID = strings.Repeat("ab", 32)
					case "task hash":
						m.TaskHash = strings.Repeat("ac", 32)
					case "producer":
						m.ProducerOperator = inputTestBuilder
					case "artifact limit":
						m.Artifacts[0].Size = "268435457"
					}
				})
				client.objects = f.objects()
			case "count":
				f.Commitments.Receipt.GeneratedTokenCount++
			case "output hash":
				f.Commitments.Output[0] ^= 1
			case "output size":
				f.Commitments.Receipt.OutputSizeBytes++
			case "generation digest":
				f.Commitments.Receipt.GenerationParamsDigest = strings.Repeat("ad", 32)
			case "missing commitment":
				f.Commitments.Receipt.RequiredEvidenceCommitments = nil
			case "duplicate commitment":
				f.Commitments.Receipt.RequiredEvidenceCommitments = append(f.Commitments.Receipt.RequiredEvidenceCommitments, f.Commitments.Receipt.RequiredEvidenceCommitments[0])
			case "manifest size":
				f.Commitments.Receipt.RequiredEvidenceCommitments[0].EncodedSizeBytes = evidencebundle.MaxManifestBytes + 1
			}
			if _, err := newEvidenceConfirmer(t, client).ConfirmWorkerValueEvidence(context.Background(), f.Commitments); err == nil {
				t.Fatalf("accepted mismatched %s", name)
			}
		})
	}
}

func TestNexusEvidenceConfirmerRejectsMetadataAndStreamMismatch(t *testing.T) {
	for _, name := range []string{"metadata key", "metadata size", "not ready", "missing bundle summary", "bundle hash", "bundle size", "bundle count", "bundle artifact sum", "gap", "overlap", "missing EOF", "early EOF", "after EOF", "oversize"} {
		t.Run(name, func(t *testing.T) {
			f := newEvidenceFixture(t)
			client := &evidenceTaskDataClient{objects: f.objects()}
			client.metadataMutation = func(m *builderclient.TaskDataMetadata) {
				switch name {
				case "metadata key":
					m.Key.ProducerOperator = inputTestBuilder
				case "metadata size":
					m.SizeBytes++
				case "not ready":
					m.Readiness = builderclient.TaskDataStored
				case "missing bundle summary":
					m.EvidenceBundle = nil
				case "bundle hash":
					if m.EvidenceBundle != nil {
						m.EvidenceBundle.EvidenceBundleHash = strings.Repeat("aa", 32)
					}
				case "bundle size":
					if m.EvidenceBundle != nil {
						m.EvidenceBundle.ManifestSizeBytes++
					}
				case "bundle count":
					if m.EvidenceBundle != nil {
						m.EvidenceBundle.ArtifactCount++
					}
				case "bundle artifact sum":
					if m.EvidenceBundle != nil {
						m.EvidenceBundle.ArtifactTotalSizeBytes++
					}
				}
			}
			client.frames = func(_ builderclient.TaskDataKey, data []byte) []builderclient.TaskDataChunk {
				switch name {
				case "gap":
					return []builderclient.TaskDataChunk{{Offset: 1, Data: data, EOF: true}}
				case "overlap":
					return []builderclient.TaskDataChunk{{Data: data[:1]}, {Data: data[1:], EOF: true}}
				case "missing EOF":
					return []builderclient.TaskDataChunk{{Data: data}}
				case "early EOF":
					return []builderclient.TaskDataChunk{{Data: data[:1], EOF: true}}
				case "after EOF":
					return []builderclient.TaskDataChunk{{Data: data, EOF: true}, {Offset: uint64(len(data)), EOF: true}}
				case "oversize":
					return []builderclient.TaskDataChunk{{Data: append(append([]byte(nil), data...), 1), EOF: true}}
				default:
					return []builderclient.TaskDataChunk{{Data: data, EOF: true}}
				}
			}
			if _, err := newEvidenceConfirmer(t, client).ConfirmWorkerValueEvidence(context.Background(), f.Commitments); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
}
