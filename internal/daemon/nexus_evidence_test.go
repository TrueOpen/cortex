package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidencebundle"
	"github.com/TrueOpen/cortex/internal/metric"
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
		metadata.EvidenceBundle = &builderclient.EvidenceBundleSummary{EvidenceManifestHash: evidencebundle.Hash(data).String(), EvidenceSchemaHash: manifest.EvidenceSchemaHash,
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
	InputTokenIDs, GeneratedTokenIDs, WorkerValues []byte
	GenerationParams                               []byte
	ValueManifest, TokenManifest                   []byte
	FinishReason                                   nodewire.FinishReasonV1
	Commitments                                    EvidenceCommitments
}

const evidenceTestTopK = 16

func newEvidenceFixture(t *testing.T) evidenceFixture {
	t.Helper()
	generation := &nodewire.GenerationContext{
		ModelID: modelservice.FakeModelID, ProfileVersion: 1, TaskType: 2, OutputBudgetBucket: 4,
		Params: nodewire.GenerationParamsV1{SchemaVersion: 1, MaxOutputTokens: 256, MaxOutputDuration: 30000,
			DecodingParams: nodewire.DecodingParamsV1{SamplingEnabled: true, TemperatureMilli: 700, TopPPPM: 950000, RepetitionPenaltyPPM: 1000000}},
	}
	digest, err := generation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	generationParams, err := generation.CanonicalJSON()
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
	for _, ref := range []string{result.OutputRef, result.TokenIDsRef, result.PositionValuesRef} {
		artifact, err := model.FetchArtifact(context.Background(), modelservice.FetchArtifactRequest{Ref: ref})
		if err != nil {
			t.Fatal(err)
		}
		artifacts = append(artifacts, artifact.Data)
	}
	f := evidenceFixture{FinishReason: result.FinishReason, GenerationParams: generationParams, Commitments: EvidenceCommitments{
		SessionID: strings.Repeat("11", 32), TaskID: outputTestTaskID, BuilderOperatorAddress: inputTestBuilder,
		EvidenceSchemaHash: evidenceTestSchemaHash, Output: artifacts[0], OutputChunkLengths: []uint64{uint64(len(artifacts[0]))},
		MaxEncodedSizeBytes: map[nodewire.EvidenceKind]uint64{nodewire.EvidenceKindWorkerValueOpening: 256 << 20, nodewire.EvidenceKindWorkerTokenOpening: 256 << 20},
		RequiredTopK:        evidenceTestTopK,
		Receipt: builderclient.SignedInferReceipt{SchemaVersion: nodewire.InferReceiptSchemaVersionV3, ChainID: outputTestChainID, TaskID: outputTestTaskID,
			TaskHash: codec.HashBytes([]byte("accepted-task")).String(), WorkerOperatorAddress: inputTestOperator,
			ServiceAuthorizationNonce: 1, GenerationParamsDigest: digest.String(),
			OutputSizeBytes: uint64(len(artifacts[0])), OutputLeafCount: 1, GeneratedTokenCount: result.GeneratedTokenCount, ExpiryHeight: 1200},
	}}
	root, err := codec.OutputMMRRootFromLengths(f.Commitments.Output, f.Commitments.OutputChunkLengths)
	if err != nil {
		t.Fatal(err)
	}
	f.Commitments.Receipt.OutputHash = root.String()
	ids, err := modelservice.DecodeTokenIDsArtifact(artifacts[1])
	if err != nil {
		t.Fatal(err)
	}
	if f.InputTokenIDs, f.GeneratedTokenIDs, err = modelservice.ProtocolTokenIDs(ids); err != nil {
		t.Fatal(err)
	}
	values, err := modelservice.DecodePositionValuesArtifact(artifacts[2])
	if err != nil {
		t.Fatal(err)
	}
	leaves, err := metric.ValueLeaves(values, evidenceTestTopK)
	if err != nil {
		t.Fatal(err)
	}
	if f.WorkerValues, err = nodewire.EncodeWorkerValues(f.valueBinding(t), leaves); err != nil {
		t.Fatal(err)
	}
	f.rebuildManifests(t, nil)
	f.sign(t)
	return f
}

func (f evidenceFixture) valueBinding(t *testing.T) nodewire.WorkerValueBindingV1 {
	t.Helper()
	r := f.Commitments.Receipt
	taskID, err := decodeCanonicalHash(r.TaskID, "task_id")
	if err != nil {
		t.Fatal(err)
	}
	taskHash, err := decodeCanonicalHash(r.TaskHash, "task_hash")
	if err != nil {
		t.Fatal(err)
	}
	return nodewire.WorkerValueBindingV1{ChainID: r.ChainID, TaskID: taskID[:], AcceptedTaskHash: taskHash[:],
		WorkerOperatorAddress: r.WorkerOperatorAddress, RequiredTopK: evidenceTestTopK}
}

func (f *evidenceFixture) sign(t *testing.T) {
	t.Helper()
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
}

// rebuildManifests encodes both Worker manifests, applying mutate to each, and
// re-derives the receipt's two commitments from the artifacts.
func (f *evidenceFixture) rebuildManifests(t *testing.T, mutate func(*evidencebundle.Manifest)) {
	t.Helper()
	r := f.Commitments.Receipt
	scope := func(kind string, artifacts ...evidencebundle.Artifact) evidencebundle.Manifest {
		return evidencebundle.Manifest{Version: 1, ChainID: r.ChainID, TaskID: r.TaskID, TaskHash: r.TaskHash, VerifyRound: 1,
			ProducerKind: "WORKER", ProducerOperator: r.WorkerOperatorAddress, EvidenceSchemaHash: f.Commitments.EvidenceSchemaHash,
			EvidenceKind: kind, Artifacts: artifacts}
	}
	value := scope(evidencebundle.KindWorkerValueOpening, evidencebundle.NewArtifact("worker_values", f.WorkerValues))
	token := scope(evidencebundle.KindWorkerTokenOpening, evidencebundle.NewArtifact("generated_token_ids", f.GeneratedTokenIDs),
		evidencebundle.NewArtifact("generation_params", f.GenerationParams), evidencebundle.NewArtifact("input_token_ids", f.InputTokenIDs))
	if mutate != nil {
		mutate(&value)
		mutate(&token)
	}
	var err error
	if f.ValueManifest, err = value.Encode(); err != nil {
		t.Fatal(err)
	}
	if f.TokenManifest, err = token.Encode(); err != nil {
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
	leaves, err := nodewire.DecodeWorkerValues(f.valueBinding(t), f.WorkerValues)
	if err != nil {
		t.Fatal(err)
	}
	valueRoot, err := nodewire.WorkerValueRoot(f.valueBinding(t), leaves)
	if err != nil {
		t.Fatal(err)
	}
	commitments, err := builderclient.WorkerEvidenceCommitments(builderclient.WorkerEvidenceFacts{
		ChainID: r.ChainID, TaskID: r.TaskID, AcceptedTaskHash: r.TaskHash, WorkerOperatorAddress: r.WorkerOperatorAddress,
		GenerationParamsDigest: r.GenerationParamsDigest, EvidenceSchemaHash: f.Commitments.EvidenceSchemaHash,
		OutputHash: outputHash, OutputSizeBytes: r.OutputSizeBytes, OutputLeafCount: r.OutputLeafCount, GeneratedTokenCount: r.GeneratedTokenCount,
		FinishReason: f.FinishReason, InputTokenIDsHash: inputHash, GeneratedTokenIDsHash: generatedHash,
		InputTokenIDsSizeBytes: uint64(len(f.InputTokenIDs)), GeneratedTokenIDsSizeBytes: uint64(len(f.GeneratedTokenIDs)),
		WorkerValueRoot: valueRoot, WorkerValuesEncodedSizeBytes: uint64(len(f.WorkerValues)),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.Commitments.Receipt.RequiredEvidenceCommitments = commitments
}

// keys are: value manifest, worker_values, token manifest,
// generated_token_ids, input_token_ids, generation_params. The last is fetched
// between the two token-id artifacts; it is appended so earlier indexes stay.
func (f evidenceFixture) keys() []builderclient.TaskDataKey {
	r := f.Commitments.Receipt
	key := func(dataKind builderclient.DataKind, hash string, kind nodewire.EvidenceKind) builderclient.TaskDataKey {
		return builderclient.EvidenceObjectKey(r.TaskHash, f.Commitments.SessionID, r.TaskID, dataKind, hash, builderclient.EvidenceProducerWorker, 1, r.WorkerOperatorAddress, kind)
	}
	value, token := nodewire.EvidenceKindWorkerValueOpening, nodewire.EvidenceKindWorkerTokenOpening
	return []builderclient.TaskDataKey{
		key(builderclient.DataKindEvidenceManifest, r.RequiredEvidenceCommitments[0].EvidenceHashOrRoot.String(), value),
		key(builderclient.DataKindEvidenceArtifact, codec.HashBytes(f.WorkerValues).String(), value),
		key(builderclient.DataKindEvidenceManifest, r.RequiredEvidenceCommitments[1].EvidenceHashOrRoot.String(), token),
		key(builderclient.DataKindEvidenceArtifact, codec.HashBytes(f.GeneratedTokenIDs).String(), token),
		key(builderclient.DataKindEvidenceArtifact, codec.HashBytes(f.InputTokenIDs).String(), token),
		key(builderclient.DataKindEvidenceArtifact, codec.HashBytes(f.GenerationParams).String(), token),
	}
}

func (f evidenceFixture) objects() map[builderclient.TaskDataKey][]byte {
	keys := f.keys()
	return map[builderclient.TaskDataKey][]byte{keys[0]: f.ValueManifest, keys[1]: f.WorkerValues, keys[2]: f.TokenManifest, keys[3]: f.GeneratedTokenIDs, keys[4]: f.InputTokenIDs, keys[5]: f.GenerationParams}
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
	result, err := newEvidenceConfirmer(t, client).ConfirmWorkerEvidence(context.Background(), f.Commitments)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.WorkerValues, f.WorkerValues) || !bytes.Equal(result.GeneratedTokenIDs, f.GeneratedTokenIDs) ||
		!bytes.Equal(result.InputTokenIDs, f.InputTokenIDs) || !bytes.Equal(result.GenerationParams, f.GenerationParams) || result.FinishReason != f.FinishReason {
		t.Fatal("confirmed evidence differs from the manifest")
	}
	keys := f.keys()
	if len(client.metadataRequests) != 6 || len(client.fetches) != 6 {
		t.Fatalf("manifest/artifact requests=%d/%d", len(client.metadataRequests), len(client.fetches))
	}
	if keys[0].ContentHash == evidencebundle.Hash(f.ValueManifest).String() || keys[0].ContentHash != f.Commitments.Receipt.RequiredEvidenceCommitments[0].EvidenceHashOrRoot.String() ||
		keys[2].ContentHash != f.Commitments.Receipt.RequiredEvidenceCommitments[1].EvidenceHashOrRoot.String() {
		t.Fatal("Worker manifest locator must be the typed commitment, independent of manifest hash")
	}
	// Artifacts are fetched in manifest order: generation_params sits between
	// the two token-id artifacts.
	fetchOrder := []builderclient.TaskDataKey{keys[0], keys[1], keys[2], keys[3], keys[5], keys[4]}
	for i, request := range client.metadataRequests {
		if request.Key != fetchOrder[i] || client.fetches[i].Key != fetchOrder[i] || client.fetches[i].Range != nil {
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
				client.objects[f.keys()[2]] = append(append([]byte(nil), f.TokenManifest...), ' ')
			case "artifact hash":
				data := append([]byte(nil), f.WorkerValues...)
				data[len(data)-1] ^= 1
				client.objects[f.keys()[1]] = data
			case "missing artifact":
				delete(client.objects, f.keys()[4])
			case "schema", "chain", "task", "task hash", "producer", "artifact limit":
				f.rebuildManifests(t, func(m *evidencebundle.Manifest) {
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
			if _, err := newEvidenceConfirmer(t, client).ConfirmWorkerEvidence(context.Background(), f.Commitments); err == nil {
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
						m.EvidenceBundle.EvidenceManifestHash = strings.Repeat("aa", 32)
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
			if _, err := newEvidenceConfirmer(t, client).ConfirmWorkerEvidence(context.Background(), f.Commitments); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
}

// A Builder can declare generation_params sizes the commitment does not bound.
// A declaration above the hard bound is refused before any artifact is
// downloaded or a buffer is sized from it.
func TestNexusEvidenceConfirmerRefusesOversizedGenerationParamsBeforeDownload(t *testing.T) {
	for _, name := range []string{"summary total", "manifest artifact"} {
		t.Run(name, func(t *testing.T) {
			f := newEvidenceFixture(t)
			huge := uint64(nodewire.MaxGenerationParamsBytes) + 1
			if name == "manifest artifact" {
				// A self-consistent lie: the manifest and the summary both claim
				// an oversized generation_params, so only the bound can stop it.
				f.rebuildManifests(t, func(m *evidencebundle.Manifest) {
					for i := range m.Artifacts {
						if m.Artifacts[i].ID == evidencebundle.ArtifactGenerationParams {
							m.Artifacts[i].Size = strconv.FormatUint(huge, 10)
						}
					}
				})
			}
			client := &evidenceTaskDataClient{objects: f.objects()}
			if name == "summary total" {
				client.metadataMutation = func(m *builderclient.TaskDataMetadata) {
					if m.EvidenceBundle != nil && m.Key.EvidenceKind == nodewire.EvidenceKindWorkerTokenOpening {
						m.EvidenceBundle.ArtifactTotalSizeBytes += huge
					}
				}
			}
			_, err := newEvidenceConfirmer(t, client).ConfirmWorkerEvidence(context.Background(), f.Commitments)
			if err == nil {
				t.Fatal("oversized generation_params declaration was accepted")
			}
			for _, fetch := range client.fetches {
				if fetch.Key.EvidenceKind == nodewire.EvidenceKindWorkerTokenOpening && fetch.Key.Kind == builderclient.DataKindEvidenceArtifact {
					t.Fatalf("token artifact %s was downloaded before the size refusal: %v", fetch.Key.ContentHash, err)
				}
			}
		})
	}
}

// Self-consistent Worker bundles, re-committed and re-signed, that still
// disagree with the receipt's generated tokens are refused, and so is a
// confirmation request without the locked required_top_k.
func TestNexusEvidenceConfirmerRefusesSelfConsistentValueMismatches(t *testing.T) {
	for name, mutate := range map[string]func([]nodewire.PositionValueV1) []nodewire.PositionValueV1{
		"leaf token differs from generated token": func(leaves []nodewire.PositionValueV1) []nodewire.PositionValueV1 {
			leaves[0].TokenID++
			for i := range leaves[0].TopK {
				if leaves[0].TopK[i].TokenID == leaves[0].TokenID {
					leaves[0].TopK[i].TokenID += 100000
				}
			}
			return leaves
		},
		"leaf count differs from generated_token_count": func(leaves []nodewire.PositionValueV1) []nodewire.PositionValueV1 {
			return leaves[:len(leaves)-1]
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newEvidenceFixture(t)
			leaves, err := nodewire.DecodeWorkerValues(f.valueBinding(t), f.WorkerValues)
			if err != nil {
				t.Fatal(err)
			}
			if f.WorkerValues, err = nodewire.EncodeWorkerValues(f.valueBinding(t), mutate(leaves)); err != nil {
				t.Fatal(err)
			}
			f.rebuildManifests(t, nil)
			f.sign(t)
			client := &evidenceTaskDataClient{objects: f.objects()}
			_, err = newEvidenceConfirmer(t, client).ConfirmWorkerEvidence(context.Background(), f.Commitments)
			want := map[string]string{
				"leaf token differs from generated token":       "not the generated token",
				"leaf count differs from generated_token_count": "not the signed generated_token_count",
			}[name]
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want a refusal containing %q", err, want)
			}
		})
	}
	f := newEvidenceFixture(t)
	f.Commitments.RequiredTopK = 0
	if _, err := newEvidenceConfirmer(t, &evidenceTaskDataClient{objects: f.objects()}).ConfirmWorkerEvidence(context.Background(), f.Commitments); err == nil ||
		!strings.Contains(err.Error(), "required_top_k") {
		t.Fatalf("RequiredTopK=0 = %v, want a refusal naming required_top_k", err)
	}
}
