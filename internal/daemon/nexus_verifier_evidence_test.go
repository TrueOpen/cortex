package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/chainclient"
	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/evidence"
	"github.com/SingaXYZ/cortex/internal/evidencebundle"
	"github.com/SingaXYZ/cortex/internal/nodewire"
	"github.com/SingaXYZ/cortex/internal/signer"
	"github.com/SingaXYZ/cortex/internal/store"
	"github.com/SingaXYZ/cortex/internal/taskfacts"
	"github.com/SingaXYZ/cortex/internal/verifier"
	"github.com/SingaXYZ/cortex/internal/worker"
)

type verifierEvidenceTaskDataClient struct {
	*builderclient.FakeClient
	uploads                []builderclient.UploadTaskResultRequest
	finalizations          []builderclient.FinalizeVerifierEvidenceRequest
	pins                   []string
	signing                signer.Signer
	signerAddress          string
	uploadErr, finalizeErr error
	metadataMutation       func(*builderclient.TaskDataMetadata)
	confirmationMutation   func(*builderclient.StorageConfirmation)
	confirmationTamper     func(*builderclient.StorageConfirmation)
}

func (c *verifierEvidenceTaskDataClient) UploadTaskResultObject(ctx context.Context, _ string, request builderclient.UploadTaskResultRequest) (builderclient.TaskDataMetadata, error) {
	c.uploads = append(c.uploads, request)
	pin, _ := builderclient.TLSPubkeyHashFromContext(ctx)
	c.pins = append(c.pins, pin)
	if c.uploadErr != nil {
		return builderclient.TaskDataMetadata{}, c.uploadErr
	}
	m := builderclient.TaskDataMetadata{Key: request.Key, SizeBytes: request.SizeBytes, Readiness: builderclient.TaskDataStored}
	if c.metadataMutation != nil {
		c.metadataMutation(&m)
	}
	return m, nil
}

func (c *verifierEvidenceTaskDataClient) FinalizeVerifierEvidence(ctx context.Context, _ string, request builderclient.FinalizeVerifierEvidenceRequest) (builderclient.FinalizeVerifierEvidenceResponse, error) {
	c.finalizations = append(c.finalizations, request)
	pin, _ := builderclient.TLSPubkeyHashFromContext(ctx)
	c.pins = append(c.pins, pin)
	if c.finalizeErr != nil {
		return builderclient.FinalizeVerifierEvidenceResponse{}, c.finalizeErr
	}
	confirmation := builderclient.StorageConfirmation{
		SchemaVersion: 1, ChainID: request.Receipt.ChainID, BuilderOperator: inputTestBuilder, ServiceAuthorizationNonce: 1,
		Key: builderclient.EvidenceObjectKey(request.TaskHash, request.SessionID, request.TaskID, builderclient.DataKindEvidenceManifest,
			hex.EncodeToString(request.Receipt.VerifierEvidenceBundleHash), builderclient.EvidenceProducerVerifier, request.VerifyRound, request.VerifierOperator),
		SizeBytes: request.Receipt.VerifierEvidenceManifestSizeBytes, ArtifactTotalSizeBytes: uint64(len(c.uploads[0].Data)), RetentionUntilHeight: 500,
	}
	if c.confirmationMutation != nil {
		c.confirmationMutation(&confirmation)
	}
	digest, err := builderclient.StorageConfirmationSigningHash(confirmation)
	if err != nil {
		return builderclient.FinalizeVerifierEvidenceResponse{}, err
	}
	confirmation.Signature, err = c.signing.SignDigest(ctx, signer.DigestRequest{KeyRef: inputTestKeyRef, ExpectedSignerAddress: c.signerAddress, Digest: digest})
	if err != nil {
		return builderclient.FinalizeVerifierEvidenceResponse{}, err
	}
	if c.confirmationTamper != nil {
		c.confirmationTamper(&confirmation)
	}
	return builderclient.FinalizeVerifierEvidenceResponse{EvidenceBundleConfirmation: confirmation}, nil
}

type verifierPublisherFixture struct {
	publisher            nexusVerifierEvidencePublisher
	client               *verifierEvidenceTaskDataClient
	state                verifier.TaskState
	receipt              nodewire.ResultReceiptV2
	manifest, proof      []byte
	endpoint             worker.BuilderEndpoint
	db                   *store.Store
	dbPath, evidenceRoot string
}

func newVerifierPublisherFixture(t *testing.T) verifierPublisherFixture {
	t.Helper()
	dbPath, evidenceRoot := filepath.Join(t.TempDir(), "index"), t.TempDir()
	db, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	evidenceStore, err := evidence.NewStore(evidenceRoot, db)
	if err != nil {
		t.Fatal(err)
	}
	auth, signing := evidenceAuth(t)
	key := signing.(*signer.LocalSigner).Keys()[0]
	proof := []byte("canonical aggregate proof")
	proofHash := codec.HashBytes(proof)
	taskHash := codec.HashBytes([]byte("accepted verifier task"))
	state := verifier.TaskState{TaskID: outputTestTaskID, SessionID: strings.Repeat("11", 32), VerifyRound: 1}
	manifest, err := (evidencebundle.Manifest{Version: 1, ChainID: outputTestChainID, TaskID: state.TaskID, TaskHash: taskHash.String(), VerifyRound: 1,
		ProducerKind: "VERIFIER", ProducerOperator: inputTestOperator, EvidenceSchemaHash: evidenceTestSchemaHash,
		Artifacts: []evidencebundle.Artifact{evidencebundle.NewArtifact("aggregate_proof", proof)}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	bundleHash := evidencebundle.Hash(manifest)
	taskID, err := hex.DecodeString(state.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	generation := codec.HashBytes([]byte("generation"))
	receipt := nodewire.ResultReceiptV2{SchemaVersion: 2, ChainID: outputTestChainID, TaskID: taskID, VerifyRound: 1, VerifierOperatorAddress: inputTestOperator,
		ServiceAuthorizationNonce: 1, GenerationParamsDigest: generation[:], MetricRoot: bytes.Repeat([]byte{0x82}, 32), MetricSummary: nodewire.MetricSummaryV1{FiniteCount: 1},
		AggregateProofHash: proofHash[:], VerifierEvidenceBundleHash: bundleHash[:], VerifierEvidenceManifestSizeBytes: uint64(len(manifest)), Salt: bytes.Repeat([]byte{0x83}, 32), ExpiryHeight: 300}
	digest, err := nodewire.ResultReceiptSigningDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.ServiceSignature, err = signing.SignDigest(context.Background(), signer.DigestRequest{KeyRef: inputTestKeyRef, ExpectedSignerAddress: key.Address, Digest: digest})
	if err != nil {
		t.Fatal(err)
	}
	client := &verifierEvidenceTaskDataClient{signing: signing, signerAddress: key.Address}
	endpoint := worker.BuilderEndpoint{OperatorAddress: inputTestBuilder, AuthorizationNonce: 1, Endpoint: "https://builder.example", ServicePubkey: key.CompressedPubkey, TLSPubkeyHash: evidenceTestPin, CurrentHeight: 100}
	provider := worker.ReceivingBuilderFunc(func(_ context.Context, ref worker.ReceivingBuilderRef) (worker.BuilderEndpoint, error) {
		if ref.SessionID != state.SessionID || ref.TaskID != state.TaskID || ref.AssignedBuilderOperator != inputTestBuilder {
			t.Fatalf("wrong Builder resolution scope: %+v", ref)
		}
		return endpoint, nil
	})
	facts := taskfacts.ReaderFunc(func(_ context.Context, taskID string) (taskfacts.Facts, error) {
		return taskfacts.Facts{TaskID: taskID, TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
			AcceptedTaskHash: taskHash[:], GenerationParamsDigest: generation[:], ProfileExecutionSnapshotHash: bytes.Repeat([]byte{0x84}, 32)}}, nil
	})
	return verifierPublisherFixture{publisher: nexusVerifierEvidencePublisher{builderOperator: inputTestBuilder,
		cfg: TaskRunnerConfig{ChainID: outputTestChainID, LocalVerifierAddress: inputTestOperator, TaskData: client, TaskDataAuth: auth, ReceivingBuilder: provider, TaskFacts: facts, Evidence: evidenceStore, Store: db, ChainStatus: fixedChainStatus{height: 100, chainID: outputTestChainID}}},
		client: client, state: state, receipt: receipt, manifest: manifest, proof: proof, endpoint: endpoint, db: db, dbPath: dbPath, evidenceRoot: evidenceRoot}
}

func (f verifierPublisherFixture) publish() error {
	return f.publisher.PublishVerifierEvidence(context.Background(), f.state, f.receipt, f.manifest, f.proof)
}

func TestNexusVerifierEvidencePublisherFinalizesSignedBundle(t *testing.T) {
	f := newVerifierPublisherFixture(t)
	if err := f.publish(); err != nil {
		t.Fatal(err)
	}
	if len(f.client.uploads) != 2 || len(f.client.finalizations) != 1 {
		t.Fatalf("uploads=%d finalize=%d", len(f.client.uploads), len(f.client.finalizations))
	}
	for i, request := range f.client.uploads {
		if request.Key.ProducerOperator != inputTestOperator || request.Key.EvidenceProducerKind != builderclient.EvidenceProducerVerifier || request.Key.VerifyRound != 1 || request.Key.SessionID != f.state.SessionID || request.Key.TaskID != f.state.TaskID {
			t.Fatalf("upload %d lost full scoped reference: %+v", i, request.Key)
		}
		if len(request.Auth.Signature) != 64 || !strings.HasSuffix(request.Auth.Method, "/UploadTaskResultObject") {
			t.Fatal("upload authorization missing")
		}
	}
	if !bytes.Equal(f.client.uploads[0].Data, f.proof) || !bytes.Equal(f.client.uploads[1].Data, f.manifest) {
		t.Fatal("upload changed committed bytes")
	}
	request := f.client.finalizations[0]
	if request.VerifierOperator != inputTestOperator || request.VerifyRound != 1 || request.TaskID != f.state.TaskID || !bytes.Equal(request.Receipt.ServiceSignature, f.receipt.ServiceSignature) || !strings.HasSuffix(request.Auth.Method, "/FinalizeVerifierEvidence") {
		t.Fatal("finalization lost signed receipt or scope")
	}
	for _, pin := range f.client.pins {
		if pin != evidenceTestPin {
			t.Fatalf("publication lost TLS pin: %s", pin)
		}
	}
}

func TestNexusVerifierEvidencePublisherPropagatesUploadAndFinalizeFailures(t *testing.T) {
	for _, stage := range []string{"upload", "finalize"} {
		t.Run(stage, func(t *testing.T) {
			f := newVerifierPublisherFixture(t)
			failure := errors.New(stage + " rejected")
			if stage == "upload" {
				f.client.uploadErr = failure
			} else {
				f.client.finalizeErr = failure
			}
			if err := f.publish(); !errors.Is(err, failure) {
				t.Fatalf("lost %s error: %v", stage, err)
			}
			if stage == "upload" && len(f.client.finalizations) != 0 {
				t.Fatal("finalized a failed upload")
			}
		})
	}
}

func TestNexusVerifierEvidencePublisherValidatesFullConfirmation(t *testing.T) {
	mutations := map[string]func(*builderclient.StorageConfirmation){
		"chain":        func(c *builderclient.StorageConfirmation) { c.ChainID += "-other" },
		"builder":      func(c *builderclient.StorageConfirmation) { c.BuilderOperator = inputTestOperator },
		"nonce":        func(c *builderclient.StorageConfirmation) { c.ServiceAuthorizationNonce++ },
		"task hash":    func(c *builderclient.StorageConfirmation) { c.Key.TaskHash = strings.Repeat("ab", 32) },
		"session":      func(c *builderclient.StorageConfirmation) { c.Key.SessionID = strings.Repeat("ac", 32) },
		"task":         func(c *builderclient.StorageConfirmation) { c.Key.TaskID = strings.Repeat("ad", 32) },
		"content hash": func(c *builderclient.StorageConfirmation) { c.Key.ContentHash = strings.Repeat("ae", 32) },
		"producer":     func(c *builderclient.StorageConfirmation) { c.Key.ProducerOperator = inputTestBuilder },
		"producer kind": func(c *builderclient.StorageConfirmation) {
			c.Key.EvidenceProducerKind = builderclient.EvidenceProducerWorker
		},
		"round":         func(c *builderclient.StorageConfirmation) { c.Key.VerifyRound = 2 },
		"size":          func(c *builderclient.StorageConfirmation) { c.SizeBytes++ },
		"artifact size": func(c *builderclient.StorageConfirmation) { c.ArtifactTotalSizeBytes++ },
		"expired":       func(c *builderclient.StorageConfirmation) { c.RetentionUntilHeight = 99 },
		"expires now":   func(c *builderclient.StorageConfirmation) { c.RetentionUntilHeight = 100 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			f := newVerifierPublisherFixture(t)
			f.client.confirmationMutation = mutate
			if err := f.publish(); err == nil {
				t.Fatalf("accepted correctly signed confirmation with mismatched %s", name)
			}
		})
	}
	for _, name := range []string{"schema", "kind", "signature", "missing signature"} {
		t.Run(name, func(t *testing.T) {
			f := newVerifierPublisherFixture(t)
			f.client.confirmationTamper = func(c *builderclient.StorageConfirmation) {
				switch name {
				case "schema":
					c.SchemaVersion = 2
				case "kind":
					c.Key.Kind = builderclient.DataKindEvidenceArtifact
				case "signature":
					c.Signature[0] ^= 1
				case "missing signature":
					c.Signature = nil
				}
			}
			if err := f.publish(); err == nil {
				t.Fatalf("accepted confirmation with invalid %s", name)
			}
		})
	}
}

func TestNexusVerifierEvidencePublisherUsesRefreshedBuilderIdentity(t *testing.T) {
	for _, name := range []string{"operator", "height", "nonce", "pubkey"} {
		t.Run(name, func(t *testing.T) {
			f := newVerifierPublisherFixture(t)
			reads := 0
			f.publisher.cfg.ReceivingBuilder = worker.ReceivingBuilderFunc(func(context.Context, worker.ReceivingBuilderRef) (worker.BuilderEndpoint, error) {
				reads++
				current := f.endpoint
				if reads > 1 {
					switch name {
					case "operator":
						current.OperatorAddress = inputTestOperator
					case "height":
						current.CurrentHeight = 0
					case "nonce":
						current.AuthorizationNonce++
					case "pubkey":
						current.ServicePubkey = strings.Repeat("02", 33)
					}
				}
				return current, nil
			})
			if err := f.publish(); err == nil {
				t.Fatalf("accepted stale confirmation after current Builder %s changed", name)
			}
			if reads != 2 {
				t.Fatalf("current Builder reads=%d", reads)
			}
		})
	}
}

func TestNexusVerifierEvidencePublisherRejectsReceiptAndUploadMismatch(t *testing.T) {
	for _, name := range []string{"manifest bytes", "manifest size", "proof bytes", "proof hash", "chain", "task", "round", "producer", "upload key", "upload size", "upload readiness"} {
		t.Run(name, func(t *testing.T) {
			f := newVerifierPublisherFixture(t)
			switch name {
			case "manifest bytes":
				f.manifest = append(f.manifest, '\n')
			case "manifest size":
				f.receipt.VerifierEvidenceManifestSizeBytes++
			case "proof bytes":
				f.proof[0] ^= 1
			case "proof hash":
				f.receipt.AggregateProofHash[0] ^= 1
			case "chain":
				f.receipt.ChainID += "-other"
			case "task":
				f.receipt.TaskID[0] ^= 1
			case "round":
				f.receipt.VerifyRound++
			case "producer":
				f.receipt.VerifierOperatorAddress = inputTestBuilder
			case "upload key":
				f.client.metadataMutation = func(m *builderclient.TaskDataMetadata) { m.Key.ContentHash = strings.Repeat("aa", 32) }
			case "upload size":
				f.client.metadataMutation = func(m *builderclient.TaskDataMetadata) { m.SizeBytes++ }
			case "upload readiness":
				f.client.metadataMutation = func(m *builderclient.TaskDataMetadata) { m.Readiness = 0 }
			}
			if err := f.publish(); err == nil {
				t.Fatalf("accepted mismatched %s", name)
			}
			if len(f.client.finalizations) != 0 {
				t.Fatal("finalized invalid upload or receipt")
			}
		})
	}
}

func TestNexusVerifierEvidencePublisherRecoversAfterReopenAndBuilderRotation(t *testing.T) {
	f := newVerifierPublisherFixture(t)
	if err := f.publish(); err != nil {
		t.Fatal(err)
	}
	manifest, err := evidencebundle.Decode(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	taskHash, err := decodeCanonicalHash(manifest.TaskHash, "task hash")
	if err != nil {
		t.Fatal(err)
	}
	before, err := f.publisher.cfg.Evidence.ReadTaskKind(context.Background(), taskHash, "verifier-evidence-confirmation-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(context.Background(), f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	reopenedEvidence, err := evidence.NewStore(f.evidenceRoot, reopened)
	if err != nil {
		t.Fatal(err)
	}
	f.publisher.cfg.Store, f.publisher.cfg.Evidence = reopened, reopenedEvidence
	f.publisher.cfg.ChainStatus = fixedChainStatus{height: 110, chainID: outputTestChainID}
	resolutions := 0
	f.publisher.cfg.ReceivingBuilder = worker.ReceivingBuilderFunc(func(context.Context, worker.ReceivingBuilderRef) (worker.BuilderEndpoint, error) {
		resolutions++
		rotated := f.endpoint
		rotated.AuthorizationNonce++
		rotated.ServicePubkey = strings.Repeat("02", 33)
		return rotated, nil
	})
	if err := f.publish(); err != nil {
		t.Fatalf("recover rotated Builder confirmation: %v", err)
	}
	if err := f.publish(); err != nil {
		t.Fatalf("repeat recovery: %v", err)
	}
	if len(f.client.finalizations) != 1 || len(f.client.uploads) != 2 || resolutions != 0 {
		t.Fatalf("recovered finalization performed network work: finalizations=%d uploads=%d resolutions=%d", len(f.client.finalizations), len(f.client.uploads), resolutions)
	}
	after, err := f.publisher.cfg.Evidence.ReadTaskKind(context.Background(), taskHash, "verifier-evidence-confirmation-1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("recovery rewrote verified identity record")
	}
}

func TestNexusVerifierEvidencePublisherRejectsInvalidRetainedConfirmation(t *testing.T) {
	base := newVerifierPublisherFixture(t)
	if err := base.publish(); err != nil {
		t.Fatal(err)
	}
	manifest, err := evidencebundle.Decode(base.manifest)
	if err != nil {
		t.Fatal(err)
	}
	taskHash, err := decodeCanonicalHash(manifest.TaskHash, "task hash")
	if err != nil {
		t.Fatal(err)
	}
	valid, err := base.publisher.cfg.Evidence.ReadTaskKind(context.Background(), taskHash, "verifier-evidence-confirmation-1")
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*verifierEvidenceConfirmation){
		"schema":              func(r *verifierEvidenceConfirmation) { r.Version = 0 },
		"nonce":               func(r *verifierEvidenceConfirmation) { r.BuilderAuthorizationNonce++ },
		"pubkey":              func(r *verifierEvidenceConfirmation) { r.BuilderServicePubkey = strings.Repeat("02", 33) },
		"future verification": func(r *verifierEvidenceConfirmation) { r.VerifiedAtHeight = 101 },
		"task":                func(r *verifierEvidenceConfirmation) { r.Confirmation.Key.TaskID = strings.Repeat("af", 32) },
		"round":               func(r *verifierEvidenceConfirmation) { r.Confirmation.Key.VerifyRound = 2 },
		"size":                func(r *verifierEvidenceConfirmation) { r.Confirmation.SizeBytes++ },
		"proof size":          func(r *verifierEvidenceConfirmation) { r.Confirmation.ArtifactTotalSizeBytes++ },
		"signature":           func(r *verifierEvidenceConfirmation) { r.Confirmation.Signature[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			f := newVerifierPublisherFixture(t)
			var record verifierEvidenceConfirmation
			if err := json.Unmarshal(valid, &record); err != nil {
				t.Fatal(err)
			}
			mutate(&record)
			encoded, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeTaskEvidence(context.Background(), f.publisher.cfg.Evidence, taskHash, f.state.SessionID, f.state.TaskID, "verifier-evidence-confirmation-1", encoded); err != nil {
				t.Fatal(err)
			}
			if err := f.publish(); err == nil {
				t.Fatal("accepted invalid retained confirmation")
			}
			if len(f.client.uploads) != 0 || len(f.client.finalizations) != 0 {
				t.Fatal("invalid retained record was replaced with a new finalization")
			}
		})
	}
	base.publisher.cfg.ChainStatus = fixedChainStatus{height: 500, chainID: outputTestChainID}
	if err := base.publish(); err == nil {
		t.Fatal("accepted expired retained confirmation")
	}
	if len(base.client.finalizations) != 1 {
		t.Fatal("re-finalized an expired retained confirmation")
	}
}

func TestNexusVerifierEvidencePublisherRequiresDurableConfirmationStore(t *testing.T) {
	f := newVerifierPublisherFixture(t)
	f.publisher.cfg.Evidence = nil
	if err := f.publish(); err == nil {
		t.Fatal("silently finalized without durable evidence")
	}
	if len(f.client.uploads) != 0 {
		t.Fatal("uploaded before checking durable evidence")
	}
}
