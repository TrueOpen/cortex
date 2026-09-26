package task_data_plane_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/daemon"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/evidencebundle"
	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/metric"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/taskdataauth"
	"github.com/TrueOpen/cortex/internal/taskfacts"
	"github.com/TrueOpen/cortex/internal/worker"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	nexusv1connect "github.com/TrueOpen/cortex/proto/nexus/v1/nexusv1connect"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
	"github.com/TrueOpen/cortex/test/internal/generationfixture"
)

const (
	proofChainID        = "trueopen-task-data-test-1"
	proofBuilder        = "trueopen1j7r6u8nwvw93l2tc0wd75v07vu89lxyfqf8fut"
	proofModelID        = "f8b762b85eb8a524e7809a53bafb399f55bdac316c495822dcba0e029909daa0"
	proofModelServiceID = "fake-model-service"
	proofServiceKeyRef  = "test-cortex-service-key"
	proofTokenCount     = uint64(4)
	proofSessionID      = "def19113d1563750293e422daac896f48dcb1428636ea240ef57474a25187919"
	proofOrderSequence  = uint64(8)
	proofOutputMedia    = "application/octet-stream"
	// proofInferDeadline is the assignment's infer deadline, which is also the
	// expiry_height a receipt credential is anchored to: node admits a receipt
	// only while height <= min(receipt.expiry_height, infer_deadline_height).
	proofInferDeadline = uint64(140)
	// proofServiceAuthorizationNonce is the nonce the fake Keeper snapshot holds
	// for this node, so it is the replay counter a real receipt would carry.
	proofServiceAuthorizationNonce = uint64(1)
)

var (
	proofInput  = []byte("contract-faithful input: alpha beta gamma delta epsilon")
	proofOutput = []byte("€§¶, Cortex data plane") // deliberately multi-byte UTF-8

	// The Worker operator's own key. Nexus's verifyRequesterKey accepts either a
	// presented key that derives the requester operator address or one that is
	// byte-equal to that operator's registered CORTEX-domain current service key,
	// so the harness operator address must be derivable from a real key for the
	// first disjunct to be reachable at all. Cortex never signs with this key;
	// it exists so the fake Nexus models both branches of the contract.
	proofOperatorPrivate = secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{0x41}, 32))
	proofOperatorPubkey  = proofOperatorPrivate.PubKey().SerializeCompressed()
	// The Worker operator address the whole package uses, derived from that key so
	// the operator-self-sign branch is reachable and stays stable across tests.
	proofWorkerOperator = mustProofWorkerOperator()
	proofTaskID         = identity.TaskIDString(proofSessionID, proofOrderSequence)
)

func mustProofWorkerOperator() string {
	address, err := signer.AddressFromCompressedPublicKey("trueopen", proofOperatorPubkey)
	if err != nil {
		panic("derive proof Worker operator address: " + err.Error())
	}
	return address
}

// TestWorkerTaskDataPlaneInputPathAndReceiptRefusal drives the real Worker across
// the whole input half of the task-data plane and then into the deliberate
// fail-closed boundary that ends the output half.
//
// The refusal is intentional: this harness omits the locked Profile's
// evidence_schema_hash and evidence requirements, so builderclient.BuildInferReceipt
// cannot sign a frozen receipt. The production daemon reads them from
// hub.v1.Query/Profile and passes them to the Worker; this test deliberately
// does not, to exercise the fail-closed boundary. task_hash and
// generation_params_digest are no longer among the gaps: the Worker reads them
// through chainclient.KeeperABCIClient.TaskReceiptFacts, and this harness serves
// that read. So the Worker must get as far as inference and durable infer
// artifacts, and then relay nothing at all: no receipt, no upload, no storage
// confirmation, no OUTPUT_AVAILABLE.
func TestWorkerTaskDataPlaneInputPathAndReceiptRefusal(t *testing.T) {
	h := newTaskDataHarness(t, harnessOptions{})
	if err := h.runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("TaskRunner.RunOnce: %v", err)
	}
	h.requireFinished(t)

	// Input half: one authenticated metadata read, one signed range, a chunked
	// stream, and exactly one inference over the bytes the Keeper committed.
	if h.model.InferCalls() != 1 || !bytes.Equal(h.model.InferInput(), proofInput) {
		t.Fatalf("model calls=%d input=%q, want one inference over fetched input", h.model.InferCalls(), h.model.InferInput())
	}
	fetchOffsets, fetchNonces, chunkSizes := h.nexus.FetchObservations()
	if len(fetchOffsets) != 1 || fetchOffsets[0] != 0 {
		t.Fatalf("fetch offsets = %v, want one complete range at zero", fetchOffsets)
	}
	if len(fetchNonces) != 1 || len(fetchNonces[0]) != 32 {
		t.Fatalf("fetch nonces = %x, want one 32-byte nonce", fetchNonces)
	}
	if len(chunkSizes) < 3 || chunkSizes[0] == chunkSizes[1] || chunkSizes[1] == chunkSizes[2] {
		t.Fatalf("fetch chunks = %v, want at least three non-uniform chunks", chunkSizes)
	}
	expiries := h.nexus.AuthExpiries()
	if len(expiries) != 3 {
		t.Fatalf("authenticated request count = %d, want metadata, fetch and output stream Header", len(expiries))
	}
	if expiries[1] <= expiries[0] {
		t.Fatalf("auth expiries = %v, want a fresh chain height on every signature", expiries)
	}

	// Output half: the refusal, named. Only the first of the remaining ordered
	// checks can ever appear in one error, and internal/builderclient owns the
	// per-field message set; what this proves is that the Worker's own callsite
	// reaches it.
	err := h.executor.TerminalError()
	if !errors.Is(err, builderclient.ErrInferReceiptInputUnavailable) {
		t.Fatalf("prepareOutput error = %v, want a refusal wrapping ErrInferReceiptInputUnavailable", err)
	}
	if !strings.Contains(err.Error(), "hub.v1.Query/Profile") {
		t.Fatalf("refusal = %v, want it to name the chain read it is waiting on", err)
	}
	if h.nexus.RelayCalls() != 0 || h.nexus.UploadCalls() != 1 {
		t.Fatalf("receipt refusal must leave only a STORED stream: relay=%d upload=%d", h.nexus.RelayCalls(), h.nexus.UploadCalls())
	}
	if got := h.publisher.OutputAvailableCount(); got != 0 {
		t.Fatalf("OUTPUT_AVAILABLE = %d, want 0 when no receipt could be signed", got)
	}
	if got := h.checkpoints.storageConfirmations(h.assignment.TaskID); len(got) != 0 {
		t.Fatalf("storage confirmations = %d, want 0", len(got))
	}
	if _, ok := h.checkpoints.inferReceipt(h.assignment.TaskID); ok {
		t.Fatal("a receipt checkpoint was written even though no receipt could be signed")
	}

	// The infer artifacts are persisted before the receipt is assembled, so the
	// evidence a later reveal needs survives the refusal. The receipt evidence
	// does not exist, so it must be absent rather than empty.
	evidencePaths := h.checkpoints.evidencePaths()
	for _, kind := range []string{"worker-output", "worker-token-ids-material", "worker-position-values-material"} {
		path, ok := evidencePaths[kind]
		if !ok {
			t.Fatalf("durable %s evidence is missing", kind)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("durable %s evidence: %v", kind, err)
		}
	}
	if _, ok := evidencePaths["worker-infer-receipt"]; ok {
		t.Fatal("receipt evidence was written for a receipt that was never signed")
	}
}

func TestWorkerTaskDataPlaneProtocolRiskAndRetries(t *testing.T) {
	t.Run("transient fetch interruption resumes at confirmed offset with fresh nonce", func(t *testing.T) {
		h := newTaskDataHarness(t, harnessOptions{behavior: nexusBehavior{interruptFetchOnce: true}})
		if err := h.runner.RunOnce(context.Background()); err != nil {
			t.Fatalf("TaskRunner.RunOnce: %v", err)
		}
		h.requireFinished(t)
		offsets, nonces, _ := h.nexus.FetchObservations()
		if len(offsets) != 2 || offsets[0] != 0 || offsets[1] != 3 {
			t.Fatalf("fetch offsets = %v, want resume [0 3]", offsets)
		}
		if len(nonces) != 2 || bytes.Equal(nonces[0], nonces[1]) {
			t.Fatalf("fetch retry nonces = %x, want distinct nonces", nonces)
		}
		// The resumed fetch still yields the committed input, so inference runs
		// once; the output half then stops at the same frozen-receipt refusal.
		if h.model.InferCalls() != 1 || !bytes.Equal(h.model.InferInput(), proofInput) {
			t.Fatalf("Infer calls=%d input=%q, want one inference over the resumed input", h.model.InferCalls(), h.model.InferInput())
		}
		if !errors.Is(h.executor.TerminalError(), builderclient.ErrInferReceiptInputUnavailable) {
			t.Fatalf("resumed run error = %v, want the frozen receipt refusal", h.executor.TerminalError())
		}
		if h.publisher.OutputAvailableCount() != 0 {
			t.Fatalf("OUTPUT_AVAILABLE = %d, want 0", h.publisher.OutputAvailableCount())
		}
	})

	t.Run("input hash mismatch prevents inference and downstream effects", func(t *testing.T) {
		keeperInput := append([]byte(nil), proofInput...)
		servedInput := append([]byte(nil), proofInput...)
		servedInput[len(servedInput)-1] ^= 0x01
		declared := codec.HashBytes(keeperInput)
		h := newTaskDataHarness(t, harnessOptions{
			keeperInput: keeperInput,
			servedInput: servedInput,
			behavior:    nexusBehavior{declaredInputSemanticHash: hex.EncodeToString(declared[:])},
		})
		if err := h.runner.RunOnce(context.Background()); err != nil {
			t.Fatalf("TaskRunner.RunOnce: %v", err)
		}
		h.requireFinished(t)
		if h.model.InferCalls() != 0 || h.nexus.RelayCalls() != 0 || h.nexus.UploadCalls() != 0 {
			t.Fatalf("forbidden calls after input mismatch: infer=%d relay=%d upload=%d", h.model.InferCalls(), h.nexus.RelayCalls(), h.nexus.UploadCalls())
		}
		if h.publisher.OutputAvailableCount() != 0 || len(h.checkpoints.storageConfirmations(h.assignment.TaskID)) != 0 {
			t.Fatal("input mismatch produced confirmation or OUTPUT_AVAILABLE")
		}
	})

	t.Run("expired request height retries only while chain deadline is open", func(t *testing.T) {
		h := newTaskDataHarness(t, harnessOptions{
			authHeight:   100,
			runnerHeight: 130,
			serverHeight: 121,
		})
		if err := h.runner.RunOnce(context.Background()); err != nil {
			t.Fatalf("first TaskRunner.RunOnce: %v", err)
		}
		h.requireActiveRetryCount(t, 1)
		firstAttempts := h.nexus.AuthAttempts()
		if len(firstAttempts) != 1 || firstAttempts[0].method != "GetTaskDataMetadata" || firstAttempts[0].expiry != 120 {
			t.Fatalf("first expired auth attempts = %#v, want metadata expiry 120", firstAttempts)
		}
		firstTask := h.activeTask(t)
		if firstTask.RetryCount != 1 || h.model.InferCalls() != 0 {
			t.Fatalf("first expired request task=%#v Infer=%d", firstTask, h.model.InferCalls())
		}

		h.authHeight.Set(101)
		h.nexus.SetCurrentHeight(122)
		h.restartRunner()
		if err := h.runner.RunOnce(context.Background()); err != nil {
			t.Fatalf("second TaskRunner.RunOnce: %v", err)
		}
		secondTask := h.activeTask(t)
		if secondTask.RetryCount != 2 {
			t.Fatalf("second expired request task=%#v, want retry 2", secondTask)
		}
		attempts := h.nexus.AuthAttempts()
		if len(attempts) != 2 || attempts[1].method != "GetTaskDataMetadata" || attempts[1].expiry != 121 ||
			bytes.Equal(attempts[0].nonce, attempts[1].nonce) {
			t.Fatalf("expired auth retries = %#v, want fresh nonce and height-bound expiry", attempts)
		}

		h.runnerHeight.Set(h.assignment.InferDeadlineHeight + 1)
		h.restartRunner()
		if err := h.runner.RunOnce(context.Background()); err != nil {
			t.Fatalf("deadline TaskRunner.RunOnce: %v", err)
		}
		h.requireFinished(t)
		if got := len(h.nexus.AuthAttempts()); got != 2 {
			t.Fatalf("auth attempts after chain deadline = %d, want no third request", got)
		}
		if h.model.InferCalls() != 0 || h.nexus.RelayCalls() != 0 || h.nexus.UploadCalls() != 0 {
			t.Fatal("expired input auth triggered forbidden inference/output effects")
		}
		if h.publisher.OutputAvailableCount() != 0 {
			t.Fatalf("OUTPUT_AVAILABLE = %d, want 0", h.publisher.OutputAvailableCount())
		}
	})
}

// TestNexusEnforcesOperatorRequesterAuthorization mirrors Nexus 44d5627: the
// signed Requester must be the on-chain selected Worker operator, while the
// presented key may be that operator's CORTEX-domain current service key.
func TestNexusEnforcesOperatorRequesterAuthorization(t *testing.T) {
	for _, name := range []string{"valid", "operator key", "unregistered key", "other operator", "stale binding", "wrong task", "body tamper", "replay"} {
		t.Run(name, func(t *testing.T) {
			h := newTaskDataHarness(t, harnessOptions{})
			key := builderclient.TaskDataKey{TaskHash: codec.HashWithDomain("PROOF_ACCEPTED_TASK_HASH_V1", []byte(proofTaskID)).String(), SessionID: proofSessionID, TaskID: proofTaskID, Kind: builderclient.DataKindInput, ContentHash: codec.HashBytes(proofInput).String()}
			body, err := builderclient.TaskDataMetadataBodyDigest(key)
			if err != nil {
				t.Fatal(err)
			}
			auth, err := h.auth.SignRequest(context.Background(), "GetTaskDataMetadata", key, proofBuilder, body)
			if err != nil {
				t.Fatal(err)
			}
			signingKey := h.servicePrivate
			switch name {
			case "operator key":
				signingKey = proofOperatorPrivate
			case "unregistered key":
				signingKey = secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{0x57}, 32))
			case "other operator":
				auth.Requester = "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"
			case "stale binding":
				auth.ServiceAuthorizationNonce++
			case "wrong task":
				key.TaskID = strings.Repeat("99", 32)
			case "body tamper":
				auth.BodyDigest = codec.HashBytes([]byte("other"))
			}
			digest, err := builderclient.TaskDataRequestSigningHash(auth)
			if err != nil {
				t.Fatal(err)
			}
			auth.Signature = compactSignature(signingKey, digest)
			request := connect.NewRequest(&nexusv1.GetTaskDataMetadataRequest{ObjectRef: proofKeyToProto(key), RequestAuth: authToProto(auth)})
			_, err = h.ingress().GetTaskDataMetadata(context.Background(), request)
			if name == "valid" || name == "replay" {
				if err != nil {
					t.Fatal(err)
				}
				if name == "replay" {
					if _, err = h.ingress().GetTaskDataMetadata(context.Background(), request); connect.CodeOf(err) != connect.CodeAlreadyExists {
						t.Fatalf("replay error=%v", err)
					}
				}
			} else if err == nil {
				t.Fatal("unauthorized or modified metadata request accepted")
			}
		})
	}
}

// proofReceiptFacts are the complete fact set a frozen receipt requires. Three
// of them are exactly what production cannot supply yet, so the fixture states
// them here and says which chain read each one stands for; going through
// builderclient.BuildInferReceipt keeps the fixture honest, because a change to
// the required fact set breaks it loudly instead of silently producing a receipt
// nobody would accept.
func proofReceiptFacts(t *testing.T) builderclient.InferReceiptFacts {
	t.Helper()
	taskHash := codec.HashWithDomain("TRUEOPEN_TASK_ORDER_V1", []byte(proofTaskID))
	generation := codec.HashWithDomain("TRUEOPEN_TASK_GENERATION_PARAMS_V1", []byte(proofTaskID))
	outputHash, _ := codec.OutputMMRRoot([][]byte{proofOutput})
	inputHash, _ := nodewire.InputTokenIDsHash([]uint32{7})
	generatedHash, _ := nodewire.GeneratedTokenIDsHash([]uint32{1, 2, 3, 4})
	evidence := proofEvidence(t, taskHash.String())
	commitments, err := builderclient.WorkerEvidenceCommitments(builderclient.WorkerEvidenceFacts{ChainID: proofChainID, TaskID: proofTaskID, AcceptedTaskHash: taskHash.String(), WorkerOperatorAddress: proofWorkerOperator, GenerationParamsDigest: generation.String(), EvidenceSchemaHash: proofEvidenceSchemaHash().String(), OutputHash: outputHash, OutputSizeBytes: uint64(len(proofOutput)), OutputLeafCount: 1, GeneratedTokenCount: proofTokenCount, FinishReason: nodewire.FinishReasonV1EosToken, InputTokenIDsHash: inputHash, GeneratedTokenIDsHash: generatedHash, InputTokenIDsSizeBytes: uint64(len(evidence.input)), GeneratedTokenIDsSizeBytes: uint64(len(evidence.generated)), WorkerValueRoot: evidence.valueRoot, WorkerValuesEncodedSizeBytes: uint64(len(evidence.values))})
	if err != nil {
		t.Fatal(err)
	}
	return builderclient.InferReceiptFacts{ChainID: proofChainID, TaskID: proofTaskID, TaskHash: taskHash.String(), WorkerOperatorAddress: proofWorkerOperator, ServiceAuthorizationNonce: proofServiceAuthorizationNonce, GenerationParamsDigest: generation.String(), OutputHash: outputHash, OutputLeafCount: 1, OutputSizeBytes: uint64(len(proofOutput)), GeneratedTokenCount: proofTokenCount, RequiredEvidenceCommitments: commitments, ProfileEvidenceRequirements: builderclient.WorkerEvidenceRequirementsV3(), ExpiryHeight: proofInferDeadline}
}

// proofRequiredTopK frames the proof Worker's worker_values.
const proofRequiredTopK = 4

func proofEvidenceSchemaHash() codec.Hash {
	return codec.HashWithDomain("TRUEOPEN_EVIDENCE_SCHEMA_V1", []byte(proofTaskID))
}

// proofWorkerEvidence is the content of the proof Worker's two bundles.
type proofWorkerEvidence struct {
	input, generated, values     []byte
	valueRoot                    codec.Hash
	valueManifest, tokenManifest []byte
}

// proofValues are the position values of the proof generation [1, 2, 3, 4].
func proofValues() []metric.PositionValue {
	values := make([]metric.PositionValue, proofTokenCount)
	for i := range values {
		id := uint32(i + 1)
		values[i] = metric.PositionValue{TokenID: id, Logprob: -0.25, Rank: 1, TopK: []metric.TokenLogprob{
			{TokenID: id, Logprob: -0.25}, {TokenID: 100 + id, Logprob: -1}, {TokenID: 200 + id, Logprob: -2}, {TokenID: 300 + id, Logprob: -3},
		}}
	}
	return values
}

func proofEvidence(t testing.TB, taskHash string) proofWorkerEvidence {
	t.Helper()
	var out proofWorkerEvidence
	out.input, _ = nodewire.EncodeTokenIDs([]uint32{7})
	out.generated, _ = nodewire.EncodeTokenIDs([]uint32{1, 2, 3, 4})
	taskID, _ := hex.DecodeString(proofTaskID)
	acceptedHash, _ := hex.DecodeString(taskHash)
	binding := nodewire.WorkerValueBindingV1{ChainID: proofChainID, TaskID: taskID, AcceptedTaskHash: acceptedHash, WorkerOperatorAddress: proofWorkerOperator, RequiredTopK: proofRequiredTopK}
	leaves, err := metric.ValueLeaves(proofValues(), proofRequiredTopK)
	if err != nil {
		t.Fatal(err)
	}
	if out.values, err = nodewire.EncodeWorkerValues(binding, leaves); err != nil {
		t.Fatal(err)
	}
	if out.valueRoot, err = nodewire.WorkerValueRoot(binding, leaves); err != nil {
		t.Fatal(err)
	}
	scope := func(kind string, artifacts ...evidencebundle.Artifact) []byte {
		encoded, err := (evidencebundle.Manifest{Artifacts: artifacts, ChainID: proofChainID, EvidenceKind: kind, EvidenceSchemaHash: proofEvidenceSchemaHash().String(), Version: 1, ProducerKind: "WORKER", ProducerOperator: proofWorkerOperator, TaskHash: taskHash, TaskID: proofTaskID, VerifyRound: 1}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	out.valueManifest = scope(evidencebundle.KindWorkerValueOpening, evidencebundle.NewArtifact("worker_values", out.values))
	out.tokenManifest = scope(evidencebundle.KindWorkerTokenOpening, evidencebundle.NewArtifact("generated_token_ids", out.generated), evidencebundle.NewArtifact("input_token_ids", out.input))
	return out
}

func proofSignedReceipt(t *testing.T, service *secp256k1.PrivateKey, facts builderclient.InferReceiptFacts) builderclient.SignedInferReceipt {
	t.Helper()
	receipt, digest, err := builderclient.BuildInferReceipt(facts)
	if err != nil {
		t.Fatalf("BuildInferReceipt: %v", err)
	}
	receipt.ServiceSignature = hex.EncodeToString(compactSignature(service, digest))
	return receipt
}

// TestNexusFrozenInferReceiptRelayAndUpload drives the real
// builderclient.ConnectTaskDataClient across the output half of the task-data
// plane with a frozen receipt. The Worker cannot reach this half today (see
// TestWorkerTaskDataPlaneInputPathAndReceiptRefusal), so these are the
// assertions that keep the relay and upload contract honest.
func TestNexusFrozenInferReceiptRelayAndUpload(t *testing.T) {
	t.Run("relay and staging require atomic finalization before fetching", func(t *testing.T) {
		h := newTaskDataHarness(t, harnessOptions{})
		receipt := proofSignedReceipt(t, h.servicePrivate, proofReceiptFacts(t))
		if err := h.relayReceipt(context.Background(), receipt); err != nil {
			t.Fatal(err)
		}
		digest, err := builderclient.InferReceiptSigningDigest(receipt)
		if err != nil {
			t.Fatal(err)
		}
		if h.nexus.ReceiptDigest() != digest || !reflect.DeepEqual(h.nexus.Receipt(), receipt) {
			t.Fatal("relay changed signed receipt")
		}
		key := h.outputKey(receipt)
		metadata, err := h.stageObject(context.Background(), key, proofOutput, proofOutputMedia)
		if err != nil || metadata.Readiness != builderclient.TaskDataStored {
			t.Fatalf("stage=%+v err=%v", metadata, err)
		}
		if err := h.fetchObject(key); err == nil {
			t.Fatal("STORED output became fetchable before finalize")
		}
		if _, err := h.finalizeReceipt(context.Background(), receipt); err == nil {
			t.Fatal("finalized with missing bundle")
		}
		h.stageBundle(t, receipt)
		finalized, err := h.finalizeReceipt(context.Background(), receipt)
		if err != nil {
			t.Fatal(err)
		}
		if len(finalized.EvidenceBundleConfirmations) != 1 {
			t.Fatal("missing bundle confirmation")
		}
		for _, c := range []builderclient.StorageConfirmation{finalized.OutputConfirmation, finalized.EvidenceBundleConfirmations[0]} {
			digest, err := builderclient.StorageConfirmationSigningHash(c)
			if err != nil {
				t.Fatal(err)
			}
			if err := signer.VerifyDigestSignature(h.builderPubkey, digest, c.Signature); err != nil {
				t.Fatal(err)
			}
		}
		if err := h.fetchObject(key); err != nil {
			t.Fatal(err)
		}
		repeat, err := h.finalizeReceipt(context.Background(), receipt)
		if err != nil || !repeat.Idempotent {
			t.Fatalf("idempotent finalize=%+v err=%v", repeat, err)
		}
		changedFacts := proofReceiptFacts(t)
		changedFacts.GeneratedTokenCount++
		if _, err := h.finalizeReceipt(context.Background(), proofSignedReceipt(t, h.servicePrivate, changedFacts)); err == nil {
			t.Fatal("conflicting finalize material accepted")
		}
	})
	t.Run("relay acknowledgment must match signed receipt", func(t *testing.T) {
		h := newTaskDataHarness(t, harnessOptions{behavior: nexusBehavior{receiptResponseMismatch: true}})
		receipt := proofSignedReceipt(t, h.servicePrivate, proofReceiptFacts(t))
		if err := h.relayReceipt(context.Background(), receipt); err == nil {
			t.Fatal("wrong relay acknowledgment accepted")
		}
	})
	mutations := map[string]func(*builderclient.SignedInferReceipt){
		"schema":            func(r *builderclient.SignedInferReceipt) { r.SchemaVersion++ },
		"chain":             func(r *builderclient.SignedInferReceipt) { r.ChainID = "other" },
		"task hash":         func(r *builderclient.SignedInferReceipt) { r.TaskHash = strings.Repeat("99", 32) },
		"output size":       func(r *builderclient.SignedInferReceipt) { r.OutputSizeBytes++ },
		"output hash":       func(r *builderclient.SignedInferReceipt) { r.OutputHash = strings.Repeat("99", 32) },
		"token count":       func(r *builderclient.SignedInferReceipt) { r.GeneratedTokenCount++ },
		"nonce":             func(r *builderclient.SignedInferReceipt) { r.ServiceAuthorizationNonce++ },
		"expiry":            func(r *builderclient.SignedInferReceipt) { r.ExpiryHeight++ },
		"generation digest": func(r *builderclient.SignedInferReceipt) { r.GenerationParamsDigest = strings.Repeat("99", 32) },
		"evidence root":     func(r *builderclient.SignedInferReceipt) { r.RequiredEvidenceCommitments[0].EvidenceHashOrRoot[0] ^= 1 },
		"evidence size":     func(r *builderclient.SignedInferReceipt) { r.RequiredEvidenceCommitments[0].EncodedSizeBytes++ },
		"missing evidence":  func(r *builderclient.SignedInferReceipt) { r.RequiredEvidenceCommitments = nil },
		"worker": func(r *builderclient.SignedInferReceipt) {
			r.WorkerOperatorAddress = "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"
		},
	}
	for name, mutate := range mutations {
		t.Run("signed receipt tamper "+name, func(t *testing.T) {
			h := newTaskDataHarness(t, harnessOptions{})
			receipt := proofSignedReceipt(t, h.servicePrivate, proofReceiptFacts(t))
			mutate(&receipt)
			_, err := h.ingress().SubmitInferReceipt(context.Background(), connect.NewRequest(&nexusv1.SubmitInferReceiptRequest{Receipt: receiptToProto(receipt)}))
			if err == nil || h.nexus.RelayCalls() != 0 {
				t.Fatal("modified signed receipt reached relay acceptance")
			}
		})
	}
	t.Run("foreign service key receipt", func(t *testing.T) {
		h := newTaskDataHarness(t, harnessOptions{})
		receipt := proofSignedReceipt(t, secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{0x57}, 32)), proofReceiptFacts(t))
		if err := h.relayReceipt(context.Background(), receipt); err == nil {
			t.Fatal("foreign key receipt accepted")
		}
	})
	t.Run("finalize binds receipt task hash and output hash", func(t *testing.T) {
		h := newTaskDataHarness(t, harnessOptions{})
		receipt := proofSignedReceipt(t, h.servicePrivate, proofReceiptFacts(t))
		h.stageBundle(t, receipt)
		other := append(append([]byte(nil), proofOutput...), []byte(" changed")...)
		key := h.outputKey(receipt)
		root, _ := codec.OutputMMRRoot([][]byte{other})
		key.ContentHash = root.String()
		if _, err := h.stageObject(context.Background(), key, other, proofOutputMedia); err != nil {
			t.Fatal(err)
		}
		if _, err := h.finalizeReceipt(context.Background(), receipt); err == nil {
			t.Fatal("finalized output not committed by receipt")
		}
		req, err := h.finalizeRequest(context.Background(), receipt, nodewire.EvidenceKindWorkerValueOpening)
		if err != nil {
			t.Fatal(err)
		}
		req.TaskHash = strings.Repeat("99", 32)
		_, err = h.ingress().FinalizeTaskResult(context.Background(), connect.NewRequest(&nexusv1.FinalizeTaskResultRequest{TaskHash: req.TaskHash, SessionId: req.SessionID, TaskId: req.TaskID, Receipt: receiptToProto(receipt), RequestAuth: authToProto(req.Auth), EvidenceKind: sharedv1.EvidenceKind(req.EvidenceKind)}))
		if err == nil {
			t.Fatal("finalize accepted mismatched task hash")
		}
	})
}

func TestWorkerTaskDataPlaneFinalizesAndRejectsBadConfirmations(t *testing.T) {
	for _, bad := range []bool{false, true} {
		t.Run(fmt.Sprint("bad confirmation=", bad), func(t *testing.T) {
			h := newTaskDataHarness(t, harnessOptions{behavior: nexusBehavior{confirmationSignatureBad: bad}})
			h.executor.workerConfig.EvidenceSchemaHash = codec.HashBytes([]byte("profile")).String()
			h.executor.workerConfig.ProfileEvidenceRequirements = builderclient.WorkerEvidenceRequirementsV3()
			h.executor.workerConfig.RequiredTopK = proofRequiredTopK
			if err := h.runner.RunOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			h.requireFinished(t)
			if bad {
				if h.executor.TerminalError() == nil || h.publisher.OutputAvailableCount() != 0 || len(h.checkpoints.storageConfirmations(proofTaskID)) != 0 {
					t.Fatal("bad Builder signature released availability")
				}
			} else {
				if h.executor.TerminalError() != nil || h.publisher.OutputAvailableCount() == 0 || len(h.checkpoints.storageConfirmations(proofTaskID)) != 3 {
					t.Fatalf("Worker did not finalize: %v", h.executor.TerminalError())
				}
				if h.nexus.Receipt().GeneratedTokenCount != proofTokenCount {
					t.Fatal("generated token count did not cross relay wire")
				}
			}
		})
	}
}

// TestWorkerTaskDataPlaneRetriesPreserveSignedMaterial drives one round per
// injected failure and then the round that finishes. That one-to-one mapping is
// the point: a round asks the relay once, and receipt-first ordering leaves
// exactly one Fin per round where the earlier ordering could spend two on a
// single RunOnce. So the number of rounds is derived from the fixture rather
// than written beside it, and the upload case deliberately keeps two failures —
// its third round resumes a prefix that a resumed round itself produced.
func TestWorkerTaskDataPlaneRetriesPreserveSignedMaterial(t *testing.T) {
	for _, failedStage := range []string{"relay", "upload"} {
		t.Run(failedStage, func(t *testing.T) {
			behavior := nexusBehavior{}
			var transientFailures int
			if failedStage == "relay" {
				behavior.failRelayAttempts = 1
				transientFailures = behavior.failRelayAttempts
			} else {
				behavior.failUploadAttempts = 2
				transientFailures = behavior.failUploadAttempts
			}
			h := newTaskDataHarness(t, harnessOptions{behavior: behavior})
			h.executor.workerConfig.EvidenceSchemaHash = codec.HashBytes([]byte("profile")).String()
			h.executor.workerConfig.ProfileEvidenceRequirements = builderclient.WorkerEvidenceRequirementsV3()
			h.executor.workerConfig.RequiredTopK = proofRequiredTopK
			var first builderclient.SignedInferReceipt
			for round := 1; round <= transientFailures; round++ {
				if round > 1 {
					h.restartRunner()
				}
				if err := h.runner.RunOnce(context.Background()); err != nil {
					t.Fatal(err)
				}
				h.requireActiveRetryCount(t, uint32(round))
				persisted, ok := h.checkpoints.inferReceipt(proofTaskID)
				if !ok {
					t.Fatal("signed receipt not persisted before retry")
				}
				var signed builderclient.SignedInferReceipt
				if err := json.Unmarshal(persisted.Payload, &signed); err != nil {
					t.Fatal(err)
				}
				if round == 1 {
					first = signed
				} else if !reflect.DeepEqual(first, signed) {
					t.Fatal("retry re-signed the persisted receipt")
				}
				if h.publisher.OutputAvailableCount() != 0 {
					t.Fatal("transient failure released output")
				}
			}
			h.restartRunner()
			if err := h.runner.RunOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			h.requireFinished(t)
			if h.executor.TerminalError() != nil || h.model.InferCalls() != 1 || !reflect.DeepEqual(first, h.nexus.Receipt()) || len(h.checkpoints.storageConfirmations(proofTaskID)) != 3 {
				t.Fatalf("retry changed durable material: %v", h.executor.TerminalError())
			}
			seen := map[string]bool{}
			for _, attempt := range h.nexus.AuthAttempts() {
				nonce := hex.EncodeToString(attempt.nonce)
				if seen[nonce] {
					t.Fatal("retry reused task-data nonce")
				}
				seen[nonce] = true
			}
		})
	}
}

func TestNexusFetchRangeIsCoveredByRequestAuthentication(t *testing.T) {
	h := newTaskDataHarness(t, harnessOptions{})
	key := builderclient.TaskDataKey{TaskHash: codec.HashWithDomain("PROOF_ACCEPTED_TASK_HASH_V1", []byte(proofTaskID)).String(), SessionID: proofSessionID, TaskID: proofTaskID, Kind: builderclient.DataKindInput, ContentHash: codec.HashBytes(proofInput).String()}
	bounds := &builderclient.TaskDataRange{Offset: 0, Length: 4}
	body, err := builderclient.TaskDataFetchBodyDigest(key, bounds)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := h.auth.SignRequest(context.Background(), "FetchTaskData", key, proofBuilder, body)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := h.ingress().FetchTaskData(context.Background(), connect.NewRequest(&nexusv1.FetchTaskDataRequest{ObjectRef: proofKeyToProto(key), Range: &nexusv1.ByteRangeV1{Offset: 1, Length: 4}, RequestAuth: authToProto(auth)}))
	if err == nil {
		defer stream.Close()
		if stream.Receive() {
			t.Fatal("range tamper delivered data")
		}
		err = stream.Err()
	}
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("range tamper error = %v", err)
	}
}

type harnessOptions struct {
	behavior     nexusBehavior
	keeperInput  []byte
	servedInput  []byte
	authHeight   uint64
	runnerHeight uint64
	serverHeight uint64
}

type proofSnapshotReader struct {
	assignment  chainclient.AssignmentFinalized
	keeperInput []byte
}

func (r *proofSnapshotReader) TaskSnapshot(ctx context.Context, taskID string) (chainclient.TaskSnapshot, error) {
	return chainclient.TaskSnapshot{
		Status: "ASSIGNED",
		Assignment: chainclient.AssignmentSnapshot{
			SessionID:                r.assignment.SessionID,
			TaskID:                   r.assignment.TaskID,
			OrderSequence:            chainclient.NewUint64String(r.assignment.OrderSequence),
			SelectedWorker:           r.assignment.Winner,
			InferDeadlineHeight:      chainclient.NewUint64String(r.assignment.InferDeadlineHeight),
			ModelID:                  r.assignment.ModelID,
			ProfileVersion:           chainclient.NewProfileVersion(r.assignment.ProfileVersion),
			AcceptedOrderPayloadHash: chainclient.HexHash(codec.HashBytes(r.keeperInput)),
		},
		CurrentContract: true,
	}, nil
}

type taskDataHarness struct {
	t              *testing.T
	storePath      string
	db             *store.Store
	builderPubkey  string
	auth           *taskdataauth.Authenticator
	servicePrivate *secp256k1.PrivateKey
	nexus          *nexusProofServer
	taskData       builderclient.TaskDataClient
	executor       *proofInferExecutor
	model          *proofModel
	publisher      *proofPublisher
	authHeight     *heightSource
	runnerHeight   *heightSource
	assignment     chainclient.AssignmentFinalized
	runnerConfig   daemon.TaskRunnerConfig
	runner         *daemon.TaskRunner
	checkpoints    *proofCheckpoints
}

func newTaskDataHarness(t *testing.T, options harnessOptions) *taskDataHarness {
	t.Helper()
	if len(options.keeperInput) == 0 {
		options.keeperInput = append([]byte(nil), proofInput...)
	}
	if len(options.servedInput) == 0 {
		options.servedInput = append([]byte(nil), options.keeperInput...)
	}
	if options.authHeight == 0 {
		options.authHeight = 100
	}
	if options.runnerHeight == 0 {
		options.runnerHeight = 120
	}
	if options.serverHeight == 0 {
		options.serverHeight = 100
	}

	servicePrivate := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{0x21}, 32))
	servicePubkey := servicePrivate.PubKey().SerializeCompressed()
	serviceAddress, err := signer.AddressFromCompressedPublicKey("trueopen", servicePubkey)
	if err != nil {
		t.Fatalf("derive deterministic service address: %v", err)
	}
	builderPrivate := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{0x31}, 32))
	authHeight := newHeightSource(options.authHeight, true)
	runnerHeight := newHeightSource(options.runnerHeight, false)
	testSigner := deterministicSigner{private: servicePrivate, address: serviceAddress, keyRef: proofServiceKeyRef}
	serviceKey := chainclient.ServiceKeySnapshot{
		ParticipantType: chainclient.ParticipantTypeCortexNode, OperatorAddress: proofWorkerOperator,
		ServiceAddress: serviceAddress, ServicePubkey: hex.EncodeToString(servicePubkey),
		AuthorizationNonce: chainclient.NewUint64String(1), Status: "ACTIVE",
	}
	auth, err := taskdataauth.New(taskdataauth.Config{
		ServiceKeys: staticServiceKeys{binding: serviceKey, served: authHeight}, Signer: testSigner,
		ChainID: proofChainID, OperatorAddress: proofWorkerOperator, ServiceAddress: serviceAddress,
		ServicePubkey: serviceKey.ServicePubkey, ServiceKeyRef: proofServiceKeyRef, ExpiryBlocks: 20,
	})
	if err != nil {
		t.Fatalf("taskdataauth.New: %v", err)
	}
	nexus := newNexusProofServer(
		t, proofChainID, proofBuilder, proofWorkerOperator, serviceAddress, servicePubkey, builderPrivate,
		options.servedInput, options.serverHeight, options.behavior,
	)
	taskData := builderclient.NewConnectTaskDataClient(http.DefaultClient, "", builderclient.TaskDataTransport{AllowInsecureEndpoint: true})
	endpoint := staticProofEndpoint{
		operator: proofBuilder, endpoint: nexus.URL(), builderPubkey: hex.EncodeToString(builderPrivate.PubKey().SerializeCompressed()),
	}
	resolver, err := daemon.NewNexusTaskInputResolver(daemon.NexusTaskInputResolverConfig{
		TaskData: taskData, Endpoints: endpoint, Auth: auth,
		RangeBytes: uint64(len(options.servedInput)), MaxInputBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("NewNexusTaskInputResolver: %v", err)
	}

	root := t.TempDir()
	storePath := filepath.Join(root, "task-data-plane.db")
	db := mustOpenStore(t, storePath)
	t.Cleanup(func() { _ = db.Close() })
	evidenceStore, err := evidence.NewStore(filepath.Join(root, "evidence"))
	if err != nil {
		t.Fatalf("evidence.NewStore: %v", err)
	}
	fakeModel := modelservice.NewFakeService()
	model := newProofModel(t, fakeModel, proofOutput, proofTokenCount)
	publisher := &proofPublisher{FakeClient: builderclient.NewFakeClient()}

	sessionID, orderSequence, taskID := proofSessionID, proofOrderSequence, proofTaskID
	assignment := chainclient.AssignmentFinalized{
		TaskID: taskID, SessionID: sessionID, OrderSequence: orderSequence,
		OrderDigest: codec.HashWithDomain("TASK_DATA_PLANE_ORDER", []byte(taskID)),
		Winner:      proofWorkerOperator, WinnerConfirmHeight: 120, InferDeadlineHeight: proofInferDeadline,
		ModelID: proofModelID, ProfileVersion: 1, Capability: modelservice.CapabilityLLMTextV1,
		Input: append([]byte(nil), options.keeperInput...), BuilderOperatorAddress: proofBuilder,
	}
	taskHash := assignment.OrderDigest
	if err := layout.MergeTask(context.Background(), db, layout.StoredHash(taskHash), layout.TaskRecord{
		SessionID:              sessionID,
		OrderSequence:          orderSequence,
		ModelID:                proofModelID,
		ProfileVersion:         1,
		AssignmentOrderDigest:  layout.StoredHash(taskHash),
		AssignmentDigest:       layout.StoredHash(taskHash),
		WorkerAddress:          proofWorkerOperator,
		BuilderOperatorAddress: proofBuilder,
		InputCID:               "nexus://input/" + taskID,
		InputDigest:            layout.StoredHashFromCodec(codec.HashBytes(options.keeperInput)),
		InputSizeBytes:         uint64(len(options.keeperInput)),
	}); err != nil {
		t.Fatalf("seed layout task record: %v", err)
	}
	if err := layout.MergeInfer(context.Background(), db, layout.StoredHash(taskHash), layout.InferRecord{
		TaskID:              taskID,
		WinnerConfirmHeight: assignment.WinnerConfirmHeight,
		InferDeadlineHeight: assignment.InferDeadlineHeight,
		Stage:               layout.StageQueued,
		DeadlineHeight:      assignment.InferDeadlineHeight,
	}); err != nil {
		t.Fatalf("seed layout infer record: %v", err)
	}
	checkpoints := newProofCheckpoints(evidenceStore, taskHash, publisher)
	receivingBuilder := worker.ReceivingBuilderFunc(
		func(_ context.Context, task worker.ReceivingBuilderRef) (worker.BuilderEndpoint, error) {
			if task.AssignedBuilderOperator != proofBuilder {
				return worker.BuilderEndpoint{}, fmt.Errorf("unexpected Builder operator %q", task.AssignedBuilderOperator)
			}
			return worker.BuilderEndpoint{
				OperatorAddress: proofBuilder, Endpoint: nexus.URL(), ServicePubkey: endpoint.builderPubkey,
				CurrentHeight:      nexus.currentHeight.Load(),
				AuthorizationNonce: 1,
			}, nil
		})
	generation := generationfixture.New(t, taskID, proofModelID, "PROOF_ACCEPTED_TASK_HASH_V1")
	executor := &proofInferExecutor{
		assignment: assignment, resolver: resolver, checkpoints: checkpoints, height: runnerHeight,
		workerConfig: worker.Config{
			WorkerAddress: proofWorkerOperator, ModelServiceID: proofModelServiceID, Model: model,
			Builder: publisher, TaskData: taskData, TaskDataAuth: auth, Persistence: checkpoints,
			StreamLimits: &chainclient.OutputStreamLimitsSnapshot{MinOutputStreamFrameBytes: 16, MaxOutputMMRLeaves: 65536},
			ChainID:      proofChainID, SignerAddress: serviceAddress, SignerKeyRef: proofServiceKeyRef,
			SignerPubkey: serviceKey.ServicePubkey, Signer: testSigner, TrustedNATSDev: true,
			ReceivingBuilder: receivingBuilder,
			SnapshotReader:   &proofSnapshotReader{assignment: assignment, keeperInput: options.keeperInput},
			// The frozen section 16.2 Task read the receipt's two consensus fields
			// come from. Both values are functions of the task id, so an answer for
			// the wrong task is visibly different rather than coincidentally right.
			TaskFacts:        taskfacts.ReaderFunc(generation.TaskFacts),
			GenerationReader: generation,
		},
	}
	cfg := daemon.TaskRunnerConfig{Store: db, InferExecutor: executor, RetryDelay: time.Nanosecond}
	return &taskDataHarness{
		t: t, storePath: storePath, db: db, builderPubkey: endpoint.builderPubkey,
		auth: auth, servicePrivate: servicePrivate,
		nexus: nexus, taskData: taskData, executor: executor, model: model, publisher: publisher,
		authHeight: authHeight, runnerHeight: runnerHeight, assignment: assignment,
		runnerConfig: cfg, runner: daemon.NewTaskRunner(cfg), checkpoints: checkpoints,
	}
}

func (h *taskDataHarness) restartRunner() {
	h.t.Helper()
	if err := h.db.Close(); err != nil {
		h.t.Fatalf("close store for restart: %v", err)
	}
	h.db = mustOpenStore(h.t, h.storePath)
	h.t.Cleanup(func() { _ = h.db.Close() })
	h.runnerConfig.Store = h.db
	h.runner = daemon.NewTaskRunner(h.runnerConfig)
}

func (h *taskDataHarness) activeTasks(t *testing.T) map[codec.Hash]store.InferTask {
	t.Helper()
	document := make(map[codec.Hash]store.InferTask)
	hashes, records, err := layout.ListInferRecords(context.Background(), h.db)
	if err != nil {
		t.Fatalf("ListInferRecords: %v", err)
	}
	for i, hsh := range hashes {
		tr, err := layout.GetTaskRecord(context.Background(), h.db, hsh)
		if err != nil {
			t.Fatalf("GetTaskRecord: %v", err)
		}
		document[codec.Hash(hsh)] = inferTaskFromRecords(tr, records[i], modelservice.CapabilityLLMTextV1)
	}
	return document
}

func inferTaskFromRecords(task layout.TaskRecord, role layout.InferRecord, capability string) store.InferTask {
	return store.InferTask{
		TaskID:                 role.TaskID,
		SessionID:              task.SessionID,
		OrderSequence:          task.OrderSequence,
		AssignmentDigest:       codec.Hash(task.AssignmentDigest),
		ModelID:                task.ModelID,
		ProfileVersion:         task.ProfileVersion,
		Capability:             capability,
		DeadlineHeight:         role.DeadlineHeight,
		InputCID:               task.InputCID,
		InputDigest:            codec.Hash(task.InputDigest),
		Stage:                  string(role.Stage),
		RetryCount:             role.RetryCount,
		RetryAtHeight:          role.RetryAtHeight,
		RetryAtUnixMilli:       role.RetryAtUnixMilli,
		LastError:              role.LastError,
		OutputCID:              role.OutputCID,
		OutputDigest:           codec.Hash(role.OutputDigest),
		ReceiptCID:             role.ReceiptCID,
		ReceiptDigest:          codec.Hash(role.ReceiptDigest),
		WorkerAddress:          task.WorkerAddress,
		WinnerConfirmHeight:    role.WinnerConfirmHeight,
		BuilderOperatorAddress: task.BuilderOperatorAddress,
		InputSizeBytes:         task.InputSizeBytes,
		BuilderSetID:           task.TaskBuilderSetID,
		BuilderSetHash:         task.TaskBuilderSetHash,
	}
}

func (h *taskDataHarness) activeTask(t *testing.T) store.InferTask {
	t.Helper()
	task, ok := h.activeTasks(t)[h.assignment.OrderDigest]
	if !ok {
		t.Fatal("active infer responsibility is missing")
	}
	return task
}

func (h *taskDataHarness) requireActiveRetryCount(t *testing.T, want uint32) {
	t.Helper()
	if got := h.activeTask(t); got.RetryCount != want {
		t.Fatalf("active infer retry count = %d error=%q, want %d", got.RetryCount, got.LastError, want)
	}
}

func (h *taskDataHarness) requireFinished(t *testing.T) {
	t.Helper()
	if tasks := h.activeTasks(t); len(tasks) != 0 {
		t.Fatalf("active infer responsibilities = %#v, want terminal removal", tasks)
	}
}

// ingress is the raw Connect client. It exists only for the requests the real
// client refuses to build, which is the only way to reach the server-side rules
// that guard against a hostile Builder.
func (h *taskDataHarness) ingress() nexusv1connect.IngressAPIClient {
	return nexusv1connect.NewIngressAPIClient(http.DefaultClient, h.nexus.URL())
}

// relayAuth signs one receipt relay. Nexus verifies the relay body digest
// directly rather than TaskDataRequestSigningHash, so the digest has to come from
// the receipt being relayed.
func (h *taskDataHarness) outputKey(receipt builderclient.SignedInferReceipt) builderclient.TaskDataKey {
	return builderclient.TaskDataKey{TaskHash: receipt.TaskHash, SessionID: h.assignment.SessionID, TaskID: h.assignment.TaskID, Kind: builderclient.DataKindOutput, ContentHash: receipt.OutputHash}
}
func (h *taskDataHarness) relayReceipt(ctx context.Context, receipt builderclient.SignedInferReceipt) error {
	return h.taskData.SubmitInferReceipt(ctx, h.nexus.URL(), builderclient.SubmitInferReceiptRequest{Receipt: receipt})
}
func (h *taskDataHarness) stageObject(ctx context.Context, key builderclient.TaskDataKey, data []byte, media string) (builderclient.TaskDataMetadata, error) {
	if key.Kind == builderclient.DataKindOutput {
		body, err := builderclient.TaskDataOutputStreamBodyDigest(key.TaskHash, key.SessionID, key.TaskID)
		if err != nil {
			return builderclient.TaskDataMetadata{}, err
		}
		auth, err := h.auth.SignRequest(ctx, "UploadTaskOutputStream", key, proofBuilder, body)
		if err != nil {
			return builderclient.TaskDataMetadata{}, err
		}
		root, err := codec.OutputMMRRoot([][]byte{data})
		if err != nil {
			return builderclient.TaskDataMetadata{}, err
		}
		if root.String() != key.ContentHash {
			return builderclient.TaskDataMetadata{}, fmt.Errorf("output MMR does not match object")
		}
		digest, err := nodewire.OutputChunkSigningDigest(proofChainID, proofHex(key.TaskHash), 0, root[:])
		if err != nil {
			return builderclient.TaskDataMetadata{}, err
		}
		headerDigest, err := builderclient.OutputStreamHeaderDigest(proofChainID, key.TaskHash)
		if err != nil {
			return builderclient.TaskDataMetadata{}, err
		}
		stream, err := h.taskData.OpenTaskOutputStream(ctx, h.nexus.URL(), builderclient.OutputStreamRequest{TaskHash: key.TaskHash, SessionID: key.SessionID, TaskID: key.TaskID, Auth: auth, HeaderSignature: compactSignature(h.servicePrivate, headerDigest), ReplayChunks: []builderclient.OutputChunk{{Text: data, MMRRoot: root, WorkerSignature: compactSignature(h.servicePrivate, digest)}}})
		if err != nil {
			return builderclient.TaskDataMetadata{}, err
		}
		defer stream.Close()
		finDigest, err := nodewire.OutputFinSigningDigest(proofChainID, proofHex(key.TaskHash), 0, root[:], nodewire.FinishReasonV1EosToken)
		if err != nil {
			return builderclient.TaskDataMetadata{}, err
		}
		_, err = stream.Finish(builderclient.OutputFin{FinishReason: nodewire.FinishReasonV1EosToken, WorkerSignature: compactSignature(h.servicePrivate, finDigest)})
		return builderclient.TaskDataMetadata{Key: key, Readiness: builderclient.TaskDataStored, SizeBytes: uint64(len(data))}, err
	}
	body, err := builderclient.TaskDataUploadBodyDigest(key, uint64(len(data)), media)
	if err != nil {
		return builderclient.TaskDataMetadata{}, err
	}
	auth, err := h.auth.SignRequest(ctx, "UploadTaskResultObject", key, proofBuilder, body)
	if err != nil {
		return builderclient.TaskDataMetadata{}, err
	}
	return h.taskData.UploadTaskResultObject(ctx, h.nexus.URL(), builderclient.UploadTaskResultRequest{Key: key, SizeBytes: uint64(len(data)), MediaType: media, Data: data, Auth: auth})
}
func (h *taskDataHarness) stageBundle(t *testing.T, receipt builderclient.SignedInferReceipt) {
	t.Helper()
	evidence := proofEvidence(t, receipt.TaskHash)
	for i, bundle := range []struct {
		kind      nodewire.EvidenceKind
		manifest  []byte
		artifacts [][]byte
	}{
		{nodewire.EvidenceKindWorkerValueOpening, evidence.valueManifest, [][]byte{evidence.values}},
		{nodewire.EvidenceKindWorkerTokenOpening, evidence.tokenManifest, [][]byte{evidence.generated, evidence.input}},
	} {
		stage := func(dataKind builderclient.DataKind, hash string, data []byte) {
			key := builderclient.EvidenceObjectKey(receipt.TaskHash, proofSessionID, proofTaskID, dataKind, hash, builderclient.EvidenceProducerWorker, 1, proofWorkerOperator, bundle.kind)
			if _, err := h.stageObject(context.Background(), key, data, ""); err != nil {
				t.Fatal(err)
			}
		}
		for _, data := range bundle.artifacts {
			stage(builderclient.DataKindEvidenceArtifact, codec.HashBytes(data).String(), data)
		}
		stage(builderclient.DataKindEvidenceManifest, receipt.RequiredEvidenceCommitments[i].EvidenceHashOrRoot.String(), bundle.manifest)
	}
}
func (h *taskDataHarness) finalizeRequest(ctx context.Context, receipt builderclient.SignedInferReceipt, kind nodewire.EvidenceKind) (builderclient.FinalizeTaskResultRequest, error) {
	req := builderclient.FinalizeTaskResultRequest{TaskHash: receipt.TaskHash, SessionID: proofSessionID, TaskID: proofTaskID, Receipt: receipt, EvidenceKind: kind}
	body, err := builderclient.TaskDataFinalizeResultBodyDigest(req)
	if err != nil {
		return req, err
	}
	req.Auth, err = h.auth.SignRequest(ctx, "FinalizeTaskResult", h.outputKey(receipt), proofBuilder, body)
	return req, err
}

// finalizeReceipt finalizes both Worker bundles, value then token, and returns
// the last response.
func (h *taskDataHarness) finalizeReceipt(ctx context.Context, receipt builderclient.SignedInferReceipt) (builderclient.FinalizeTaskResultResponse, error) {
	var response builderclient.FinalizeTaskResultResponse
	for _, kind := range []nodewire.EvidenceKind{nodewire.EvidenceKindWorkerValueOpening, nodewire.EvidenceKindWorkerTokenOpening} {
		req, err := h.finalizeRequest(ctx, receipt, kind)
		if err != nil {
			return builderclient.FinalizeTaskResultResponse{}, err
		}
		if response, err = h.taskData.FinalizeTaskResult(ctx, h.nexus.URL(), req); err != nil {
			return response, err
		}
	}
	return response, nil
}
func (h *taskDataHarness) fetchObject(key builderclient.TaskDataKey) error {
	body, err := builderclient.TaskDataFetchBodyDigest(key, nil)
	if err != nil {
		return err
	}
	auth, err := h.auth.SignRequest(context.Background(), "FetchTaskData", key, proofBuilder, body)
	if err != nil {
		return err
	}
	return h.taskData.FetchTaskData(context.Background(), h.nexus.URL(), builderclient.FetchTaskDataRequest{Key: key, Auth: auth}, func(builderclient.TaskDataChunk) error { return nil })
}

// proofInferExecutor is the package-local assembly seam that production has not
// wired yet: TaskRunner owns the compact Pebble responsibility document, while
// the Worker owns immutable infer/output checkpoints and evidence.
type proofInferExecutor struct {
	assignment   chainclient.AssignmentFinalized
	resolver     daemon.TaskInputResolver
	checkpoints  *proofCheckpoints
	height       *heightSource
	workerConfig worker.Config

	// terminalErr keeps the permanent failure TaskRunner is told to retire, which
	// is otherwise unobservable: RunInfer reports it as a terminal success so the
	// responsibility is removed rather than retried forever.
	mu          sync.Mutex
	terminalErr error
}

func (e *proofInferExecutor) TerminalError() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.terminalErr
}

func (e *proofInferExecutor) RunInfer(ctx context.Context, taskHash codec.Hash, task store.InferTask) (store.InferTask, bool, error) {
	if taskHash != e.assignment.OrderDigest || task.AssignmentDigest != taskHash || task.TaskID != e.assignment.TaskID {
		return task, true, nil
	}
	if e.height.Next() > task.DeadlineHeight {
		return task, true, nil
	}
	node := worker.New(e.workerConfig)
	event := e.assignment
	facts, err := e.workerConfig.TaskFacts.TaskFacts(ctx, event.TaskID)
	if err != nil {
		return task, false, err
	}
	event.Input, err = e.resolver.ResolveTaskInput(ctx, daemon.TaskInputRef{
		TaskHash:  codec.Hash(facts.AcceptedTaskHash),
		SessionID: task.SessionID, TaskID: task.TaskID, PayloadCID: task.InputCID,
		PayloadHash: chainclient.HexHash(task.InputDigest), BuilderOperatorAddress: event.BuilderOperatorAddress,
	})
	if err != nil {
		if builderclient.IsRetryable(err) {
			return task, false, err
		}
		e.mu.Lock()
		e.terminalErr = err
		e.mu.Unlock()
		return task, true, nil
	}
	result, err := node.HandleAssignmentFinalized(ctx, event)
	if err != nil {
		if builderclient.IsRetryable(err) {
			return task, false, err
		}
		e.mu.Lock()
		e.terminalErr = err
		e.mu.Unlock()
		return task, true, nil
	}
	if err := e.checkpoints.publishPending(ctx); err != nil {
		return task, false, builderclient.Retryable(err)
	}
	task.Stage = "confirmed"
	task.OutputCID = result.OutputRef
	if digest, decodeErr := hex.DecodeString(result.TaskDataReceipt.OutputHash); decodeErr == nil && len(digest) == len(codec.Hash{}) {
		copy(task.OutputDigest[:], digest)
	}
	return task, true, nil
}

type proofCheckpoints struct {
	mu       sync.Mutex
	evidence *evidence.Store
	// taskHash is a path component of every object this harness stores, the
	// same way the daemon's own persistence carries it: the local layout is
	// task-scoped, so there is nowhere to put bytes that name no task.
	taskHash      codec.Hash
	publisher     *proofPublisher
	paths         map[string]string
	outbox        map[codec.Hash]worker.OutboxRecord
	jobs          []worker.ModelJobCheckpoint
	artifacts     map[string][]byte
	receipts      map[string]worker.InferReceiptCheckpoint
	confirmations map[string][]worker.StorageConfirmationCheckpoint
}

func newProofCheckpoints(store *evidence.Store, taskHash codec.Hash, publisher *proofPublisher) *proofCheckpoints {
	return &proofCheckpoints{
		evidence: store, taskHash: taskHash, publisher: publisher, paths: make(map[string]string),
		outbox: make(map[codec.Hash]worker.OutboxRecord), artifacts: make(map[string][]byte),
		receipts: make(map[string]worker.InferReceiptCheckpoint), confirmations: make(map[string][]worker.StorageConfirmationCheckpoint),
	}
}

func (p *proofCheckpoints) WriteEvidence(ctx context.Context, record worker.EvidenceRecord) error {
	ref, err := p.evidence.Write(ctx, evidence.WriteRequest{TaskHash: p.taskHash, TaskID: record.TaskID, Kind: record.Kind, Data: record.Data})
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.paths[record.Kind] = ref.Path
	if p.artifacts == nil {
		p.artifacts = make(map[string][]byte)
	}
	p.artifacts[record.TaskID+"/"+record.Kind] = append([]byte(nil), record.Data...)
	p.mu.Unlock()
	return nil
}

func (p *proofCheckpoints) OutputStreamFrames(_ context.Context, taskID string) ([]builderclient.OutputChunk, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var frames []builderclient.OutputChunk
	for seq := uint64(0); ; seq++ {
		data, ok := p.artifacts[taskID+"/"+worker.OutputStreamFrameKind(seq)]
		if !ok {
			return frames, nil
		}
		var frame builderclient.OutputChunk
		if err := json.Unmarshal(data, &frame); err != nil {
			return nil, err
		}
		frames = append(frames, frame)
	}
}

// PublishWorkerBundle stores one Worker bundle in the evidence store's bundle
// layout, as the daemon does.
func (p *proofCheckpoints) PublishWorkerBundle(ctx context.Context, _ string, kind nodewire.EvidenceKind, manifest []byte, artifacts [][]byte) error {
	id, err := p.bundleID(kind)
	if err != nil {
		return err
	}
	_, err = p.evidence.PublishBundle(ctx, evidence.BundleRequest{ID: id, Manifest: manifest, Artifacts: artifacts})
	return err
}

func (p *proofCheckpoints) WorkerBundle(_ context.Context, _ string, kind nodewire.EvidenceKind) ([]byte, map[string][]byte, error) {
	id, err := p.bundleID(kind)
	if err != nil {
		return nil, nil, err
	}
	manifestBytes, _, err := p.evidence.ReadBundleManifest(id)
	if err != nil {
		return nil, nil, err
	}
	manifest, err := evidencebundle.Decode(manifestBytes)
	if err != nil {
		return nil, nil, err
	}
	artifacts := map[string][]byte{}
	for _, artifact := range manifest.Artifacts {
		raw, err := hex.DecodeString(artifact.ContentHash)
		if err != nil || len(raw) != 32 {
			return nil, nil, fmt.Errorf("artifact %s content hash is not Hash32", artifact.ID)
		}
		size, err := artifact.SizeBytes()
		if err != nil {
			return nil, nil, err
		}
		if artifacts[artifact.ID], err = p.evidence.ReadBundleArtifact(id, codec.Hash(raw), int64(size)); err != nil {
			return nil, nil, err
		}
	}
	return manifestBytes, artifacts, nil
}

func (p *proofCheckpoints) bundleID(kind nodewire.EvidenceKind) (evidence.BundleID, error) {
	switch kind {
	case nodewire.EvidenceKindWorkerTokenOpening:
		return evidence.WorkerTokenBundle(p.taskHash), nil
	case nodewire.EvidenceKindWorkerValueOpening:
		return evidence.WorkerValueBundle(p.taskHash), nil
	default:
		return evidence.BundleID{}, fmt.Errorf("evidence kind %d is not a Worker bundle", kind)
	}
}

func (p *proofCheckpoints) CheckpointInferOutput(ctx context.Context, taskID string, output, tokenIDs, positionValues []byte, cp worker.InferOutputCheckpoint) error {
	for _, rec := range []worker.EvidenceRecord{
		{TaskID: taskID, Kind: "worker-output", Data: output},
		{TaskID: taskID, Kind: "worker-token-ids-material", Data: tokenIDs},
		{TaskID: taskID, Kind: "worker-position-values-material", Data: positionValues},
		{TaskID: taskID, Kind: "worker-output-descriptor", Data: cp.DescriptorJSON},
	} {
		if err := p.WriteEvidence(ctx, rec); err != nil {
			return err
		}
	}
	return nil
}

func (p *proofCheckpoints) WriteBuilderOutbox(_ context.Context, record worker.OutboxRecord) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	existing, ok := p.outbox[record.Digest]
	if ok && (record.Status == "held" || (existing.Status == "sent" && record.Status == "pending")) {
		return nil
	}
	record.Payload = append([]byte(nil), record.Payload...)
	p.outbox[record.Digest] = record
	return nil
}

func (p *proofCheckpoints) publishPending(ctx context.Context) error {
	p.mu.Lock()
	pending := make(map[codec.Hash]worker.OutboxRecord)
	for digest, record := range p.outbox {
		if record.Status == "pending" {
			pending[digest] = record
		}
	}
	p.mu.Unlock()
	for digest, record := range pending {
		if err := p.publisher.Publish(ctx, builderclient.PublishRequest{Subject: record.Subject, TaskID: record.TaskID, Payload: record.Payload}); err != nil {
			return err
		}
		p.mu.Lock()
		current := p.outbox[digest]
		current.Status = "sent"
		p.outbox[digest] = current
		p.mu.Unlock()
	}
	return nil
}

func (p *proofCheckpoints) CheckpointInferInput(context.Context, worker.InferInputCheckpoint) error {
	return nil
}
func (p *proofCheckpoints) InferInput(context.Context, string) (worker.InferInputCheckpoint, error) {
	return worker.InferInputCheckpoint{}, worker.ErrCheckpointNotFound
}
func (p *proofCheckpoints) CheckpointModelJob(_ context.Context, record worker.ModelJobCheckpoint) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.jobs = append(p.jobs, record)
	return nil
}

func (p *proofCheckpoints) CheckpointInferReceipt(_ context.Context, record worker.InferReceiptCheckpoint) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing, ok := p.receipts[record.TaskID]; ok && (existing.MaterialDigest != record.MaterialDigest || !bytes.Equal(existing.Payload, record.Payload)) {
		return fmt.Errorf("conflicting infer receipt checkpoint")
	}
	record.Payload = append([]byte(nil), record.Payload...)
	p.receipts[record.MaterialDigest] = record
	return nil
}

func (p *proofCheckpoints) InferReceipts(_ context.Context, _ string) ([]worker.InferReceiptCheckpoint, error) {
	out := make([]worker.InferReceiptCheckpoint, 0, len(p.receipts))
	for _, r := range p.receipts {
		out = append(out, r)
	}
	return out, nil
}

func (p *proofCheckpoints) CheckpointStorageConfirmation(_ context.Context, record worker.StorageConfirmationCheckpoint) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, existing := range p.confirmations[record.TaskID] {
		if existing.MaterialDigest == record.MaterialDigest {
			return nil
		}
	}
	record.Signature = append([]byte(nil), record.Signature...)
	p.confirmations[record.TaskID] = append(p.confirmations[record.TaskID], record)
	return nil
}

func (p *proofCheckpoints) ReadArtifact(_ context.Context, taskID string, kind string) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.artifacts == nil {
		return nil, worker.ErrCheckpointNotFound
	}
	data, ok := p.artifacts[taskID+"/"+kind]
	if !ok {
		return nil, worker.ErrCheckpointNotFound
	}
	return append([]byte(nil), data...), nil
}

func (p *proofCheckpoints) StorageConfirmations(_ context.Context, taskID string) ([]worker.StorageConfirmationCheckpoint, error) {
	return p.storageConfirmations(taskID), nil
}

func (p *proofCheckpoints) BuilderMessage(_ context.Context, digest string) (worker.BuilderMessageCheckpoint, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for hash, record := range p.outbox {
		if hex.EncodeToString(hash[:]) == digest {
			return worker.BuilderMessageCheckpoint{Digest: digest, TaskID: record.TaskID, Subject: record.Subject, Status: record.Status, Payload: append([]byte(nil), record.Payload...)}, nil
		}
	}
	return worker.BuilderMessageCheckpoint{}, worker.ErrCheckpointNotFound
}

func (p *proofCheckpoints) storageConfirmations(taskID string) []worker.StorageConfirmationCheckpoint {
	p.mu.Lock()
	defer p.mu.Unlock()
	records := append([]worker.StorageConfirmationCheckpoint(nil), p.confirmations[taskID]...)
	for i := range records {
		records[i].Signature = append([]byte(nil), records[i].Signature...)
	}
	return records
}

func (p *proofCheckpoints) inferReceipt(taskID string) (worker.InferReceiptCheckpoint, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, record := range p.receipts {
		if record.TaskID == taskID {
			return record, true
		}
	}
	return worker.InferReceiptCheckpoint{}, false
}

func (p *proofCheckpoints) evidencePaths() map[string]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	paths := make(map[string]string, len(p.paths))
	for kind, path := range p.paths {
		paths[kind] = path
	}
	return paths
}

type deterministicSigner struct {
	private *secp256k1.PrivateKey
	address string
	keyRef  string
}

func (s deterministicSigner) SignDigest(_ context.Context, request signer.DigestRequest) ([]byte, error) {
	if request.KeyRef != s.keyRef || request.ExpectedSignerAddress != s.address {
		return nil, fmt.Errorf("unexpected deterministic signer identity")
	}
	return compactSignature(s.private, request.Digest), nil
}

func (deterministicSigner) SignCosmosTx(context.Context, signer.CosmosTxRequest) ([]byte, error) {
	return nil, errors.New("Cosmos transaction signing is not supported by the test key")
}

func (deterministicSigner) CanSignCosmosTx() bool { return false }

type staticServiceKeys struct {
	binding chainclient.ServiceKeySnapshot
	// served answers with the height Keeper served the binding from, advancing one
	// block per read so successive signatures carry successive expiries.
	served *heightSource
}

func (s staticServiceKeys) CommittedCurrentServiceKey(_ context.Context, participantType, operator string) (chainclient.ServiceKeySnapshot, uint64, error) {
	if participantType != chainclient.ParticipantTypeCortexNode || operator != s.binding.OperatorAddress {
		return chainclient.ServiceKeySnapshot{}, 0, fmt.Errorf("unexpected service-key lookup %s/%s", participantType, operator)
	}
	return s.binding, s.served.Next(), nil
}

type heightSource struct {
	height atomic.Uint64
	step   bool
}

func newHeightSource(height uint64, step bool) *heightSource {
	h := &heightSource{step: step}
	h.height.Store(height)
	return h
}

func (h *heightSource) Set(height uint64) { h.height.Store(height) }

// Next reports the current height, advancing by one block per call when the
// source was created stepping.
func (h *heightSource) Next() uint64 {
	if h.step {
		return h.height.Add(1) - 1
	}
	return h.height.Load()
}

func (h *heightSource) ChainStatus(context.Context) (uint64, string, error) {
	return h.height.Load(), proofChainID, nil
}

type staticProofEndpoint struct {
	operator      string
	endpoint      string
	builderPubkey string
}

func (e staticProofEndpoint) ResolveBuilderEndpoint(_ context.Context, operator string) (daemon.BuilderEndpoint, error) {
	if operator != e.operator {
		return daemon.BuilderEndpoint{}, fmt.Errorf("unexpected Builder endpoint lookup %q", operator)
	}
	return daemon.BuilderEndpoint{
		OperatorAddress: e.operator, Endpoint: e.endpoint, ServicePubkey: e.builderPubkey,
		Source: daemon.BuilderEndpointSourceBootstrap, DescriptorVersion: 1, SnapshotHeight: 100,
	}, nil
}

type staticLiability struct {
	liability chainclient.TaskLiabilitySnapshot
}

func (s staticLiability) TaskLiability(_ context.Context, sessionID, taskID, operator, duty string) (chainclient.TaskLiabilitySnapshot, error) {
	if sessionID != s.liability.SessionID || taskID != s.liability.TaskID || operator != s.liability.OperatorAddress || duty != s.liability.Duty {
		return chainclient.TaskLiabilitySnapshot{}, fmt.Errorf("unexpected task liability lookup")
	}
	return s.liability, nil
}

func proofLiability(assignment chainclient.AssignmentFinalized) chainclient.TaskLiabilitySnapshot {
	return chainclient.TaskLiabilitySnapshot{
		SessionID: assignment.SessionID, TaskID: assignment.TaskID, OperatorAddress: assignment.Winner, Duty: "WORKER",
		BondVersion: 1, CapabilityVersion: 1, ReservedAmount: 100, Status: "RESERVED",
		CreatedHeight: chainclient.NewUint64String(assignment.WinnerConfirmHeight), ModelID: assignment.ModelID,
		ProfileVersion: chainclient.NewProfileVersion(assignment.ProfileVersion),
	}
}

type proofModel struct {
	modelservice.Client
	mu                sync.Mutex
	inferCalls        int
	inferInput        []byte
	outputRef         string
	tokenIDsRef       string
	positionValuesRef string
	tokenCount        uint64
	fake              *modelservice.FakeService
	output            []byte
}

func newProofModel(t *testing.T, fake *modelservice.FakeService, output []byte, tokenCount uint64) *proofModel {
	t.Helper()
	return &proofModel{
		Client: fake, fake: fake, output: append([]byte(nil), output...), outputRef: fake.PutArtifactForTest(output),
		tokenIDsRef:       fake.PutArtifactForTest(proofTokenIDsMaterial(t)),
		positionValuesRef: fake.PutArtifactForTest(proofPositionValuesMaterial(t)), tokenCount: tokenCount,
	}
}

func (m *proofModel) Infer(_ context.Context, req modelservice.InferRequest) (modelservice.InferResponse, error) {
	m.mu.Lock()
	m.inferCalls++
	m.inferInput = append([]byte(nil), req.Input...)
	m.mu.Unlock()
	tokenIDsRef, positionValuesRef := m.tokenIDsRef, m.positionValuesRef
	if req.Generation != nil {
		tokenIDs, positionValues, err := generationfixture.Material(req, m.tokenCount)
		if err != nil {
			return modelservice.InferResponse{}, err
		}
		tokenIDsRef, positionValuesRef = m.fake.PutArtifactForTest(tokenIDs), m.fake.PutArtifactForTest(positionValues)
	}
	return modelservice.InferResponse{
		RequestID: req.RequestID, ModelServiceID: req.ModelServiceID, JobID: req.JobID,
		TaskID: req.TaskID, ModelID: req.ModelID, ProfileVersion: req.ProfileVersion,
		RequestDigest: append([]byte(nil), req.RequestDigest...), OutputRef: m.outputRef,
		TokenIDsRef: tokenIDsRef, PositionValuesRef: positionValuesRef,
		GeneratedTokenCount: m.tokenCount, WorkUnit: 17,
		FinishReason: nodewire.FinishReasonV1EosToken, GenerationParamsDigest: append([]byte(nil), req.GenerationParamsDigest...),
	}, nil
}

func (m *proofModel) InferCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.inferCalls
}

func (m *proofModel) InferInput() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.inferInput...)
}

type proofPublisher struct {
	*builderclient.FakeClient
	mu sync.Mutex
}

func (p *proofPublisher) Publish(ctx context.Context, request builderclient.PublishRequest) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.FakeClient.Publish(ctx, request)
}

func (p *proofPublisher) OutputAvailableCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	count := 0
	for _, published := range p.Published {
		if published.Subject != "" && published.Subject == builderclient.NATSOutputAvailableSubject(published.TaskID) {
			count++
		}
	}
	return count
}

func mustOpenStore(t *testing.T, path string) *store.Store {
	t.Helper()
	db, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	return db
}

func proofTokenIDsMaterial(t testing.TB) []byte {
	t.Helper()
	data, err := modelservice.EncodeTokenIDsArtifact(modelservice.TokenIDs{Input: []uint32{7}, Generated: []uint32{1, 2, 3, 4}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func proofPositionValuesMaterial(t testing.TB) []byte {
	t.Helper()
	data, err := modelservice.EncodePositionValuesArtifact(proofValues())
	if err != nil {
		t.Fatal(err)
	}
	return data
}
