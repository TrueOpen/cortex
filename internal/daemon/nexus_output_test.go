package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/taskdataauth"
)

const (
	outputTestChainID = "trueopen-devnet-1"
	// outputTestWorker must be a canonical Bech32 operator address: the frozen
	// receipt preimage frames its address codec bytes, so a placeholder string
	// cannot produce a digest at all.
	outputTestWorker = "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc"
	// outputTestTaskID is a canonical Hash32 hex, which is what the frozen wire
	// declares task_id to be and what identity.TaskIDString produces.
	outputTestTaskID    = "7b0f6d2c1a3e59748596a7b8c9d0e1f2031425364758697a8b9cadbecfd0e1f2"
	outputTestOutputRef = "cortex-artifact://svc/output/" + outputTestTaskID
)

const outputConfirmationSizeBytes = uint64(4096)

// outputConfirmationMaterial derives, from one canonical output package, the
// Builder metadata that proves the Builder holds it and the Keeper receipt
// snapshot that metadata has to agree with. Both are derived rather than typed
// out so a test cannot accidentally assert an internally inconsistent receipt:
// infer_receipt_hash is computed by the same Node derivation the confirmer
// recomputes.
func outputConfirmationMaterial(
	t *testing.T, chainID, worker string, pkg builderclient.OutputPackage,
) (builderclient.TaskDataMetadata, chainclient.InferReceiptSnapshot) {
	t.Helper()
	traceRoot := codec.HashWithDomain("TRACE", []byte(pkg.TaskID))
	receipt, _, err := builderclient.BuildInferReceipt(builderclient.InferReceiptFacts{
		ChainID: chainID, TaskID: pkg.TaskID, TaskHash: hex.EncodeToString(pkg.ReceiptHash[:]),
		WorkerOperatorAddress: worker, ServiceAuthorizationNonce: 13,
		GenerationParamsDigest: hexHash(codec.HashWithDomain("GENERATION", []byte(pkg.TaskID))),
		OutputHash:             pkg.OutputHash, OutputSizeBytes: outputConfirmationSizeBytes, OutputLeafCount: 1,
		RequiredEvidenceCommitments: []builderclient.EvidenceCommitment{{
			EvidenceKind: nodewire.EvidenceKindWorkerValueOpening, EvidenceHashOrRoot: traceRoot, EncodedSizeBytes: 21,
		}},
		// The locked Profile's requirement set, which BuildInferReceipt requires.
		// Only max_encoded_size_bytes needs a real Profile read, so the fixture uses
		// the derived V1 shape at the contract ceiling.
		ProfileEvidenceRequirements: builderclient.WorkerValueEvidenceRequirementsV2(),
		ExpiryHeight:                1200,
	})
	if err != nil {
		t.Fatalf("BuildInferReceipt: %v", err)
	}
	receipt.ServiceSignature = strings.Repeat("ab", 64)
	receiptDigest, err := builderclient.InferReceiptSigningDigest(receipt)
	if err != nil {
		t.Fatalf("InferReceiptSigningDigest: %v", err)
	}
	acceptedReceiptHash := hex.EncodeToString(receiptDigest[:])
	metadata := builderclient.TaskDataMetadata{
		Readiness: builderclient.TaskDataReady, Key: builderclient.TaskDataKey{TaskHash: receipt.TaskHash, SessionID: pkg.SessionID, TaskID: pkg.TaskID, Kind: builderclient.DataKindOutput, ContentHash: hex.EncodeToString(pkg.OutputHash[:])},
		SizeBytes: outputConfirmationSizeBytes, MediaType: "application/octet-stream",
		ChunkLengths: []uint32{uint32(outputConfirmationSizeBytes)}, OutputLeafCount: 1,
		RetainUntilHeight:  500,
		SignedInferReceipt: &receipt,
	}
	snapshot := chainclient.InferReceiptSnapshot{
		SessionID: pkg.SessionID, TaskID: pkg.TaskID, WinnerWorker: worker,
		InferReceiptCommitHash:     chainclient.HexHash(pkg.ReceiptHash),
		InferReceiptHash:           mustHexHash(t, acceptedReceiptHash),
		OutputHash:                 chainclient.HexHash(pkg.OutputHash),
		OutputSizeBytes:            chainclient.NewUint64String(outputConfirmationSizeBytes),
		OutputLeafCount:            chainclient.NewUint64String(1),
		TraceCommitRoot:            chainclient.HexHash(traceRoot),
		CheckpointCommitRoot:       chainclient.HexHash(traceRoot),
		BatchLogRoot:               chainclient.HexHash(codec.HashBytes(nil)),
		TokenCount:                 chainclient.NewUint64String(13),
		WorkUnit:                   chainclient.NewUint64String(21),
		WorkerSignature:            receipt.ServiceSignature,
		CanonicalOutputPackageHash: chainclient.HexHash(pkg.PackageHash),
		OutputDeliveryCommitment:   chainclient.HexHash(codec.HashBytes([]byte("delivery"))),
		ReceiptMode:                "COMMIT_ONLY",
		ReceiptHeight:              chainclient.NewUint64String(215),
	}
	return metadata, snapshot
}

// canonicalOutputPackage builds the package the Worker would have produced: the
// TRUEOPEN_OUTPUT_PACKAGE_V1 digest over the locator triple is what it commits on
// chain, so a fixture that computed it any other way would not exercise the
// policy precheck the confirmed package feeds.
// hexHash is the canonical lowercase 64-hex form the frozen wire's Hash32
// string fields carry.
func hexHash(value codec.Hash) string { return hex.EncodeToString(value[:]) }

func canonicalOutputPackage(t *testing.T, sessionID, taskID, outputRef string) builderclient.OutputPackage {
	t.Helper()
	body := bytes.Repeat([]byte("x"), int(outputConfirmationSizeBytes))
	outputHash, err := codec.OutputMMRRoot([][]byte{body})
	if err != nil {
		t.Fatal(err)
	}
	traceRef := "cortex-artifact://svc/trace/" + taskID
	checkpointRef := "cortex-artifact://svc/checkpoint/" + taskID
	packageHash := codec.HashWithDomain("TRUEOPEN_OUTPUT_PACKAGE_V1",
		[]byte(taskID), []byte(outputRef), []byte(traceRef), []byte(checkpointRef), outputHash[:])
	receiptHash := codec.HashWithDomain("TRUEOPEN_INFER_RECEIPT_RESULT_V1",
		[]byte(taskID), outputHash[:], packageHash[:])
	payload, err := builderclient.EncodeInferReceiptMaterial(builderclient.InferReceiptMaterial{
		TaskID: taskID, OutputRef: outputRef, OutputHash: outputHash,
		PackageHash: packageHash, ReceiptResultHash: receiptHash,
		ActualOutputSummary: fmt.Sprintf("%d bytes output", outputConfirmationSizeBytes),
	})
	if err != nil {
		t.Fatalf("EncodeInferReceiptMaterial: %v", err)
	}
	return builderclient.OutputPackage{
		SessionID: sessionID, TaskID: taskID, OutputRef: outputRef,
		TraceRef: traceRef, CheckpointRef: checkpointRef,
		OutputHash: outputHash, PackageHash: packageHash,
		Output: body, OutputChunkLengths: []uint64{outputConfirmationSizeBytes},
		ReceiptHash: receiptHash, ReceiptPayload: payload,
		WorkerSignature: []byte("worker-signature"),
	}
}

// outputFixture is one internally consistent output: the package a Verifier will
// read, the Builder metadata that proves the Builder holds it, and the Keeper
// receipt snapshot the metadata has to agree with.
type outputFixture struct {
	Package     builderclient.OutputPackage
	Metadata    builderclient.TaskDataMetadata
	Snapshot    chainclient.InferReceiptSnapshot
	Commitments OutputCommitments
}

func newOutputFixture(t *testing.T) outputFixture {
	t.Helper()
	pkg := canonicalOutputPackage(t, strings.Repeat("11", 32), outputTestTaskID, outputTestOutputRef)
	metadata, snapshot := outputConfirmationMaterial(t, outputTestChainID, outputTestWorker, pkg)
	fixture := outputFixture{Package: pkg, Metadata: metadata, Snapshot: snapshot}
	fixture.Commitments = OutputCommitments{
		SessionID: pkg.SessionID, TaskID: pkg.TaskID, TaskHash: pkg.ReceiptHash,
		BuilderOperatorAddress: inputTestBuilder,
		WorkerOperatorAddress:  outputTestWorker,
		OutputHash:             pkg.OutputHash,
		PackageHash:            pkg.PackageHash,
		KeeperReceipt:          &fixture.Snapshot,
	}
	return fixture
}

func mustHexHash(t *testing.T, value string) chainclient.HexHash {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 {
		t.Fatalf("hex hash %q: %v", value, err)
	}
	var out chainclient.HexHash
	copy(out[:], raw)
	return out
}

// staticOutputPackages models the shared package store's addressing contract:
// the only reference that can name a package is the content address of the
// package hash the caller already holds, and the stored package has to agree
// with it. Requests are recorded so a test can assert which address was asked
// for -- the whole point of the change is that it comes from the chain.
type staticOutputPackages struct {
	packages  map[string]builderclient.OutputPackage
	requested []string
	err       error
}

func (s *staticOutputPackages) LoadOutputPackage(_ context.Context, ref string, expected codec.Hash) (builderclient.OutputPackage, error) {
	s.requested = append(s.requested, ref)
	if s.err != nil {
		return builderclient.OutputPackage{}, s.err
	}
	if ref != builderclient.FixtureOutputPackageRef(expected) {
		return builderclient.OutputPackage{}, fmt.Errorf("output package reference %q is not the content address of the expected hash", ref)
	}
	pkg, ok := s.packages[ref]
	if !ok {
		return builderclient.OutputPackage{}, fmt.Errorf("no output package for %q", ref)
	}
	if pkg.PackageHash != expected {
		return builderclient.OutputPackage{}, errors.New("output package digest mismatch")
	}
	return pkg, nil
}

// outputPackagesFor stores pkg under the address the confirmer must derive from
// the chain-committed canonical package hash.
func outputPackagesFor(pkg builderclient.OutputPackage) *staticOutputPackages {
	return &staticOutputPackages{packages: map[string]builderclient.OutputPackage{
		builderclient.FixtureOutputPackageRef(pkg.PackageHash): pkg,
	}}
}

func newOutputConfirmer(t *testing.T, chainID string, client *inputTaskDataClient, packages builderclient.OutputPackageLoader) *NexusOutputConfirmer {
	t.Helper()
	signing, binding := localInputServiceSigner(t)
	auth, err := taskdataauth.New(taskdataauth.Config{
		ServiceKeys: &inputServiceKeys{binding: binding}, Signer: signing,
		ChainID: chainID, OperatorAddress: inputTestOperator,
		ServiceAddress: binding.ServiceAddress, ServicePubkey: binding.ServicePubkey,
		ServiceKeyRef: inputTestKeyRef, ExpiryBlocks: inputTestExpiry,
	})
	if err != nil {
		t.Fatalf("taskdataauth.New: %v", err)
	}
	confirmer, err := NewNexusOutputConfirmer(NexusOutputConfirmerConfig{
		TaskData: client,
		Endpoints: staticEndpoints{endpoint: BuilderEndpoint{
			OperatorAddress: inputTestBuilder,
			Endpoint:        "https://builder.example",
			Source:          BuilderEndpointSourceDescriptor,
		}},
		Auth: auth, Packages: packages, ChainID: chainID,
	})
	if err != nil {
		t.Fatalf("NewNexusOutputConfirmer: %v", err)
	}
	return confirmer
}

func TestNexusOutputConfirmerConfirmsThroughTaskDataMetadata(t *testing.T) {
	fixture := newOutputFixture(t)
	client := &inputTaskDataClient{metadata: fixture.Metadata}
	packages := outputPackagesFor(fixture.Package)
	confirmer := newOutputConfirmer(t, outputTestChainID, client, packages)

	pkg, err := confirmer.ConfirmOutput(context.Background(), fixture.Commitments)
	if err != nil {
		t.Fatalf("ConfirmOutput: %v", err)
	}
	if pkg.TaskID != fixture.Package.TaskID || pkg.PackageHash != fixture.Package.PackageHash {
		t.Fatalf("confirmed package = %#v", pkg)
	}
	// The locator is derived from the chain-committed canonical package hash,
	// never supplied by a caller: OutputCommitments has no locator field to
	// supply one with, and this is the address the store was asked for.
	wantRef := builderclient.FixtureOutputPackageRef(fixture.Package.PackageHash)
	if len(packages.requested) != 1 || packages.requested[0] != wantRef {
		t.Fatalf("package references requested = %#v, want exactly [%q]", packages.requested, wantRef)
	}
	if len(client.metadataRequests) != 1 {
		t.Fatalf("metadata requests = %d, want exactly one", len(client.metadataRequests))
	}
	request := client.metadataRequests[0]
	if request.Key.Kind != builderclient.DataKindOutput {
		t.Fatalf("data kind = %v, want DATA_KIND_OUTPUT", request.Key.Kind)
	}
	if request.Key.SessionID != fixture.Commitments.SessionID || request.Key.TaskID != outputTestTaskID || request.Key.TaskHash != fixture.Commitments.TaskHash.String() {
		t.Fatalf("key = %#v", request.Key)
	}
	// The request is a signed Worker/Verifier responsibility, bound to the
	// receiving Builder and to this method.
	if request.Auth.Method != builderclient.TaskDataProcedure("GetTaskDataMetadata") || request.Auth.BuilderAddress != inputTestBuilder ||
		request.Auth.ChainID != outputTestChainID || len(request.Auth.Signature) == 0 {
		t.Fatalf("request auth = %#v", request.Auth)
	}
}

// TestNexusOutputConfirmerRefusals is the check mapping stated as behaviour: each
// case is one commitment the deleted FetchOutputRef path used to enforce,
// expressed against TaskDataMetadataV1 plus the signed infer receipt.
func TestNexusOutputConfirmerRefusals(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		mutate  func(*outputFixture)
		wantErr string
	}{
		{
			name:    "metadata absent",
			mutate:  func(f *outputFixture) { f.Metadata = builderclient.TaskDataMetadata{} },
			wantErr: "holds no OUTPUT object",
		},
		{
			name: "semantic hash disagrees with the committed output hash",
			mutate: func(f *outputFixture) {
				other := codec.HashWithDomain("OTHER_OUTPUT", []byte(outputTestTaskID))
				f.Metadata.Key.ContentHash = hex.EncodeToString(other[:])
			},
			wantErr: "does not match the committed output hash",
		},
		{
			name:    "signed infer receipt missing",
			mutate:  func(f *outputFixture) { f.Metadata.SignedInferReceipt = nil },
			wantErr: "carries no signed infer receipt",
		},
		{
			name: "signed infer receipt names another Worker",
			mutate: func(f *outputFixture) {
				receipt := *f.Metadata.SignedInferReceipt
				receipt.WorkerOperatorAddress = "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"
				f.Metadata.SignedInferReceipt = &receipt
			},
			wantErr: "does not match the Keeper winner",
		},
		{
			name: "size mismatch between metadata and the signed receipt",
			mutate: func(f *outputFixture) {
				f.Metadata.SizeBytes = f.Metadata.SignedInferReceipt.OutputSizeBytes + 1
			},
			wantErr: "does not match the signed infer receipt size",
		},
		{
			// The receipt carries no self-asserted hash any more, so a tampered
			// signed fact surfaces where the derived digest is compared: against
			// the Keeper's accepted infer_receipt_hash.
			name: "signed fact tampering moves the derived receipt digest",
			mutate: func(f *outputFixture) {
				receipt := *f.Metadata.SignedInferReceipt
				receipt.ServiceAuthorizationNonce++
				f.Metadata.SignedInferReceipt = &receipt
				// Drop the Builder's own echo so the refusal has to come from the
				// Keeper comparison: the derived digest, not a self-consistent
				// pair of Builder-supplied values, is what the chain is asked
				// about.
			},
			wantErr: "infer_receipt_hash",
		},
		{
			name: "object task hash does not match the signed receipt",
			mutate: func(f *outputFixture) {
				other := codec.HashBytes([]byte("other-receipt"))
				f.Metadata.Key.TaskHash = hex.EncodeToString(other[:])
			},
			wantErr: "object reference",
		},
		{
			name: "accepted receipt hash contradicts the Keeper receipt",
			mutate: func(f *outputFixture) {
				f.Snapshot.InferReceiptHash = chainclient.HexHash(codec.HashBytes([]byte("other-receipt")))
				f.Commitments.KeeperReceipt = &f.Snapshot
			},
			wantErr: "infer_receipt_hash",
		},
		{
			name: "output hash contradicts the Keeper receipt",
			mutate: func(f *outputFixture) {
				f.Snapshot.OutputHash = chainclient.HexHash(codec.HashBytes([]byte("other-output")))
				f.Commitments.KeeperReceipt = &f.Snapshot
			},
			wantErr: "output_hash",
		},
		{
			name: "service signature contradicts the accepted Keeper signature",
			mutate: func(f *outputFixture) {
				f.Snapshot.WorkerSignature = strings.Repeat("cd", 64)
				f.Commitments.KeeperReceipt = &f.Snapshot
			},
			wantErr: "service signature does not match",
		},
		{
			name: "loaded package is not the committed output",
			mutate: func(f *outputFixture) {
				f.Package.TaskID = "task-other"
			},
			wantErr: "confirmed output package task",
		},
		{
			// The fetch key is the chain-committed canonical package hash, so a
			// store that does not hold that exact package cannot satisfy the
			// confirmation by holding some other one.
			name: "store holds nothing at the chain-committed address",
			mutate: func(f *outputFixture) {
				f.Commitments.PackageHash = codec.HashBytes([]byte("other-package"))
			},
			wantErr: "no output package for",
		},
		{
			name:    "receiving Builder is not named on the assignment",
			mutate:  func(f *outputFixture) { f.Commitments.BuilderOperatorAddress = "" },
			wantErr: "receiving Builder operator is required",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newOutputFixture(t)
			testCase.mutate(&fixture)
			client := &inputTaskDataClient{metadata: fixture.Metadata}
			confirmer := newOutputConfirmer(t, outputTestChainID, client, outputPackagesFor(fixture.Package))

			_, err := confirmer.ConfirmOutput(context.Background(), fixture.Commitments)
			if err == nil {
				t.Fatal("ConfirmOutput() error = nil, want a refusal")
			}
			if !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("ConfirmOutput() error = %q, want it to contain %q", err, testCase.wantErr)
			}
		})
	}
}

// TestNexusOutputConfirmerWithoutKeeperReceipt covers the candidate handraise
// window, where the receipt is not on chain yet. The chain cross-check has
// nothing to compare against there, so the receipt-internal and bus checks have
// to stand on their own rather than becoming a pass.
func TestNexusOutputConfirmerWithoutKeeperReceipt(t *testing.T) {
	fixture := newOutputFixture(t)
	fixture.Commitments.KeeperReceipt = nil
	packages := outputPackagesFor(fixture.Package)

	if _, err := newOutputConfirmer(t, outputTestChainID, &inputTaskDataClient{metadata: fixture.Metadata}, packages).
		ConfirmOutput(context.Background(), fixture.Commitments); err != nil {
		t.Fatalf("ConfirmOutput without a Keeper receipt: %v", err)
	}

	tampered := *fixture.Metadata.SignedInferReceipt
	tampered.OutputSizeBytes = tampered.OutputSizeBytes + 1
	metadata := fixture.Metadata
	metadata.SignedInferReceipt = &tampered
	_, err := newOutputConfirmer(t, outputTestChainID, &inputTaskDataClient{metadata: metadata}, packages).
		ConfirmOutput(context.Background(), fixture.Commitments)
	if err == nil || !strings.Contains(err.Error(), "does not match the signed infer receipt size") {
		t.Fatalf("ConfirmOutput() error = %v, want a size refusal without a Keeper receipt", err)
	}
}

// TestNexusOutputConfirmerAcceptedReceiptHashIsOptionalButBinding isolates the
// asymmetry at the confirmer boundary, in both the settled and the candidate
// window. accepted_receipt_hash is the Builder's echo of its own chain read, and
// nexus main leaves it empty for every OUTPUT because chaincli.QueryTask stopped
// carrying InferReceipt; requiring it refused every confirmation. Absence is
// tolerated, a present value still has to agree -- including when there is no
// Keeper receipt yet and this is the only place the disagreement can surface.
func TestNexusOutputConfirmerObjectReferenceIsAlwaysBinding(t *testing.T) {
	for _, keeper := range []struct {
		name       string
		withKeeper bool
	}{{name: "with the Keeper receipt", withKeeper: true}, {name: "candidate window", withKeeper: false}} {
		t.Run(keeper.name, func(t *testing.T) {
			absent := newOutputFixture(t)
			if !keeper.withKeeper {
				absent.Commitments.KeeperReceipt = nil
			}
			packages := outputPackagesFor(absent.Package)
			pkg, err := newOutputConfirmer(t, outputTestChainID, &inputTaskDataClient{metadata: absent.Metadata}, packages).
				ConfirmOutput(context.Background(), absent.Commitments)
			if err != nil {
				t.Fatalf("ConfirmOutput with an absent accepted_receipt_hash: %v", err)
			}
			if pkg.PackageHash != absent.Package.PackageHash {
				t.Fatalf("confirmed package = %#v, want the committed output package", pkg)
			}

			disagreeing := newOutputFixture(t)
			other := codec.HashBytes([]byte("other-accepted-receipt"))
			disagreeing.Metadata.Key.TaskHash = hex.EncodeToString(other[:])
			if !keeper.withKeeper {
				disagreeing.Commitments.KeeperReceipt = nil
			}
			_, err = newOutputConfirmer(t, outputTestChainID, &inputTaskDataClient{metadata: disagreeing.Metadata},
				outputPackagesFor(disagreeing.Package)).
				ConfirmOutput(context.Background(), disagreeing.Commitments)
			if err == nil || !strings.Contains(err.Error(), "object reference") {
				t.Fatalf("ConfirmOutput() error = %v, want a refusal on a disagreeing accepted_receipt_hash", err)
			}
			if builderclient.IsRetryable(err) {
				t.Fatalf("ConfirmOutput() error = %v, want a permanent refusal", err)
			}
		})
	}
}

// taskDataOutputFixture is an internally consistent output whose commitments are
// derived from the body itself. The shared-store fixture above cannot be reused:
// it hashes a domain string rather than any bytes, so nothing could ever be
// fetched that satisfies an output MMR commitment.
func newTaskDataOutputFixture(t *testing.T) (outputFixture, []byte) {
	t.Helper()
	body := bytes.Repeat([]byte("trueopen-output-body-"), 1+int(outputConfirmationSizeBytes)/21)[:outputConfirmationSizeBytes]
	outputHash, err := codec.OutputMMRRoot([][]byte{body})
	if err != nil {
		t.Fatal(err)
	}
	// The package hash stays the Worker's TRUEOPEN_OUTPUT_PACKAGE_V1 commitment over
	// the locator triple. The Verifier cannot recompute it -- that is the point --
	// so it is only ever copied through from the Keeper receipt.
	packageHash := codec.HashWithDomain("TRUEOPEN_OUTPUT_PACKAGE_V1",
		[]byte(outputTestTaskID), []byte(outputTestOutputRef),
		[]byte("cortex-artifact://svc/trace/"+outputTestTaskID),
		[]byte("cortex-artifact://svc/checkpoint/"+outputTestTaskID), outputHash[:])
	pkg := builderclient.OutputPackage{
		SessionID: strings.Repeat("11", 32), TaskID: outputTestTaskID,
		OutputHash: outputHash, PackageHash: packageHash,
		ReceiptHash: codec.HashWithDomain("TRUEOPEN_INFER_RECEIPT_RESULT_V1",
			[]byte(outputTestTaskID), outputHash[:], packageHash[:]),
	}
	metadata, snapshot := outputConfirmationMaterial(t, outputTestChainID, outputTestWorker, pkg)
	fixture := outputFixture{Package: pkg, Metadata: metadata, Snapshot: snapshot}
	fixture.Commitments = OutputCommitments{
		SessionID: pkg.SessionID, TaskID: pkg.TaskID, TaskHash: pkg.ReceiptHash,
		BuilderOperatorAddress: inputTestBuilder,
		WorkerOperatorAddress:  outputTestWorker,
		OutputHash:             pkg.OutputHash,
		PackageHash:            pkg.PackageHash,
		KeeperReceipt:          &fixture.Snapshot,
	}
	return fixture, body
}

// A node running a real model transport has no shared package store -- only the
// fake transport ever builds one -- so requiring one left every such node without
// a confirmer, and a Verifier that cannot confirm never signs a handraise. The
// confirmation reads the OUTPUT object off the task-data plane instead, and the
// binding it establishes is stronger than the store's: the bytes the Builder
// served have to hash to the output hash Keeper committed.
func TestNexusOutputConfirmerReadsTheOutputWhenNoPackageStoreIsConfigured(t *testing.T) {
	fixture, body := newTaskDataOutputFixture(t)
	client := &inputTaskDataClient{metadata: fixture.Metadata, payload: body}
	confirmer := newOutputConfirmer(t, outputTestChainID, client, nil)

	pkg, err := confirmer.ConfirmOutput(context.Background(), fixture.Commitments)
	if err != nil {
		t.Fatalf("ConfirmOutput: %v", err)
	}
	if pkg.Provenance != builderclient.OutputPackageFromTaskData {
		t.Fatalf("provenance = %v, want the task-data plane", pkg.Provenance)
	}
	if !bytes.Equal(pkg.Output, body) {
		t.Fatalf("confirmed output = %d bytes, want the %d served", len(pkg.Output), len(body))
	}
	if pkg.OutputHash != fixture.Commitments.OutputHash || pkg.PackageHash != fixture.Commitments.PackageHash {
		t.Fatalf("confirmed commitments = %#v, want the Keeper-committed pair", pkg)
	}
	// The refs are absent by construction: no wire carries them, so asserting
	// values for them would be asserting something unchecked.
	if pkg.OutputRef != "" || pkg.TraceRef != "" || pkg.CheckpointRef != "" {
		t.Fatalf("confirmed package carries locator refs %#v, want none", pkg)
	}
	if len(client.ranges) != 1 {
		t.Fatalf("fetch ranges = %#v, want exactly one", client.ranges)
	}
	if got := client.ranges[0]; got.Range.Offset != 0 || got.Range.Length != outputConfirmationSizeBytes ||
		got.Key.Kind != builderclient.DataKindOutput || got.Auth.BuilderAddress != inputTestBuilder {
		t.Fatalf("signed range = %#v, want the whole OUTPUT object from the receiving Builder", got)
	}
	// Both consumers of a confirmed package have to accept this shape, or the
	// confirmation is useless: the Verifier validates it and then feeds its
	// summary to the L0-L4 precheck.
	if err := builderclient.NewNexusClient(nil).ValidateOutputPackage(context.Background(), pkg); err != nil {
		t.Fatalf("ValidateOutputPackage: %v", err)
	}
	summary := outputPackageSummary(pkg)
	if !summary.FromTaskData {
		t.Fatalf("summary = %#v, want the task-data provenance carried into the precheck", summary)
	}
}

func TestNexusOutputConfirmerRefusesTaskDataOutputThatBreaksItsCommitments(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*outputFixture, *inputTaskDataClient)
		wantText string
	}{
		{
			// The one check the whole fetch exists for. Everything upstream of it
			// is metadata the Builder asserted about itself.
			name: "body does not hash to the committed output hash",
			mutate: func(_ *outputFixture, c *inputTaskDataClient) {
				c.payload = append([]byte("x"), c.payload[1:]...)
			},
			wantText: "not the committed output hash",
		},
		{
			name: "stream stops short of the signed length",
			mutate: func(_ *outputFixture, c *inputTaskDataClient) {
				full := c.payload
				c.fetch = func(_ builderclient.FetchTaskDataRequest, receive func(builderclient.TaskDataChunk) error) error {
					return receive(builderclient.TaskDataChunk{Offset: 0, Data: full[:16], EOF: true})
				}
			},
			wantText: "of 4096 signed bytes",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture, body := newTaskDataOutputFixture(t)
			client := &inputTaskDataClient{metadata: fixture.Metadata, payload: body}
			tt.mutate(&fixture, client)
			confirmer := newOutputConfirmer(t, outputTestChainID, client, nil)

			_, err := confirmer.ConfirmOutput(context.Background(), fixture.Commitments)
			if err == nil || !strings.Contains(err.Error(), tt.wantText) {
				t.Fatalf("ConfirmOutput() error = %v, want %q", err, tt.wantText)
			}
		})
	}
}

// The bound is applied to the size the Worker signed for, before a byte is
// requested, so an oversized object is refused rather than streamed and then
// rejected.
func TestNexusOutputConfirmerRefusesAnOutputAboveTheConfiguredBound(t *testing.T) {
	fixture, body := newTaskDataOutputFixture(t)
	client := &inputTaskDataClient{metadata: fixture.Metadata, payload: body}
	confirmer := newOutputConfirmer(t, outputTestChainID, client, nil)
	confirmer.cfg.MaxOutputBytes = outputConfirmationSizeBytes - 1

	_, err := confirmer.ConfirmOutput(context.Background(), fixture.Commitments)
	if err == nil || !strings.Contains(err.Error(), "above the") {
		t.Fatalf("ConfirmOutput() error = %v, want the size bound refusal", err)
	}
	if len(client.ranges) != 0 {
		t.Fatalf("fetch ranges = %#v, want no fetch attempted", client.ranges)
	}
}

// withoutPackageHash is the real chain: task.v1.InferReceiptState deleted
// canonical_output_package_hash (proto/CHAIN_BINDINGS.md:265), and
// cortex-detailed-design.md:1032 makes that deliberate rather than a gap -- output_hash is
// V1's only output content commitment and the general layer must not generate a
// parallel package hash. Every confirmation therefore has to run with the field absent.
func (f outputFixture) withoutPackageHash() outputFixture {
	f.Snapshot.CanonicalOutputPackageHash = chainclient.HexHash{}
	f.Commitments.PackageHash = codec.Hash{}
	f.Commitments.KeeperReceipt = &f.Snapshot
	return f
}

func TestNexusOutputConfirmerConfirmsWithNoCanonicalPackageHash(t *testing.T) {
	fixture, body := newTaskDataOutputFixture(t)
	fixture = fixture.withoutPackageHash()
	client := &inputTaskDataClient{metadata: fixture.Metadata, payload: body}
	confirmer := newOutputConfirmer(t, outputTestChainID, client, nil)

	pkg, err := confirmer.ConfirmOutput(context.Background(), fixture.Commitments)
	if err != nil {
		t.Fatalf("ConfirmOutput with no committed package hash: %v", err)
	}
	if pkg.OutputHash != fixture.Commitments.OutputHash {
		t.Fatalf("confirmed output hash = %s, want the Keeper-committed %s", pkg.OutputHash, fixture.Commitments.OutputHash)
	}
	if !bytes.Equal(pkg.Output, body) {
		t.Fatalf("confirmed output = %d bytes, want the %d served", len(pkg.Output), len(body))
	}
	// The confirmed package still has to satisfy both of its consumers with the
	// package hash absent, or nothing downstream can use it.
	if err := builderclient.NewNexusClient(nil).ValidateOutputPackage(context.Background(), pkg); err != nil {
		t.Fatalf("ValidateOutputPackage with no package hash: %v", err)
	}
}

// A candidate never reaches this code, and that is the point: data-plane-and-evidence-transfer.md §6
// puts candidate metadata on the ORDER_BROADCAST / OPEN_VERIFY control messages and
// says GetTaskDataMetadata "is not a prerequisite step of the normal Task flow". What
// survives here is V7a, run only after the chain confirmed selection -- and it reads
// metadata once before the body, so a Builder that does not hold the object costs no
// transfer.
func TestConfirmOutputReadsMetadataOnceBeforeTransferringAnyBytes(t *testing.T) {
	fixture, body := newTaskDataOutputFixture(t)
	fixture = fixture.withoutPackageHash()
	client := &inputTaskDataClient{metadata: fixture.Metadata, payload: body}
	confirmer := newOutputConfirmer(t, outputTestChainID, client, nil)

	pkg, err := confirmer.ConfirmOutput(context.Background(), fixture.Commitments)
	if err != nil {
		t.Fatalf("ConfirmOutput: %v", err)
	}
	if len(client.metadataRequests) != 1 {
		t.Fatalf("metadata requests = %d, want exactly one", len(client.metadataRequests))
	}
	if len(client.ranges) != 1 {
		t.Fatalf("fetch ranges = %#v, want exactly the one signed range", client.ranges)
	}
	if pkg.TaskID != fixture.Commitments.TaskID || pkg.SessionID != fixture.Commitments.SessionID {
		t.Fatalf("confirmed package identity = %#v, want the committed task", pkg)
	}
	if uint64(len(pkg.Output)) != outputConfirmationSizeBytes {
		t.Fatalf("confirmed output = %d bytes, want the signed %d", len(pkg.Output), outputConfirmationSizeBytes)
	}
	if pkg.ReceiptHash != codec.Hash(fixture.Snapshot.InferReceiptHash) {
		t.Fatalf("confirmed receipt hash = %s, want the Keeper-accepted %s",
			pkg.ReceiptHash, codec.Hash(fixture.Snapshot.InferReceiptHash))
	}
}

// The metadata read is a gate: an object the Builder does not hold is refused
// there, before a single byte is requested.
func TestConfirmOutputRefusesAnOutputTheBuilderDoesNotHold(t *testing.T) {
	fixture, body := newTaskDataOutputFixture(t)
	fixture = fixture.withoutPackageHash()
	fixture.Metadata.Readiness = builderclient.TaskDataStored
	client := &inputTaskDataClient{metadata: fixture.Metadata, payload: body}
	confirmer := newOutputConfirmer(t, outputTestChainID, client, nil)

	_, err := confirmer.ConfirmOutput(context.Background(), fixture.Commitments)
	if err == nil || !strings.Contains(err.Error(), "holds no OUTPUT object") {
		t.Fatalf("ConfirmOutput() error = %v, want the absent-object refusal", err)
	}
	if len(client.ranges) != 0 {
		t.Fatalf("fetch ranges = %#v, want nothing transferred after the gate refused", client.ranges)
	}
}

// The frozen task.v1.InferReceiptState has no worker_signature column --
// task_id, winner_worker, infer_receipt_hash, generation_params_digest,
// output_hash, output_size_bytes, expiry_height, receipt_height and nothing else
// (internal/chainclient/query_task_v1.go). Comparing the Builder's relayed
// signature against an always-empty chain value refused every V7a download on a
// real chain, so absence is skipped. The receipt is still bound: its derived
// signing digest must equal the infer_receipt_hash the chain accepted, which is a
// commitment over the very material that signature covers.
func TestConfirmOutputToleratesAKeeperReceiptThatCarriesNoWorkerSignature(t *testing.T) {
	fixture, body := newTaskDataOutputFixture(t)
	fixture = fixture.withoutPackageHash()
	chainReceipt := fixture.Snapshot
	chainReceipt.WorkerSignature = ""
	fixture.Commitments.KeeperReceipt = &chainReceipt
	client := &inputTaskDataClient{metadata: fixture.Metadata, payload: body}
	confirmer := newOutputConfirmer(t, outputTestChainID, client, nil)

	pkg, err := confirmer.ConfirmOutput(context.Background(), fixture.Commitments)
	if err != nil {
		t.Fatalf("ConfirmOutput with no on-chain worker signature: %v", err)
	}
	if pkg.OutputHash != fixture.Commitments.OutputHash {
		t.Fatalf("confirmed output hash = %s, want the Keeper-committed %s", pkg.OutputHash, fixture.Commitments.OutputHash)
	}
}

// A signature the chain DOES carry still has to agree, so tolerating absence is
// not tolerating disagreement.
func TestConfirmOutputStillRefusesAWorkerSignatureTheChainContradicts(t *testing.T) {
	fixture, body := newTaskDataOutputFixture(t)
	fixture = fixture.withoutPackageHash()
	chainReceipt := fixture.Snapshot
	chainReceipt.WorkerSignature = strings.Repeat("cd", 64)
	fixture.Commitments.KeeperReceipt = &chainReceipt
	client := &inputTaskDataClient{metadata: fixture.Metadata, payload: body}
	confirmer := newOutputConfirmer(t, outputTestChainID, client, nil)

	_, err := confirmer.ConfirmOutput(context.Background(), fixture.Commitments)
	if err == nil || !strings.Contains(err.Error(), "service signature does not match") {
		t.Fatalf("ConfirmOutput() error = %v, want the signature refusal", err)
	}
}

// output_size_bytes is a chain fact with a field of its own now rather than a
// value smuggled through TokenCount/WorkUnit, so it is judged. A Builder serving
// a different length than the Worker signed for is serving a different object,
// and V7a signs a range over exactly this number.
func TestConfirmOutputRefusesAReceiptSizeTheChainContradicts(t *testing.T) {
	fixture, body := newTaskDataOutputFixture(t)
	fixture = fixture.withoutPackageHash()
	chainReceipt := fixture.Snapshot
	chainReceipt.OutputSizeBytes = chainclient.NewUint64String(outputConfirmationSizeBytes + 1)
	fixture.Commitments.KeeperReceipt = &chainReceipt
	client := &inputTaskDataClient{metadata: fixture.Metadata, payload: body}
	confirmer := newOutputConfirmer(t, outputTestChainID, client, nil)

	_, err := confirmer.ConfirmOutput(context.Background(), fixture.Commitments)
	if err == nil || !strings.Contains(err.Error(), "output size") {
		t.Fatalf("ConfirmOutput() error = %v, want the size refusal", err)
	}
}

func setOutputMMRFixture(t *testing.T, fixture *outputFixture, body []byte, lengths []uint64) {
	t.Helper()
	root, err := codec.OutputMMRRootFromLengths(body, lengths)
	if err != nil {
		t.Fatal(err)
	}
	fixture.Commitments.OutputHash = root
	fixture.Metadata.Key.ContentHash = root.String()
	fixture.Metadata.SizeBytes = uint64(len(body))
	fixture.Metadata.ChunkLengths = make([]uint32, len(lengths))
	for i, length := range lengths {
		fixture.Metadata.ChunkLengths[i] = uint32(length)
	}
	fixture.Metadata.OutputLeafCount = uint64(len(lengths))
	receipt := fixture.Metadata.SignedInferReceipt
	receipt.OutputHash, receipt.OutputSizeBytes, receipt.OutputLeafCount = root.String(), uint64(len(body)), uint64(len(lengths))
	digest, err := builderclient.InferReceiptSigningDigest(*receipt)
	if err != nil {
		t.Fatal(err)
	}
	fixture.Snapshot.OutputHash = chainclient.HexHash(root)
	fixture.Snapshot.OutputSizeBytes = chainclient.NewUint64String(uint64(len(body)))
	fixture.Snapshot.OutputLeafCount = chainclient.NewUint64String(uint64(len(lengths)))
	fixture.Snapshot.InferReceiptHash = chainclient.HexHash(digest)
	fixture.Commitments.KeeperReceipt = &fixture.Snapshot
}

func TestNexusOutputConfirmerPreservesMMRBoundariesAndEmptyOutput(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    []byte
		lengths []uint64
	}{
		{"multiple chunks", []byte("Hello, world!"), []uint64{5, 2, 5, 1}},
		{"empty output", nil, []uint64{0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture, _ := newTaskDataOutputFixture(t)
			setOutputMMRFixture(t, &fixture, tc.body, tc.lengths)
			client := &inputTaskDataClient{metadata: fixture.Metadata, payload: tc.body}
			pkg, err := newOutputConfirmer(t, outputTestChainID, client, nil).ConfirmOutput(context.Background(), fixture.Commitments)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pkg.Output, tc.body) || !slices.Equal(pkg.OutputChunkLengths, tc.lengths) {
				t.Fatal("confirmed output lost exact TEXT boundaries")
			}
		})
	}
}

func TestNexusOutputConfirmerRejectsIncorrectMMRMetadata(t *testing.T) {
	for _, name := range []string{"missing lengths", "missing leaf count", "short lengths", "long lengths", "wrong leaf count", "rechunked bytes", "UTF-8 split"} {
		t.Run(name, func(t *testing.T) {
			fixture, body := newTaskDataOutputFixture(t)
			switch name {
			case "missing lengths":
				fixture.Metadata.ChunkLengths = nil
			case "missing leaf count":
				fixture.Metadata.OutputLeafCount = 0
			case "short lengths":
				fixture.Metadata.ChunkLengths[0]--
			case "long lengths":
				fixture.Metadata.ChunkLengths[0]++
			case "wrong leaf count":
				fixture.Metadata.OutputLeafCount++
			case "rechunked bytes", "UTF-8 split":
				if name == "UTF-8 split" {
					body = []byte{0xc3, 0xa9}
					setOutputMMRFixture(t, &fixture, body, []uint64{2})
				}
				fixture.Metadata.ChunkLengths = []uint32{1, uint32(len(body) - 1)}
				fixture.Metadata.OutputLeafCount = 2
				fixture.Metadata.SignedInferReceipt.OutputLeafCount = 2
				digest, err := builderclient.InferReceiptSigningDigest(*fixture.Metadata.SignedInferReceipt)
				if err != nil {
					t.Fatal(err)
				}
				fixture.Snapshot.OutputLeafCount = chainclient.NewUint64String(2)
				fixture.Snapshot.InferReceiptHash = chainclient.HexHash(digest)
				fixture.Commitments.KeeperReceipt = &fixture.Snapshot
			}
			client := &inputTaskDataClient{metadata: fixture.Metadata, payload: body}
			if _, err := newOutputConfirmer(t, outputTestChainID, client, nil).ConfirmOutput(context.Background(), fixture.Commitments); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
}
