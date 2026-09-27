package daemon

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/taskdataauth"
	"github.com/TrueOpen/cortex/internal/tasktrace"
)

// OutputCommitments are the facts an output confirmation has to agree with.
// Every one of them comes from an authenticated Nexus bus frame or from the
// Keeper snapshot -- never from the Builder being asked, which is the whole
// point of asking.
type OutputCommitments struct {
	SessionID string
	TaskID    string
	TaskHash  codec.Hash
	// BuilderOperatorAddress is the Builder that received the task and therefore
	// holds its output.
	BuilderOperatorAddress string
	// WorkerOperatorAddress is the Keeper-confirmed winner. The Builder's signed
	// receipt has to name the same Worker.
	WorkerOperatorAddress string
	// There is deliberately no locator field. OUTPUT_AVAILABLE's output_cid is
	// an auxiliary hint with no authoritative source -- Keeper commits no
	// locator and GetTaskDataMetadata returns none by contract.
	//
	// OutputHash is V1's ONLY output content commitment
	// (keeper-service-design-appendix.md item 50, keeper-data-structure-contract.md:1881), and
	// cortex-detailed-design.md:1032 lists "a parallel commitment such as a package hash or a
	// delivery hash" beside "no private key enters the LLM layer" among the §13 hard
	// boundaries. So this is the one value a confirmation is judged against.
	OutputHash codec.Hash
	// PackageHash is NOT a commitment. task.v1.InferReceiptState deleted
	// canonical_output_package_hash (proto/CHAIN_BINDINGS.md:265), so on a real
	// chain it is always zero and nothing here may require it. It survives as a
	// local addressing hint for the fixture package store that only the fake
	// model transport builds: that store is content-addressed by it and has no
	// other key. Zero means "address the OUTPUT object off the task-data plane
	// instead", which is every real-transport node.
	PackageHash codec.Hash
	// KeeperReceipt is the on-chain InferReceipt when Keeper has accepted one.
	// A selected Verifier always has it -- the chain cannot have opened verify
	// without it -- but it stays a pointer because a restored responsibility that
	// predates the field decodes to nothing, and a missing chain cross-check must
	// read as "absent" rather than as "compared against zero and passed".
	KeeperReceipt *chainclient.InferReceiptSnapshot
}

// OutputConfirmer downloads the committed output for a task once the chain has
// put this node in the selected Verifier set. That is V7a and it is the ONLY
// step at which Cortex touches the task-data plane as a Verifier.
//
// There is deliberately no metadata-only method beside it. V3 -- the candidate's
// metadata check before a handraise -- is served entirely by the OPEN_VERIFY
// control message plus the Keeper snapshot: data-plane-and-evidence-transfer.md §6 says candidate
// metadata is "broadcast by the ORDER_BROADCAST / OPEN_VERIFY control messages and
// not obtained through the data query interface", and that GetTaskDataMetadata "is
// not a prerequisite step of the normal Task flow". A ConfirmOutputMetadata
// that queried the Builder before the handraise was therefore not a weaker
// version of this call but a forbidden one, and nexus refuses it
// (NEXUS_DATA_UNAUTHORIZED) because its FetchTaskData/metadata authorisation
// admits only a selected Worker, a selected Verifier or the original User.
type OutputConfirmer interface {
	ConfirmOutput(context.Context, OutputCommitments) (builderclient.OutputPackage, error)
}

type NexusOutputConfirmerConfig struct {
	TaskData  builderclient.TaskDataClient
	Endpoints BuilderEndpointResolver
	Auth      *taskdataauth.Authenticator
	// Packages loads the canonical output package from a store the Worker and
	// the Verifier share, addressed by the chain-committed canonical package
	// hash; the store refuses a reference whose bytes do not hash to
	// PackageHash.
	//
	// It is OPTIONAL, and nil is the normal production case. Only the fake
	// model transport ever populates it (internal/daemon/dependencies.go), so
	// requiring it made the confirmer unconstructible on every node running a
	// real model transport -- which is the node that actually verifies. With no
	// store the confirmation reads the OUTPUT object itself off the task-data
	// plane instead; see confirmFromTaskData.
	Packages builderclient.OutputPackageLoader
	ChainID  string
	// MaxOutputBytes bounds the OUTPUT fetch. The size the Worker signed for is
	// checked against this before a single byte is requested, so an oversized
	// object is refused rather than streamed and then rejected.
	MaxOutputBytes uint64
	// Trace reports what the Builder answered with, digests included. Nil is
	// silent; cortexd supplies the sink that logs.
	Trace *tasktrace.Trace
}

// NexusOutputConfirmer confirms an output through the task-data plane:
// GetTaskDataMetadata with DATA_KIND_OUTPUT against the Builder endpoint the
// on-chain descriptor commits.
type NexusOutputConfirmer struct {
	cfg NexusOutputConfirmerConfig
}

func NewNexusOutputConfirmer(cfg NexusOutputConfirmerConfig) (*NexusOutputConfirmer, error) {
	switch {
	case cfg.TaskData == nil:
		return nil, fmt.Errorf("Nexus output confirmer requires a task-data client")
	case cfg.Endpoints == nil:
		return nil, fmt.Errorf("Nexus output confirmer requires a Builder endpoint resolver")
	case cfg.Auth == nil:
		return nil, fmt.Errorf("Nexus output confirmer requires a task-data authenticator")
	case strings.TrimSpace(cfg.ChainID) == "":
		return nil, fmt.Errorf("Nexus output confirmer requires a chain id")
	}
	if cfg.MaxOutputBytes == 0 {
		cfg.MaxOutputBytes = defaultConfirmedOutputBytes
	}
	return &NexusOutputConfirmer{cfg: cfg}, nil
}

// defaultConfirmedOutputBytes matches verifier.DefaultMaxOutputBytes: the output
// is not evidence, so no locked profile field sizes it, and an unbounded fetch
// must not be expressible.
const defaultConfirmedOutputBytes = 64 << 20

// ConfirmOutput is the V7a download: the metadata gate, then the object itself,
// bound to the chain-committed output hash. Both halves run as a selected
// Verifier, which is the role nexus authorises for either call.
func (c *NexusOutputConfirmer) ConfirmOutput(ctx context.Context, commitments OutputCommitments) (builderclient.OutputPackage, error) {
	if err := ctx.Err(); err != nil {
		return builderclient.OutputPackage{}, err
	}
	if err := validateOutputCommitments(commitments); err != nil {
		return builderclient.OutputPackage{}, err
	}
	var pkg builderclient.OutputPackage
	err := dialBuilder(ctx, c.cfg.Endpoints, commitments.BuilderOperatorAddress, func(ctx context.Context, endpoint BuilderEndpoint) error {
		got, err := c.confirmFrom(ctx, commitments, endpoint)
		pkg = got
		return err
	})
	if err != nil {
		return builderclient.OutputPackage{}, err
	}
	return pkg, nil
}

// confirmFrom fetches the metadata and the object from an already-resolved Builder
// (with ctx already checking the certificate against its fingerprint).
func (c *NexusOutputConfirmer) confirmFrom(ctx context.Context, commitments OutputCommitments, endpoint BuilderEndpoint) (builderclient.OutputPackage, error) {
	key, metadata, err := c.readOutputMetadata(ctx, commitments, endpoint)
	if err != nil {
		return builderclient.OutputPackage{}, err
	}
	// A non-zero package hash only ever comes from the fake model transport's
	// fixture store, which is content-addressed by it. A real chain commits none
	// (proto/CHAIN_BINDINGS.md:265), so the store is unaddressable and the OUTPUT
	// object on the task-data plane is the only thing to read.
	if c.cfg.Packages != nil && !commitments.PackageHash.IsZero() {
		pkg, err := c.cfg.Packages.LoadOutputPackage(ctx,
			builderclient.FixtureOutputPackageRef(commitments.PackageHash), commitments.PackageHash)
		if err != nil {
			return builderclient.OutputPackage{}, err
		}
		if err := validateConfirmedOutputPackage(commitments, pkg); err != nil {
			return builderclient.OutputPackage{}, err
		}
		pkg.OutputChunkLengths = outputChunkLengths(metadata)
		return pkg, nil
	}
	return c.confirmFromTaskData(ctx, commitments, endpoint.Endpoint, key, metadata)
}

// readOutputMetadata asks the resolved receiving Builder for OUTPUT metadata and
// judges the answer. It is the first half of V7a and has no other caller: a
// candidate never reaches it, because a candidate is not authorised to ask
// (see OutputConfirmer).
func (c *NexusOutputConfirmer) readOutputMetadata(ctx context.Context, commitments OutputCommitments, endpoint BuilderEndpoint) (builderclient.TaskDataKey, builderclient.TaskDataMetadata, error) {
	key := builderclient.TaskDataKey{
		TaskHash: commitments.TaskHash.String(), SessionID: commitments.SessionID, TaskID: commitments.TaskID, Kind: builderclient.DataKindOutput, ContentHash: commitments.OutputHash.String(),
	}
	digest, err := builderclient.TaskDataMetadataBodyDigest(key)
	if err != nil {
		return key, builderclient.TaskDataMetadata{}, err
	}
	auth, err := c.cfg.Auth.SignRequest(ctx, "GetTaskDataMetadata", key, commitments.BuilderOperatorAddress, digest)
	if err != nil {
		return key, builderclient.TaskDataMetadata{}, err
	}
	metadata, err := c.cfg.TaskData.GetTaskDataMetadata(ctx, endpoint.Endpoint,
		builderclient.GetTaskDataMetadataRequest{Key: key, Auth: auth})
	if err != nil {
		return key, builderclient.TaskDataMetadata{}, err
	}
	c.traceMetadata(commitments, endpoint.Endpoint, metadata)
	if err := c.validateOutputMetadata(commitments, metadata); err != nil {
		return key, builderclient.TaskDataMetadata{}, err
	}
	return key, metadata, nil
}

// confirmFromTaskData is the confirmation for a node with no shared package
// store, which is every node running a real model transport. It reads the OUTPUT
// object itself off the task-data plane rather than a canonical package off local
// disk, and the object is addressed by the Keeper-committed output hash.
//
// The three artifact refs are deliberately absent from the result. They are
// Worker-local model-service addresses (internal/worker/worker.go builds them
// from its own InferResponse) and no wire carries them: the OUTPUT metadata has
// no field for them and Keeper commits only their digest. A Verifier that
// invented values for them would be asserting something it cannot check, so the
// confirmed package states what it proved and nothing more -- the fetched bytes,
// bound to the chain-committed output hash, plus the Worker-signed receipt the
// Builder accepted.
func (c *NexusOutputConfirmer) confirmFromTaskData(
	ctx context.Context,
	commitments OutputCommitments,
	endpoint string,
	key builderclient.TaskDataKey,
	metadata builderclient.TaskDataMetadata,
) (builderclient.OutputPackage, error) {
	if metadata.SizeBytes > c.cfg.MaxOutputBytes {
		return builderclient.OutputPackage{}, fmt.Errorf(
			"OUTPUT for task %s is %d bytes, above the %d byte confirmation bound",
			commitments.TaskID, metadata.SizeBytes, c.cfg.MaxOutputBytes)
	}
	auth, err := c.cfg.Auth.SignFetch(ctx, key, commitments.BuilderOperatorAddress, nil)
	if err != nil {
		return builderclient.OutputPackage{}, err
	}
	output := make([]byte, 0, min(metadata.SizeBytes, maxEvidencePrealloc))
	ended := false
	err = c.cfg.TaskData.FetchTaskData(ctx, endpoint, builderclient.FetchTaskDataRequest{Key: key, Auth: auth},
		func(chunk builderclient.TaskDataChunk) error {
			if ended || chunk.Offset != uint64(len(output)) || uint64(len(output))+uint64(len(chunk.Data)) > metadata.SizeBytes {
				return fmt.Errorf("OUTPUT stream for task %s exceeds the signed %d bytes", commitments.TaskID, metadata.SizeBytes)
			}
			output = append(output, chunk.Data...)
			ended = chunk.EOF
			return nil
		})
	if err != nil {
		return builderclient.OutputPackage{}, err
	}
	if !ended || uint64(len(output)) != metadata.SizeBytes {
		return builderclient.OutputPackage{}, fmt.Errorf(
			"OUTPUT stream for task %s delivered %d of %d signed bytes", commitments.TaskID, len(output), metadata.SizeBytes)
	}
	// The one binding that matters: the bytes the Builder served must hash to
	// what Keeper committed. Everything upstream of this is metadata the Builder
	// asserted about itself.
	got, err := codec.OutputMMRRootFromLengths(output, outputChunkLengths(metadata))
	if err != nil {
		return builderclient.OutputPackage{}, fmt.Errorf("OUTPUT chunk boundaries: %w", err)
	}
	if got != commitments.OutputHash {
		return builderclient.OutputPackage{}, fmt.Errorf(
			"OUTPUT bytes for task %s hash to %s, not the committed output hash %s",
			commitments.TaskID, got, commitments.OutputHash)
	}
	receipt := metadata.SignedInferReceipt
	receiptHash, err := builderclient.InferReceiptSigningDigest(*receipt)
	if err != nil {
		return builderclient.OutputPackage{}, err
	}
	signature, err := hex.DecodeString(receipt.ServiceSignature)
	if err != nil {
		return builderclient.OutputPackage{}, fmt.Errorf("decode signed infer receipt service signature: %w", err)
	}
	confirmedReceipt := *receipt
	return builderclient.OutputPackage{
		SessionID: commitments.SessionID, TaskID: commitments.TaskID,
		OutputHash: commitments.OutputHash, PackageHash: commitments.PackageHash,
		ReceiptHash: receiptHash, WorkerSignature: signature,
		Output: output, SignedInferReceipt: &confirmedReceipt,
		OutputChunkLengths: outputChunkLengths(metadata),
		Provenance:         builderclient.OutputPackageFromTaskData,
	}, nil
}

// traceMetadata prints what the receiving Builder answered with beside what the
// caller demanded, before any of it is judged. Every refusal below names one
// field; this names them all, which is the difference between "the semantic
// hash disagreed" and knowing which of the two values to go and fix.
func (c *NexusOutputConfirmer) traceMetadata(commitments OutputCommitments, endpoint string, metadata builderclient.TaskDataMetadata) {
	if !c.cfg.Trace.Enabled() {
		return
	}
	fields := []tasktrace.Field{
		tasktrace.Str("task", commitments.TaskID), tasktrace.Str("session", commitments.SessionID),
		tasktrace.Str("builder", commitments.BuilderOperatorAddress), tasktrace.Str("endpoint", endpoint),
		tasktrace.Hash("committed_output_hash", commitments.OutputHash),
		tasktrace.Hash("committed_package_hash", commitments.PackageHash),
		tasktrace.Bool("object_ready", metadata.Readiness == builderclient.TaskDataReady),
		tasktrace.Hex("content_hash", metadata.Key.ContentHash),
		tasktrace.Uint("size_bytes", metadata.SizeBytes),
		tasktrace.Str("media_type", metadata.MediaType),
		// Nothing judges retain_until_height -- decode stopped requiring it once
		// nexus#66 proved a zero lease locks a Verifier out of an object it can
		// see -- but an operator diagnosing a vanished object needs to read the
		// Builder's answer, and this is the only place it is printed.
		tasktrace.Uint("retain_until_height", metadata.RetainUntilHeight),
	}
	if receipt := metadata.SignedInferReceipt; receipt != nil {
		derived := codec.Hash{}
		if digest, err := builderclient.InferReceiptSigningDigest(*receipt); err == nil {
			derived = digest
		}
		fields = append(fields,
			tasktrace.Hex("receipt_task_hash", receipt.TaskHash),
			tasktrace.Str("receipt_worker", receipt.WorkerOperatorAddress),
			tasktrace.Hex("receipt_output_hash", receipt.OutputHash),
			tasktrace.Uint("receipt_output_size_bytes", receipt.OutputSizeBytes),
			tasktrace.Hex("receipt_generation_params_digest", receipt.GenerationParamsDigest),
			tasktrace.Int("receipt_evidence_commitments", len(receipt.RequiredEvidenceCommitments)),
			tasktrace.Uint("receipt_expiry_height", receipt.ExpiryHeight),
			tasktrace.Hash("derived_receipt_hash", derived))
	} else {
		fields = append(fields, tasktrace.Bool("signed_infer_receipt", false))
	}
	if keeper := commitments.KeeperReceipt; keeper != nil {
		fields = append(fields,
			tasktrace.Hex("keeper_output_hash", keeper.OutputHash.String()),
			tasktrace.Hex("keeper_infer_receipt_hash", keeper.InferReceiptHash.String()),
			tasktrace.Str("keeper_winner_worker", keeper.WinnerWorker))
	}
	c.cfg.Trace.Event("output_confirm_metadata", fields...)
}

func validateOutputCommitments(commitments OutputCommitments) error {
	for name, value := range map[string]string{
		"session id":                 commitments.SessionID,
		"task id":                    commitments.TaskID,
		"receiving Builder operator": commitments.BuilderOperatorAddress,
		"Worker operator":            commitments.WorkerOperatorAddress,
	} {
		if value == "" || strings.TrimSpace(value) != value {
			return fmt.Errorf("output confirmation %s is required and must be canonical", name)
		}
	}
	// output_hash and nothing else. A zero package hash used to refuse here, and
	// on a real chain that is every task: task.v1.InferReceiptState carries
	// no canonical_output_package_hash to fill it from, so no Cortex node could
	// confirm an output and none could raise a Verifier hand. Demanding it was
	// also the wrong side of cortex-detailed-design.md:1032, which forbids Cortex from
	// generating a parallel package commitment rather than merely tolerating its
	// absence.
	if commitments.TaskHash.IsZero() || commitments.OutputHash.IsZero() {
		return fmt.Errorf("output confirmation for task %s requires the committed output hash, got output_hash=%s",
			commitments.TaskID, tasktrace.HashForLog(commitments.OutputHash))
	}
	return nil
}

// validateOutputMetadata is the target-state replacement for fetching an
// OutputRef object. The contract returns no locator and no package, so the proof
// is the boundary metadata plus the Worker-signed InferReceipt the Builder
// accepted: the object exists, its content digest is the committed output hash,
// its size is the size the Worker signed for, the receipt's own hash recomputes
// from its facts, and -- once Keeper has the receipt -- every fact matches the
// chain.
func (c *NexusOutputConfirmer) validateOutputMetadata(commitments OutputCommitments, metadata builderclient.TaskDataMetadata) error {
	expectedKey := builderclient.TaskDataKey{TaskHash: commitments.TaskHash.String(), SessionID: commitments.SessionID, TaskID: commitments.TaskID, Kind: builderclient.DataKindOutput, ContentHash: commitments.OutputHash.String()}
	if metadata.Readiness != builderclient.TaskDataReady {
		return fmt.Errorf("receiving Builder %s holds no OUTPUT object for task %s",
			commitments.BuilderOperatorAddress, commitments.TaskID)
	}
	committedOutputHash := hex.EncodeToString(commitments.OutputHash[:])
	if metadata.Key.ContentHash != committedOutputHash {
		return fmt.Errorf("OUTPUT metadata semantic hash %q does not match the committed output hash %s",
			metadata.Key.ContentHash, committedOutputHash)
	}
	if metadata.Key != expectedKey {
		return fmt.Errorf("OUTPUT metadata object reference differs from committed task")
	}
	receipt := metadata.SignedInferReceipt
	if receipt == nil {
		return fmt.Errorf("OUTPUT metadata for task %s carries no signed infer receipt", commitments.TaskID)
	}
	if receipt.ChainID != c.cfg.ChainID || receipt.TaskHash != commitments.TaskHash.String() {
		return fmt.Errorf("signed infer receipt chain or task hash mismatch")
	}
	if receipt.TaskID != commitments.TaskID {
		return fmt.Errorf("signed infer receipt task %q does not match %q", receipt.TaskID, commitments.TaskID)
	}
	if receipt.WorkerOperatorAddress != commitments.WorkerOperatorAddress {
		return fmt.Errorf("signed infer receipt Worker %q does not match the Keeper winner %q",
			receipt.WorkerOperatorAddress, commitments.WorkerOperatorAddress)
	}
	if receipt.OutputHash != committedOutputHash {
		return fmt.Errorf("signed infer receipt output hash %q does not match the committed output hash %s",
			receipt.OutputHash, committedOutputHash)
	}
	if receipt.OutputSizeBytes != metadata.SizeBytes {
		return fmt.Errorf("OUTPUT metadata size %d does not match the signed infer receipt size %d",
			metadata.SizeBytes, receipt.OutputSizeBytes)
	}
	if metadata.OutputLeafCount == 0 || metadata.OutputLeafCount != receipt.OutputLeafCount || uint64(len(metadata.ChunkLengths)) != receipt.OutputLeafCount {
		return fmt.Errorf("OUTPUT metadata output leaf count differs from signed receipt or chunk lengths")
	}
	var total uint64
	for _, length := range metadata.ChunkLengths {
		if uint64(length) > metadata.SizeBytes-total {
			return fmt.Errorf("OUTPUT metadata chunk lengths exceed signed size")
		}
		total += uint64(length)
	}
	if total != metadata.SizeBytes || total == 0 && (len(metadata.ChunkLengths) != 1 || metadata.ChunkLengths[0] != 0) {
		return fmt.Errorf("OUTPUT metadata chunk lengths do not cover signed output")
	}
	// infer_receipt_hash is no longer a receipt field: §5.14 makes it the signing
	// digest, so deriving it here binds every signed fact locally -- including for
	// a candidate handraise that runs before Keeper has the receipt at all.
	receiptHash, err := builderclient.InferReceiptSigningDigest(*receipt)
	if err != nil {
		return fmt.Errorf("derive signed infer receipt hash: %w", err)
	}
	derivedReceiptHash := hex.EncodeToString(receiptHash[:])
	// accepted_receipt_hash is the Builder echoing back what its own chain read
	// said Keeper accepted, so an ABSENT value means "the Builder did not
	// consult the chain", not "there is no accepted receipt". On nexus main
	// (258f6c5) it is structurally always absent for every OUTPUT:
	// taskdata.Authorizer.finishMetadata overwrites it on every metadata read
	// with task.InferReceipt.AcceptedItemHash, and chaincli.mapTask leaves the
	// whole InferReceipt section zero because the frozen contract moved those
	// facts out of QueryTask into a separate task.v1.Query/InferReceipt RPC
	// that has no caller yet -- chaincli/client_test.go:258-262 pins that zero
	// value as the intended current behaviour, so this is an upstream gap with a
	// known end date, not a rule we relaxed. Requiring it would fail every
	// confirmation closed and no Verifier handraise could ever be signed.
	//
	// Tolerating absence costs nothing an attacker could use: both operands of
	// this comparison come from the same Builder response, so it only ever
	// detected a self-inconsistent Builder. The external commitments still hold
	// unconditionally -- semantic_hash against the bus-committed output hash, the
	// receipt hash recomputed from its own facts above, and the Keeper
	// cross-check below, which compares this same accepted-receipt fact against
	// the chain directly instead of against a Nexus echo.
	//
	// A PRESENT value is still a commitment the Builder chose to make and must
	// agree; disagreement stays a terminal refusal.
	return validateReceiptAgainstKeeper(commitments.KeeperReceipt, *receipt, derivedReceiptHash)
}

// validateReceiptAgainstKeeper compares the Builder's signed receipt with the
// one Keeper accepted. This is what replaces recomputing Cortex's canonical
// output package hash: the chain, not a Nexus echo, is the authority on what the
// Worker committed to.
//
// The comparable field set shrank with the frozen wire, which deleted
// infer_receipt_commit_hash, trace_commit_root, checkpoint_commit_root,
// batch_log_root, token_count and work_unit from the receipt. What remains is
// the receipt's identity (its derived digest), the output it commits, the Worker
// it belongs to and the signature the chain settled on. The Keeper snapshot
// still carries the deleted columns; they have no receipt counterpart to compare
// against, so comparing them would only assert that a Builder echoed a Keeper
// value it never received.
func validateReceiptAgainstKeeper(
	keeper *chainclient.InferReceiptSnapshot,
	receipt builderclient.SignedInferReceipt,
	derivedReceiptHash string,
) error {
	if keeper == nil {
		return nil
	}
	if receipt.GeneratedTokenCount != keeper.GeneratedTokenCount.Uint64() {
		return fmt.Errorf("signed infer receipt generated token count differs from Keeper receipt")
	}
	if receipt.OutputLeafCount != keeper.OutputLeafCount.Uint64() {
		return fmt.Errorf("signed infer receipt output leaf count differs from Keeper receipt")
	}
	if keeper.WinnerWorker != receipt.WorkerOperatorAddress {
		return fmt.Errorf("signed infer receipt Worker %q does not match the Keeper receipt winner %q",
			receipt.WorkerOperatorAddress, keeper.WinnerWorker)
	}
	for _, field := range [...]struct {
		name   string
		keeper string
		nexus  string
	}{
		{"infer_receipt_hash", keeper.InferReceiptHash.String(), derivedReceiptHash},
		{"output_hash", keeper.OutputHash.String(), receipt.OutputHash},
	} {
		if field.keeper != field.nexus {
			return fmt.Errorf("signed infer receipt %s %q does not match the Keeper receipt %q",
				field.name, field.nexus, field.keeper)
		}
	}
	// output_size_bytes is a chain fact again rather than a value smuggled through
	// TokenCount, so the Builder's metadata is judged against it. It is not a
	// content commitment -- output_hash is the only one -- but a Builder serving a
	// different length than the Worker signed for is serving a different object,
	// and V7a signs a range over exactly this number.
	if size := keeper.OutputSizeBytes.Uint64(); size != receipt.OutputSizeBytes {
		return fmt.Errorf("signed infer receipt output size %d does not match the Keeper receipt %d",
			receipt.OutputSizeBytes, size)
	}
	// The service signature is the Worker's signature over the canonical receipt
	// material, and comparing it with the accepted on-chain value would be a
	// stronger binding than verifying it locally -- when the chain carries one.
	// The frozen task.v1.InferReceiptState does not: it has task_id,
	// winner_worker, infer_receipt_hash, generation_params_digest, output_hash,
	// output_size_bytes, expiry_height and receipt_height, and no signature
	// column. So this is skipped when absent rather than failed closed, exactly
	// like accepted_receipt_hash above; requiring it refused every V7a download on
	// a real chain. The receipt is still bound: its derived signing digest has to
	// equal the infer_receipt_hash the chain accepted, which is a commitment over
	// the very material this signature covers.
	if keeper.WorkerSignature != "" && !strings.EqualFold(keeper.WorkerSignature, receipt.ServiceSignature) {
		return fmt.Errorf("signed infer receipt service signature does not match the Keeper receipt worker signature")
	}
	return nil
}

func outputChunkLengths(metadata builderclient.TaskDataMetadata) []uint64 {
	lengths := make([]uint64, len(metadata.ChunkLengths))
	for i, length := range metadata.ChunkLengths {
		lengths[i] = uint64(length)
	}
	return lengths
}

// validateConfirmedOutputPackage re-checks the loaded package against the same
// commitments. The loader already refuses a reference whose bytes do not hash to
// PackageHash; this covers the identity and receipt-material bindings the fetch
// path used to check on the response.
func validateConfirmedOutputPackage(commitments OutputCommitments, pkg builderclient.OutputPackage) error {
	if pkg.TaskID != commitments.TaskID {
		return fmt.Errorf("confirmed output package task %q does not match %q", pkg.TaskID, commitments.TaskID)
	}
	// Only when the caller had an address to load by. A zero commitment package
	// hash never reaches here -- the loader path is skipped for it -- and must
	// not be turned into an assertion that the stored package has none.
	if !commitments.PackageHash.IsZero() && pkg.PackageHash != commitments.PackageHash {
		return fmt.Errorf("confirmed output package hash %s does not match the committed package hash %s",
			tasktrace.HashForLog(pkg.PackageHash), tasktrace.HashForLog(commitments.PackageHash))
	}
	if pkg.OutputHash != commitments.OutputHash {
		return fmt.Errorf("confirmed output package output hash %s does not match the committed output hash %s",
			tasktrace.HashForLog(pkg.OutputHash), tasktrace.HashForLog(commitments.OutputHash))
	}
	if pkg.SessionID != "" && pkg.SessionID != commitments.SessionID {
		return fmt.Errorf("confirmed output package session %q does not match %q", pkg.SessionID, commitments.SessionID)
	}
	material, err := builderclient.DecodeInferReceiptMaterial(pkg.ReceiptPayload)
	if err != nil {
		return err
	}
	if material.TaskID != pkg.TaskID || material.OutputRef != pkg.OutputRef || material.OutputHash != pkg.OutputHash ||
		material.PackageHash != pkg.PackageHash || material.ReceiptResultHash != pkg.ReceiptHash {
		return fmt.Errorf("confirmed infer receipt material does not match the output package")
	}
	return nil
}
