package integration_readiness

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/taskdataauth"
	"github.com/TrueOpen/cortex/internal/taskfacts"
	"github.com/TrueOpen/cortex/internal/worker"
	"github.com/TrueOpen/cortex/test/internal/generationfixture"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

type memoryPersistence struct {
	evidence      []worker.EvidenceRecord
	outbox        []worker.OutboxRecord
	jobs          []worker.ModelJobCheckpoint
	receipts      map[string]worker.InferReceiptCheckpoint
	artifacts     map[string][]byte
	confirmations map[string][]worker.StorageConfirmationCheckpoint
	builder       *builderclient.FakeClient
}

func (p *memoryPersistence) WriteEvidence(_ context.Context, record worker.EvidenceRecord) error {
	p.evidence = append(p.evidence, record)
	if p.artifacts == nil {
		p.artifacts = make(map[string][]byte)
	}
	p.artifacts[record.TaskID+"/"+record.Kind] = append([]byte(nil), record.Data...)
	return nil
}
func (p *memoryPersistence) CheckpointInferOutput(ctx context.Context, taskID string, output, trace, checkpoint []byte, cp worker.InferOutputCheckpoint) error {
	for _, rec := range []worker.EvidenceRecord{
		{TaskID: taskID, Kind: "worker-output", Data: output},
		{TaskID: taskID, Kind: "worker-trace", Data: trace},
		{TaskID: taskID, Kind: "worker-checkpoint", Data: checkpoint},
		{TaskID: taskID, Kind: "worker-output-descriptor", Data: cp.DescriptorJSON},
	} {
		if err := p.WriteEvidence(ctx, rec); err != nil {
			return err
		}
	}
	return nil
}

func (p *memoryPersistence) WriteBuilderOutbox(_ context.Context, record worker.OutboxRecord) error {
	record.Payload = append([]byte(nil), record.Payload...)
	if record.Status == "" {
		record.Status = "pending"
	}
	for i := range p.outbox {
		if p.outbox[i].Digest != record.Digest {
			continue
		}
		if record.Status == "held" || (p.outbox[i].Status == "sent" && record.Status == "pending") {
			return nil
		}
		p.outbox[i] = record
		return nil
	}
	p.outbox = append(p.outbox, record)
	return nil
}

func TestMemoryPersistencePreservesMonotonicOutboxState(t *testing.T) {
	ctx := context.Background()
	digest := codec.HashBytes([]byte("outbox"))
	p := &memoryPersistence{}

	write := func(status, payload string) {
		t.Helper()
		if err := p.WriteBuilderOutbox(ctx, worker.OutboxRecord{
			TaskID: "task-1", Subject: "trueopen.output.available.task-1",
			Digest: digest, Status: status, Payload: []byte(payload),
		}); err != nil {
			t.Fatalf("WriteBuilderOutbox(%s): %v", status, err)
		}
	}

	write("held", "held")
	write("held", "changed-held")
	if got := string(p.outbox[0].Payload); got != "held" {
		t.Fatalf("duplicate held payload = %q, want immutable original", got)
	}
	write("pending", "released")
	write("held", "downgraded")
	if got := p.outbox[0].Status; got != "pending" {
		t.Fatalf("held downgrade status = %q, want pending", got)
	}
	write("sent", "sent")
	write("held", "held-after-sent")
	if got := p.outbox[0]; got.Status != "sent" || string(got.Payload) != "sent" {
		t.Fatalf("held-after-sent outbox = status %q payload %q, want sent/sent", got.Status, got.Payload)
	}
	write("pending", "reopened")
	if got := p.outbox[0].Status; got != "sent" {
		t.Fatalf("sent reopen status = %q, want sent", got)
	}
}

func (p *memoryPersistence) CheckpointInferInput(context.Context, worker.InferInputCheckpoint) error {
	return nil
}
func (p *memoryPersistence) InferInput(context.Context, string) (worker.InferInputCheckpoint, error) {
	return worker.InferInputCheckpoint{}, worker.ErrCheckpointNotFound
}
func (p *memoryPersistence) CheckpointModelJob(_ context.Context, record worker.ModelJobCheckpoint) error {
	p.jobs = append(p.jobs, record)
	return nil
}

func (p *memoryPersistence) CheckpointInferReceipt(_ context.Context, record worker.InferReceiptCheckpoint) error {
	if p.receipts == nil {
		p.receipts = make(map[string]worker.InferReceiptCheckpoint)
	}
	if existing, ok := p.receipts[record.TaskID]; ok {
		if existing.MaterialDigest != record.MaterialDigest || !bytes.Equal(existing.Payload, record.Payload) {
			return fmt.Errorf("infer receipt %s conflicts with persisted signed evidence", record.TaskID)
		}
		return nil
	}
	record.Payload = append([]byte(nil), record.Payload...)
	p.receipts[record.MaterialDigest] = record
	return nil
}

func (p *memoryPersistence) InferReceipts(_ context.Context, _ string) ([]worker.InferReceiptCheckpoint, error) {
	out := make([]worker.InferReceiptCheckpoint, 0, len(p.receipts))
	for _, r := range p.receipts {
		out = append(out, r)
	}
	return out, nil
}

func (p *memoryPersistence) CheckpointStorageConfirmation(_ context.Context, record worker.StorageConfirmationCheckpoint) error {
	if p.confirmations == nil {
		p.confirmations = make(map[string][]worker.StorageConfirmationCheckpoint)
	}
	if record.BuilderServicePubkey == "" || len(record.Signature) == 0 {
		return fmt.Errorf("storage confirmation record is incomplete")
	}
	records := p.confirmations[record.TaskID]
	for _, existing := range records {
		if existing.DataKind != record.DataKind || existing.BuilderOperator != record.BuilderOperator ||
			existing.MaterialDigest != record.MaterialDigest {
			continue
		}
		if existing.SemanticHash != record.SemanticHash || existing.SizeBytes != record.SizeBytes ||
			existing.RetentionUntilHeight != record.RetentionUntilHeight || !bytes.Equal(existing.Signature, record.Signature) ||
			existing.BuilderServicePubkey != record.BuilderServicePubkey {
			return fmt.Errorf("storage confirmation for task %s conflicts with persisted signed evidence", record.TaskID)
		}
		return nil
	}
	record.Signature = append([]byte(nil), record.Signature...)
	p.confirmations[record.TaskID] = append(records, record)
	return nil
}

func (p *memoryPersistence) ReadArtifact(_ context.Context, taskID string, kind string) ([]byte, error) {
	if p.artifacts == nil {
		return nil, worker.ErrCheckpointNotFound
	}
	data, ok := p.artifacts[taskID+"/"+kind]
	if !ok {
		return nil, worker.ErrCheckpointNotFound
	}
	return append([]byte(nil), data...), nil
}

func (p *memoryPersistence) OutputStreamFrames(_ context.Context, taskID string) ([]builderclient.OutputChunk, error) {
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

func (p *memoryPersistence) StorageConfirmations(_ context.Context, taskID string) ([]worker.StorageConfirmationCheckpoint, error) {
	records := p.confirmations[taskID]
	out := make([]worker.StorageConfirmationCheckpoint, len(records))
	for i, record := range records {
		record.Signature = append([]byte(nil), record.Signature...)
		out[i] = record
	}
	return out, nil
}

func (p *memoryPersistence) BuilderMessage(_ context.Context, digest string) (worker.BuilderMessageCheckpoint, error) {
	for _, record := range p.outbox {
		if hex.EncodeToString(record.Digest[:]) == digest {
			return worker.BuilderMessageCheckpoint{
				Digest: digest, Subject: record.Subject, TaskID: record.TaskID,
				Payload: append([]byte(nil), record.Payload...), Status: record.Status,
			}, nil
		}
	}
	return worker.BuilderMessageCheckpoint{}, worker.ErrCheckpointNotFound
}

// readinessSnapshotReader returns a snapshot derived from a registered assignment.
type readinessSnapshotReader struct {
	mu         sync.Mutex
	assignment chainclient.AssignmentFinalized
}

func (r *readinessSnapshotReader) set(assignment chainclient.AssignmentFinalized) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.assignment = assignment
}

func (r *readinessSnapshotReader) TaskSnapshot(ctx context.Context, taskID string) (chainclient.TaskSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
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
			AcceptedOrderPayloadHash: chainclient.HexHash(codec.HashBytes(r.assignment.Input)),
		},
		CurrentContract: true,
	}, nil
}

func TestFakeBackedIntegrationReadinessWorkerPath(t *testing.T) {
	cfg := config.Config{
		Mode:    config.ModeFake,
		ChainID: "trueopen-devnet-1",
		Admin: config.AdminConfig{
			UDSPath: "/tmp/cortexd.sock",
		},
		ModelManagement: config.ModelManagementConfig{
			Endpoint:  "127.0.0.1:9090",
			Transport: "fake",
		},
		Node: config.NodeConfig{
			RPCEndpoint: "http://127.0.0.1:26657",
		},
		Artifacts: config.ArtifactsConfig{
			Root: t.TempDir(),
		},
		Store: config.StoreConfig{
			Path: t.TempDir() + "/cortex.kv",
		},
		Signer: config.SignerConfig{
			URI: "file:///tmp/cortex/signer.key",
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	const sessionID = "9a60be7e8311c94a69157b3e09c6a9fcca224e0e09f9eb5db7484dc183a926dc"
	const orderSequence = uint64(7)
	taskID := identity.TaskIDString(sessionID, orderSequence)
	orderDigest := codec.HashWithDomain("E2E_ORDER", []byte(taskID))

	model := modelservice.NewFakeService()
	builder := builderclient.NewFakeClient()
	outputFixture := newReadinessWorkerOutputFixture(t, builder, cfg.ChainID, "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc", "trueopen1j7r6u8nwvw93l2tc0wd75v07vu89lxyfqf8fut", 90)
	persistence := &memoryPersistence{builder: builder}
	evidenceSchemaHash := codec.HashWithDomain("TRUEOPEN_EVIDENCE_SCHEMA_V1", []byte(taskID))
	snapshotReader := &readinessSnapshotReader{}
	generation := generationfixture.New(t, taskID, "llama-dev", "READINESS_ACCEPTED_TASK_HASH_V1")
	workerNode := worker.New(worker.Config{
		WorkerAddress:               "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc",
		ModelServiceID:              "fake-model-service",
		Model:                       model,
		Builder:                     builder,
		TaskData:                    outputFixture.taskData,
		StreamLimits:                &chainclient.OutputStreamLimitsSnapshot{MinOutputStreamFrameBytes: 16, MaxOutputMMRLeaves: 65536},
		TaskDataAuth:                outputFixture.auth,
		Persistence:                 persistence,
		InferDeadlineDeltaHeights:   20,
		ChainID:                     cfg.ChainID,
		SessionID:                   sessionID,
		OrderSequence:               orderSequence,
		SignerAddress:               outputFixture.serviceAddress,
		SignerKeyRef:                outputFixture.serviceKeyRef,
		SignerPubkey:                outputFixture.servicePubkey,
		Signer:                      outputFixture.signer,
		NexusEnvelopeSigner:         testNexusEnvelopeSigner(),
		EvidenceSchemaHash:          hex.EncodeToString(evidenceSchemaHash[:]),
		ProfileEvidenceRequirements: builderclient.WorkerValueEvidenceRequirementsV2(),
		ReceivingBuilder:            worker.ReceivingBuilderFunc(outputFixture.receivingBuilder),
		TaskFacts:                   taskfacts.ReaderFunc(generation.TaskFacts),
		GenerationReader:            generation,
		SnapshotReader:              snapshotReader,
	})

	event := chainclient.AssignmentFinalized{
		TaskID:                 taskID,
		SessionID:              sessionID,
		OrderSequence:          orderSequence,
		OrderDigest:            orderDigest,
		Winner:                 "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc",
		WinnerConfirmHeight:    90,
		InferDeadlineHeight:    110,
		ModelID:                "llama-dev",
		ProfileVersion:         1,
		Capability:             modelservice.CapabilityLLMTextV1,
		Input:                  []byte("hello"),
		BuilderOperatorAddress: "trueopen1j7r6u8nwvw93l2tc0wd75v07vu89lxyfqf8fut",
	}
	snapshotReader.set(event)
	// With the locked Profile's evidence schema supplied, the Worker can sign a
	// frozen task.v1.InferReceiptV2 and publish OUTPUT_AVAILABLE.
	result, err := workerNode.HandleAssignmentFinalized(context.Background(), event)
	if err != nil {
		t.Fatalf("HandleAssignmentFinalized() error = %v", err)
	}
	if !result.Started {
		t.Fatalf("Started = false, want a started responsibility")
	}
	outputAvailableCount := 0
	for _, req := range builder.Published {
		t.Logf("published subject=%s", req.Subject)
		if req.Subject == builderclient.NATSOutputAvailableSubject(taskID) {
			outputAvailableCount++
		}
	}
	if outputAvailableCount != 1 {
		t.Fatalf("OUTPUT_AVAILABLE publishes = %d, want 1", outputAvailableCount)
	}
	// Receipt was submitted and output was announced.
	if len(outputFixture.taskData.SubmittedInferReceipts) == 0 {
		t.Fatalf("want a submitted infer receipt")
	}

	// The model ran, its package was validated, and the three infer artifacts a
	// later reveal needs are on disk.
	if len(builder.ValidatedPackages) != 1 {
		t.Fatalf("validated packages = %d, want the inference to have completed", len(builder.ValidatedPackages))
	}
	if len(persistence.evidence) != 13 {
		t.Fatalf("evidence records = %d, want completed model response, result artifacts, token vectors, signed output frame and Fin, and stored acknowledgement", len(persistence.evidence))
	}
	evidenceKinds := make(map[string]bool, len(persistence.evidence))
	for _, record := range persistence.evidence {
		evidenceKinds[record.Kind] = record.TaskID == taskID
	}
	for _, kind := range []string{"worker-output", "worker-trace", "worker-checkpoint", "worker-output-descriptor", "worker-infer-receipt", "worker-result", "worker-evidence-manifest", "worker-input_token_ids", "worker-generated_token_ids", worker.OutputStreamFinKind, "worker-output-stream-stored", "worker-model-result", worker.OutputStreamFrameKind(0)} {
		if !evidenceKinds[kind] {
			t.Fatalf("evidence kinds = %#v, want task-bound %s", evidenceKinds, kind)
		}
	}
}

func testNexusEnvelopeSigner() builderclient.BusEnvelopeSigner {
	// Bound to the envelope, not a constant: a stub that returns fixed bytes
	// regardless of what it was asked to sign cannot fail when the signing
	// preimage changes, which is exactly how a wrong-preimage bug once reached
	// main with every test green. These flows do not verify the signature, so the
	// value need not be a real secp256k1 one - it only has to move when the
	// digest moves.
	return builderclient.BusEnvelopeSignerFunc(func(envelope builderclient.BusEnvelope) ([]byte, error) {
		digest, err := builderclient.BusEnvelopeSignDigest(envelope)
		if err != nil {
			return nil, err
		}
		return append(append([]byte(nil), digest[:]...), digest[:]...), nil
	})
}

type readinessWorkerOutputFixture struct {
	taskData       *readinessSignedTaskData
	auth           *taskdataauth.Authenticator
	signer         readinessOutputSigner
	serviceAddress string
	servicePubkey  string
	serviceKeyRef  string
	builder        worker.BuilderEndpoint
}

func newReadinessWorkerOutputFixture(
	t *testing.T,
	client *builderclient.FakeClient,
	chainID string,
	workerAddress string,
	builderOperator string,
	currentHeight uint64,
) readinessWorkerOutputFixture {
	t.Helper()
	servicePrivate := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{0x51}, 32))
	servicePublic := servicePrivate.PubKey().SerializeCompressed()
	serviceAddress, err := signer.AddressFromCompressedPublicKey("trueopen", servicePublic)
	if err != nil {
		t.Fatalf("derive Worker service address: %v", err)
	}
	const serviceKeyRef = "test-worker-key"
	outputSigner := readinessOutputSigner{private: servicePrivate, address: serviceAddress, keyRef: serviceKeyRef}
	servicePubkey := hex.EncodeToString(servicePublic)
	auth, err := taskdataauth.New(taskdataauth.Config{
		ServiceKeys: readinessServiceKeys{served: currentHeight, binding: chainclient.ServiceKeySnapshot{
			ParticipantType:    chainclient.ParticipantTypeCortexNode,
			OperatorAddress:    workerAddress,
			ServiceAddress:     serviceAddress,
			ServicePubkey:      servicePubkey,
			AuthorizationNonce: chainclient.NewUint64String(1),
			Status:             "ACTIVE",
		}},
		Signer:          outputSigner,
		ChainID:         chainID,
		OperatorAddress: workerAddress,
		ServiceAddress:  serviceAddress,
		ServicePubkey:   servicePubkey,
		ServiceKeyRef:   serviceKeyRef,
		ExpiryBlocks:    20,
	})
	if err != nil {
		t.Fatalf("taskdataauth.New: %v", err)
	}
	builderPrivate := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{0x61}, 32))
	return readinessWorkerOutputFixture{
		taskData:       &readinessSignedTaskData{FakeClient: client, builderPrivate: builderPrivate},
		auth:           auth,
		signer:         outputSigner,
		serviceAddress: serviceAddress,
		servicePubkey:  servicePubkey,
		serviceKeyRef:  serviceKeyRef,
		builder: worker.BuilderEndpoint{
			OperatorAddress:    builderOperator,
			Endpoint:           "https://builder.example",
			ServicePubkey:      hex.EncodeToString(builderPrivate.PubKey().SerializeCompressed()),
			CurrentHeight:      currentHeight,
			AuthorizationNonce: 1,
		},
	}
}

// receivingBuilder implements worker.ReceivingBuilderProvider: the fixture keeps
// the assignment's Builder as the only authority, exactly as the daemon provider
// does today.
func (f readinessWorkerOutputFixture) receivingBuilder(
	_ context.Context,
	task worker.ReceivingBuilderRef,
) (worker.BuilderEndpoint, error) {
	if task.AssignedBuilderOperator != f.builder.OperatorAddress {
		return worker.BuilderEndpoint{}, fmt.Errorf("unexpected Builder operator %q", task.AssignedBuilderOperator)
	}
	return f.builder, nil
}

type readinessOutputSigner struct {
	private *secp256k1.PrivateKey
	address string
	keyRef  string
}

func (s readinessOutputSigner) SignDigest(_ context.Context, request signer.DigestRequest) ([]byte, error) {
	if request.KeyRef != s.keyRef || request.ExpectedSignerAddress != s.address {
		return nil, fmt.Errorf("unexpected Worker output signer identity")
	}
	return readinessCompactSignature(s.private, request.Digest), nil
}

func (readinessOutputSigner) SignCosmosTx(context.Context, signer.CosmosTxRequest) ([]byte, error) {
	return nil, fmt.Errorf("not supported")
}

func (readinessOutputSigner) CanSignCosmosTx() bool { return false }

func readinessCompactSignature(private *secp256k1.PrivateKey, digest codec.Hash) []byte {
	signature := ecdsa.Sign(private, digest[:])
	r, s := signature.R(), signature.S()
	rBytes, sBytes := r.Bytes(), s.Bytes()
	out := make([]byte, 64)
	copy(out[:32], rBytes[:])
	copy(out[32:], sBytes[:])
	return out
}

type readinessServiceKeys struct {
	binding chainclient.ServiceKeySnapshot
	// served is the height Keeper answers the committed service-key read at.
	served uint64
}

func (s readinessServiceKeys) CommittedCurrentServiceKey(context.Context, string, string) (chainclient.ServiceKeySnapshot, uint64, error) {
	return s.binding, s.served, nil
}

type readinessSignedTaskData struct {
	*builderclient.FakeClient
	builderPrivate *secp256k1.PrivateKey
}

func (c *readinessSignedTaskData) FinalizeTaskResult(ctx context.Context, endpoint string, request builderclient.FinalizeTaskResultRequest) (builderclient.FinalizeTaskResultResponse, error) {
	result, err := c.FakeClient.FinalizeTaskResult(ctx, endpoint, request)
	if err != nil {
		return result, err
	}
	confirmations := []*builderclient.StorageConfirmation{&result.OutputConfirmation}
	for i := range result.EvidenceBundleConfirmations {
		confirmations = append(confirmations, &result.EvidenceBundleConfirmations[i])
	}
	for _, confirmation := range confirmations {
		digest, err := builderclient.StorageConfirmationSigningHash(*confirmation)
		if err != nil {
			return builderclient.FinalizeTaskResultResponse{}, err
		}
		confirmation.Signature = readinessCompactSignature(c.builderPrivate, digest)
	}
	return result, nil
}
