package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/daemon"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/evidencebundle"
	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/keepercontract"
	"github.com/TrueOpen/cortex/internal/modelregistry"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/observability"
	"github.com/TrueOpen/cortex/internal/policy"
	signerclient "github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/taskdataauth"
	"github.com/TrueOpen/cortex/internal/taskfacts"
	"github.com/TrueOpen/cortex/internal/tasktrace"
	"github.com/TrueOpen/cortex/internal/txclient"
	"github.com/TrueOpen/cortex/internal/verifier"
	"github.com/TrueOpen/cortex/internal/worker"
	cortexv1 "github.com/TrueOpen/cortex/proto/cortex/v1"
	"github.com/TrueOpen/cortex/test/internal/generationfixture"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

// integrationVerifierAddress is the Verifier's operator address. The frozen
// VerifyCommitV1 and ResultReceiptV1 preimages decode verifier_operator_address
// as a Bech32 address, so a placeholder like "verifier-1" is refused for its
// shape before any missing frozen input is reached. The Keeper fake's formal
// verifier set names the same address, so this node is genuinely assigned.
const integrationVerifierAddress = "trueopen1gdm6ttxkdhzukec53gjgrrg728apsw7j73xf2q"

func TestAdapterBackedCortexFlowRegisterSupportInferVerifySettlementCleanupAndRestart(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	storePath := filepath.Join(t.TempDir(), "cortex.kv")
	kvStore := mustOpenStoreAt(t, storePath)
	evidenceStore, err := evidence.NewStore(root, kvStore)
	if err != nil {
		t.Fatal(err)
	}

	const (
		modelID         = "adapter-llm-text"
		modelSvcID      = "grpc-model-service"
		chainID         = "chain-integration"
		workerAddress   = "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc"
		verifierAddr    = integrationVerifierAddress
		gasPayer        = "cortex1operator"
		builderOperator = "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"
	)
	nats := &memoryNATS{}
	builder := &natsBackedBuilder{nats: nats}
	persistence := &integrationPersistence{
		store: kvStore, evidence: evidenceStore, evidenceRoot: root, cleanupHeight: 300,
		builder: builder,
	}
	servicePrivate := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{0x51}, 32))
	servicePubkey := servicePrivate.PubKey().SerializeCompressed()
	serviceAddress, err := signerclient.AddressFromCompressedPublicKey("trueopen", servicePubkey)
	if err != nil {
		t.Fatalf("derive integration service address: %v", err)
	}
	const serviceKeyRef = "test-worker-key"
	outputSigner := integrationOutputSigner{private: servicePrivate, address: serviceAddress, keyRef: serviceKeyRef}
	servicePubkeyHex := hex.EncodeToString(servicePubkey)
	taskAuth, err := taskdataauth.New(taskdataauth.Config{
		ServiceKeys: integrationServiceKeys{binding: chainclient.ServiceKeySnapshot{
			ParticipantType: chainclient.ParticipantTypeCortexNode, OperatorAddress: workerAddress,
			ServiceAddress: serviceAddress, ServicePubkey: servicePubkeyHex,
			AuthorizationNonce: chainclient.NewUint64String(1), Status: "ACTIVE",
		}},
		Signer: outputSigner, ChainID: chainID,
		OperatorAddress: workerAddress, ServiceAddress: serviceAddress,
		ServicePubkey: servicePubkeyHex, ServiceKeyRef: serviceKeyRef, ExpiryBlocks: 20,
	})
	if err != nil {
		t.Fatalf("taskdataauth.New: %v", err)
	}
	builderPrivate := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{0x61}, 32))
	taskData := &integrationTaskData{FakeClient: builderclient.NewFakeClient(), builderPrivate: builderPrivate}
	signer := &recordingSigner{address: gasPayer}
	rpc := &scriptedRPC{account: txclient.Account{Address: gasPayer, Sequence: 7}}
	tx := txclient.NewBroadcaster(txclient.BroadcasterConfig{
		ChainID:      chainID,
		GasPayer:     gasPayer,
		MaxFeeAmount: 1_000,
		FeeDenom:     "utrueopen",
		MaxAttempts:  3,
		GasLimit:     200000,
		Signer:       signer,
		RPC:          rpc,
		Confirmer: txclient.ConfirmFunc(func(context.Context, txclient.Request, txclient.InclusionResult) (bool, error) {
			return true, nil
		}),
	})
	registry := modelregistry.NewRegistry(modelregistry.RegistryConfig{
		NowHeight:  func() (uint64, error) { return 100, nil },
		Treasury:   "treasury-1",
		FeeDenom:   "utrueopen",
		Outbox:     integrationRegistrationOutbox{},
		SelfTester: passingSelfTest,
		Signer: func(context.Context, modelregistry.RegistrationMaterial) (string, error) {
			return strings.Repeat("ab", 64), nil
		},
		FeeGrant:            modelregistry.StaticFeeGrant{Granter: gasPayer, Amount: 100, GasLimit: 50},
		MinGasGrant:         10,
		SupporterAddress:    workerAddress,
		InferenceCapability: true,
		SupportConfirmer: modelregistry.NewTxSupportConfirmer(tx, modelregistry.TxSupportConfirmerOptions{
			ChainID: chainID, OperatorAddress: workerAddress,
			Signer: testDigestSigner(), ServiceKeyRef: "test-worker-key", ServiceAddress: workerAddress,
			ServiceIdentity: func(context.Context) (uint64, uint64, uint64, uint64, error) { return 3, 100, 1, 199, nil },
			GasPayer:        gasPayer, FeeCap: txclient.Coin{Amount: 5, Denom: "utrueopen"},
			SupportedProfiles: []keepercontract.ProfileRef{{ModelID: modelID, ProfileVersion: 1}},
		}),
	})

	modelServer := newIntegrationGRPCServer(t)
	model := modelservice.NewRemoteClient(modelservice.NewGRPCTransportForClient(modelServer.client))
	keeperServer := newKeeperServer(t, modelID)
	keeper := chainclient.NewKeeperABCIClient(keeperServer.URL)
	height, err := keeper.ChainHeight(ctx)
	if err != nil {
		t.Fatalf("keeper ChainHeight returned error: %v", err)
	}
	if height != 123 {
		t.Fatalf("keeper height = %d, want 123", height)
	}

	manifest, err := registry.GenerateManifest(ctx, modelregistry.ManifestInput{
		ModelID:        modelID,
		Version:        "2026-07-10",
		Digest:         "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Tokenizer:      "tiktoken-cl100k",
		ModelServiceID: modelSvcID,
		Verification:   modelregistry.VerificationSpec{Method: "trace_sample_v1", ProfileVersion: "1"},
		Pricing:        modelregistry.PricingSpec{Denom: "utrueopen", PromptUnitPrice: 1, CompletionUnitPrice: 2},
		TokenizerHash:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RuntimeVersion: "runtime-v1",
		RuntimeHash: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", QuantHash: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		HardwareTierFloor: 1, ResourceTier: "3",
		MinStake: 500000, ChallengeOpenWindowBlocks: 100, EpsilonParams: "epsilon-v1", TimeoutBootstrapProfile: "timeout-v1",
		SchemaHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", MetadataHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	})
	if err != nil {
		t.Fatalf("GenerateManifest returned error: %v", err)
	}
	registration, err := registry.Register(ctx, modelregistry.RegisterRequest{
		Manifest: manifest,
		Quote: modelregistry.FeeQuote{
			Height:              101,
			ExpiresAtHeight:     200,
			Denom:               "utrueopen",
			TreasuryDestination: "treasury-1",
			FeeKind:             modelregistry.FeeKindRegistration,
			Amount:              10,
			GasLimit:            50,
		},
		Mode: modelregistry.SubmitViaBuilder,
	})
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if registration.OutboxID == "" || registration.TxID != "" || len(rpc.broadcasts) != 0 {
		t.Fatalf("registration = %#v broadcasts=%d, want Builder outbox without unregistered Keeper tx", registration, len(rpc.broadcasts))
	}
	intent, err := registry.PrepareOperatorSupportIntent(ctx, modelregistry.SupportRequest{ModelID: manifest.ModelID, ProfileVersion: "1", Supported: true})
	if err != nil || intent.Message.OperatorAddress != workerAddress {
		t.Fatalf("PrepareOperatorSupportIntent = %#v, %v", intent, err)
	}
	if len(rpc.broadcasts) != 0 {
		t.Fatalf("operator support intent broadcast %d service-signed transactions", len(rpc.broadcasts))
	}
	if _, err := registry.DailySupport(ctx, modelregistry.DailySupportRequest{ModelID: manifest.ModelID, Enabled: true}); err != nil {
		t.Fatalf("DailySupport returned error: %v", err)
	}

	const sessionID = "9d36f5fac299f7d5afb105c5fb36a135ae42ce60fb3b33df56cdd81a3013dc95"
	const orderSequence = uint64(7)
	taskID := identity.TaskIDString(sessionID, orderSequence)
	orderDigest := codec.HashWithDomain("INTEGRATION_ORDER", []byte(taskID))
	taskHash := codec.HashWithDomain("INTEGRATION_ACCEPTED_TASK_HASH_V1", []byte(taskID))
	persistence.taskHash = taskHash
	assignment := chainclient.AssignmentFinalized{
		TaskID:                 taskID,
		SessionID:              sessionID,
		OrderSequence:          orderSequence,
		OrderDigest:            orderDigest,
		Winner:                 workerAddress,
		WinnerConfirmHeight:    120,
		InferDeadlineHeight:    140,
		ModelID:                modelID,
		ProfileVersion:         1,
		Capability:             modelservice.CapabilityLLMTextV1,
		Input:                  []byte("adapter integration prompt"),
		BuilderOperatorAddress: builderOperator,
	}
	keeperServer.AddAssignment(assignment)
	keeperServer.AddEvent(chainclient.KeeperEvent{
		Type:           chainclient.KeeperEventAssignAcceptedPendingRandomness,
		TaskID:         taskID,
		Height:         119,
		SessionID:      sessionID,
		OrderSequence:  orderSequence,
		OrderDigest:    orderDigest,
		ModelID:        modelID,
		ProfileVersion: "1",
	})
	keeperServer.AddEvent(chainclient.KeeperEvent{
		Type:           chainclient.KeeperEventAssignmentFinalized,
		TaskID:         taskID,
		Height:         120,
		SessionID:      sessionID,
		OrderSequence:  orderSequence,
		OrderDigest:    orderDigest,
		Worker:         workerAddress,
		ModelID:        modelID,
		ProfileVersion: "1",
	})
	reconciler := daemon.NewReconciler(daemon.ReconcilerOptions{TaskReader: keeperServer})
	taskOwner := daemon.NewTaskRunner(daemon.TaskRunnerConfig{
		Store:              kvStore,
		LocalWorkerAddress: workerAddress, LocalVerifierAddress: verifierAddr,
	})
	poller := daemon.NewKeeperPoller(kvStore, keeperServer, reconciler, daemon.KeeperPollerConfig{
		MaxChainLag: 20,
		EffectSink:  taskOwner.ApplyReconcilerEffects,
	})
	if err := poller.RunOnce(ctx); err != nil {
		t.Fatalf("KeeperPoller RunOnce returned error: %v", err)
	}
	processedHeight, err := kvStore.KeeperLastProcessedHeight(ctx)
	if err != nil || processedHeight != 120 {
		t.Fatalf("Keeper processed height = %d err=%v, want 120", processedHeight, err)
	}
	inferRecord, err := layout.GetInferRecord(ctx, kvStore, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatalf("GetInferRecord after poller/scheduler: %v", err)
	}
	if inferRecord.Stage != layout.StageQueued {
		t.Fatalf("infer record = %#v, want queued task keyed by accepted task hash", inferRecord)
	}
	evidenceSchemaHash := codec.Hash(integrationLockedProfile(modelID).Profile.VerificationProfile.EvidenceSchemaHash)
	// The joint-debugging trace, collected instead of logged. Asserted after the
	// receipt is built, because the digests it prints are the ones a peer derives
	// for itself: if they stop reaching the log, a disagreement with Nexus or
	// Keeper becomes undiagnosable from this node's side.
	var traceRecords []observability.LogRecord
	generation := generationfixture.New(t, taskID, modelID, "INTEGRATION_ACCEPTED_TASK_HASH_V1")
	workerNode := worker.New(worker.Config{
		WorkerAddress:             workerAddress,
		ModelServiceID:            modelSvcID,
		Model:                     model,
		Builder:                   builder,
		TaskData:                  taskData,
		TaskDataAuth:              taskAuth,
		Persistence:               workerPersistence{persistence},
		InferDeadlineDeltaHeights: 20,
		ChainID:                   chainID,
		SessionID:                 sessionID,
		OrderSequence:             orderSequence,
		SignerAddress:             serviceAddress,
		SignerKeyRef:              serviceKeyRef,
		SignerPubkey:              servicePubkeyHex,
		Signer:                    outputSigner,
		NexusEnvelopeSigner:       testNexusEnvelopeSigner(),
		// The locked Profile's evidence schema. In production the daemon reads it
		// from hub.v1.Query/Profile and passes it to the Worker. This rig
		// supplies the same V1 shape directly so the receipt can be signed.
		EvidenceSchemaHash:          hex.EncodeToString(evidenceSchemaHash[:]),
		ProfileEvidenceRequirements: builderclient.WorkerValueEvidenceRequirementsV2(),
		StreamLimits:                &chainclient.OutputStreamLimitsSnapshot{MaxOutputMMRLeaves: 65536, MinOutputStreamFrameBytes: 16},
		// The fixture keeps the assignment's Builder as the only authority, the
		// same binding daemon.receivingBuilders enforces in production.
		ReceivingBuilder: worker.ReceivingBuilderFunc(
			func(_ context.Context, task worker.ReceivingBuilderRef) (worker.BuilderEndpoint, error) {
				if task.AssignedBuilderOperator != builderOperator {
					return worker.BuilderEndpoint{}, fmt.Errorf(
						"unexpected Builder operator %q", task.AssignedBuilderOperator)
				}
				return worker.BuilderEndpoint{
					OperatorAddress: builderOperator, Endpoint: "https://builder.example",
					ServicePubkey: hex.EncodeToString(builderPrivate.PubKey().SerializeCompressed()), CurrentHeight: 120, AuthorizationNonce: 1,
				}, nil
			}),
		// The frozen section 16.2 Task read the receipt's two consensus fields
		// come from. The values are functions of the task id, so an answer for the
		// wrong task would be visibly different rather than coincidentally right.
		TaskFacts:        taskfacts.ReaderFunc(generation.TaskFacts),
		GenerationReader: generation,
		SnapshotReader:   &workerSnapshotReader{assignment: assignment},
		Trace:            &tasktrace.Trace{Emit: func(record observability.LogRecord) { traceRecords = append(traceRecords, record) }},
	})
	// With the locked Profile's evidence schema supplied, the Worker can now
	// sign a frozen task.v1.InferReceiptV1 and publish OUTPUT_AVAILABLE.
	infer, err := workerNode.HandleAssignmentFinalized(ctx, assignment)
	if err != nil {
		t.Fatalf("HandleAssignmentFinalized error = %v", err)
	}
	if !infer.Started {
		t.Fatalf("infer = %#v, want a started responsibility", infer)
	}
	publishedOutput := nats.Published(builderclient.NATSOutputAvailableSubject(taskID))
	if len(publishedOutput) != 1 {
		t.Fatalf("published output available count = %d, want 1", len(publishedOutput))
	}
	// The inference itself ran and its package was validated, so the output the
	// Verifier grades below is real Worker output rather than a fixture.
	if len(builder.validatedPackages) != 1 {
		t.Fatalf("validated packages = %d, want the inference to have completed", len(builder.validatedPackages))
	}

	receiptTrace := traceEvent(t, traceRecords, "infer_receipt_built")
	for _, field := range []string{
		"output_hash=" + infer.Receipt.OutputHash.String(),
		"package_hash=" + infer.PackageHash.String(),
		"receipt_result_hash=" + infer.Receipt.ReceiptResultHash.String(),
		"signing_digest=", "evidence_commitment_root=", "generation_params_digest=",
	} {
		if !strings.Contains(receiptTrace, field) {
			t.Fatalf("infer_receipt_built trace\n%s\ndoes not carry %q", receiptTrace, field)
		}
	}
	if strings.Contains(receiptTrace, "=zero") {
		t.Fatalf("infer_receipt_built trace reports an unset digest:\n%s", receiptTrace)
	}
	traceEvent(t, traceRecords, "task_result_finalized")
	traceEvent(t, traceRecords, "output_available_published")

	outputPackage := builder.validatedPackages[0]
	frames, err := workerPersistence{persistence}.OutputStreamFrames(ctx, taskID)
	if err != nil {
		t.Fatal(err)
	}
	lengths := make([]uint64, len(frames))
	for i, frame := range frames {
		lengths[i] = uint64(len(frame.Text))
	}
	inferDigest, err := builderclient.InferReceiptSigningDigest(infer.TaskDataReceipt)
	if err != nil {
		t.Fatal(err)
	}
	verifierState := verifier.TaskState{
		TaskID:           taskID,
		SessionID:        sessionID,
		OrderSequence:    orderSequence,
		OrderDigest:      orderDigest,
		VerifyRound:      1,
		InferReceiptHash: inferDigest,
		Member: builderclient.CandidateMemberRefMessage{
			CandidatePoolSnapshotID: strings.Repeat("31", 32), Slot: 1, SlotVersion: 1,
			OperatorAddress: verifierAddr,
		},
		ModelID:                     modelID,
		ProfileVersion:              1,
		Capability:                  modelservice.CapabilityLLMTextV1,
		WorkerAddress:               workerAddress,
		OutputPackage:               outputPackageSummary(outputPackage),
		OutputConfirmed:             true,
		ConfirmedOutputChunkLengths: lengths,
		ConfirmedInferReceipt:       &infer.TaskDataReceipt,
		ConfirmedFinishReason:       nodewire.FinishReasonV1EosToken,
		AssignedVerifiers:           []string{verifierAddr},
		OpenVerifyHeight:            150,
		HandraiseExpiryHeight:       170,
		CurrentHeight:               151,
		FutureBeaconID:              "beacon-1",
		BatchLogRoot:                codec.HashWithDomain("BATCH_LOG", []byte(taskID)),
		CommitDeadlineHeight:        180,
		// The Keeper fake's reveal deadline for this round; the frozen
		// ResultReceiptV1 carries it as expiry_height.
		RevealDeadlineHeight: 200,
		// TRUEOPEN_BUS_ENVELOPE_V1 fields 11 and 12, bound by the accepted Task:
		// verification cannot precede the acceptance that locked the set.
	}
	verifierState.ConfirmedOutput = persistence.artifacts[taskID+"/worker-output"]
	verifierState.ConfirmedTrace = persistence.artifacts[taskID+"/worker-trace"]
	verifierState.ConfirmedCheckpoint = persistence.artifacts[taskID+"/worker-checkpoint"]
	verifierState.ConfirmedInputTokenIDs = persistence.artifacts[taskID+"/worker-input_token_ids"]
	verifierState.ConfirmedGeneratedTokenIDs = persistence.artifacts[taskID+"/worker-generated_token_ids"]
	var verifyTraceRecords []observability.LogRecord
	verifierPrivate := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{0x71}, 32))
	verifierPubkey := verifierPrivate.PubKey().SerializeCompressed()
	verifierServiceAddress, err := signerclient.AddressFromCompressedPublicKey("trueopen", verifierPubkey)
	if err != nil {
		t.Fatal(err)
	}
	verifierSigner := integrationOutputSigner{private: verifierPrivate, address: verifierServiceAddress, keyRef: "test-verifier-key"}
	verifierAuth, err := taskdataauth.New(taskdataauth.Config{
		ServiceKeys: integrationServiceKeys{binding: chainclient.ServiceKeySnapshot{
			ParticipantType: chainclient.ParticipantTypeCortexNode, OperatorAddress: verifierAddr,
			ServiceAddress: verifierServiceAddress, ServicePubkey: hex.EncodeToString(verifierPubkey),
			AuthorizationNonce: chainclient.NewUint64String(23), Status: "ACTIVE",
		}},
		Signer: verifierSigner, ChainID: chainID, OperatorAddress: verifierAddr,
		ServiceAddress: verifierServiceAddress, ServicePubkey: hex.EncodeToString(verifierPubkey),
		ServiceKeyRef: "test-verifier-key", ExpiryBlocks: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifierConfig := verifier.Config{
		VerifierAddress: verifierAddr,
		ModelServiceID:  modelSvcID,
		Model:           model,
		Builder:         builder,
		Persistence:     verifierPersistence{persistence},
		ChainID:         chainID,
		SignerAddress:   verifierServiceAddress,
		SignerKeyRef:    "test-verifier-key",
		Signer:          verifierSigner,
		EvidencePublisher: integrationVerifierEvidencePublisher{
			taskData: taskData, auth: verifierAuth, builderOperator: builderOperator,
			builderPubkey:  hex.EncodeToString(builderPrivate.PubKey().SerializeCompressed()),
			verifierPubkey: hex.EncodeToString(verifierPubkey),
		},
		VerifyDeadlineDeltaHeight: 30,
		// Envelope field 7; zero is a refusal, not an empty field.
		ServiceAuthorizationNonce: 23,
		// Fake inference does not make the identity fake: the node still signs every
		// outbound envelope. The Worker half above has a signer wired and the Verifier
		// half does not - that asymmetry is exactly what kept the "unsigned" path alive.
		NexusEnvelopeSigner: testNexusEnvelopeSigner(),
		// The same frozen section 16.2 read the Worker half above serves.
		// generation_params_digest is a consensus value the verifier copies
		// through, so the result credential refuses without this reader.
		TaskFacts: taskfacts.ReaderFunc(generation.TaskFacts),
		Trace:     &tasktrace.Trace{Emit: func(record observability.LogRecord) { verifyTraceRecords = append(verifyTraceRecords, record) }},
		// The commit exit, over the same tx boundary the settlement stages below
		// use. No relay is wired because none exists: the bus registers no
		// VERIFY_COMMIT kind, so the signed commit reaches CommitState only from
		// here, and only under the current Cortex service address (§10.6 rule 6)
		// -- which in this rig is the verifier's own SignerAddress.
		CommitSubmitter: verifier.NewSettlementManager(verifier.SettlementConfig{
			Tx: tx, VerifierAddress: verifierAddr, SubmitterAddress: verifierServiceAddress,
			GasPayer: gasPayer, CommitFeeCap: txclient.Coin{Amount: 10, Denom: "utrueopen"},
		}),
		// The locked model profile the metric pipeline binds every leaf to, and
		// whose MetricSpec decides the two optional MetricSummaryV1 members.
		// Without it the reveal stops at the result-credential gap.
		ProfileReader: integrationLockedProfileReader{profile: integrationLockedProfile(modelID)},
	}
	verifierNode := verifier.New(verifierConfig)
	builder.beforePublish = func(request builderclient.PublishRequest) error {
		if request.Subject != builderclient.NATSVerifyResultSubject(taskID) {
			return nil
		}
		if len(taskData.FinalizedVerifierEvidence) != 1 {
			return fmt.Errorf("VERIFY_RESULT preceded evidence finalization")
		}
		message, err := builderclient.ResultReceiptProto(taskData.FinalizedVerifierEvidence[0].Receipt)
		if err != nil {
			return err
		}
		want, err := proto.Marshal(message)
		if err != nil {
			return err
		}
		envelope, err := builderclient.DecodeBusEnvelope(request.Payload)
		if err != nil {
			return err
		}
		if !bytes.Equal(envelope.Payload, want) {
			return fmt.Errorf("VERIFY_RESULT differs from the finalized signed receipt")
		}
		return nil
	}
	handraise, err := verifierNode.EvaluateAndHandraise(ctx, verifierState)
	if err != nil {
		t.Fatalf("EvaluateAndHandraise returned error: %v", err)
	}
	if !handraise.Signed {
		t.Fatalf("handraise = %#v, want signed", handraise)
	}
	publishedHandraises := nats.Published(builderclient.NATSVerifierHandraiseSubject(taskID))
	if len(publishedHandraises) != 1 {
		t.Fatalf("published verifier handraises = %d, want 1", len(publishedHandraises))
	}
	signedHandraise := publishedHandraises[0].Data
	if err := layout.AdmissionBatch(ctx, kvStore, sessionID, 1, layout.StoredHash(taskHash), layout.CandidateAdmission{
		SignedOrder:      []byte("{}"),
		HandraisePayload: signedHandraise,
		HandraiseDigest:  layout.StoredHashFromCodec(codec.HashBytes(signedHandraise)),
		PublishTS:        1,
	}); err != nil {
		t.Fatalf("AdmissionBatch: %v", err)
	}
	keeperServer.AddEvent(chainclient.KeeperEvent{
		Type:           chainclient.KeeperEventInferReceiptAccepted,
		TaskID:         taskID,
		Height:         121,
		SessionID:      sessionID,
		OrderDigest:    orderDigest,
		ModelID:        modelID,
		ProfileVersion: "1",
	})
	keeperServer.AddEvent(chainclient.KeeperEvent{
		Type:           chainclient.KeeperEventOpenVerifyAccepted,
		TaskID:         taskID,
		Height:         122,
		SessionID:      sessionID,
		OrderDigest:    orderDigest,
		Verifier:       verifierAddr,
		ModelID:        modelID,
		ProfileVersion: "1",
	})
	keeperServer.AddEvent(chainclient.KeeperEvent{
		Type:           chainclient.KeeperEventVerificationSampleSeedReady,
		TaskID:         taskID,
		Height:         123,
		SessionID:      sessionID,
		OrderDigest:    orderDigest,
		Verifier:       verifierAddr,
		ModelID:        modelID,
		ProfileVersion: "1",
	})
	verifierReconciler := daemon.NewReconciler(daemon.ReconcilerOptions{TaskReader: keeperServer})
	verifierPoller := daemon.NewKeeperPoller(kvStore, keeperServer, verifierReconciler, daemon.KeeperPollerConfig{
		MaxChainLag: 20,
		EffectSink:  taskOwner.ApplyReconcilerEffects,
	})
	if err := verifierPoller.RunOnce(ctx); err != nil {
		t.Fatalf("KeeperPoller verifier RunOnce returned error: %v", err)
	}
	// The chain accepting the infer receipt does NOT release the Worker
	// responsibility, and the record has to survive it. Three steps come after
	// the relay -- output upload, storage confirmation, OUTPUT_AVAILABLE -- and
	// deleting the record here removed them from under a running executor: the
	// next checkpoint hit store.ErrNotFound and the round lost its
	// OUTPUT_AVAILABLE for good. It is released at settlement instead, asserted
	// after the SettleAccepted poll below.
	if inferAfterReceipt, err := layout.GetInferRecord(ctx, kvStore, layout.StoredHash(taskHash)); err != nil || inferAfterReceipt.TaskID != taskID {
		t.Fatalf("infer record after the receipt was accepted = %#v err=%v, want the responsibility intact", inferAfterReceipt, err)
	}
	verifyRecord, err := layout.GetVerifyRecord(ctx, kvStore, layout.StoredHash(taskHash))
	if err != nil {
		t.Fatalf("GetVerifyRecord after sample-ready: %v", err)
	}
	if verifyRecord.TaskID != taskID || verifyRecord.Stage != layout.StageQueued {
		t.Fatalf("verify record = %#v, want queued task independent from infer document", verifyRecord)
	}
	verifierState.OpenVerifyAccepted = true
	// The commit half completes: local verification runs and the signed commit
	// reaches the chain. Nothing is published to the Builder, because the reveal
	// is a separate responsibility that only EventRevealPhaseStarted opens -- see
	// the HandleRevealPhaseStarted calls below.
	//
	// The commit credential is no longer the first refusal. It used to be, because
	// the rig left ServiceAuthorizationNonce zero; the 20-field
	// TRUEOPEN_BUS_ENVELOPE_V1 makes that nonce a precondition of the handraise
	// asserted above, so the rig states it and the VerifyCommitV1 preimage is
	// complete.
	broadcastsBeforeVerify := len(rpc.broadcasts)
	verifyResult, err := verifierNode.HandleOpenVerifyAccepted(ctx, verifierState)
	if err != nil {
		t.Fatalf("HandleOpenVerifyAccepted error = %v, want the commit half to complete", err)
	}
	// The commit is built, signed AND on chain; nothing reveals, so the
	// VerifyResult subject stays empty.
	if verifyResult.CommitHash == (codec.Hash{}) || verifyResult.CommitWire.ServiceAuthorizationNonce != 23 ||
		len(nats.Published(builderclient.NATSVerifyResultSubject(taskID))) != 0 {
		t.Fatalf("verify=%#v nats=%d, want a commit credential and no VerifyResult publish", verifyResult, len(nats.Published(builderclient.NATSVerifyResultSubject(taskID))))
	}
	// The commit exit ran on the way to that refusal. It is the point of the
	// whole round: without it a signed commit stayed a local evidence file and
	// the chain recorded no CommitState, so the reveal phase could never open.
	// One real signed transaction reached the RPC boundary during verify: the
	// whole txclient.Broadcaster path ran, not a fake stand-in for it.
	if got := len(rpc.broadcasts) - broadcastsBeforeVerify; got != 1 {
		t.Fatalf("verify-phase broadcasts = %d, want exactly one commit self-submission", got)
	}
	if !verifyResult.CommitDelivery.SelfSubmitted || !verifyResult.CommitDelivery.ChainAccepted ||
		verifyResult.CommitDelivery.Reason != verifier.CommitExitRelayChannelAbsent {
		t.Fatalf("commit delivery = %#v, want a chain-confirmed self-submission triggered by the absent relay", verifyResult.CommitDelivery)
	}
	exitTrace := traceEvent(t, verifyTraceRecords, "verify_commit_exit")
	for _, field := range []string{
		`exit="self_submit"`,
		"keeper_confirmed=true",
		"commit_hash=" + verifyResult.CommitHash.String(),
	} {
		if !strings.Contains(exitTrace, field) {
			t.Fatalf("verify_commit_exit trace\n%s\ndoes not carry %q", exitTrace, field)
		}
	}
	// The commit was signed, so its digests are in the trace even though the
	// result credential below is the one this rig cannot build.
	commitTrace := traceEvent(t, verifyTraceRecords, "verify_commit_signed")
	for _, field := range []string{
		"commit_hash=" + verifyResult.CommitHash.String(),
		"verification_sample_seed=" + verifyResult.VerificationSampleSeed.String(),
		"result_digest=" + verifyResult.ResultDigest.String(),
		"output_hash=" + outputPackage.OutputHash.String(),
		"package_hash=" + outputPackage.PackageHash.String(),
		"commit_signing_digest=",
	} {
		if !strings.Contains(commitTrace, field) {
			t.Fatalf("verify_commit_signed trace\n%s\ndoes not carry %q", commitTrace, field)
		}
	}

	// The reveal half, driven by the reveal phase rather than by the commit. With
	// the phase unopened it refuses as a wait; with the deadline known it reaches
	// the frozen result body, where the only remaining gap is the metric
	// pipeline. generation_params_digest is not a gap: the verifier reads it
	// through chainclient.KeeperABCIClient.TaskReceiptFacts, which this rig serves.
	revealNotStarted := verifierState
	revealNotStarted.RevealDeadlineHeight = 0
	if _, err := verifierNode.HandleRevealPhaseStarted(ctx, revealNotStarted); !errors.Is(err, verifier.ErrRevealPhaseNotStarted) {
		t.Fatalf("HandleRevealPhaseStarted before the phase = %v, want the reveal phase reported as not started", err)
	}
	// Rebuild the verifier before reveal: the payload, proof and manifest must
	// come from the persisted evidence record without another model call.
	verifierNode = verifier.New(verifierConfig)
	verifyCallsBeforeRestart := modelServer.VerifyCalls()
	finalizeFailure := errors.New("Builder rejected verifier evidence finalization")
	taskData.verifierFinalizeErr = finalizeFailure
	if result, err := verifierNode.HandleRevealPhaseStarted(ctx, verifierState); !errors.Is(err, finalizeFailure) || result.Published {
		t.Fatalf("reveal with failed finalization = %+v, %v", result, err)
	}
	if len(nats.Published(builderclient.NATSVerifyResultSubject(taskID))) != 0 {
		t.Fatal("VERIFY_RESULT was published after failed evidence finalization")
	}
	taskData.verifierFinalizeErr = nil
	reveal, err := verifierNode.HandleRevealPhaseStarted(ctx, verifierState)
	if err != nil {
		t.Fatalf("HandleRevealPhaseStarted error = %v, want a complete result credential", err)
	}
	if !reveal.Published || reveal.ResultSigningDigest.IsZero() {
		t.Fatalf("reveal = %#v, want a published credential with its own TRUEOPEN_RESULT_V1 digest", reveal)
	}
	if published := len(nats.Published(builderclient.NATSVerifyResultSubject(taskID))); published != 1 {
		t.Fatalf("VerifyResult publishes = %d, want exactly one now that every metric field has a producer", published)
	}
	if modelServer.VerifyCalls() != verifyCallsBeforeRestart || len(taskData.FinalizedVerifierEvidence) != 1 {
		t.Fatal("restart reran verification or did not finalize its persisted evidence")
	}
	finalizedReceipt := taskData.FinalizedVerifierEvidence[0].Receipt
	if !bytes.Equal(finalizedReceipt.Salt, verifyResult.Salt[:]) ||
		finalizedReceipt.VerifierEvidenceManifestSizeBytes != uint64(len(verifyResult.EvidenceManifest)) {
		t.Fatal("finalization lost the persisted salt or manifest size")
	}
	// The three values this whole metric pipeline exists to produce, read off
	// the verify run that produced them rather than off the credential alone.
	if verifyResult.MetricMaterial.Root.IsZero() ||
		verifyResult.MetricMaterial.AggregateProof.Hash.IsZero() ||
		verifyResult.MetricMaterial.LeafCount == 0 {
		t.Fatalf("verify produced no metric material: %#v", verifyResult.MetricMaterial)
	}

	settlementManager := verifier.NewSettlementManager(verifier.SettlementConfig{
		Tx:               tx,
		WorkerAddress:    workerAddress,
		SubmitterAddress: gasPayer,
		GasPayer:         gasPayer,
		FeeCap:           txclient.Coin{Amount: 10, Denom: "utrueopen"},
	})
	// Settlement uses the signed Worker receipt persisted by the inference run.
	receiptRef := persistence.refByKind("worker-infer-receipt")
	if receiptRef == "" {
		t.Fatalf("worker infer receipt evidence missing")
	}
	sampledValueSetHash := codec.HashWithDomain("INTEGRATION_SAMPLED_VALUE_SET", []byte(taskID))
	receiptSignature := bytes.Repeat([]byte{0x7a}, 64)
	workerReveal, err := settlementManager.HandleDeadlineRisk(ctx, verifier.DeadlineRisk{
		TaskID:         taskID,
		Type:           verifier.WorkerRevealDeadlineRisk,
		CurrentHeight:  199,
		DeadlineHeight: 200,
		Margin:         1,
		WorkerReveal: verifier.ReceiptOnlyWorkerReveal{
			SessionID: sessionID, VerifyRound: 1, WorkerAddress: workerAddress, SampledValueSetHash: sampledValueSetHash,
			EvidenceSchemaVersion: "llm-text-v1", ReceiptSignature: receiptSignature,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "registers no worker reveal Msg") || workerReveal.Submitted {
		t.Fatalf("worker reveal = %#v err=%v, want the frozen worker-reveal fail-closed", workerReveal, err)
	}
	settlementMessage, settlementRoot := integrationSettlementMessage(taskID)
	envelope, err := verifier.BuildSettlementEnvelope(verifier.SettlementInput{Message: settlementMessage, LocalRoot: settlementRoot})
	if err != nil {
		t.Fatalf("BuildSettlementEnvelope returned error: %v", err)
	}
	settleObs, err := settlementManager.HandleStage3BuilderFailure(ctx, verifier.SettlementInput{
		Message: settlementMessage, LocalRoot: envelope.EvidenceRoot, OpeningsValid: true,
	})
	if err == nil || !strings.Contains(err.Error(), "authoritative Keeper") || settleObs.Submitted {
		t.Fatalf("settlement = %#v err=%v, want fail-closed without authoritative Keeper state", settleObs, err)
	}
	if err := persistence.writeEvidencePackage(ctx, taskHash, 220); err != nil {
		t.Fatalf("write task evidence package: %v", err)
	}
	metadata, err := (&evidence.LayoutStoreIndex{Store: kvStore}).Evidence(ctx, taskHash)
	if err != nil || metadata.TerminalOrSettled || metadata.FinalityHeight != 220 {
		t.Fatalf("active evidence metadata = %#v err=%v, want finality-aware package", metadata, err)
	}
	keeperServer.AddEvent(chainclient.KeeperEvent{
		Type:           chainclient.KeeperEventSettleAccepted,
		Height:         124,
		SessionID:      sessionID,
		TaskID:         taskID,
		OrderDigest:    orderDigest,
		ModelID:        modelID,
		ProfileVersion: "1",
	})
	if err := poller.RunOnce(ctx); err != nil {
		t.Fatalf("KeeperPoller terminal RunOnce returned error: %v", err)
	}
	if _, err := layout.GetCandidateAdmission(ctx, kvStore, layout.StoredHash(taskHash)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("terminal candidate error = %v, want removed", err)
	}
	// Task terminal is what releases the infer responsibility now, through the
	// same TaskTerminalBatch that drops the verify record.
	if _, err := layout.GetInferRecord(ctx, kvStore, layout.StoredHash(taskHash)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("terminal infer task remained active: %v", err)
	}

	plan, err := evidence.PlanCleanup(ctx, evidence.CleanupConfig{
		Root: root, Index: &evidence.LayoutStoreIndex{Store: kvStore}, TaskHashes: []codec.Hash{taskHash}, CurrentHeight: 300,
		RetentionPolicyVersion: "retention-v1",
		TaskStatus: func(context.Context, codec.Hash) (evidence.TaskCleanupStatus, error) {
			return evidence.TaskCleanupStatus{TerminalOrSettled: true}, nil
		},
	})
	if err != nil {
		t.Fatalf("PlanCleanup returned error: %v", err)
	}
	cleanup, err := evidence.Cleanup(ctx, evidence.CleanupConfig{
		Root: root, Index: &evidence.LayoutStoreIndex{Store: kvStore}, TaskHashes: []codec.Hash{taskHash}, CurrentHeight: 300,
		RetentionPolicyVersion: "retention-v1",
		ConfirmDigest:          plan.Digest,
		TaskStatus: func(context.Context, codec.Hash) (evidence.TaskCleanupStatus, error) {
			return evidence.TaskCleanupStatus{TerminalOrSettled: true}, nil
		},
	})
	if err != nil {
		t.Fatalf("Cleanup returned error: %v", err)
	}
	if cleanup.Cleaned != 1 {
		t.Fatalf("cleanup = %#v, want one deleted task evidence package", cleanup)
	}
	if err := kvStore.Close(); err != nil {
		t.Fatalf("close store before restart: %v", err)
	}
	if reopened, err := store.Open(ctx, storePath); err != nil {
		t.Fatalf("restart open store returned error: %v", err)
	} else {
		t.Cleanup(func() {
			_ = reopened.Close()
		})
		height, err := reopened.KeeperLastProcessedHeight(ctx)
		if err != nil || height != 124 {
			t.Fatalf("reopened Keeper processed height = %d err=%v, want 124", height, err)
		}
		inferHashes, _, err := layout.ListInferRecords(ctx, reopened)
		if err != nil || len(inferHashes) != 0 {
			t.Fatalf("reopened active infer records = %d err=%v, terminal work must be absent", len(inferHashes), err)
		}
		verifyHashes, _, err := layout.ListVerifyRecords(ctx, reopened)
		if err != nil || len(verifyHashes) != 0 {
			t.Fatalf("reopened active verify records = %d err=%v, terminal work must be absent", len(verifyHashes), err)
		}
		if _, err := (&evidence.LayoutStoreIndex{Store: reopened}).Evidence(ctx, taskHash); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("reopened Evidence error = %v, want cleaned metadata absent", err)
		}
	}
	if keeperServer.HeightRequests() == 0 || keeperServer.EventRequests() == 0 || modelServer.InferCalls() == 0 || modelServer.VerifyCalls() == 0 || signer.SignCalls() == 0 || len(rpc.broadcasts) == 0 {
		t.Fatalf("adapter calls missing: keeper height=%d events=%d infer=%d verify=%d sign=%d broadcasts=%d", keeperServer.HeightRequests(), keeperServer.EventRequests(), modelServer.InferCalls(), modelServer.VerifyCalls(), signer.SignCalls(), len(rpc.broadcasts))
	}
}

func testDigestSigner() signerclient.DigestSigner {
	return signerclient.DigestSignerFunc(func(context.Context, signerclient.DigestRequest) ([]byte, error) {
		signature := make([]byte, 64)
		signature[0] = 1
		return signature, nil
	})
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

// workerSnapshotReader returns a snapshot that matches the supplied assignment.
type workerSnapshotReader struct {
	assignment chainclient.AssignmentFinalized
}

func (r *workerSnapshotReader) TaskSnapshot(ctx context.Context, taskID string) (chainclient.TaskSnapshot, error) {
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

type integrationRegistrationOutbox struct{}

func (integrationRegistrationOutbox) WriteRegistration(_ context.Context, msg modelregistry.OutboxMessage) (string, error) {
	return "registration-" + msg.Material.ManifestHash, nil
}

// integrationSettlementMessage builds the frozen MsgSettleTask: task_id plus the
// Cosmos submitter, with every settlement fact derived by the Keeper.
func integrationSettlementMessage(taskID string) (txclient.SettleTaskMessage, codec.Hash) {
	root := codec.HashWithDomain("TRUEOPEN_TASK_EVIDENCE_ROOT_V1", []byte(taskID))
	return txclient.SettleTaskMessage{TaskID: txclient.ProtoBytes32(taskID), SubmitterAddress: "builder-1"}, root
}

type integrationPersistence struct {
	store    *store.Store
	evidence *evidence.Store
	// taskHash is a path component of every object this harness stores, the
	// same way the daemon's own persistence carries it: the local layout is
	// task-scoped, so there is nowhere to put bytes that name no task.
	taskHash             codec.Hash
	evidenceRoot         string
	cleanupHeight        uint64
	builder              *natsBackedBuilder
	refs                 []string
	byKind               map[string]string
	builderMessages      map[string]worker.BuilderMessageCheckpoint
	modelJobs            map[string]worker.ModelJobCheckpoint
	inferReceipts        map[string]worker.InferReceiptCheckpoint
	storageConfirmations map[string][]worker.StorageConfirmationCheckpoint
	artifacts            map[string][]byte
}

func (p *integrationPersistence) WriteBuilderOutbox(_ context.Context, record worker.OutboxRecord) error {
	if p.builderMessages == nil {
		p.builderMessages = make(map[string]worker.BuilderMessageCheckpoint)
	}
	digest := fmt.Sprintf("%x", record.Digest[:])
	p.builderMessages[digest] = worker.BuilderMessageCheckpoint{
		Digest: digest, TaskID: record.TaskID, Subject: record.Subject,
		Payload: append([]byte(nil), record.Payload...), Status: record.Status,
	}
	return nil
}

func (p *integrationPersistence) WriteSettleMaterial(ctx context.Context, material verifier.SettleMaterial) error {
	return p.writeEvidence(ctx, material.TaskID, "settlement-"+material.Kind, material.Payload)
}

func (p *integrationPersistence) writeEvidence(ctx context.Context, taskID string, kind string, data []byte) error {
	ref, err := p.evidence.Write(ctx, evidence.WriteRequest{TaskHash: p.taskHash, TaskID: taskID, Kind: kind, Data: data})
	if err != nil {
		return err
	}
	if p.byKind == nil {
		p.byKind = map[string]string{}
	}
	refString := ref.String()
	p.refs = append(p.refs, refString)
	p.byKind[kind] = refString
	if p.artifacts == nil {
		p.artifacts = make(map[string][]byte)
	}
	p.artifacts[taskID+"/"+kind] = append([]byte(nil), data...)
	return nil
}

func (p *integrationPersistence) writeEvidencePackage(ctx context.Context, taskHash codec.Hash, finalityHeight uint64) error {
	payload, err := json.Marshal(p.byKind)
	if err != nil {
		return err
	}
	indexed, err := evidence.NewStore(p.evidenceRoot, p.store)
	if err != nil {
		return err
	}
	_, err = indexed.Write(ctx, evidence.WriteRequest{
		TaskHash: taskHash, Kind: "task-evidence-package", Data: payload,
		FinalityHeight: finalityHeight, CleanupHeight: p.cleanupHeight,
	})
	return err
}

func (p *integrationPersistence) refByKind(kind string) string {
	return p.byKind[kind]
}

type integrationOutputSigner struct {
	private *secp256k1.PrivateKey
	address string
	keyRef  string
}

func (s integrationOutputSigner) SignDigest(_ context.Context, request signerclient.DigestRequest) ([]byte, error) {
	if request.KeyRef != s.keyRef || request.ExpectedSignerAddress != s.address {
		return nil, fmt.Errorf("unexpected integration output signer identity")
	}
	return integrationCompactSignature(s.private, request.Digest), nil
}

func (integrationOutputSigner) SignCosmosTx(context.Context, signerclient.CosmosTxRequest) ([]byte, error) {
	return nil, fmt.Errorf("not supported")
}

func (integrationOutputSigner) CanSignCosmosTx() bool { return false }

func integrationCompactSignature(private *secp256k1.PrivateKey, digest codec.Hash) []byte {
	signature := ecdsa.Sign(private, digest[:])
	r, s := signature.R(), signature.S()
	rBytes, sBytes := r.Bytes(), s.Bytes()
	out := make([]byte, 64)
	copy(out[:32], rBytes[:])
	copy(out[32:], sBytes[:])
	return out
}

type integrationServiceKeys struct {
	binding chainclient.ServiceKeySnapshot
}

// integrationServedHeight is the height Keeper answers the committed service-key
// read at.
const integrationServedHeight = uint64(120)

func (s integrationServiceKeys) CommittedCurrentServiceKey(context.Context, string, string) (chainclient.ServiceKeySnapshot, uint64, error) {
	return s.binding, integrationServedHeight, nil
}

type integrationTaskData struct {
	*builderclient.FakeClient
	builderPrivate      *secp256k1.PrivateKey
	relays              []builderclient.SubmitInferReceiptRequest
	uploads             []builderclient.UploadTaskResultRequest
	commitRelays        []builderclient.SubmitVerifyCommitRequest
	verifierFinalizeErr error
}

func (*integrationTaskData) GetTaskDataMetadata(context.Context, string, builderclient.GetTaskDataMetadataRequest) (builderclient.TaskDataMetadata, error) {
	return builderclient.TaskDataMetadata{}, fmt.Errorf("unexpected metadata request")
}

func (*integrationTaskData) FetchTaskData(context.Context, string, builderclient.FetchTaskDataRequest, func(builderclient.TaskDataChunk) error) error {
	return fmt.Errorf("unexpected task-data fetch")
}

func (c *integrationTaskData) SubmitInferReceipt(_ context.Context, _ string, request builderclient.SubmitInferReceiptRequest) error {
	c.relays = append(c.relays, request)
	return nil
}

func (c *integrationTaskData) SubmitVerifyCommit(_ context.Context, _ string, request builderclient.SubmitVerifyCommitRequest) (builderclient.VerifyRelayAck, error) {
	c.commitRelays = append(c.commitRelays, request)
	return builderclient.VerifyRelayAck{CommitKey: codec.HashBytes([]byte("integration-relay"))}, nil
}

func (c *integrationTaskData) UploadTaskResultObject(ctx context.Context, endpoint string, request builderclient.UploadTaskResultRequest) (builderclient.TaskDataMetadata, error) {
	c.uploads = append(c.uploads, request)
	return c.FakeClient.UploadTaskResultObject(ctx, endpoint, request)
}

func (c *integrationTaskData) FinalizeTaskResult(ctx context.Context, endpoint string, request builderclient.FinalizeTaskResultRequest) (builderclient.FinalizeTaskResultResponse, error) {
	response, err := c.FakeClient.FinalizeTaskResult(ctx, endpoint, request)
	if err != nil {
		return response, err
	}
	confirmations := []*builderclient.StorageConfirmation{&response.OutputConfirmation}
	for i := range response.EvidenceBundleConfirmations {
		confirmations = append(confirmations, &response.EvidenceBundleConfirmations[i])
	}
	for _, confirmation := range confirmations {
		digest, err := builderclient.StorageConfirmationSigningHash(*confirmation)
		if err != nil {
			return response, err
		}
		confirmation.Signature = integrationCompactSignature(c.builderPrivate, digest)
	}
	return response, nil
}

func (c *integrationTaskData) FinalizeVerifierEvidence(ctx context.Context, endpoint string, request builderclient.FinalizeVerifierEvidenceRequest) (builderclient.FinalizeVerifierEvidenceResponse, error) {
	if c.verifierFinalizeErr != nil {
		return builderclient.FinalizeVerifierEvidenceResponse{}, c.verifierFinalizeErr
	}
	response, err := c.FakeClient.FinalizeVerifierEvidence(ctx, endpoint, request)
	if err != nil {
		return response, err
	}
	confirmation := &response.EvidenceBundleConfirmation
	digest, err := builderclient.StorageConfirmationSigningHash(*confirmation)
	if err != nil {
		return response, err
	}
	confirmation.Signature = integrationCompactSignature(c.builderPrivate, digest)
	return response, nil
}

type integrationVerifierEvidencePublisher struct {
	taskData                                       *integrationTaskData
	auth                                           *taskdataauth.Authenticator
	builderOperator, builderPubkey, verifierPubkey string
}

func (p integrationVerifierEvidencePublisher) PublishVerifierEvidence(ctx context.Context, state verifier.TaskState, receipt nodewire.ResultReceiptV2, manifestBytes, proof []byte) error {
	manifest, err := evidencebundle.Decode(manifestBytes)
	if err != nil {
		return err
	}
	digest, err := nodewire.ResultReceiptSigningDigest(receipt)
	if err != nil {
		return err
	}
	if err := signerclient.VerifyDigestSignature(p.verifierPubkey, digest, receipt.ServiceSignature); err != nil {
		return err
	}
	bundleHash, proofHash := evidencebundle.Hash(manifestBytes), codec.HashBytes(proof)
	if manifest.ProducerKind != "VERIFIER" || manifest.ProducerOperator != receipt.VerifierOperatorAddress ||
		manifest.TaskID != state.TaskID || manifest.VerifyRound != uint32(state.VerifyRound) ||
		!bytes.Equal(receipt.VerifierEvidenceBundleHash, bundleHash[:]) || !bytes.Equal(receipt.AggregateProofHash, proofHash[:]) ||
		receipt.VerifierEvidenceManifestSizeBytes != uint64(len(manifestBytes)) ||
		len(manifest.Artifacts) != 1 || manifest.Artifacts[0] != evidencebundle.NewArtifact("aggregate_proof", proof) {
		return fmt.Errorf("Verifier evidence differs from its signed receipt")
	}
	key := func(kind builderclient.DataKind, hash string) builderclient.TaskDataKey {
		return builderclient.EvidenceObjectKey(manifest.TaskHash, state.SessionID, state.TaskID, kind, hash,
			builderclient.EvidenceProducerVerifier, manifest.VerifyRound, receipt.VerifierOperatorAddress)
	}
	manifestKey := key(builderclient.DataKindEvidenceManifest, bundleHash.String())
	for _, object := range []struct {
		key  builderclient.TaskDataKey
		data []byte
	}{
		{key(builderclient.DataKindEvidenceArtifact, proofHash.String()), proof}, {manifestKey, manifestBytes},
	} {
		digest, err := builderclient.TaskDataUploadBodyDigest(object.key, uint64(len(object.data)), "")
		if err != nil {
			return err
		}
		auth, err := p.auth.SignRequest(ctx, "UploadTaskResultObject", object.key, p.builderOperator, digest)
		if err != nil {
			return err
		}
		metadata, err := p.taskData.UploadTaskResultObject(ctx, "https://builder.example", builderclient.UploadTaskResultRequest{
			Key: object.key, SizeBytes: uint64(len(object.data)), Auth: auth, Data: object.data,
		})
		if err != nil {
			return err
		}
		if metadata.Key != object.key || metadata.SizeBytes != uint64(len(object.data)) ||
			(metadata.Readiness != builderclient.TaskDataStored && metadata.Readiness != builderclient.TaskDataReady) {
			return fmt.Errorf("Verifier upload metadata differs from its object")
		}
	}
	request := builderclient.FinalizeVerifierEvidenceRequest{TaskHash: manifest.TaskHash, SessionID: state.SessionID, TaskID: state.TaskID,
		VerifyRound: manifest.VerifyRound, VerifierOperator: manifest.ProducerOperator, Receipt: receipt}
	digest, err = builderclient.TaskDataFinalizeVerifierBodyDigest(request)
	if err != nil {
		return err
	}
	request.Auth, err = p.auth.SignRequest(ctx, "FinalizeVerifierEvidence", manifestKey, p.builderOperator, digest)
	if err != nil {
		return err
	}
	response, err := p.taskData.FinalizeVerifierEvidence(ctx, "https://builder.example", request)
	if err != nil {
		return err
	}
	confirmation := response.EvidenceBundleConfirmation
	if confirmation.Key != manifestKey || confirmation.BuilderOperator != p.builderOperator || confirmation.ServiceAuthorizationNonce != 1 ||
		confirmation.ChainID != receipt.ChainID || confirmation.SizeBytes != uint64(len(manifestBytes)) ||
		confirmation.ArtifactTotalSizeBytes != uint64(len(proof)) || confirmation.RetentionUntilHeight <= integrationServedHeight {
		return fmt.Errorf("Verifier evidence confirmation differs from the finalized bundle")
	}
	digest, err = builderclient.StorageConfirmationSigningHash(confirmation)
	if err != nil {
		return err
	}
	return signerclient.VerifyDigestSignature(p.builderPubkey, digest, confirmation.Signature)
}

type workerPersistence struct{ base *integrationPersistence }

func (p workerPersistence) WriteEvidence(ctx context.Context, record worker.EvidenceRecord) error {
	return p.base.writeEvidence(ctx, record.TaskID, record.Kind, record.Data)
}
func (p workerPersistence) CheckpointInferOutput(ctx context.Context, taskID string, output, trace, checkpoint []byte, cp worker.InferOutputCheckpoint) error {
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

func (p workerPersistence) WriteBuilderOutbox(ctx context.Context, record worker.OutboxRecord) error {
	return p.base.WriteBuilderOutbox(ctx, record)
}

func (p workerPersistence) CheckpointInferInput(context.Context, worker.InferInputCheckpoint) error {
	return nil
}
func (p workerPersistence) InferInput(context.Context, string) (worker.InferInputCheckpoint, error) {
	return worker.InferInputCheckpoint{}, worker.ErrCheckpointNotFound
}
func (p workerPersistence) CheckpointModelJob(_ context.Context, record worker.ModelJobCheckpoint) error {
	if p.base.modelJobs == nil {
		p.base.modelJobs = make(map[string]worker.ModelJobCheckpoint)
	}
	p.base.modelJobs[record.JobID] = record
	return nil
}

func (p workerPersistence) CheckpointInferReceipt(_ context.Context, record worker.InferReceiptCheckpoint) error {
	if p.base.inferReceipts == nil {
		p.base.inferReceipts = make(map[string]worker.InferReceiptCheckpoint)
	}
	p.base.inferReceipts[record.MaterialDigest] = record
	return nil
}

func (p workerPersistence) InferReceipts(_ context.Context, _ string) ([]worker.InferReceiptCheckpoint, error) {
	out := make([]worker.InferReceiptCheckpoint, 0, len(p.base.inferReceipts))
	for _, r := range p.base.inferReceipts {
		out = append(out, r)
	}
	return out, nil
}

func (p workerPersistence) CheckpointStorageConfirmation(_ context.Context, record worker.StorageConfirmationCheckpoint) error {
	if p.base.storageConfirmations == nil {
		p.base.storageConfirmations = make(map[string][]worker.StorageConfirmationCheckpoint)
	}
	p.base.storageConfirmations[record.TaskID] = append(p.base.storageConfirmations[record.TaskID], record)
	return nil
}

func (p workerPersistence) ReadArtifact(_ context.Context, taskID string, kind string) ([]byte, error) {
	if p.base.artifacts == nil {
		return nil, worker.ErrCheckpointNotFound
	}
	data, ok := p.base.artifacts[taskID+"/"+kind]
	if !ok {
		return nil, worker.ErrCheckpointNotFound
	}
	return append([]byte(nil), data...), nil
}

func (p workerPersistence) OutputStreamFrames(ctx context.Context, taskID string) ([]builderclient.OutputChunk, error) {
	artifacts, err := p.base.evidence.TaskArtifacts(ctx, p.base.taskHash)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []builderclient.OutputChunk
	for _, artifact := range artifacts {
		kind := string(artifact.Kind)
		if !strings.HasPrefix(kind, worker.OutputStreamFramePrefix) {
			continue
		}
		data, err := p.base.evidence.ReadTaskKind(ctx, p.base.taskHash, kind)
		if err != nil {
			return nil, err
		}
		var frame builderclient.OutputChunk
		if err := json.Unmarshal(data, &frame); err != nil {
			return nil, err
		}
		out = append(out, frame)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out, nil
}

func (p workerPersistence) StorageConfirmations(_ context.Context, taskID string) ([]worker.StorageConfirmationCheckpoint, error) {
	return append([]worker.StorageConfirmationCheckpoint(nil), p.base.storageConfirmations[taskID]...), nil
}

func (p workerPersistence) BuilderMessage(_ context.Context, digest string) (worker.BuilderMessageCheckpoint, error) {
	record, ok := p.base.builderMessages[digest]
	if !ok {
		return worker.BuilderMessageCheckpoint{}, worker.ErrCheckpointNotFound
	}
	return record, nil
}

type verifierPersistence struct{ base *integrationPersistence }

func (p verifierPersistence) ReadVerifierEvidence(ctx context.Context, kind string) ([]byte, error) {
	return p.base.evidence.ReadTaskKind(ctx, p.base.taskHash, kind)
}

func (p verifierPersistence) WriteEvidence(ctx context.Context, record verifier.EvidenceRecord) error {
	return p.base.writeEvidence(ctx, record.TaskID, record.Kind, record.Data)
}

func (p verifierPersistence) WriteSettleMaterial(ctx context.Context, material verifier.SettleMaterial) error {
	return p.base.WriteSettleMaterial(ctx, material)
}

func (p verifierPersistence) CheckpointModelJob(_ context.Context, _ verifier.ModelJobCheckpoint) error {
	return nil
}

type defaultFeeTx struct {
	base     txclient.Client
	gasPayer string
	feeCap   txclient.Coin
}

func (t defaultFeeTx) Submit(ctx context.Context, req txclient.Request) (txclient.Observation, error) {
	if req.GasPayer == "" {
		req.GasPayer = t.gasPayer
	}
	if req.FeeCap == (txclient.Coin{}) {
		req.FeeCap = t.feeCap
	}
	return t.base.Submit(ctx, req)
}

type natsBackedBuilder struct {
	nats              *memoryNATS
	validatedPackages []builderclient.OutputPackage
	packagesByKey     map[string]builderclient.OutputPackage
	beforePublish     func(builderclient.PublishRequest) error
}

func (b *natsBackedBuilder) ValidateOutputPackage(_ context.Context, pkg builderclient.OutputPackage) error {
	if pkg.TaskID == "" || pkg.OutputRef == "" {
		return fmt.Errorf("output package missing required fields")
	}
	material, err := builderclient.DecodeInferReceiptMaterial(pkg.ReceiptPayload)
	if err != nil {
		return err
	}
	if material.TaskID != pkg.TaskID || material.OutputRef != pkg.OutputRef || material.ReceiptResultHash != pkg.ReceiptHash {
		return fmt.Errorf("receipt material mismatch")
	}
	b.validatedPackages = append(b.validatedPackages, pkg)
	if b.packagesByKey == nil {
		b.packagesByKey = map[string]builderclient.OutputPackage{}
	}
	b.packagesByKey[outputPackageKey(pkg.TaskID, pkg.PackageHash)] = pkg
	return nil
}

func (b *natsBackedBuilder) Publish(ctx context.Context, req builderclient.PublishRequest) error {
	if b.beforePublish != nil {
		if err := b.beforePublish(req); err != nil {
			return err
		}
	}
	return b.nats.Publish(ctx, builderclient.NATSMessage{Subject: req.Subject, Data: req.Payload})
}

type memoryNATS struct {
	mu        sync.Mutex
	published map[string][]builderclient.NATSMessage
}

func (n *memoryNATS) Publish(_ context.Context, msg builderclient.NATSMessage) error {
	if msg.Subject == "" || len(msg.Data) == 0 {
		return fmt.Errorf("nats message missing subject or data")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.published == nil {
		n.published = map[string][]builderclient.NATSMessage{}
	}
	msg.Data = append([]byte(nil), msg.Data...)
	n.published[msg.Subject] = append(n.published[msg.Subject], msg)
	return nil
}

func (n *memoryNATS) Published(subject string) []builderclient.NATSMessage {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := append([]builderclient.NATSMessage(nil), n.published[subject]...)
	return out
}

type keeperHarness struct {
	*httptest.Server
	mu             sync.Mutex
	modelID        string
	assignments    []chainclient.AssignmentFinalized
	events         []chainclient.KeeperEvent
	heightRequests int
	eventRequests  int
}

func newKeeperServer(t *testing.T, modelID string) *keeperHarness {
	t.Helper()
	h := &keeperHarness{modelID: modelID}
	h.Server = httptest.NewServer(http.HandlerFunc(h.handle))
	t.Cleanup(h.Close)
	return h
}

func (h *keeperHarness) AddAssignment(event chainclient.AssignmentFinalized) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.assignments = append(h.assignments, event)
}

func (h *keeperHarness) AddEvent(event chainclient.KeeperEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, event)
}

func (h *keeperHarness) HeightRequests() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.heightRequests
}

func (h *keeperHarness) EventRequests() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.eventRequests
}

func (h *keeperHarness) Task(_ context.Context, sessionID, taskID string) (chainclient.TaskSnapshot, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, assignment := range h.assignments {
		if assignment.SessionID != sessionID || assignment.TaskID != taskID {
			continue
		}
		status := "VERIFYING"
		settlement := chainclient.SettlementSnapshot{}
		for _, event := range h.events {
			if event.TaskID == taskID && event.Type == chainclient.KeeperEventSettleAccepted {
				status = "SETTLED"
				settlement = chainclient.SettlementSnapshot{
					TaskVerdict:      "PASS",
					SettlementHeight: chainclient.NewUint64String(event.Height),
				}
				break
			}
		}
		acceptedHash := codec.HashWithDomain("INTEGRATION_ACCEPTED_TASK_HASH_V1", []byte(assignment.TaskID))
		return chainclient.TaskSnapshot{
			Status:     status,
			Settlement: settlement,
			Assignment: chainclient.AssignmentSnapshot{
				SessionID: assignment.SessionID, TaskID: assignment.TaskID,
				OrderSequence:       chainclient.NewUint64String(assignment.OrderSequence),
				SelectedWorker:      assignment.Winner,
				InferDeadlineHeight: chainclient.NewUint64String(assignment.InferDeadlineHeight),
				WinnerConfirmHeight: chainclient.NewUint64String(assignment.WinnerConfirmHeight),
				ModelID:             assignment.ModelID, ProfileVersion: chainclient.NewProfileVersion(assignment.ProfileVersion),
				AcceptedOrderPayloadHash: chainclient.HexHash(codec.HashBytes(assignment.Input)),
				BuilderOperatorAddress:   assignment.BuilderOperatorAddress,
				TaskReceiptFactsSnapshot: chainclient.TaskReceiptFactsSnapshot{
					AcceptedTaskHash: chainclient.ProtoBytes32(acceptedHash[:]),
				},
			},
			VerifierAssignment: chainclient.VerifierAssignmentSnapshot{
				SessionID: assignment.SessionID, TaskID: assignment.TaskID,
				VerifyRound:                chainclient.NewUint64String(1),
				OpenVerifyHeight:           chainclient.NewUint64String(150),
				FormalVerifierSet:          chainclient.CSVStrings{integrationVerifierAddress, "verifier-2", "verifier-3"},
				SampleSeedReadyHeight:      chainclient.NewUint64String(123),
				VerificationSampleSeed:     chainclient.HexHash(codec.HashWithDomain("VERIFY_SEED", []byte(taskID))),
				CommitDeadlineHeight:       chainclient.NewUint64String(180),
				WorkerRevealDeadlineHeight: chainclient.NewUint64String(190),
				RevealDeadlineHeight:       chainclient.NewUint64String(200),
				VerifyDeadlineHeight:       chainclient.NewUint64String(210), SampleSeedStatus: "READY",
				VerifierCandidateWindowHash: chainclient.HexHash(codec.HashWithDomain("VERIFY_WINDOW", []byte(taskID))),
				ParamVersion:                "v1", SampleRandomnessAggregationBlocks: chainclient.NewUint64String(1),
				WorkerRevealWindowBlocks: chainclient.NewUint64String(10), RevealWindowBlocks: chainclient.NewUint64String(10),
				Stage3BuilderGraceBlocks: chainclient.NewUint64String(5),
			},
		}, nil
	}
	return chainclient.TaskSnapshot{}, fmt.Errorf("task %s/%s not found", sessionID, taskID)
}

func (h *keeperHarness) FinalizedEvents(_ context.Context, after chainclient.EventPosition) (chainclient.KeeperEventsPage, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.eventRequests++
	page := chainclient.KeeperEventsPage{ChainHeight: 130}
	for _, event := range h.events {
		if event.Height <= after.Height {
			continue
		}
		page.Events = append(page.Events, event)
		if event.Height > page.FinalizedHeight {
			page.FinalizedHeight = event.Height
			page.LastEventHeight = event.Height
		}
	}
	if page.FinalizedHeight > 0 {
		page.RangeStartHeight = after.Height + 1
		page.RangeEndHeight = page.FinalizedHeight
		page.RangeComplete = true
		page.LastPosition = chainclient.BlockEndPosition(page.FinalizedHeight)
	}
	return page, nil
}

func (h *keeperHarness) handle(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch r.URL.Path {
	case "/status":
		h.heightRequests++
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":-1,"result":{"sync_info":{"latest_block_height":"123"}}}`))
	default:
		http.NotFound(w, r)
	}
}

type integrationGRPCServer struct {
	cortexv1.UnimplementedModelManagementServiceServer
	listener    *bufconn.Listener
	grpcServer  *grpc.Server
	client      cortexv1.ModelManagementServiceClient
	mu          sync.Mutex
	inferCalls  int
	verifyCalls int
	artifacts   map[string][]byte
}

func newIntegrationGRPCServer(t *testing.T) *integrationGRPCServer {
	t.Helper()
	s := &integrationGRPCServer{listener: bufconn.Listen(1024 * 1024), artifacts: make(map[string][]byte)}
	s.grpcServer = grpc.NewServer()
	cortexv1.RegisterModelManagementServiceServer(s.grpcServer, s)
	go func() {
		_ = s.grpcServer.Serve(s.listener)
	}()
	conn, err := grpc.DialContext(context.Background(), "bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return s.listener.Dial()
	}), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("DialContext returned error: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		s.grpcServer.Stop()
		_ = s.listener.Close()
	})
	s.client = cortexv1.NewModelManagementServiceClient(conn)
	return s
}

func (s *integrationGRPCServer) Infer(_ context.Context, req *cortexv1.InferRequest) (*cortexv1.InferResponse, error) {
	g, p, d := req.GetGeneration(), req.GetGeneration().GetParams(), req.GetGeneration().GetParams().GetDecodingParams()
	generation := nodewire.GenerationContext{
		ModelID: g.GetModelId(), ProfileVersion: g.GetProfileVersion(), TaskType: g.GetTaskType(), OutputBudgetBucket: g.GetOutputBudgetBucket(),
		Params: nodewire.GenerationParamsV1{SchemaVersion: p.GetGenerationParamsSchemaVersion(), MaxOutputTokens: p.GetMaxOutputTokens(), MaxOutputDuration: p.GetMaxOutputDuration(),
			DecodingParams: nodewire.DecodingParamsV1{
				SamplingEnabled: d.GetSamplingEnabled(), TemperatureMilli: d.GetTemperatureMilli(), TopPPPM: d.GetTopPPpm(), TopK: d.GetTopK(), Seed: d.GetSeed(),
				PresencePenaltyMilli: d.GetPresencePenaltyMilli(), FrequencyPenaltyMilli: d.GetFrequencyPenaltyMilli(), RepetitionPenaltyPPM: d.GetRepetitionPenaltyPpm(),
				StopSequences: d.GetStopSequences(), StopTokenIDs: d.GetStopTokenIds(),
			}},
	}
	trace, checkpoint, err := generationfixture.Evidence(modelservice.InferRequest{
		ModelID: req.GetModelId(), ProfileVersion: req.GetProfileVersion(), Generation: &generation, GenerationParamsDigest: req.GetGenerationParamsDigest(),
	}, []byte("artifact-output"), 2)
	if err != nil {
		return nil, err
	}
	traceRef, checkpointRef := modelservice.NewArtifactRef("svc-1", trace).String(), modelservice.NewArtifactRef("svc-1", checkpoint).String()
	s.mu.Lock()
	s.inferCalls++
	s.artifacts[traceRef], s.artifacts[checkpointRef] = trace, checkpoint
	s.mu.Unlock()
	return &cortexv1.InferResponse{
		RequestId:              req.GetRequestId(),
		ModelServiceId:         req.GetModelServiceId(),
		JobId:                  req.GetJobId(),
		TaskId:                 req.GetTaskId(),
		ModelId:                req.GetModelId(),
		ProfileVersion:         req.GetProfileVersion(),
		RequestDigest:          req.GetRequestDigest(),
		OutputRef:              modelservice.NewArtifactRef("svc-1", []byte("artifact-output")).String(),
		TraceRef:               traceRef,
		CheckpointRef:          checkpointRef,
		GeneratedTokenCount:    2,
		GenerationParamsDigest: req.GetGenerationParamsDigest(),
		FinishReason:           "eos_token",
		WorkUnit:               1,
	}, nil
}

func (s *integrationGRPCServer) Verify(_ context.Context, req *cortexv1.VerifyRequest) (*cortexv1.VerifyResponse, error) {
	s.mu.Lock()
	s.verifyCalls++
	s.mu.Unlock()
	sampleDigest := sha256.Sum256(req.GetSample())
	var trace, checkpoint []byte
	for _, item := range req.GetEvidence() {
		if item.GetEvidenceKind() == modelservice.EvidenceKindWorkerValueOpening {
			trace = item.GetTrace()
			checkpoint = item.GetCheckpoint()
			break
		}
	}
	materialDigest := sha256.Sum256(append(trace, checkpoint...))
	return &cortexv1.VerifyResponse{
		RequestId:                      req.GetRequestId(),
		ModelServiceId:                 req.GetModelServiceId(),
		JobId:                          req.GetJobId(),
		TaskId:                         req.GetTaskId(),
		ModelId:                        req.GetModelId(),
		ProfileVersion:                 req.GetProfileVersion(),
		RequestDigest:                  req.GetRequestDigest(),
		MainMismatchCount:              2,
		SelectedPositionsOrCheckpoints: []int32{1, 3},
		SampleValueSequenceRef:         modelservice.NewArtifactRef("svc-1", []byte("7")).String(),
		SampleValueDigest:              sampleDigest[:],
		ResultCommitMaterialDigest:     materialDigest[:],
		GenerationParamsDigest:         req.GetGenerationParamsDigest(),
		// The per-token comparison, carried over the model management RPC. It is
		// what proves the grpc boundary maps the metric fields at all: the fake
		// model service in internal/modelservice never crosses a transport, so
		// only this rig can catch a dropped field there.
		MetricSamples: integrationMetricSamples(),
	}, nil
}

func (s *integrationGRPCServer) FetchArtifact(req *cortexv1.FetchArtifactRequest, stream cortexv1.ModelManagementService_FetchArtifactServer) error {
	dataByRef := map[string][]byte{
		modelservice.NewArtifactRef("svc-1", []byte("artifact-output")).String(): []byte("artifact-output"),
		modelservice.NewArtifactRef("svc-1", []byte("trace")).String():           []byte("trace"),
		modelservice.NewArtifactRef("svc-1", []byte("checkpoint")).String():      []byte("checkpoint"),
		modelservice.NewArtifactRef("svc-1", []byte("7")).String():               []byte("7"),
	}
	data := dataByRef[req.GetRef()]
	if data == nil {
		s.mu.Lock()
		data = s.artifacts[req.GetRef()]
		s.mu.Unlock()
	}
	if data == nil {
		return fmt.Errorf("unknown artifact ref %s", req.GetRef())
	}
	chunks := [][]byte{data}
	offset := int64(0)
	for i, chunk := range chunks {
		digest := sha256.Sum256(chunk)
		if err := stream.Send(&cortexv1.ArtifactChunk{RequestId: req.GetRequestId(), ArtifactId: "artifact", Offset: offset, Bytes: chunk, FinalChunk: i == len(chunks)-1, ChunkDigest: digest[:]}); err != nil {
			return err
		}
		offset += int64(len(chunk))
	}
	return nil
}

func (s *integrationGRPCServer) InferCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inferCalls
}

func (s *integrationGRPCServer) VerifyCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verifyCalls
}

type recordingSigner struct {
	address string
	mu      sync.Mutex
	calls   int
}

func (s *recordingSigner) Address(context.Context, txclient.Kind) (string, error) {
	return s.address, nil
}

func (s *recordingSigner) Sign(_ context.Context, req txclient.SignRequest) ([]byte, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return []byte("signed:" + req.TaskID + ":" + string(req.Kind)), nil
}

func (s *recordingSigner) SignCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

type scriptedRPC struct {
	account    txclient.Account
	broadcasts [][]byte
}

func (r *scriptedRPC) Account(context.Context, string) (txclient.Account, error) {
	account := r.account
	r.account.Sequence++
	return account, nil
}

func (r *scriptedRPC) BroadcastTx(_ context.Context, tx []byte) (txclient.BroadcastResult, error) {
	r.broadcasts = append(r.broadcasts, append([]byte(nil), tx...))
	return txclient.BroadcastResult{Code: txclient.CodeOK, TxHash: fmt.Sprintf("0x%02d", len(r.broadcasts))}, nil
}

func (r *scriptedRPC) Tx(_ context.Context, txHash string) (txclient.InclusionResult, error) {
	return txclient.InclusionResult{Code: txclient.CodeOK, Height: 123, TxHash: txHash}, nil
}

func passingSelfTest(_ context.Context, manifest modelregistry.Manifest) (modelregistry.SelfTestResult, error) {
	return modelregistry.SelfTestResult{Passed: true, RegistrationMaterial: &modelregistry.RegistrationMaterial{ManifestHash: manifest.Hash}}, nil
}

func mustOpenStoreAt(t *testing.T, path string) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("store.Open returned error: %v", err)
	}
	t.Cleanup(func() {
		_ = s.Close()
	})
	return s
}

func mustEvidenceStore(t *testing.T, root string) *evidence.Store {
	t.Helper()
	s, err := evidence.NewStore(root)
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	return s
}

func outputPackageSummary(pkg builderclient.OutputPackage) policy.OutputPackageSummary {
	return policy.OutputPackageSummary{TaskID: pkg.TaskID, OutputRef: pkg.OutputRef, TraceRef: pkg.TraceRef, CheckpointRef: pkg.CheckpointRef, OutputHash: pkg.OutputHash, PackageHash: pkg.PackageHash}
}

func outputPackageKey(taskID string, packageHash codec.Hash) string {
	return taskID + ":" + fmt.Sprintf("%x", packageHash[:])
}

// traceEvent returns the one trace line for a milestone, failing when the
// milestone was never reached. Absence is the failure worth catching: an
// operator reads a missing line as "that step did not run".
func traceEvent(t *testing.T, records []observability.LogRecord, name string) string {
	t.Helper()
	prefix := "task trace event=" + name + " "
	for _, record := range records {
		line := record.Message
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	t.Fatalf("trace event %q was never emitted; records: %#v", name, records)
	return ""
}
