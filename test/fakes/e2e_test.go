package fakes_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidence"
	"github.com/TrueOpen/cortex/internal/evidencebundle"
	"github.com/TrueOpen/cortex/internal/identity"
	"github.com/TrueOpen/cortex/internal/modelregistry"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/policy"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/taskdataauth"
	"github.com/TrueOpen/cortex/internal/taskfacts"
	"github.com/TrueOpen/cortex/internal/taskfsm"
	"github.com/TrueOpen/cortex/internal/txclient"
	"github.com/TrueOpen/cortex/internal/verifier"
	"github.com/TrueOpen/cortex/internal/worker"
	"github.com/TrueOpen/cortex/test/internal/generationfixture"
)

// fakeWorkerSnapshotReader returns a snapshot that matches the supplied assignment.
type fakeWorkerSnapshotReader struct {
	assignment chainclient.AssignmentFinalized
}

func (r *fakeWorkerSnapshotReader) TaskSnapshot(ctx context.Context, taskID string) (chainclient.TaskSnapshot, error) {
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

func TestFakeBackedLLMTextV1EndToEndFlow(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	kvStore := mustOpenStore(t)
	evidenceStore := mustEvidenceStore(t, root)
	model := modelservice.NewFakeService()
	builder := builderclient.NewFakeClient()
	persistence := &e2ePersistence{
		store: kvStore, evidence: evidenceStore, evidenceRoot: root, cleanupHeight: 300,
		builder: builder,
	}
	outputFixture := newE2EWorkerOutputFixture(t, builder, "chain-fake", "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc", "trueopen1j7r6u8nwvw93l2tc0wd75v07vu89lxyfqf8fut", 120)
	txs := txclient.NewFake()
	registry := modelregistry.NewRegistry(modelregistry.RegistryConfig{
		NowHeight:  func() (uint64, error) { return 100, nil },
		Treasury:   "treasury-1",
		FeeDenom:   "utrueopen",
		Outbox:     registrationOutbox{},
		SelfTester: passingSelfTest,
		Signer: func(context.Context, modelregistry.RegistrationMaterial) (string, error) {
			return strings.Repeat("ab", 64), nil
		},
		FeeGrant:    modelregistry.StaticFeeGrant{Granter: "node-1", Amount: 100, GasLimit: 50},
		MinGasGrant: 10,
	})

	manifest, err := registry.GenerateManifest(ctx, modelregistry.ManifestInput{
		ModelID:        modelservice.FakeModelID,
		Version:        "2026-07-08",
		Digest:         "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Tokenizer:      "tiktoken-cl100k",
		ModelServiceID: "fake-model-service",
		Verification:   modelregistry.VerificationSpec{Method: "trace_sample_v1", ProfileVersion: modelservice.CapabilityLLMTextV1},
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
	if err := registry.ValidateManifest(ctx, manifest); err != nil {
		t.Fatalf("ValidateManifest returned error: %v", err)
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
			GasLimit:            10,
		},
		Mode: modelregistry.SubmitViaBuilder,
	})
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if registration.ManifestHash != manifest.Hash || registration.OutboxID == "" || registration.TxID != "" {
		t.Fatalf("registration = %#v, want manifest hash and Builder outbox", registration)
	}
	status, err := registry.Support(ctx, modelregistry.SupportRequest{ModelID: manifest.ModelID, Supported: true, DryRun: true})
	if err != nil {
		t.Fatalf("Support preview returned error: %v", err)
	}
	if !status.Supported {
		t.Fatalf("model support preview = false, want true")
	}
	status, err = registry.DailySupport(ctx, modelregistry.DailySupportRequest{ModelID: manifest.ModelID, Enabled: true})
	if err != nil {
		t.Fatalf("DailySupport returned error: %v", err)
	}
	if !status.DailySupportEnabled {
		t.Fatalf("daily support status = false, want true")
	}

	sessionID := "7738711542ae2980af57ee006157a5fe85946c5119c96a1f739d729741b8e398"
	orderSequence := uint64(7)
	taskID := identity.TaskIDString(sessionID, orderSequence)
	orderDigest := codec.HashWithDomain("E2E_ORDER", []byte(taskID))
	persistence.taskHash = orderDigest
	inferRec := layout.InferRecord{
		TaskID: taskID, InferDeadlineHeight: 140, Stage: layout.StageQueued,
	}
	if err := layout.MergeInfer(ctx, kvStore, layout.StoredHash(orderDigest), inferRec); err != nil {
		t.Fatalf("seed infer record: %v", err)
	}
	tr := layout.TaskRecord{
		SessionID: sessionID, OrderSequence: orderSequence,
		ModelID: manifest.ModelID, ProfileVersion: 1,
		AssignmentOrderDigest: layout.StoredHash(orderDigest),
	}
	if err := layout.MergeTask(ctx, kvStore, layout.StoredHash(orderDigest), tr); err != nil {
		t.Fatalf("seed task record: %v", err)
	}
	node := chainclient.NewFakeClient()
	assignment := chainclient.AssignmentFinalized{
		TaskID:                 taskID,
		SessionID:              sessionID,
		OrderSequence:          orderSequence,
		OrderDigest:            orderDigest,
		Winner:                 "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc",
		WinnerConfirmHeight:    120,
		InferDeadlineHeight:    140,
		ModelID:                manifest.ModelID,
		ProfileVersion:         1,
		Capability:             modelservice.CapabilityLLMTextV1,
		Input:                  []byte("summarize cortex fake mvp"),
		BuilderOperatorAddress: "trueopen1j7r6u8nwvw93l2tc0wd75v07vu89lxyfqf8fut",
	}
	node.AddAssignmentFinalized(assignment)
	generation := generationfixture.New(t, taskID, assignment.ModelID, "E2E_ACCEPTED_TASK_HASH_V1")
	evidenceSchemaHash := codec.Hash(fakeLockedProfile().Profile.VerificationProfile.EvidenceSchemaHash)
	workerNode := worker.New(worker.Config{
		WorkerAddress:               "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc",
		ModelServiceID:              "fake-model-service",
		Model:                       model,
		Builder:                     builder,
		TaskData:                    outputFixture.taskData,
		StreamLimits:                &chainclient.OutputStreamLimitsSnapshot{MinOutputStreamFrameBytes: 16, MaxOutputMMRLeaves: 65536},
		TaskDataAuth:                outputFixture.auth,
		Tx:                          txs,
		Persistence:                 workerPersistence{persistence},
		InferDeadlineDeltaHeights:   20,
		ChainID:                     "chain-fake",
		SessionID:                   sessionID,
		OrderSequence:               orderSequence,
		SignerAddress:               outputFixture.serviceAddress,
		SignerKeyRef:                outputFixture.serviceKeyRef,
		SignerPubkey:                outputFixture.servicePubkey,
		Signer:                      outputFixture.signer,
		NexusEnvelopeSigner:         testNexusEnvelopeSigner(),
		EvidenceSchemaHash:          hex.EncodeToString(evidenceSchemaHash[:]),
		ProfileEvidenceRequirements: builderclient.WorkerEvidenceRequirementsV3(),
		RequiredTopK:                e2eRequiredTopK,
		ReceivingBuilder:            worker.ReceivingBuilderFunc(outputFixture.receivingBuilder),
		TaskFacts:                   taskfacts.ReaderFunc(generation.TaskFacts),
		GenerationReader:            generation,
		SnapshotReader:              &fakeWorkerSnapshotReader{assignment: assignment},
	})
	// With the locked Profile's evidence schema supplied, the Worker can sign a
	// frozen task.v1.InferReceiptV2 and publish OUTPUT_AVAILABLE.
	infer, err := workerNode.HandleAssignmentFinalized(ctx, assignment)
	if err != nil {
		t.Fatalf("HandleAssignmentFinalized error = %v", err)
	}
	if !infer.Started {
		t.Fatalf("infer = %#v, want a started responsibility", infer)
	}
	outputAvailableCount := 0
	for _, req := range builder.Published {
		if req.Subject == builderclient.NATSOutputAvailableSubject(taskID) {
			outputAvailableCount++
		}
	}
	if outputAvailableCount != 1 {
		t.Fatalf("OUTPUT_AVAILABLE publishes = %d, want 1", outputAvailableCount)
	}
	if len(outputFixture.taskData.SubmittedInferReceipts) == 0 {
		t.Fatalf("want a submitted infer receipt")
	}
	// The inference itself ran and its package was validated, so the output the
	// Verifier grades below is real Worker output rather than a fixture.
	if len(builder.ValidatedPackages) != 1 {
		t.Fatalf("validated packages = %d, want the inference to have completed", len(builder.ValidatedPackages))
	}

	// The frozen VerifyCommitV1 preimage decodes verifier_operator_address, so
	// the rig has to name the Verifier the way a deployment does. A placeholder
	// like "verifier-1" would be refused for its shape and hide the frozen-input
	// gap this test exists to pin.
	const verifierAddress = "trueopen1gdm6ttxkdhzukec53gjgrrg728apsw7j73xf2q"
	outputPackage := builder.ValidatedPackages[0]
	confirmedReceipt := outputFixture.taskData.SubmittedInferReceipts[0].Receipt
	confirmedReceiptHash, err := builderclient.InferReceiptSigningDigest(confirmedReceipt)
	if err != nil {
		t.Fatal(err)
	}
	verifierState := verifier.TaskState{
		TaskID:           taskID,
		SessionID:        sessionID,
		OrderSequence:    orderSequence,
		OrderDigest:      orderDigest,
		VerifyRound:      1,
		InferReceiptHash: confirmedReceiptHash,
		Member: builderclient.CandidateMemberRefMessage{
			CandidatePoolSnapshotID: strings.Repeat("31", 32), Slot: 1, SlotVersion: 1,
			OperatorAddress: verifierAddress,
		},
		ModelID:        manifest.ModelID,
		ProfileVersion: 1,
		Capability:     modelservice.CapabilityLLMTextV1,
		WorkerAddress:  "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc",
		OutputPackage:  outputPackageSummary(outputPackage),
		// The daemon's Nexus output confirmer sets this in production; this rig
		// assembles the state directly, so it states the confirmation the
		// Verifier now requires before it will sign a handraise.
		OutputConfirmed:             true,
		ConfirmedInferReceipt:       &confirmedReceipt,
		ConfirmedInputTokenIDs:      append([]byte(nil), persistence.artifacts[taskID+"/worker-input_token_ids"]...),
		ConfirmedGeneratedTokenIDs:  append([]byte(nil), persistence.artifacts[taskID+"/worker-generated_token_ids"]...),
		ConfirmedFinishReason:       nodewire.FinishReasonV1EosToken,
		ConfirmedOutputChunkLengths: append([]uint64(nil), outputPackage.OutputChunkLengths...),
		OpenVerifyAccepted:          false,
		AssignedVerifiers:           []string{verifierAddress},
		OpenVerifyHeight:            150,
		HandraiseExpiryHeight:       170,
		CurrentHeight:               151,
		FutureBeaconID:              "beacon-1",
		BatchLogRoot:                codec.HashWithDomain("BATCH_LOG", []byte(taskID)),
		CommitDeadlineHeight:        180,
		// Keeper's reveal window for this verify round; the frozen ResultReceiptV1
		// carries it as expiry_height.
		RevealDeadlineHeight: 300,
		// TRUEOPEN_BUS_ENVELOPE_V1 fields 11 and 12. A verifier-stage message always
		// follows an accepted proposal, so the only admissible authority is the
		// Task's locked BuilderSet reference.
	}
	verifierNode := verifier.New(verifier.Config{
		EvidencePublisher:         e2eVerifierEvidencePublisher{client: builder},
		VerifierAddress:           verifierAddress,
		ModelServiceID:            "fake-model-service",
		Model:                     model,
		Builder:                   builder,
		Persistence:               verifierPersistence{persistence},
		ChainID:                   "chain-fake",
		SignerAddress:             verifierAddress,
		SignerKeyRef:              "test-verifier-key",
		Signer:                    testDigestSigner(),
		VerifyDeadlineDeltaHeight: 30,
		// Envelope field 7. Non-zero is a hard requirement of the 20-field
		// envelope, so the handraise cannot be signed without it.
		ServiceAuthorizationNonce: 23,
		FakeOutput:                true,
		// Fake inference does not make this node's identity fake: it still signs
		// every outbound envelope. The Worker half of this rig (above) already
		// supplied a signer; the Verifier half omitting one was the asymmetry
		// that let the unsigned path survive.
		NexusEnvelopeSigner: testNexusEnvelopeSigner(),
		// The same frozen section 16.2 read the Worker half of this rig serves.
		// generation_params_digest is a consensus value the verifier copies
		// through, so the result credential refuses without this reader.
		TaskFacts: taskfacts.ReaderFunc(generation.TaskFacts),
		// The commit exit. There is no relay to wire -- the bus registers no
		// VERIFY_COMMIT kind -- so the signed commit goes on chain from here,
		// signed by the current Cortex service address (keeper §10.6 rule 6).
		CommitSubmitter: verifier.NewSettlementManager(verifier.SettlementConfig{
			Tx: txs, VerifierAddress: verifierAddress, SubmitterAddress: verifierAddress,
			GasPayer: verifierAddress,
		}),
		// The locked model profile. The metric pipeline binds every leaf to its
		// version tokens and takes the presence of the two optional
		// MetricSummaryV1 members from its MetricSpec, so without it this rig
		// would stop at the result-credential gap and never exercise a reveal.
		ProfileReader: fakeLockedProfileReader{profile: fakeLockedProfile()},
	})
	handraise, err := verifierNode.EvaluateAndHandraise(ctx, verifierState)
	if err != nil {
		t.Fatalf("EvaluateAndHandraise returned error: %v", err)
	}
	if !handraise.Signed {
		t.Fatalf("handraise was not signed: %#v", handraise)
	}
	verifierState.OpenVerifyAccepted = true
	// The commit half completes: the local verification runs, its evidence is
	// persisted, and the signed VerifyCommitV1 reaches the chain.
	//
	// The commit credential is no longer the first refusal. It used to be, because
	// the rig left ServiceAuthorizationNonce zero; the 20-field
	// TRUEOPEN_BUS_ENVELOPE_V1 makes that nonce a precondition of the handraise this
	// test already asserted was signed, so the rig now states it and the
	// VerifyCommitV1 preimage is complete. generation_params_digest is not a gap
	// either - the verifier reads it through
	// chainclient.KeeperABCIClient.TaskReceiptFacts, which this rig serves.
	verifyResult, err := verifierNode.HandleOpenVerifyAccepted(ctx, verifierState)
	if err != nil {
		t.Fatalf("HandleOpenVerifyAccepted error = %v, want the commit half to complete", err)
	}
	// The commit credential itself is complete: the same ServiceKey binding nonce
	// the envelope carries as field 7 fills frozen preimage field 6, so the
	// refusal above withholds the result receipt alone.
	if verifyResult.CommitHash == (codec.Hash{}) || verifyResult.CommitWire.ServiceAuthorizationNonce != 23 {
		t.Fatalf("verify result = %#v, want a commit credential bound to the binding nonce", verifyResult)
	}
	// The commit DID go out, and it is the only transaction the verify path
	// sends. This used to assert the opposite -- "normal verifier path submitted
	// direct tx" was a failure -- on the belief that a Task Builder relays the
	// commit. Nothing relays it: the bus has no VERIFY_COMMIT kind and nexus's
	// ingress refuses the unary rpc, so self-submission is the normal exit.
	commitTxs := txs.Requests()
	if len(commitTxs) != 1 || commitTxs[0].Kind != txclient.MsgSubmitVerifyCommit {
		t.Fatalf("verify path transactions = %#v, want exactly one MsgSubmitVerifyCommit", commitTxs)
	}
	if commitTxs[0].DeadlineHeight != verifierState.CommitDeadlineHeight {
		t.Fatalf("commit tx timeout height = %d, want the commit deadline %d", commitTxs[0].DeadlineHeight, verifierState.CommitDeadlineHeight)
	}
	if !verifyResult.CommitDelivery.SelfSubmitted || !verifyResult.CommitDelivery.ChainAccepted {
		t.Fatalf("commit delivery = %#v, want a self-submission the chain confirmed", verifyResult.CommitDelivery)
	}

	// The reveal is a separate responsibility, and before the chain opens the
	// reveal phase it refuses as a WAIT rather than as a missing input. This is
	// the state a devnet node sits in between its commit landing and
	// EventRevealPhaseStarted, and it used to be indistinguishable from a broken
	// reveal.
	notStarted := verifierState
	notStarted.RevealDeadlineHeight = 0
	if _, err := verifierNode.HandleRevealPhaseStarted(ctx, notStarted); !errors.Is(err, verifier.ErrRevealPhaseNotStarted) {
		t.Fatalf("HandleRevealPhaseStarted before the phase = %v, want the reveal phase reported as not started", err)
	}
	// With the phase open and the deadline known, the reveal assembles a
	// COMPLETE frozen result body and publishes it. Every one of the twelve
	// preimage values now has a producer: metric_root, the ten typed
	// MetricSummaryV1 members and aggregate_proof_hash come from the metric
	// pipeline, and result_reveal_hash from the persisted compact reveal. This
	// line used to assert the opposite, and it is the end-to-end proof that
	// resultReceiptCredential stopped refusing on its own rather than by being
	// loosened.
	reveal, err := verifierNode.HandleRevealPhaseStarted(ctx, verifierState)
	if err != nil {
		t.Fatalf("HandleRevealPhaseStarted error = %v, want a complete result credential", err)
	}
	if !reveal.Published || reveal.ResultSigningDigest.IsZero() {
		t.Fatalf("reveal = %#v, want a published credential with its own TRUEOPEN_RESULT_V1 digest", reveal)
	}
	if reveal.ExpiryHeight != verifierState.RevealDeadlineHeight {
		t.Fatalf("reveal expiry_height = %d, want the Keeper reveal deadline %d", reveal.ExpiryHeight, verifierState.RevealDeadlineHeight)
	}
	if len(builder.FinalizedVerifierEvidence) != 1 {
		t.Fatal("Verifier result was published without finalizing its evidence bundle")
	}

	settlementManager := verifier.NewSettlementManager(verifier.SettlementConfig{Tx: txs, WorkerAddress: "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc", SubmitterAddress: "service-1", GasPayer: "service-1"})

	// The remaining stages are about reveal and settlement, not about assembling a
	// receipt, so the rig states the three receipt-shaped inputs the refusal above
	// withheld. Each one is Worker material with no Cortex source today; stating
	// them here keeps reveal and settlement exercised without pretending the
	// Worker produced them. The settlement manager binds them structurally
	// (non-zero sampled value set hash, non-empty receipt signature, a real
	// evidence ref), which is the part these stages are responsible for.
	if err := persistence.writeEvidence(ctx, taskID, "worker-infer-receipt", []byte("stand-in worker infer receipt")); err != nil {
		t.Fatalf("write stand-in receipt evidence: %v", err)
	}
	receiptRef := persistence.refByKind("worker-infer-receipt")
	if receiptRef == "" {
		t.Fatalf("worker-infer-receipt evidence ref missing")
	}
	sampledValueSetHash := codec.HashWithDomain("E2E_SAMPLED_VALUE_SET", []byte(taskID))
	receiptSignature := bytes.Repeat([]byte{0x7a}, 64)
	workerReveal, err := settlementManager.HandleDeadlineRisk(ctx, verifier.DeadlineRisk{
		TaskID:         taskID,
		Type:           verifier.WorkerRevealDeadlineRisk,
		CurrentHeight:  199,
		DeadlineHeight: 200,
		Margin:         1,
		WorkerReveal: verifier.ReceiptOnlyWorkerReveal{
			SessionID: sessionID, VerifyRound: 1, WorkerAddress: "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc", SampledValueSetHash: sampledValueSetHash,
			EvidenceSchemaVersion: "llm-text-v1", ReceiptSignature: receiptSignature,
		},
	})
	// The frozen contract registers no worker reveal Msg; the worker opening is a
	// commitment inside MsgSubmitInferReceipt instead.
	if err == nil || !strings.Contains(err.Error(), "registers no worker reveal Msg") || workerReveal.Submitted {
		t.Fatalf("worker reveal = %#v err=%v, want the frozen worker-reveal fail-closed", workerReveal, err)
	}
	settlementMessage, settlementRoot := e2eSettlementMessage(taskID)
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
	// The verifier settle material is the frozen VerifyCommitV1 item. Its missing
	// input used to be the ServiceKey binding nonce; the 20-field envelope makes
	// that nonce a precondition of the handraise, so it now reaches this preimage
	// too and the commit item is persisted for settlement rather than withheld.
	if ref := persistence.refByKind("settlement-verifier-result-commit"); ref == "" {
		t.Fatal("settlement-verifier-result-commit ref is empty, want the persisted commit item")
	}
	if err := persistence.writeEvidencePackage(ctx, orderDigest, 0); err != nil {
		t.Fatalf("write evidence package: %v", err)
	}

	plan, err := evidence.PlanCleanup(ctx, evidence.CleanupConfig{
		Root:                   root,
		Index:                  &evidence.LayoutStoreIndex{Store: kvStore},
		TaskHashes:             []codec.Hash{orderDigest},
		CurrentHeight:          300,
		RetentionPolicyVersion: "retention-v1",
	})
	if err != nil {
		t.Fatalf("PlanCleanup returned error: %v", err)
	}
	cleanup, err := evidence.Cleanup(ctx, evidence.CleanupConfig{
		Root:                   root,
		Index:                  &evidence.LayoutStoreIndex{Store: kvStore},
		TaskHashes:             []codec.Hash{orderDigest},
		CurrentHeight:          300,
		RetentionPolicyVersion: "retention-v1",
		ConfirmDigest:          plan.Digest,
	})
	if err != nil {
		t.Fatalf("Cleanup returned error: %v", err)
	}
	if cleanup.Scanned != 0 || cleanup.Cleaned != 0 || len(cleanup.Records) != 0 {
		t.Fatalf("cleanup = %#v, unfinished task evidence must not be removed", cleanup)
	}
	settlementRecord, err := (&evidence.LayoutStoreIndex{Store: kvStore}).Evidence(ctx, orderDigest)
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}
	if settlementRecord.TerminalOrSettled || settlementRecord.FinalityHeight != 0 {
		t.Fatalf("evidence = %#v, want active unfinished-task package", settlementRecord)
	}
}

func TestFakeBackedFlowRejectsNonCanonicalAssignmentTaskID(t *testing.T) {
	ctx := context.Background()
	model := modelservice.NewFakeService()
	builder := builderclient.NewFakeClient()
	workerNode := worker.New(worker.Config{
		WorkerAddress:             "worker-1",
		ModelServiceID:            "fake-model-service",
		Model:                     model,
		Builder:                   builder,
		InferDeadlineDeltaHeights: 20,
		ChainID:                   "chain-fake",
		SignerAddress:             "worker-1",
		SignerKeyRef:              "test-worker-key",
		Signer:                    testDigestSigner(),
		SnapshotReader:            &fakeWorkerSnapshotReader{assignment: chainclient.AssignmentFinalized{TaskID: "task-e2e-1", SessionID: "7738711542ae2980af57ee006157a5fe85946c5119c96a1f739d729741b8e398", Winner: "worker-1"}},
	})

	_, err := workerNode.HandleAssignmentFinalized(ctx, chainclient.AssignmentFinalized{
		TaskID:              "task-e2e-1",
		SessionID:           "7738711542ae2980af57ee006157a5fe85946c5119c96a1f739d729741b8e398",
		OrderSequence:       7,
		OrderDigest:         codec.HashWithDomain("E2E_ORDER", []byte("task-e2e-1")),
		Winner:              "worker-1",
		WinnerConfirmHeight: 120,
		ModelID:             modelservice.FakeModelID,
		ProfileVersion:      1,
		Capability:          modelservice.CapabilityLLMTextV1,
		Input:               []byte("summarize cortex fake mvp"),
	})
	if err == nil {
		t.Fatalf("non-canonical task id accepted")
	}
	if len(builder.ValidatedPackages) != 0 || len(builder.SubmittedInferReceipts) != 0 ||
		len(builder.UploadedTaskResults) != 0 || len(builder.Published) != 0 {
		t.Fatalf("builder/task-data effects emitted after non-canonical task id rejection")
	}
}

func testDigestSigner() signer.DigestSigner {
	return signer.DigestSignerFunc(func(_ context.Context, request signer.DigestRequest) ([]byte, error) {
		return e2eCompactSignature(secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{0x51}, 32)), request.Digest), nil
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

type e2eWorkerOutputFixture struct {
	taskData       *e2eSignedTaskData
	auth           *taskdataauth.Authenticator
	signer         e2eOutputSigner
	serviceAddress string
	servicePubkey  string
	serviceKeyRef  string
	builder        worker.BuilderEndpoint
}

func newE2EWorkerOutputFixture(
	t *testing.T,
	client *builderclient.FakeClient,
	chainID string,
	workerAddress string,
	builderOperator string,
	currentHeight uint64,
) e2eWorkerOutputFixture {
	t.Helper()
	servicePrivate := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{0x51}, 32))
	servicePublic := servicePrivate.PubKey().SerializeCompressed()
	serviceAddress, err := signer.AddressFromCompressedPublicKey("trueopen", servicePublic)
	if err != nil {
		t.Fatalf("derive Worker service address: %v", err)
	}
	const serviceKeyRef = "test-worker-key"
	outputSigner := e2eOutputSigner{private: servicePrivate, address: serviceAddress, keyRef: serviceKeyRef}
	servicePubkey := hex.EncodeToString(servicePublic)
	auth, err := taskdataauth.New(taskdataauth.Config{
		ServiceKeys: e2eServiceKeys{served: currentHeight, binding: chainclient.ServiceKeySnapshot{
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
	return e2eWorkerOutputFixture{
		taskData:       &e2eSignedTaskData{FakeClient: client, builderPrivate: builderPrivate},
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
func (f e2eWorkerOutputFixture) receivingBuilder(
	_ context.Context,
	task worker.ReceivingBuilderRef,
) (worker.BuilderEndpoint, error) {
	if task.AssignedBuilderOperator != f.builder.OperatorAddress {
		return worker.BuilderEndpoint{}, fmt.Errorf("unexpected Builder operator %q", task.AssignedBuilderOperator)
	}
	return f.builder, nil
}

type e2eOutputSigner struct {
	private *secp256k1.PrivateKey
	address string
	keyRef  string
}

func (s e2eOutputSigner) SignDigest(_ context.Context, request signer.DigestRequest) ([]byte, error) {
	if request.KeyRef != s.keyRef || request.ExpectedSignerAddress != s.address {
		return nil, fmt.Errorf("unexpected Worker output signer identity")
	}
	return e2eCompactSignature(s.private, request.Digest), nil
}

func (e2eOutputSigner) SignCosmosTx(context.Context, signer.CosmosTxRequest) ([]byte, error) {
	return nil, fmt.Errorf("not supported")
}

func (e2eOutputSigner) CanSignCosmosTx() bool { return false }

func e2eCompactSignature(private *secp256k1.PrivateKey, digest codec.Hash) []byte {
	signature := ecdsa.Sign(private, digest[:])
	r, s := signature.R(), signature.S()
	rBytes, sBytes := r.Bytes(), s.Bytes()
	out := make([]byte, 64)
	copy(out[:32], rBytes[:])
	copy(out[32:], sBytes[:])
	return out
}

type e2eServiceKeys struct {
	binding chainclient.ServiceKeySnapshot
	served  uint64
}

// served is the height Keeper answers the committed service-key read at.
func (s e2eServiceKeys) CommittedCurrentServiceKey(context.Context, string, string) (chainclient.ServiceKeySnapshot, uint64, error) {
	return s.binding, s.served, nil
}

type e2eSignedTaskData struct {
	*builderclient.FakeClient
	builderPrivate *secp256k1.PrivateKey
}

type e2eVerifierEvidencePublisher struct{ client *builderclient.FakeClient }

func (p e2eVerifierEvidencePublisher) PublishVerifierEvidence(ctx context.Context, state verifier.TaskState, receipt nodewire.ResultReceiptV3, encoded, proof []byte) error {
	manifest, err := evidencebundle.Decode(encoded)
	if err != nil {
		return err
	}
	if evidencebundle.Hash(encoded) != codec.Hash(receipt.VerifierEvidenceBundleHash) || uint64(len(encoded)) != receipt.VerifierEvidenceManifestSizeBytes {
		return fmt.Errorf("verifier receipt differs from manifest")
	}
	authFor := func(method string, digest codec.Hash) (builderclient.TaskDataRequestAuth, error) {
		auth := builderclient.TaskDataRequestAuth{SchemaVersion: 1, ChainID: receipt.ChainID, BuilderAddress: "trueopen1j7r6u8nwvw93l2tc0wd75v07vu89lxyfqf8fut", Method: builderclient.TaskDataProcedure(method), BodyDigest: digest, RequesterKind: builderclient.TaskDataRequesterCortexService, Requester: receipt.VerifierOperatorAddress, ServiceAuthorizationNonce: receipt.ServiceAuthorizationNonce, RequestNonce: bytes.Repeat([]byte{1}, 32), ExpiresAtHeight: receipt.ExpiryHeight}
		hash, err := builderclient.TaskDataRequestSigningHash(auth)
		if err != nil {
			return auth, err
		}
		auth.Signature = e2eCompactSignature(secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{0x51}, 32)), hash)
		return auth, nil
	}
	for i, data := range [][]byte{proof, encoded} {
		kind, hash := builderclient.DataKindEvidenceArtifact, codec.HashBytes(data)
		if i == 1 {
			kind, hash = builderclient.DataKindEvidenceManifest, evidencebundle.Hash(data)
		}
		key := builderclient.EvidenceObjectKey(manifest.TaskHash, state.SessionID, state.TaskID, kind, hash.String(), builderclient.EvidenceProducerVerifier, uint32(state.VerifyRound), receipt.VerifierOperatorAddress, nodewire.EvidenceKindVerifierValueOpening)
		body, err := builderclient.TaskDataUploadBodyDigest(key, uint64(len(data)), "")
		if err != nil {
			return err
		}
		auth, err := authFor("UploadTaskResultObject", body)
		if err != nil {
			return err
		}
		if _, err := p.client.UploadTaskResultObject(ctx, "", builderclient.UploadTaskResultRequest{Key: key, Data: data, SizeBytes: uint64(len(data)), Auth: auth}); err != nil {
			return err
		}
	}
	request := builderclient.FinalizeVerifierEvidenceRequest{TaskHash: manifest.TaskHash, SessionID: state.SessionID, TaskID: state.TaskID, VerifyRound: uint32(state.VerifyRound), VerifierOperator: receipt.VerifierOperatorAddress, Receipt: receipt}
	body, err := builderclient.TaskDataFinalizeVerifierBodyDigest(request)
	if err != nil {
		return err
	}
	request.Auth, err = authFor("FinalizeVerifierEvidence", body)
	if err != nil {
		return err
	}
	_, err = p.client.FinalizeVerifierEvidence(ctx, "", request)
	return err
}

func (c *e2eSignedTaskData) FinalizeTaskResult(ctx context.Context, endpoint string, request builderclient.FinalizeTaskResultRequest) (builderclient.FinalizeTaskResultResponse, error) {
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
		confirmation.Signature = e2eCompactSignature(c.builderPrivate, digest)
	}
	return result, nil
}

// e2eSettlementMessage builds the frozen MsgSettleTask. Every fact the deleted
// giant MsgSettle carried - verdict, payout, evidence root, receipt refs - is
// derived by the Keeper, so the locally computed root only travels beside the
// payload.
func e2eSettlementMessage(taskID string) (txclient.SettleTaskMessage, codec.Hash) {
	root := codec.HashWithDomain("TRUEOPEN_TASK_EVIDENCE_ROOT_V1", []byte(taskID))
	return txclient.SettleTaskMessage{TaskID: txclient.ProtoBytes32(taskID), SubmitterAddress: "trueopen1j7r6u8nwvw93l2tc0wd75v07vu89lxyfqf8fut"}, root
}

func TestChallengeVerifierDisabledPathIsAlertOnlyWhenAssigned(t *testing.T) {
	fsm := taskfsm.New(taskfsm.Config{LocalOperatorAddress: "node-1", Duties: []taskfsm.Duty{taskfsm.DutyVerifier}, ChallengeVerifierEnabled: false})

	next, effects, err := fsm.Apply(taskfsm.Task{ID: "task-1", State: taskfsm.StateSettled}, taskfsm.Event{
		Type:        taskfsm.EventChallengeVerifierAssigned,
		TaskID:      "task-1",
		ChallengeID: "challenge-1",
		Verifier:    "node-1",
	})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if next.ChallengeState != taskfsm.ChallengeStateAlertOnly {
		t.Fatalf("challenge state = %s, want ALERT_ONLY", next.ChallengeState)
	}
	if len(effects) != 1 || effects[0] != taskfsm.EffectRecordChallengeAlert {
		t.Fatalf("effects = %#v, want record challenge alert only", effects)
	}
}

type e2ePersistence struct {
	store    *store.Store
	evidence *evidence.Store
	// taskHash is a path component of every object this harness stores, the
	// same way the daemon's own persistence carries it: the local layout is
	// task-scoped, so there is nowhere to put bytes that name no task.
	taskHash             codec.Hash
	evidenceRoot         string
	cleanupHeight        uint64
	refs                 []string
	byKind               map[string]string
	builderMessages      map[string]worker.BuilderMessageCheckpoint
	modelJobs            map[string]worker.ModelJobCheckpoint
	inferReceipts        map[string]worker.InferReceiptCheckpoint
	storageConfirmations map[string][]worker.StorageConfirmationCheckpoint
	artifacts            map[string][]byte
	builder              *builderclient.FakeClient
}

func (p *e2ePersistence) WriteBuilderOutbox(_ context.Context, record worker.OutboxRecord) error {
	status := record.Status
	if status == "" {
		status = "pending"
	}
	if p.builderMessages == nil {
		p.builderMessages = make(map[string]worker.BuilderMessageCheckpoint)
	}
	digest := fmt.Sprintf("%x", record.Digest[:])
	p.builderMessages[digest] = worker.BuilderMessageCheckpoint{
		Digest: digest, Subject: record.Subject, TaskID: record.TaskID,
		Payload: append([]byte(nil), record.Payload...), Status: status,
	}
	return nil
}

func (p *e2ePersistence) WriteSettleMaterial(ctx context.Context, material verifier.SettleMaterial) error {
	return p.writeEvidence(ctx, material.TaskID, "settlement-"+material.Kind, material.Payload)
}

func (p *e2ePersistence) writeEvidence(ctx context.Context, taskID string, kind string, data []byte) error {
	ref, err := p.evidence.Write(ctx, evidence.WriteRequest{TaskHash: p.taskHash, TaskID: taskID, Kind: kind, Data: data})
	if err != nil {
		return err
	}
	if p.byKind == nil {
		p.byKind = make(map[string]string)
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

func (p *e2ePersistence) writeEvidencePackage(ctx context.Context, taskHash codec.Hash, finalityHeight uint64) error {
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

func (p *e2ePersistence) refByKind(kind string) string {
	return p.byKind[kind]
}

type workerPersistence struct {
	base *e2ePersistence
}

func (p workerPersistence) WriteEvidence(ctx context.Context, record worker.EvidenceRecord) error {
	return p.base.writeEvidence(ctx, record.TaskID, record.Kind, record.Data)
}

// PublishWorkerBundle stores one Worker bundle in the evidence store's bundle
// layout, exactly as the daemon does.
func (p workerPersistence) PublishWorkerBundle(ctx context.Context, _ string, kind nodewire.EvidenceKind, manifest []byte, artifacts [][]byte) error {
	id, err := p.bundleID(kind)
	if err != nil {
		return err
	}
	_, err = p.base.evidence.PublishBundle(ctx, evidence.BundleRequest{ID: id, Manifest: manifest, Artifacts: artifacts})
	return err
}

func (p workerPersistence) WorkerBundle(_ context.Context, _ string, kind nodewire.EvidenceKind) ([]byte, map[string][]byte, error) {
	id, err := p.bundleID(kind)
	if err != nil {
		return nil, nil, err
	}
	manifestBytes, _, err := p.base.evidence.ReadBundleManifest(id)
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
		if artifacts[artifact.ID], err = p.base.evidence.ReadBundleArtifact(id, codec.Hash(raw), int64(size)); err != nil {
			return nil, nil, err
		}
	}
	return manifestBytes, artifacts, nil
}

func (p workerPersistence) bundleID(kind nodewire.EvidenceKind) (evidence.BundleID, error) {
	switch kind {
	case nodewire.EvidenceKindWorkerTokenOpening:
		return evidence.WorkerTokenBundle(p.base.taskHash), nil
	case nodewire.EvidenceKindWorkerValueOpening:
		return evidence.WorkerValueBundle(p.base.taskHash), nil
	default:
		return evidence.BundleID{}, fmt.Errorf("evidence kind %d is not a Worker bundle", kind)
	}
}

func (p workerPersistence) CheckpointInferOutput(ctx context.Context, taskID string, output, tokenIDs, positionValues []byte, cp worker.InferOutputCheckpoint) error {
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

func (p workerPersistence) OutputStreamFrames(_ context.Context, taskID string) ([]builderclient.OutputChunk, error) {
	var frames []builderclient.OutputChunk
	for seq := uint64(0); ; seq++ {
		data, ok := p.base.artifacts[taskID+"/"+worker.OutputStreamFrameKind(seq)]
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

type verifierPersistence struct {
	base *e2ePersistence
}

func (p verifierPersistence) WriteEvidence(ctx context.Context, record verifier.EvidenceRecord) error {
	return p.base.writeEvidence(ctx, record.TaskID, record.Kind, record.Data)
}

func (p verifierPersistence) WriteSettleMaterial(ctx context.Context, material verifier.SettleMaterial) error {
	return p.base.WriteSettleMaterial(ctx, material)
}

func (p verifierPersistence) CheckpointModelJob(_ context.Context, record verifier.ModelJobCheckpoint) error {
	return nil
}

func mustOpenStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "cortex.kv"))
	if err != nil {
		t.Fatalf("store.Open returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Fatalf("store.Close returned error: %v", err)
		}
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

func passingSelfTest(_ context.Context, manifest modelregistry.Manifest) (modelregistry.SelfTestResult, error) {
	return modelregistry.SelfTestResult{
		Passed: true,
		RegistrationMaterial: &modelregistry.RegistrationMaterial{
			ManifestHash: manifest.Hash,
		},
	}, nil
}

type registrationOutbox struct{}

func (registrationOutbox) WriteRegistration(_ context.Context, msg modelregistry.OutboxMessage) (string, error) {
	return "outbox-" + msg.Material.ManifestHash, nil
}

func outputPackageSummary(pkg builderclient.OutputPackage) policy.OutputPackageSummary {
	return policy.OutputPackageSummary{
		TaskID:            pkg.TaskID,
		OutputRef:         pkg.OutputRef,
		TokenIDsRef:       pkg.TokenIDsRef,
		PositionValuesRef: pkg.PositionValuesRef,
		OutputHash:        pkg.OutputHash,
		PackageHash:       pkg.PackageHash,
	}
}

// e2eRequiredTopK is the locked Profile's required_top_k in this harness.
const e2eRequiredTopK = 4
