package verifier

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/evidencebundle"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/policy"
	"github.com/TrueOpen/cortex/internal/revealcontract"
	"github.com/TrueOpen/cortex/internal/taskfacts"
	"github.com/TrueOpen/cortex/internal/txclient"
)

const (
	envVerifierVLLMURL       = "CORTEX_TEST_VLLM_URL"
	envVerifierVLLMKeeperRPC = "CORTEX_TEST_VLLM_KEEPER_RPC"
	envVerifierVLLMModel     = "CORTEX_TEST_VLLM_MODEL"
	envVerifierVLLMPrompt    = "CORTEX_TEST_VLLM_PROMPT"
	// realVLLMServiceID namespaces the artifact refs the real service mints.
	// verifier Config.ModelServiceID has to carry the same string or every
	// FetchArtifact the verifier issues is refused before it reads a byte.
	realVLLMServiceID = "real-vllm-verifier"
)

// keeperVerifierProfileResolver mirrors internal/daemon's unexported
// keeperLocalProfileResolver: read the chain's current profile and hand back the
// snapshot the local service applies. It has to be the chain rather than a
// fixture because the profile decides the sampling parameters the verifier
// replays the prefill with; a fixture profile would have the verifier recompute
// logprobs under a policy the worker never generated under, and the comparison
// would measure the fixture rather than the model.
type keeperVerifierProfileResolver struct {
	keeper *chainclient.KeeperABCIClient
}

func (r keeperVerifierProfileResolver) ResolveLocalProfile(ctx context.Context, modelID string, profileVersion string) (chainclient.CurrentProfileSnapshot, error) {
	snapshot, err := r.keeper.CurrentModelProfile(ctx, modelID, profileVersion)
	if err != nil {
		return chainclient.CurrentProfileSnapshot{}, err
	}
	return snapshot.Profile, nil
}

// realVLLMTraceEnvelope is the subset of internal/modelservice's unexported
// traceEnvelope this package needs to count real generated tokens. It is a
// read-only projection by json tag, so it cannot drift into asserting anything
// the producer does not actually emit.
type realVLLMTraceEnvelope struct {
	ModelID             string `json:"model_id"`
	ProfileVersion      string `json:"profile_version"`
	GeneratedTokenCount int    `json:"generated_token_count"`
	FinishReason        string `json:"finish_reason"`
	InputTokenIDs       []int  `json:"input_token_ids"`
	OutTokens           []struct {
		TokenID int     `json:"token_id"`
		Logprob float64 `json:"logprob"`
	} `json:"out_tokens"`
}

// realVLLMVerificationEnvelope is the same kind of projection over the
// sample-value-sequence artifact the real service publishes from Verify.
type realVLLMVerificationEnvelope struct {
	Verdict       string   `json:"verdict"`
	RawVerdict    string   `json:"raw_verdict"`
	RejectReasons []string `json:"reject_reasons"`
	VerifierID    string   `json:"verifier_id"`
	Values        []struct {
		Position int      `json:"position"`
		TokenID  int      `json:"token_id"`
		Logprob  *float64 `json:"logprob"`
		Present  bool     `json:"present"`
	} `json:"values"`
	// The metrics the chain's pass band is actually expressed over, not just the
	// mean. PassAbsLogprobDiffP95Max is the condition that decides STRICT versus
	// INCONCLUSIVE for this model (#303), so a run that does not print P95 cannot
	// be compared against the policy it was judged under.
	Metrics struct {
		FiniteCount          int     `json:"finite_count"`
		MissingSelectedCount int     `json:"missing_selected_count"`
		MeanAbsLogprobDiff   float64 `json:"mean_abs_logprob_diff"`
		AbsLogprobDiffP95    float64 `json:"abs_logprob_diff_p95"`
		AbsLogprobDiffP99    float64 `json:"abs_logprob_diff_p99"`
		RankDeltaNonzeroRate float64 `json:"rank_delta_nonzero_rate"`
		ComparedTopKCount    int     `json:"compared_topk_count"`
	} `json:"metrics"`
}

// realVLLMRecorder wraps the real LocalService and keeps what the verifier
// asked it and what it answered, so the assertions below are made against the
// traffic that actually crossed the model boundary rather than against values
// the test recomputed for itself.
//
// It has no deviations. It used to carry a canonicalSampleValues mode that
// re-published the real envelope's SHA-256 as a decimal uint64, because the
// retired compact reveal encoding could not accept the envelope the real
// service publishes; the reveal binds the VerifierResult payload now
// (revealcontract.CanonicalVerifierResultPayload) and reads the envelope not at all.
type realVLLMRecorder struct {
	*modelservice.LocalService

	verifyRequests  []modelservice.VerifyRequest
	verifyResponses []modelservice.VerifyResponse
	fetches         []modelservice.FetchArtifactRequest
}

func (m *realVLLMRecorder) Verify(ctx context.Context, req modelservice.VerifyRequest) (modelservice.VerifyResponse, error) {
	m.verifyRequests = append(m.verifyRequests, req)
	resp, err := m.LocalService.Verify(ctx, req)
	if err != nil {
		return resp, err
	}
	m.verifyResponses = append(m.verifyResponses, resp)
	return resp, nil
}

func (m *realVLLMRecorder) FetchArtifact(ctx context.Context, req modelservice.FetchArtifactRequest) (modelservice.Artifact, error) {
	m.fetches = append(m.fetches, req)
	return m.LocalService.FetchArtifact(ctx, req)
}

// realVLLMEvidence is one real inference: the refs the worker would have
// published plus the bytes behind them.
type realVLLMEvidence struct {
	modelID    string
	output     modelservice.Artifact
	trace      modelservice.Artifact
	checkpoint modelservice.Artifact
	traceEnv   realVLLMTraceEnvelope
}

// TestVerifierVerifiesRealVLLMOutput is the Verifier layer against a real model
// service. internal/modelservice already covers Verify against live vLLM as a
// self-verify and internal/worker covers the Worker side end to end; what was
// unverified above them is everything the Verifier does with a REAL inference
// result: derive the verification sample seed over the real output package, pass
// the chain-derived required-evidence set down with the real trace root and
// size, replay the prefill, and turn the answer into commit and reveal material.
// Every other test in this package runs with modelservice.NewFakeService(),
// whose trace is a fixture of a few hundred bytes and whose sample-value
// sequence is a single synthetic uint64.
//
// Requires CORTEX_TEST_VLLM_KEEPER_RPC as well as the vLLM URL. Two separate
// chain reads are involved and neither may be a fixture:
//   - Config.ProfileReader: the verifier re-derives evidence_schema_hash from the
//     locked profile's evidence_schema and refuses on mismatch, and it takes the
//     per-kind max_encoded_size_bytes that bounds the real ~78KB trace from the
//     same read. A fixture would be asserting against a schema this deployment
//     never locked.
//   - LocalService's profile resolver: the sampling parameters the verifier
//     replays the prefill under. A fixture here would compare the worker's real
//     logprobs against a recomputation done under different sampling, so the
//     metrics would describe the fixture rather than the model.
func TestVerifierVerifiesRealVLLMOutput(t *testing.T) {
	endpoint := strings.TrimSpace(os.Getenv(envVerifierVLLMURL))
	if endpoint == "" {
		t.Skipf("set %s to run the real vLLM verifier test", envVerifierVLLMURL)
	}
	keeperRPC := strings.TrimSpace(os.Getenv(envVerifierVLLMKeeperRPC))
	if keeperRPC == "" {
		t.Skipf("set %s to resolve the locked profile the verifier judges under", envVerifierVLLMKeeperRPC)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	keeper := chainclient.NewKeeperABCIClient(keeperRPC)
	service := modelservice.NewLocalService(endpoint, realVLLMServiceID, 1, 5*time.Minute, 5*time.Minute)
	service.SetProfileResolver(keeperVerifierProfileResolver{keeper: keeper})

	caps, err := service.ListCapabilities(ctx, modelservice.ListCapabilitiesRequest{RequestID: "real-vllm-verifier-caps"})
	if err != nil {
		t.Fatalf("ListCapabilities() error = %v", err)
	}
	if len(caps.Capabilities) == 0 {
		t.Fatal("ListCapabilities() returned no models")
	}
	modelID := strings.TrimSpace(os.Getenv(envVerifierVLLMModel))
	if modelID == "" {
		modelID = caps.Capabilities[0].ModelID
	}

	// The locked profile facts the verifier's own precheck consumes. Logged
	// because the required-evidence set and its size bound are what the
	// assertions below compare the real trace against, so a run under a
	// different profile has to be recognisable in the log.
	profile, err := keeper.CurrentModelProfile(ctx, modelID, "1")
	if err != nil {
		t.Fatalf("CurrentModelProfile(%q) error = %v", modelID, err)
	}
	verification := profile.Profile.VerificationProfile
	if strings.Trim(verification.EvidenceSchemaHash.Hex(), "0") == "" {
		t.Fatalf("chain profile %s@1 publishes no verification_profile.evidence_schema_hash", modelID)
	}
	if verification.EvidenceSchema.SchemaVersion == 0 || len(verification.EvidenceSchema.RequiredInferEvidence) == 0 {
		t.Fatalf("chain profile %s@1 publishes no evidence_schema.required_infer_evidence", modelID)
	}
	for index, requirement := range verification.EvidenceSchema.RequiredInferEvidence {
		t.Logf("locked profile evidence requirement %d: kind=%d commitment_schema=%d max_encoded_size=%d",
			index, requirement.EvidenceKind,
			requirement.CommitmentSchemaVersion, requirement.MaxEncodedSizeBytes.Uint64())
	}
	t.Logf("locked profile: evidence_schema_version=%d evidence_schema_hash=%s judgment=%s mode=%s compared_topk=%d",
		verification.EvidenceSchema.SchemaVersion, verification.EvidenceSchemaHash.Hex(),
		verification.JudgmentFunctionVersion, verification.VerificationMode, verification.Metrics.ComparedTopK)

	evidence := runRealVLLMInference(t, ctx, service, modelID)

	// One subtest, not two. It used to be split, because the real path stopped
	// mid-way: the retired compact reveal encoding demanded one canonical decimal
	// uint64 per sample-value record and modelservice.LocalService publishes a
	// JSON verificationEnvelope, so a real run always ended at "result reveal
	// value 0 must be a canonical uint64" and the commit half could only be
	// reached by a recorder that re-published the envelope's SHA-256 as a
	// decimal. The reveal binds the VerifierResult payload now
	// (revealcontract.CanonicalVerifierResultPayload) and does not read the envelope
	// at all, so the real path runs end to end and the deviation is gone.
	t.Run("real path through the model boundary, commit and reveal", func(t *testing.T) {
		recorder := &realVLLMRecorder{LocalService: service}
		h := newRealVLLMHarness(t, recorder, keeper)
		state := realVLLMTaskState(t, evidence)
		generation, err := modelservice.GenerationContextFromTrace(evidence.trace.Data)
		if err != nil {
			t.Fatal(err)
		}
		generationDigest, err := generation.Digest()
		if err != nil {
			t.Fatal(err)
		}
		h.verifier.cfg.TaskFacts = taskfacts.ReaderFunc(func(_ context.Context, taskID string) (taskfacts.Facts, error) {
			facts := servedTaskFacts(taskID)
			facts.GenerationParamsDigest = chainclient.ProtoBytes32(generationDigest[:])
			return facts, nil
		})
		bindWorkerReceiptForTest(t, h.verifier, &state)

		result, err := h.verifier.HandleOpenVerifyAccepted(ctx, state)
		if err != nil {
			t.Fatalf("HandleOpenVerifyAccepted error = %v, want the commit half to complete on real inference", err)
		}

		// The seed the verifier derived is checked first because everything
		// downstream is keyed by it. It has to be a function of the REAL output
		// package: the same task under the fixture output hash must not produce
		// this seed, or the sample the verifier committed to would not be bound
		// to the output it verified.
		want := VerificationSampleSeed(SeedInput{
			ChainID: "chain-A", TaskID: state.TaskID, VerifyRound: state.VerifyRound,
			OpenVerifyHeight: state.OpenVerifyHeight, Profile: "1", FutureBeaconID: state.FutureBeaconID,
			PackageHash: state.OutputPackage.PackageHash, OutputHash: state.OutputPackage.OutputHash,
		})
		fixtureOutputRoot, err := codec.OutputMMRRoot([][]byte{[]byte("worker output")})
		if err != nil {
			t.Fatal(err)
		}
		fixtureSeed := VerificationSampleSeed(SeedInput{
			ChainID: "chain-A", TaskID: state.TaskID, VerifyRound: state.VerifyRound,
			OpenVerifyHeight: state.OpenVerifyHeight, Profile: "1", FutureBeaconID: state.FutureBeaconID,
			PackageHash: state.OutputPackage.PackageHash, OutputHash: fixtureOutputRoot,
		})
		if want == fixtureSeed {
			t.Fatalf("seed over the real output equals the seed over the fixture output %x", fixtureSeed)
		}
		if len(recorder.verifyRequests) != 1 {
			t.Fatalf("model Verify calls = %d, want exactly one real replay", len(recorder.verifyRequests))
		}
		issued := recorder.verifyRequests[0]
		t.Logf("verify request: task=%s model=%s@%s capability=%s sample=%x request_digest=%x",
			issued.TaskID, issued.ModelID, issued.ProfileVersion, issued.Capability, issued.Sample, issued.RequestDigest)
		if string(issued.Sample) != string(want[:]) {
			t.Fatalf("verify sample = %x, want the derived seed %x", issued.Sample, want)
		}
		if issued.TaskID != state.TaskID {
			t.Fatalf("verify task id = %q, want the canonical %q", issued.TaskID, state.TaskID)
		}

		// The evidence that crossed the boundary is the real trace and
		// checkpoint, described by the chain-derived requirement set.
		opening := issued.Evidence[modelservice.EvidenceKindWorkerValueOpening]
		traceRoot := codec.HashBytes(evidence.trace.Data)
		t.Logf("verify evidence: trace=%dB checkpoint=%dB expected_root=%x required=%d",
			len(opening.Trace), len(opening.Checkpoint), opening.ExpectedRoot, len(issued.RequiredEvidence))
		if string(opening.Trace) != string(evidence.trace.Data) || string(opening.Checkpoint) != string(evidence.checkpoint.Data) {
			t.Fatalf("verify evidence is not the real trace/checkpoint pair")
		}
		if string(opening.ExpectedRoot) != string(traceRoot[:]) || opening.EncodedSizeBytes != uint64(len(evidence.trace.Data)) {
			t.Fatalf("verify evidence root/size = %x/%d, want %x/%d",
				opening.ExpectedRoot, opening.EncodedSizeBytes, traceRoot[:], len(evidence.trace.Data))
		}
		if len(issued.RequiredEvidence) != len(verification.EvidenceSchema.RequiredInferEvidence) {
			t.Fatalf("required evidence set = %d entries, want the locked profile's %d",
				len(issued.RequiredEvidence), len(verification.EvidenceSchema.RequiredInferEvidence))
		}
		// The real-versus-fake discriminator. modelservice.NewFakeService emits a
		// trace of a few hundred bytes; 128 real generated tokens with top-k
		// logprobs run to tens of kilobytes, and this is the only input whose
		// size the locked profile bounds, so it is where the profile bound and
		// the digest over real data are actually exercised.
		const minRealTraceBytes = 8 << 10
		if opening.EncodedSizeBytes < minRealTraceBytes {
			t.Fatalf("verify trace is %dB, want at least %dB of real logprob trace rather than a fixture",
				opening.EncodedSizeBytes, minRealTraceBytes)
		}

		if len(recorder.verifyResponses) != 1 {
			t.Fatalf("model Verify responses = %d, want one", len(recorder.verifyResponses))
		}
		answer := recorder.verifyResponses[0]
		t.Logf("verify response: main_mismatch=%d selected=%d sample_digest=%x material_digest=%x sequence_ref=%q",
			answer.MainMismatchCount, len(answer.SelectedPositionsOrCheckpoints),
			answer.SampleDigest, answer.MaterialDigest, answer.SampleValueSequenceRef)
		if answer.MainMismatchCount != 0 {
			t.Fatalf("MainMismatchCount = %d, want a non-reject replay of the real prefill", answer.MainMismatchCount)
		}
		if len(answer.MaterialDigest) == 0 || len(answer.SampleDigest) == 0 {
			t.Fatalf("verify response digests are empty: %+v", answer)
		}

		envelope := decodeRealVLLMVerification(t, ctx, service, answer.SampleValueSequenceRef)
		t.Logf("verification envelope: verdict=%s raw_verdict=%s reject_reasons=%v verifier=%s values=%d finite=%d missing_selected=%d mean_abs_diff=%g p95=%g p99=%g rank_delta_rate=%g compared_topk=%d",
			envelope.Verdict, envelope.RawVerdict, envelope.RejectReasons, envelope.VerifierID,
			len(envelope.Values), envelope.Metrics.FiniteCount, envelope.Metrics.MissingSelectedCount,
			envelope.Metrics.MeanAbsLogprobDiff, envelope.Metrics.AbsLogprobDiffP95, envelope.Metrics.AbsLogprobDiffP99,
			envelope.Metrics.RankDeltaNonzeroRate, envelope.Metrics.ComparedTopKCount)
		if envelope.Verdict == "VERDICT_REJECT" || envelope.RawVerdict == "VERDICT_REJECT" {
			t.Fatalf("verification verdict = %s/%s, want non-reject", envelope.Verdict, envelope.RawVerdict)
		}
		if len(envelope.Values) != evidence.traceEnv.GeneratedTokenCount {
			t.Fatalf("verification produced %d sample values, want one per real generated token (%d)",
				len(envelope.Values), evidence.traceEnv.GeneratedTokenCount)
		}

		// The reveal completes on real inference. This is the strongest available
		// check on the metric pipeline: the samples come from an actual prefill
		// against vLLM and the binding from the chain's own locked profile, so a
		// fixture that happened to satisfy the encoder cannot carry it.
		reveal, err := h.verifier.HandleRevealPhaseStarted(ctx, state)
		if err != nil {
			t.Fatalf("HandleRevealPhaseStarted error = %v, want a complete result credential on real inference", err)
		}
		if !reveal.Published || reveal.ResultSigningDigest.IsZero() {
			t.Fatalf("reveal = %#v, want a published credential with its own TRUEOPEN_RESULT_V1 digest", reveal)
		}
		if result.MetricMaterial.LeafCount == 0 || result.MetricMaterial.Root.IsZero() {
			t.Fatalf("real verification produced no metric material: %#v", result.MetricMaterial)
		}
		t.Logf("metric material: leaves=%d root=%s aggregate_proof_hash=%s summary=%+v",
			result.MetricMaterial.LeafCount, result.MetricMaterial.Root,
			result.MetricMaterial.AggregateProof.Hash, result.MetricMaterial.Summary)
		t.Logf("verify result: started=%v seed=%x salt=%x result_digest=%x commit_hash=%x mismatch=%d",
			result.Started, result.VerificationSampleSeed, result.Salt, result.ResultDigest, result.CommitHash, result.MainMismatchCount)
		t.Logf("result reveal: %d bytes %x", len(result.ResultReveal), result.ResultReveal)

		if !result.Started {
			t.Fatal("result.Started = false, want the verifier to have run the real replay")
		}
		if result.VerificationSampleSeed == (codec.Hash{}) || result.Salt == (codec.Hash{}) ||
			result.ResultDigest == (codec.Hash{}) || result.CommitHash == (codec.Hash{}) {
			t.Fatalf("verify result carries a zero digest: %+v", result)
		}
		if result.MainMismatchCount != 0 {
			t.Fatalf("MainMismatchCount = %d, want a non-reject outcome over real output", result.MainMismatchCount)
		}

		// Every derived value is bound to the task AND to the real material. The
		// salt mixes the real MaterialDigest, so recomputing it with the fixture
		// digest the fake service would have produced must not match.
		wantSalt := codec.HashWithDomain("TRUEOPEN_RESULT_COMMIT_SALT_V1",
			[]byte(state.TaskID), []byte(fixtureVerifierAddress), result.VerificationSampleSeed[:], answer.MaterialDigest)
		if result.Salt != wantSalt {
			t.Fatalf("salt = %x, want the salt over the real material digest %x", result.Salt, wantSalt)
		}
		// The reveal is the VerifierResult payload, so it re-derives from this
		// run's own metric material plus the two consensus reads, and the
		// sample-value envelope the model service published is not an input at
		// all. Recomputing it here is what says the bytes the commit bound are
		// the bytes this run's material produces.
		metricSummaryHash, err := nodewire.MetricSummaryHash(result.MetricMaterial.Summary)
		if err != nil {
			t.Fatalf("MetricSummaryHash error = %v", err)
		}
		taskIDBytes, err := hex.DecodeString(state.TaskID)
		if err != nil {
			t.Fatalf("task id %q is not canonical hex: %v", state.TaskID, err)
		}
		var taskIDHash codec.Hash
		copy(taskIDHash[:], taskIDBytes)
		facts := servedTaskFacts(state.TaskID)
		wantReveal, err := revealcontract.CanonicalVerifierResultPayload(revealcontract.VerifierResultPayloadV1{
			ChainID:                           "chain-A",
			TaskID:                            taskIDHash,
			TaskHash:                          codec.Hash(facts.AcceptedTaskHash),
			VerifyRound:                       uint32(state.VerifyRound),
			VerifierOperatorAddress:           fixtureVerifierAddress,
			InferReceiptHash:                  state.InferReceiptHash,
			MetricRoot:                        result.MetricMaterial.Root,
			MetricLeafCount:                   uint32(result.MetricMaterial.LeafCount),
			MetricSummaryHash:                 metricSummaryHash,
			AggregateProofHash:                result.MetricMaterial.AggregateProof.Hash,
			ProfileExecutionSnapshotHash:      codec.Hash(facts.ProfileExecutionSnapshotHash),
			GenerationParamsDigest:            codec.Hash(facts.GenerationParamsDigest),
			VerifierEvidenceBundleHash:        evidencebundle.Hash(result.EvidenceManifest),
			VerifierEvidenceManifestSizeBytes: uint64(len(result.EvidenceManifest)),
		})
		if err != nil {
			t.Fatalf("CanonicalVerifierResultPayload over the real material error = %v", err)
		}
		if !bytes.Equal(result.ResultReveal, wantReveal) {
			t.Fatalf("result reveal = %x, want the reveal over the real material %x", result.ResultReveal, wantReveal)
		}
		// commit_hash is the frozen six-field TRUEOPEN_RESULT_COMMITMENT_V1
		// derivation, so it is checked against nodewire and NOT against
		// keepercontract.LocalCommitDigest - that is the retired Cortex-local
		// formula, which survives only for the alert-only challenge verifier.
		resultRevealHash := nodewire.ResultPayloadHash(result.ResultReveal)
		wantCommit, err := nodewire.ResultCommitmentHash(nodewire.ResultCommitmentV2{
			ChainID:                 "chain-A",
			TaskID:                  taskIDBytes,
			TaskHash:                facts.AcceptedTaskHash,
			VerifyRound:             uint32(state.VerifyRound),
			VerifierOperatorAddress: fixtureVerifierAddress,
			ResultPayloadHash:       resultRevealHash[:],
			Salt:                    result.Salt[:],
		})
		if err != nil {
			t.Fatalf("ResultCommitmentHash error = %v", err)
		}
		if result.CommitHash != wantCommit {
			t.Fatalf("commit hash = %x, want the frozen commitment over the real reveal %x", result.CommitHash, wantCommit)
		}

		// The frozen commit body is the chain-facing product of all of the above,
		// and it must name this task, this round and this verifier.
		commit := result.CommitWire
		t.Logf("commit wire: schema=%d chain=%s task=%x round=%d verifier=%s nonce=%d expiry=%d signature=%dB",
			commit.SchemaVersion, commit.ChainID, commit.TaskID, commit.VerifyRound,
			commit.VerifierOperatorAddress, commit.ServiceAuthorizationNonce, commit.ExpiryHeight, len(commit.ServiceSignature))
		if hex.EncodeToString(commit.TaskID) != state.TaskID {
			t.Fatalf("commit task id = %s, want %s", hex.EncodeToString(commit.TaskID), state.TaskID)
		}
		if hex.EncodeToString(commit.CommitHash) != hexOfHash(result.CommitHash) {
			t.Fatalf("commit wire commit_hash = %x, want %x", commit.CommitHash, result.CommitHash)
		}
		if uint64(commit.VerifyRound) != state.VerifyRound || commit.VerifierOperatorAddress != fixtureVerifierAddress {
			t.Fatalf("commit wire is not bound to this task: %+v", commit)
		}
		if commit.ExpiryHeight != state.CommitDeadlineHeight {
			t.Fatalf("commit expiry = %d, want the commit deadline %d", commit.ExpiryHeight, state.CommitDeadlineHeight)
		}
		signingDigest, err := nodewire.VerifyCommitSigningDigest(commit)
		if err != nil {
			t.Fatalf("VerifyCommitSigningDigest error = %v", err)
		}
		if string(commit.ServiceSignature) != string(fixtureSignature(signingDigest)) {
			t.Fatalf("commit signature does not cover the frozen body it is attached to")
		}

		// Settlement material is what a challenge would be answered from, so a
		// real verification that stored nothing is silent data loss.
		t.Logf("persisted: %s", describeRealVLLMVerifierPersistence(h.persistence))
		stored := map[string]int{}
		for _, record := range h.persistence.evidence {
			stored[record.Kind] = len(record.Data)
		}
		for _, kind := range []string{"verifier-v-values", "verifier-full-result-reveal-state", "verifier-result-commit-receipt"} {
			if stored[kind] == 0 {
				t.Fatalf("persisted evidence %q is missing or empty; have %v", kind, stored)
			}
		}
		var settled *SettleMaterial
		for index, material := range h.persistence.settle {
			if material.Kind == "verifier-result-commit" {
				settled = &h.persistence.settle[index]
			}
		}
		if settled == nil {
			t.Fatal("no verifier-result-commit settle material, want the commit queued for settlement")
		}
		if settled.TaskID != state.TaskID || settled.Digest == (codec.Hash{}) || len(settled.Payload) == 0 {
			t.Fatalf("settle material is not bound to the task: %+v", *settled)
		}
		t.Logf("settle material: task=%s kind=%s payload=%dB digest=%x",
			settled.TaskID, settled.Kind, len(settled.Payload), settled.Digest)
		// The job is succeeded even though the result credential could not be
		// built: the model work finished and its evidence is stored.
		if last := h.persistence.jobs[len(h.persistence.jobs)-1]; last.Status != "succeeded" {
			t.Fatalf("last model job status = %q, want succeeded", last.Status)
		}
	})
}

// runRealVLLMInference produces the worker-side evidence the verifier consumes.
// It is a real Infer against live vLLM followed by a real FetchArtifact of each
// ref, which is exactly what a deployed worker publishes and what the Task
// Builder would have handed the verifier.
func runRealVLLMInference(t *testing.T, ctx context.Context, service *modelservice.LocalService, modelID string) realVLLMEvidence {
	t.Helper()
	load, err := service.LoadModel(ctx, modelservice.LoadModelRequest{
		RequestID: "real-vllm-verifier-load", ModelID: modelID, Capability: modelservice.CapabilityLLMTextV1,
	})
	if err != nil {
		t.Fatalf("LoadModel(%q) error = %v", modelID, err)
	}
	if !load.Loaded {
		t.Fatalf("LoadModel(%q) = %+v, want loaded", modelID, load)
	}
	prompt := strings.TrimSpace(os.Getenv(envVerifierVLLMPrompt))
	if prompt == "" {
		prompt = "Name one property of a deterministic verifier."
	}
	taskID := canonicalTaskID(realVLLMSessionID, realVLLMOrderSequence)
	generation := nodewire.GenerationContext{
		ModelID: modelID, ProfileVersion: 1, TaskType: 2, OutputBudgetBucket: 1,
		Params: nodewire.GenerationParamsV1{SchemaVersion: 1, MaxOutputTokens: 1024, MaxOutputDuration: 300000,
			DecodingParams: nodewire.DecodingParamsV1{TopPPPM: 1000000, RepetitionPenaltyPPM: 1000000}},
	}
	generationDigest, err := generation.Digest()
	if err != nil {
		t.Fatal(err)
	}
	infer, err := service.Infer(ctx, modelservice.InferRequest{
		Generation: &generation, GenerationParamsDigest: generationDigest[:],
		RequestID: "real-vllm-verifier-infer", JobID: "real-vllm-verifier-job", TaskID: taskID,
		ModelID: modelID, ProfileVersion: "1", Capability: modelservice.CapabilityLLMTextV1,
		Input: []byte(prompt),
	})
	if err != nil {
		t.Fatalf("Infer() error = %v", err)
	}
	if infer.OutputRef == "" || infer.TraceRef == "" || infer.CheckpointRef == "" {
		t.Fatalf("Infer() refs = %+v, want output, trace, and checkpoint refs", infer)
	}
	fetch := func(name, ref string) modelservice.Artifact {
		artifact, err := service.FetchArtifact(ctx, modelservice.FetchArtifactRequest{
			RequestID: "real-vllm-verifier-fetch-" + name, ModelServiceID: realVLLMServiceID, Ref: ref,
		})
		if err != nil {
			t.Fatalf("FetchArtifact(%s=%q) error = %v", name, ref, err)
		}
		if len(artifact.Data) == 0 {
			t.Fatalf("FetchArtifact(%s) returned no bytes", name)
		}
		return artifact
	}
	evidence := realVLLMEvidence{
		modelID:    modelID,
		output:     fetch("output", infer.OutputRef),
		trace:      fetch("trace", infer.TraceRef),
		checkpoint: fetch("checkpoint", infer.CheckpointRef),
	}
	if err := json.Unmarshal(evidence.trace.Data, &evidence.traceEnv); err != nil {
		t.Fatalf("unmarshal real trace envelope: %v", err)
	}
	if evidence.traceEnv.GeneratedTokenCount == 0 || len(evidence.traceEnv.OutTokens) != evidence.traceEnv.GeneratedTokenCount {
		t.Fatalf("real trace generated_token_count=%d out_tokens=%d, want a consistent non-empty trace",
			evidence.traceEnv.GeneratedTokenCount, len(evidence.traceEnv.OutTokens))
	}
	t.Logf("real inference: output=%dB trace=%dB checkpoint=%dB generated_tokens=%d input_tokens=%d finish=%s",
		len(evidence.output.Data), len(evidence.trace.Data), len(evidence.checkpoint.Data),
		evidence.traceEnv.GeneratedTokenCount, len(evidence.traceEnv.InputTokenIDs), evidence.traceEnv.FinishReason)
	t.Logf("real output: %q", strings.TrimSpace(string(evidence.output.Data)))
	return evidence
}

func decodeRealVLLMVerification(t *testing.T, ctx context.Context, service *modelservice.LocalService, ref string) realVLLMVerificationEnvelope {
	t.Helper()
	artifact, err := service.FetchArtifact(ctx, modelservice.FetchArtifactRequest{
		RequestID: "real-vllm-verifier-sequence", ModelServiceID: realVLLMServiceID, Ref: ref,
	})
	if err != nil {
		t.Fatalf("FetchArtifact(sample sequence %q) error = %v", ref, err)
	}
	var envelope realVLLMVerificationEnvelope
	if err := json.Unmarshal(artifact.Data, &envelope); err != nil {
		t.Fatalf("unmarshal verification envelope (%dB): %v", len(artifact.Data), err)
	}
	return envelope
}

const (
	// realVLLMSessionID/realVLLMOrderSequence are the same canonical identity
	// shape the fixture tests use. TaskID has to be canonical 32-byte hex or the
	// frozen commit body refuses it before anything is signed.
	realVLLMSessionID     = "84097828fc31a8c8d29210df48901a85de7fd013f686b17be77d1be29cb7a98b"
	realVLLMOrderSequence = 9
)

// realVLLMTaskState is the fixture TaskState with the REAL output package
// substituted. The heights, member reference, builder set and beacon id stay
// fixtures because the task was never proposed on chain - this run publishes
// nothing and broadcasts no transaction - and they are consensus bookkeeping the
// verifier only range-checks. The output package is the part that must be real:
// every digest the verifier derives is a function of it.
func realVLLMTaskState(t *testing.T, evidence realVLLMEvidence) TaskState {
	t.Helper()
	taskID := canonicalTaskID(realVLLMSessionID, realVLLMOrderSequence)
	// This harness does not submit a receipt on chain; supply its finish-reason
	// fixture from the real evidence that would enter that receipt commitment.
	finishReason := nodewire.FinishReasonV1EosToken
	if evidence.traceEnv.FinishReason == "length" {
		finishReason = nodewire.FinishReasonV1MaxOutputTokens
	}
	outputHash, err := codec.OutputMMRRoot([][]byte{evidence.output.Data})
	if err != nil {
		t.Fatal(err)
	}
	pkg := policy.OutputPackageSummary{
		TaskID:        taskID,
		OutputRef:     modelservice.NewArtifactRef(realVLLMServiceID, evidence.output.Data).String(),
		TraceRef:      modelservice.NewArtifactRef(realVLLMServiceID, evidence.trace.Data).String(),
		CheckpointRef: modelservice.NewArtifactRef(realVLLMServiceID, evidence.checkpoint.Data).String(),
		OutputHash:    outputHash,
	}
	pkg.PackageHash = codec.HashWithDomain(
		"TRUEOPEN_OUTPUT_PACKAGE_V1",
		[]byte(pkg.TaskID), []byte(pkg.OutputRef), []byte(pkg.TraceRef), []byte(pkg.CheckpointRef), pkg.OutputHash[:],
	)
	return TaskState{
		TaskID:           taskID,
		SessionID:        realVLLMSessionID,
		OrderSequence:    realVLLMOrderSequence,
		OrderDigest:      codec.HashWithDomain("TEST_ORDER_DIGEST", []byte("order-9")),
		VerifyRound:      1,
		InferReceiptHash: codec.HashWithDomain("TEST_INFER_RECEIPT", []byte(taskID)),
		Member: builderclient.CandidateMemberRefMessage{
			CandidatePoolSnapshotID: strings.Repeat("31", 32), Slot: 1, SlotVersion: 1,
			OperatorAddress: fixtureVerifierAddress,
		},
		ModelID:                     evidence.modelID,
		ProfileVersion:              1,
		Capability:                  modelservice.CapabilityLLMTextV1,
		WorkerAddress:               "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz",
		OutputPackage:               pkg,
		OutputConfirmed:             true,
		ConfirmedFinishReason:       finishReason,
		ConfirmedOutput:             evidence.output.Data,
		ConfirmedOutputChunkLengths: []uint64{uint64(len(evidence.output.Data))},
		ConfirmedTrace:              evidence.trace.Data,
		ConfirmedCheckpoint:         evidence.checkpoint.Data,
		OpenVerifyAccepted:          true,
		AssignedVerifiers:           []string{fixtureVerifierAddress},
		OpenVerifyHeight:            220,
		HandraiseExpiryHeight:       240,
		CurrentHeight:               220,
		FutureBeaconID:              "proposer-vrf-epoch-12",
		CommitDeadlineHeight:        260,
		RevealDeadlineHeight:        300,
	}
}

// newRealVLLMHarness builds the verifier the way internal/daemon does for a
// deployed node, except for the two inputs the daemon cannot supply yet: the
// ServiceKey binding nonce (Config.ServiceAuthorizationNonce, no daemon path
// publishes it into the task plane) and the TaskFacts reader (the task was never
// proposed on chain, so there is nothing to read). Both are the same fixtures
// newHarness uses; everything the real inference touches is real.
func newRealVLLMHarness(t *testing.T, model modelservice.Client, keeper *chainclient.KeeperABCIClient) harness {
	t.Helper()
	builder := builderclient.NewFakeClient()
	persistence := &recordingPersistence{}
	tx := txclient.NewFake()
	v := New(Config{
		VerifierAddress:           fixtureVerifierAddress,
		ModelServiceID:            realVLLMServiceID,
		Model:                     model,
		Builder:                   builder,
		Persistence:               persistence,
		ChainID:                   "chain-A",
		SignerAddress:             "service-1",
		SignerKeyRef:              "test-verifier-key",
		Signer:                    testDigestSigner(),
		VerifyDeadlineDeltaHeight: 40,
		// The deployed setting. The verifier must read the locked profile from
		// the chain rather than falling back to the fake-mode default.
		FakeOutput:                false,
		ServiceAuthorizationNonce: 11,
		TaskFacts:                 fixtureTaskFacts{},
		ProfileReader:             keeper,
		// The deployed setting here too: a real-mode node self-submits its
		// commit, so a harness without a submitter would stop at the commit exit
		// and never reach the reveal-side gap these tests are about.
		CommitSubmitter: testCommitSubmitter(tx),
	})
	return harness{builder: builder, persistence: persistence, tx: tx, verifier: v}
}

// describeRealVLLMVerifierPersistence summarises what a real verification wrote,
// by kind and size. A count alone would not distinguish a run that stored the
// real reveal state from one that stored a fixture stub.
func describeRealVLLMVerifierPersistence(p *recordingPersistence) string {
	var parts []string
	for _, record := range p.evidence {
		parts = append(parts, "evidence:"+record.Kind+"="+strconv.Itoa(len(record.Data)))
	}
	for _, material := range p.settle {
		parts = append(parts, "settle:"+material.Kind+"="+strconv.Itoa(len(material.Payload)))
	}
	for _, job := range p.jobs {
		parts = append(parts, "job:"+job.Status)
	}
	return strings.Join(parts, " ")
}

func hexOfHash(value codec.Hash) string {
	return hex.EncodeToString(value[:])
}
