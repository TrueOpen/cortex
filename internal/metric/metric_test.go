package metric

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// The four pinned hex values below are REGRESSION vectors, not conformance
// vectors, and the distinction matters.
//
// They are the output of this repository. That means they catch a later change
// to the encoding - which is what they are for - but they could not have caught
// the encoding being wrong on day one, because the vector would simply have
// recorded the wrong bytes. The metric root is over V3 leaves, which wire
// publishes vectors for (leaf_v3_test.go); the summary is checked by
// spec_conformance_test.go against an independent encoder. Read those files
// together with this one: they say the encoding is right, this one says it has
// not moved.
const (
	fixtureMetricRootHex = "bed50329055c4c44bd2d888ade2dd7a665fe6262f371e38393b568bd07dcbc17"
	// The same summary with fields 7/8 present, and with them absent. Two
	// different facts, two different hashes - see §9.7.
	fixtureSummaryHashWithOptionalsHex    = "347cbe49201e4f41708fd3e4bf59a8c0854041c1429b01d10ecdd96b248415af"
	fixtureSummaryHashWithoutOptionalsHex = "536822decaa2c96009a43f82101c8650c0765e6a2515a6a435324124089e91c3"
	// The aggregate proof's own encoding is Cortex's rather than the protocol's
	// (see BuildAggregateProof), which is exactly why it is pinned: nothing
	// upstream would notice it moving.
	fixtureAggregateProofHashHex = "68edd48784c103a582644611558ed2b560e723617df40afe550b20bc008e774d"
)

func TestMetricRootIsDeterministicForAFixedInput(t *testing.T) {
	binding := fixtureBinding()
	samples := fixtureSamples()

	first, err := Build(binding, samples)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	second, err := Build(binding, samples)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if first.Root != second.Root {
		t.Fatalf("metric_root is not reproducible: %s vs %s", first.Root, second.Root)
	}
	if first.Root.IsZero() {
		t.Fatalf("metric_root is zero")
	}
	if got := first.Root.String(); got != fixtureMetricRootHex {
		t.Fatalf("metric_root = %s, want the pinned vector %s.\n"+
			"If this change was intended, update the vector AND say which encoding rule moved.", got, fixtureMetricRootHex)
	}
}

// The root must be a function of the locked profile, not only of the numbers. A
// leaf carries eleven binding fields precisely so the same token comparison
// under a different profile cannot re-use the same material.
func TestMetricRootIsBoundToTheLockedProfile(t *testing.T) {
	base, err := Build(fixtureBinding(), fixtureSamples())
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	for name, mutate := range map[string]func(*Binding){
		"chain_id":                       func(b *Binding) { b.ChainID = "chain-B" },
		"task_id":                        func(b *Binding) { b.TaskID = fill(0x99) },
		"model_id":                       func(b *Binding) { b.ModelID = strings.Repeat("ab", 32) },
		"profile_version":                func(b *Binding) { b.ProfileVersion = 2 },
		"judgment_function_version":      func(b *Binding) { b.JudgmentFunctionVersion = "PREFILL_GENERATED_TOKEN_METRICS_V2" },
		"canonical_encoding_version":     func(b *Binding) { b.CanonicalEncodingVersion = "CANONICAL_ENCODING_V2" },
		"evidence_schema_hash":           func(b *Binding) { b.EvidenceSchemaHash = fill(0x98) },
		"metric_aggregate_proof_version": func(b *Binding) { b.MetricAggregateProofVersion = "OTHER_PROOF_V1" },
		"tokenizer_hash":                 func(b *Binding) { b.TokenizerHash = fill(0x97) },
		"generation_params_digest":       func(b *Binding) { b.GenerationParamsDigest = fill(0x96) },
		"required_top_k":                 func(b *Binding) { b.RequiredTopK = 5; b.Spec.ComparedTopK = 5 },
	} {
		t.Run(name, func(t *testing.T) {
			binding := fixtureBinding()
			mutate(&binding)
			changed, err := Build(binding, fixtureSamples())
			if err != nil {
				t.Fatalf("Build returned error: %v", err)
			}
			if changed.Root == base.Root {
				t.Fatalf("changing %s did not change metric_root", name)
			}
		})
	}
}

// output_position is expressed as tree index and nowhere else, so a gap or a
// reordering has to be refused rather than rooted: the tree cannot tell the
// difference afterwards.
func TestNonContiguousOrOutOfOrderPositionsAreRefused(t *testing.T) {
	for name, samples := range map[string][]Sample{
		"gap":       {sampleAt(0), sampleAt(2)},
		"duplicate": {sampleAt(0), sampleAt(0)},
		"descending": {
			sampleAt(1), sampleAt(0),
		},
		"does not start at zero": {sampleAt(1), sampleAt(2)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Build(fixtureBinding(), samples); err == nil {
				t.Fatalf("%s positions were accepted", name)
			}
		})
	}
}

func TestEmptySampleSetIsRefusedRatherThanRootedEmpty(t *testing.T) {
	_, err := Build(fixtureBinding(), nil)
	if err == nil {
		t.Fatalf("an empty sample set produced a signed-able root")
	}
	if !strings.Contains(err.Error(), "empty tree") {
		t.Fatalf("error does not explain the empty-tree refusal: %v", err)
	}
}

// §9.7: presence of fields 7 and 8 is decided by the locked MetricSpec alone.
// Both directions are checked, and so is the consequence - the two summaries
// must not hash alike, or the distinction would not reach the Keeper.
func TestOptionalSummaryMembersFollowTheLockedMetricSpec(t *testing.T) {
	measured := fixtureAggregates()

	withOptionals, err := Summary(Spec{
		CompareTopKJaccard: true, CompareUnionJS: true, ComparedTopK: 4,
	}, measured)
	if err != nil {
		t.Fatalf("Summary returned error: %v", err)
	}
	if !withOptionals.TopkJaccardMeanFP1e6.Present || !withOptionals.UnionJSP99FP1e6.Present {
		t.Fatalf("profile asked for both optionals and the summary omitted one: %#v", withOptionals)
	}

	withoutOptionals, err := Summary(Spec{ComparedTopK: 4}, measured)
	if err != nil {
		t.Fatalf("Summary returned error: %v", err)
	}
	if withoutOptionals.TopkJaccardMeanFP1e6.Present || withoutOptionals.UnionJSP99FP1e6.Present {
		t.Fatalf("profile asked for neither optional and the summary carried one: %#v", withoutOptionals)
	}

	present, err := nodewire.MetricSummaryHash(withOptionals)
	if err != nil {
		t.Fatalf("MetricSummaryHash returned error: %v", err)
	}
	absent, err := nodewire.MetricSummaryHash(withoutOptionals)
	if err != nil {
		t.Fatalf("MetricSummaryHash returned error: %v", err)
	}
	if present == absent {
		t.Fatalf("present and absent optionals hash to the same metric_summary_hash %s", present)
	}
	if got := present.String(); got != fixtureSummaryHashWithOptionalsHex {
		t.Fatalf("metric_summary_hash with optionals = %s, want the pinned vector %s", got, fixtureSummaryHashWithOptionalsHex)
	}
	if got := absent.String(); got != fixtureSummaryHashWithoutOptionalsHex {
		t.Fatalf("metric_summary_hash without optionals = %s, want the pinned vector %s", got, fixtureSummaryHashWithoutOptionalsHex)
	}
}

// A profile that judges on a metric the run never measured is a refusal, not an
// absent field: absent means "this profile does not judge on it", which would be
// a false statement the Keeper then judges against.
func TestARequiredOptionalTheRunDidNotMeasureIsRefused(t *testing.T) {
	measured := fixtureAggregates()
	measured.TopKJaccardMean = OptionalFP{}

	_, err := Summary(Spec{CompareTopKJaccard: true, ComparedTopK: 4}, measured)
	if err == nil {
		t.Fatalf("a required but unmeasured optional was silently omitted")
	}
	if !strings.Contains(err.Error(), "compare_topk_jaccard") {
		t.Fatalf("error does not name the profile flag that required it: %v", err)
	}
}

// A metric the profile does NOT ask for must not reach the preimage even when
// the run measured it - the run measures everything the model service can give,
// and the profile is what the sample is judged on.
func TestAMeasuredOptionalTheProfileDoesNotAskForIsDropped(t *testing.T) {
	summary, err := Summary(Spec{ComparedTopK: 4}, fixtureAggregates())
	if err != nil {
		t.Fatalf("Summary returned error: %v", err)
	}
	if summary.TopkJaccardMeanFP1e6 != (nodewire.OptionalUint32{}) {
		t.Fatalf("a measured but unrequested jaccard reached the summary: %#v", summary.TopkJaccardMeanFP1e6)
	}
}

// keeper §9.7 judgment layer 2: the Keeper "must not accept a verdict field carried
// by the Verifier itself". The wire type has no place for one, and this asserts the
// producer did not grow a channel for it either.
func TestSummaryCarriesNoVerdictField(t *testing.T) {
	typ := reflect.TypeFor[nodewire.MetricSummaryV1]()
	for i := 0; i < typ.NumField(); i++ {
		name := strings.ToLower(typ.Field(i).Name)
		for _, forbidden := range []string{"verdict", "pass", "fail", "reject", "inconclusive"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("MetricSummaryV1 field %s looks like a verdict; the Keeper recomputes the verdict", typ.Field(i).Name)
			}
		}
	}
	typ = reflect.TypeFor[Aggregates]()
	for i := 0; i < typ.NumField(); i++ {
		name := strings.ToLower(typ.Field(i).Name)
		for _, forbidden := range []string{"verdict", "pass", "fail", "reject"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("Aggregates field %s carries a verdict into the summary producer", typ.Field(i).Name)
			}
		}
	}
}

// aggregate_proof_hash is one of the three bare-SHA-256 producers
// canonical-encoding-and-domain-hashing §9.3 permits. It is neither H_V1 nor H_FIELDS_V1, and the
// check is written against an independently computed SHA-256 rather than
// against the pipeline's own helper.
func TestAggregateProofHashIsAPlainSHA256OfTheProofBytes(t *testing.T) {
	material, err := Build(fixtureBinding(), fixtureSamples())
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if len(material.AggregateProof.Bytes) == 0 {
		t.Fatalf("aggregate proof carries no bytes")
	}
	if got := material.AggregateProof.Hash.String(); got != fixtureAggregateProofHashHex {
		t.Fatalf("aggregate_proof_hash = %s, want the pinned vector %s", got, fixtureAggregateProofHashHex)
	}
	want := sha256.Sum256(material.AggregateProof.Bytes)
	if material.AggregateProof.Hash != codec.Hash(want) {
		t.Fatalf("aggregate_proof_hash = %s, want plain SHA256(proof) = %s",
			material.AggregateProof.Hash, hex.EncodeToString(want[:]))
	}
	// The two hash schemes it must not be.
	if material.AggregateProof.Hash == codec.HashV1(AggregateProofVersionV1, material.AggregateProof.Bytes) {
		t.Fatalf("aggregate_proof_hash was derived with H_V1")
	}
	if material.AggregateProof.Hash == codec.HashWithDomain(AggregateProofVersionV1, material.AggregateProof.Bytes) {
		t.Fatalf("aggregate_proof_hash was derived with H_FIELDS_V1")
	}
}

func TestAggregateProofIsDeterministicAndCommitsToRootAndSummary(t *testing.T) {
	base, err := Build(fixtureBinding(), fixtureSamples())
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	again, err := Build(fixtureBinding(), fixtureSamples())
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if base.AggregateProof.Hash != again.AggregateProof.Hash {
		t.Fatalf("aggregate_proof_hash is not reproducible")
	}

	// A sample whose comparison changed moves the summary without changing the
	// number of leaves, so this isolates the summary commitment from the root
	// and count commitments below.
	movedSummary := fixtureSamples()
	movedSummary[0].Finite = false
	changed, err := Build(fixtureBinding(), movedSummary)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if changed.AggregateProof.Hash == base.AggregateProof.Hash {
		t.Fatalf("a different summary produced the same aggregate_proof_hash")
	}

	movedRoot := append(fixtureSamples(), sampleAt(2))
	changed, err = Build(fixtureBinding(), movedRoot)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if changed.AggregateProof.Hash == base.AggregateProof.Hash {
		t.Fatalf("a different metric_root produced the same aggregate_proof_hash")
	}
}

// keeper §9.7: BATCH_SAMPLES is rejected with ERR_BATCH_VERIFICATION_UNSUPPORTED and
// a verifier "must not choose batch aggregation semantics on its own". The refusal
// has to happen at binding time - before any model work is hashed - and must be
// classified as an unsupported profile so the caller stops instead of retrying to
// the deadline.
func TestBatchSamplesProfileIsRefused(t *testing.T) {
	profile := fixtureProfileSnapshot()
	profile.VerificationProfile.VerificationMode = "VERIFICATION_MODE_BATCH_SAMPLES"

	_, err := BindTask("chain-A", fill(0x11), fill(0x33), 1, profile, fill(0x22))
	if err == nil {
		t.Fatalf("a BATCH_SAMPLES profile was accepted")
	}
	if !errors.Is(err, ErrProfileUnsupported) {
		t.Fatalf("error is not ErrProfileUnsupported, so a caller would retry it: %v", err)
	}
	if !strings.Contains(err.Error(), "BATCH_SAMPLES") {
		t.Fatalf("error does not name the mode it refused: %v", err)
	}
}

func TestUnsupportedScaleAndProofVersionAreRefused(t *testing.T) {
	for name, mutate := range map[string]func(*chainclient.CurrentProfileSnapshot){
		"numeric_scale": func(p *chainclient.CurrentProfileSnapshot) {
			p.VerificationProfile.Metrics.NumericScale = "NUMERIC_SCALE_FP_1E9"
		},
		"metric_aggregate_proof_version": func(p *chainclient.CurrentProfileSnapshot) {
			p.VerificationProfile.MetricAggregateProofVersion = "PREFILL_METRIC_AGGREGATE_PROOF_V2"
		},
	} {
		t.Run(name, func(t *testing.T) {
			profile := fixtureProfileSnapshot()
			mutate(&profile)
			_, err := BindTask("chain-A", fill(0x11), fill(0x33), 1, profile, fill(0x22))
			if !errors.Is(err, ErrProfileUnsupported) {
				t.Fatalf("error is not ErrProfileUnsupported: %v", err)
			}
		})
	}
}

func TestBindTaskAcceptsBothTheBareAndPrefixedEnumSpelling(t *testing.T) {
	profile := fixtureProfileSnapshot()
	profile.VerificationProfile.VerificationMode = "SINGLE_SAMPLE"
	profile.VerificationProfile.Metrics.NumericScale = "FP_1E6"

	if _, err := BindTask("chain-A", fill(0x11), fill(0x33), 1, profile, fill(0x22)); err != nil {
		t.Fatalf("bare enum spelling was refused: %v", err)
	}
}

func TestBindTaskRefusesAnUnsetConsensusField(t *testing.T) {
	for name, mutate := range map[string]func(*chainclient.CurrentProfileSnapshot){
		"tokenizer_hash":       func(p *chainclient.CurrentProfileSnapshot) { p.TokenizerHash = nil },
		"evidence_schema_hash": func(p *chainclient.CurrentProfileSnapshot) { p.VerificationProfile.EvidenceSchemaHash = nil },
		"judgment_function_version": func(p *chainclient.CurrentProfileSnapshot) {
			p.VerificationProfile.JudgmentFunctionVersion = ""
		},
		"canonical_encoding_version": func(p *chainclient.CurrentProfileSnapshot) {
			p.VerificationProfile.CanonicalEncodingVersion = ""
		},
		"required_top_k": func(p *chainclient.CurrentProfileSnapshot) { p.RequiredTopK = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			profile := fixtureProfileSnapshot()
			mutate(&profile)
			if _, err := BindTask("chain-A", fill(0x11), fill(0x33), 1, profile, fill(0x22)); err == nil {
				t.Fatalf("an unset %s was accepted into every leaf preimage", name)
			}
		})
	}
	if _, err := BindTask("chain-A", fill(0x11), fill(0x33), 1, fixtureProfileSnapshot(), codec.Hash{}); err == nil {
		t.Fatalf("an unset generation_params_digest was accepted")
	}
}

// The uint32 fp_1e6 fields top out at 4294.967295 and the protocol defines no
// truncation. Truncating would be a signable claim that the sample agreed far
// better than it did, so the summary is refused instead.
func TestSummaryOverflowIsRefusedNotTruncated(t *testing.T) {
	aggregates := fixtureAggregates()
	aggregates.MeanAbsLogprobDiff = 5000 // 5e9 in fp_1e6, past MaxUint32

	_, err := Summary(Spec{ComparedTopK: 4}, aggregates)
	if err == nil {
		t.Fatalf("an overflowing mean_abs_logprob_diff was silently narrowed")
	}
	if !strings.Contains(err.Error(), "ceiling") {
		t.Fatalf("error does not explain the refusal: %v", err)
	}
}

func TestNonFiniteMetricsAreRefused(t *testing.T) {
	aggregates := fixtureAggregates()
	aggregates.AbsLogprobDiffP99 = math.NaN()
	if _, err := Summary(Spec{ComparedTopK: 4}, aggregates); err == nil {
		t.Fatalf("NaN reached the summary")
	}

	samples := fixtureSamples()
	samples[0].VerifierLogprob = math.Inf(-1)
	if _, err := Build(fixtureBinding(), samples); err == nil {
		t.Fatalf("an infinite logprob reached a leaf")
	}
}

// The rounding mode is undocumented upstream, so it is pinned here: a verifier
// that truncated instead of rounding half-away-from-zero would produce a
// different leaf for the same model output.
func TestFixedPointRoundsHalfAwayFromZero(t *testing.T) {
	for _, tc := range []struct {
		value float64
		want  int64
	}{
		{value: -1.0000005, want: -1000001},
		{value: 1.0000005, want: 1000001},
		{value: -1.0000004, want: -1000000},
		{value: 1.0000004, want: 1000000},
	} {
		got, err := signedFP1e6("value", tc.value)
		if err != nil {
			t.Fatalf("signedFP1e6(%v) returned error: %v", tc.value, err)
		}
		if got != tc.want {
			t.Fatalf("signedFP1e6(%v) = %d, want %d", tc.value, got, tc.want)
		}
	}
}

func fixtureBinding() Binding {
	binding, err := BindTask("chain-A", fill(0x11), fill(0x33), 1, fixtureProfileSnapshot(), fill(0x22))
	if err != nil {
		panic(err)
	}
	return binding
}

func fixtureProfileSnapshot() chainclient.CurrentProfileSnapshot {
	evidenceSchemaHash := fill(0x33)
	tokenizerHash := fill(0x44)
	return chainclient.CurrentProfileSnapshot{
		ModelID:        "099066ebc1498400466fabe744606f360622d8eb24447a109b7a22f89cf4403f",
		ProfileVersion: chainclient.ProfileVersion("1"),
		TokenizerHash:  chainclient.ProtoBytes32(tokenizerHash[:]),
		RequiredTopK:   4,
		VerificationProfile: chainclient.CurrentVerificationProfileSnapshot{
			VerificationProfileID:       1,
			JudgmentFunctionVersion:     "PREFILL_GENERATED_TOKEN_METRICS_V1",
			VerificationMode:            "VERIFICATION_MODE_SINGLE_SAMPLE",
			TokenScope:                  "TOKEN_SCOPE_ALL_GENERATED_OUTPUT_TOKENS",
			CanonicalEncodingVersion:    "CANONICAL_ENCODING_V1",
			EvidenceSchemaHash:          chainclient.ProtoBytes32(evidenceSchemaHash[:]),
			MetricAggregateProofVersion: AggregateProofVersionV1,
			Metrics: chainclient.CurrentMetricSpecSnapshot{
				CompareLogprobDiff: true, CompareRankDelta: true,
				CompareTopKJaccard: true, CompareUnionJS: true,
				ComparedTopK: 4, NumericScale: "NUMERIC_SCALE_FP_1E6",
			},
		},
	}
}

func fixtureSamples() []Sample {
	return []Sample{sampleAt(0), sampleAt(1)}
}

func sampleAt(position uint32) Sample {
	return Sample{
		OutputPosition:  position,
		EmittedTokenID:  1000 + position,
		WorkerLogprob:   -0.125 - float64(position)/8,
		VerifierLogprob: -0.130 - float64(position)/8,
		WorkerRank:      1,
		VerifierRank:    1,
		TopKJaccard:     PresentFP(0.875),
		UnionJS:         PresentFP(0.002),
		Missing:         false,
		Finite:          true,
	}
}

func fixtureAggregates() Aggregates {
	return Aggregates{
		FiniteCount:          2,
		MissingComparedCount: 0,
		MeanAbsLogprobDiff:   0.005,
		AbsLogprobDiffP95:    0.005,
		AbsLogprobDiffP99:    0.005,
		RankDeltaNonzeroRate: 0,
		TopKJaccardMean:      PresentFP(0.875),
		UnionJSP99:           PresentFP(0.002),
		ComparedTopKCount:    2,
		ComparedRankCount:    2,
	}
}

func fill(b byte) codec.Hash {
	var out codec.Hash
	for i := range out {
		out[i] = b
	}
	return out
}
