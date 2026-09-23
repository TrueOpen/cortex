package metric

// Independent conformance: a second encoder, written from the specification
// text rather than from the production code, driven against the same inputs.
//
// # Why the pinned hex vectors are not enough on their own
//
// metric_test.go pins hex values that were produced by this repository. That
// catches a LATER change to the encoding, which is worth having, but it cannot
// catch the encoding being wrong on the first day - the vector would simply
// record the wrong bytes. Upstream publishes no leaf/root/summary vector to
// check against (the only published vector in this area is MERKLE_ROOT_V1
// §10.4, which internal/codec already drives), so the strongest check available
// is two independent implementations of the same written rules.
//
// The encoder below is deliberately naive and literal. It uses encoding/binary
// directly, spells out every length prefix, and shares NO code with
// internal/hfields or the production leaf/summary encoders. Where it agrees
// with them, the spec text and the production framing agree. Where it does not,
// one of the two misread §1.2 / §3.2 / §4.3 / §4.4 - and that is the failure
// this file exists to produce.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// specFrame implements FRAME_V1 from canonical-encoding-and-domain-hashing §3.2 literally:
//
//	FRAME_V1(v1, ..., vn) = u64_be(len(v1)) || v1 || ... || u64_be(len(vn)) || vn
func specFrame(values ...[]byte) []byte {
	var out bytes.Buffer
	for _, value := range values {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		out.Write(length[:])
		out.Write(value)
	}
	return out.Bytes()
}

// specHFields implements H_FIELDS_V1 from §4.1 literally: the domain is the
// first length-framed value of the same frame, and the digest is SHA-256 of it.
func specHFields(domain string, values ...[]byte) codec.Hash {
	return sha256.Sum256(specFrame(append([][]byte{[]byte(domain)}, values...)...))
}

// §4.3 scalar encodings, written out one per function so a misreading of any
// single row is visible.
func specU32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
func specU64(v uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, v); return b }
func specI64(v int64) []byte  { return specU64(uint64(v)) }
func specI32(v int32) []byte  { return specU32(uint32(v)) }

func specBool(v bool) []byte {
	if v {
		return []byte{1}
	}
	return []byte{0}
}

// §4.4 Optional: absent is a single 0x00; present is 0x01 followed by the value
// in its own frame.
func specOptional(present bool, value []byte) []byte {
	if !present {
		return []byte{0}
	}
	return append([]byte{1}, specFrame(value)...)
}

// TestLeafHashAgreesWithAnIndependentSpecEncoder drives the production leaf
// derivation and a from-the-text one against the same sample.
//
// The leaf formula (05-verification-algorithm §7) is
//
//	leaf_hash = H_FIELDS_V1(leaf_domain, leaf_version, canonical_leaf_bytes)
//
// so the top level has exactly two fields and the leaf's own fields live inside
// canonical_leaf_bytes as a nested frame. Flattening them into the top level is
// the single most plausible way to get this wrong, and it is what this test
// would catch first.
func TestLeafHashAgreesWithAnIndependentSpecEncoder(t *testing.T) {
	binding := fixtureBinding()

	for name, sample := range map[string]Sample{
		"both optionals present": sampleAt(0),
		"optionals absent": func() Sample {
			s := sampleAt(1)
			s.TopKJaccard = OptionalFP{}
			s.UnionJS = OptionalFP{}
			return s
		}(),
		"missing and not finite": func() Sample {
			s := sampleAt(2)
			s.Missing = true
			s.Finite = false
			s.VerifierRank = 0
			return s
		}(),
		"verifier ranks the token lower": func() Sample {
			s := sampleAt(3)
			s.WorkerRank = 1
			s.VerifierRank = 9
			return s
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := LeafHash(binding, sample)
			if err != nil {
				t.Fatalf("LeafHash returned error: %v", err)
			}
			if got != specLeafHash(t, binding, sample) {
				t.Fatalf("production leaf hash %s disagrees with the independent spec encoder.\n"+
					"One of the two misread 05-verification-algorithm §7 or canonical-encoding-and-domain-hashing §1.2/§4.3/§4.4.", got)
			}
		})
	}
}

// specLeafHash independently encodes the released V2 metric field table.
func specLeafHash(t *testing.T, binding Binding, sample Sample) codec.Hash {
	t.Helper()

	// *_fp_1e6 = value * 1_000_000, rounded half away from zero.
	fp := func(v float64) int64 {
		scaled := v * 1_000_000
		if scaled < 0 {
			return int64(scaled - 0.5)
		}
		return int64(scaled + 0.5)
	}
	workerLogprob := fp(sample.WorkerLogprob)
	verifierLogprob := fp(sample.VerifierLogprob)
	absDiff := workerLogprob - verifierLogprob
	if absDiff < 0 {
		absDiff = -absDiff
	}

	optional := func(o OptionalFP) []byte {
		if !o.Present {
			return specOptional(false, nil)
		}
		return specOptional(true, specU32(uint32(fp(o.Value))))
	}

	canonicalLeafBytes := specFrame(
		[]byte(binding.ChainID),
		binding.TaskID[:],
		binding.TaskHash[:],
		specU32(binding.VerifyRound),
		[]byte(binding.ModelID),
		specU32(binding.ProfileVersion),
		[]byte(binding.JudgmentFunctionVersion),
		[]byte(binding.CanonicalEncodingVersion),
		binding.EvidenceSchemaHash[:],
		[]byte(binding.MetricAggregateProofVersion),
		binding.TokenizerHash[:],
		binding.GenerationParamsDigest[:],
		specU32(sample.OutputPosition),
		specU32(sample.EmittedTokenID),
		specU32(binding.RequiredTopK),
		specI64(workerLogprob),
		specI64(verifierLogprob),
		specU64(uint64(absDiff)),
		specU32(sample.WorkerRank),
		specU32(sample.VerifierRank),
		specI64(int64(sample.VerifierRank)-int64(sample.WorkerRank)),
		optional(sample.TopKJaccard),
		optional(sample.UnionJS),
		specBool(sample.Missing),
		specBool(sample.Finite),
	)
	return specHFields(DomainLeafV2, specU32(LeafVersionV1), canonicalLeafBytes)
}

// TestMetricSummaryHashAgreesWithAnIndependentSpecEncoder transcribes the §9.7
// field-number table and checks the production digest against it.
//
// §9.7 says metric_summary_hash length-frames the message field by field and that
// "the field number order is part of the preimage and must match the table below
// byte for byte", so the ten members are written out here in that exact order, by
// hand.
func TestMetricSummaryHashAgreesWithAnIndependentSpecEncoder(t *testing.T) {
	for name, spec := range map[string]Spec{
		"both optionals required": {CompareTopKJaccard: true, CompareUnionJS: true, ComparedTopK: 4},
		"neither required":        {ComparedTopK: 4},
		"only jaccard required":   {CompareTopKJaccard: true, ComparedTopK: 4},
	} {
		t.Run(name, func(t *testing.T) {
			summary, err := Summary(spec, fixtureAggregates())
			if err != nil {
				t.Fatalf("Summary returned error: %v", err)
			}
			got, err := nodewire.MetricSummaryHash(summary)
			if err != nil {
				t.Fatalf("MetricSummaryHash returned error: %v", err)
			}

			// The whole message is ONE nested field of the domain frame, not ten
			// top-level fields.
			canonicalSummary := specFrame(
				specU32(summary.FiniteCount),
				specU32(summary.MissingComparedCount),
				specU32(summary.MeanAbsLogprobDiffFP1e6),
				specU32(summary.AbsLogprobDiffP95FP1e6),
				specU32(summary.AbsLogprobDiffP99FP1e6),
				specU32(summary.RankDeltaNonzeroRateFP1e6),
				specOptional(summary.TopkJaccardMeanFP1e6.Present, specU32(summary.TopkJaccardMeanFP1e6.Value)),
				specOptional(summary.UnionJSP99FP1e6.Present, specU32(summary.UnionJSP99FP1e6.Value)),
				specU32(summary.ComparedTopkCount),
				specU32(summary.ComparedRankCount),
			)
			want := specHFields(nodewire.DomainMetricSummaryV1, canonicalSummary)
			if got != want {
				t.Fatalf("production metric_summary_hash %s disagrees with the independent §9.7 encoder %s", got, want)
			}
		})
	}
}

// TestResultCommitmentHashAgreesWithAnIndependentSpecEncoder covers all seven
// V2 commitment fields using an independent framing implementation.
func TestResultCommitmentHashAgreesWithAnIndependentSpecEncoder(t *testing.T) {
	const verifier = "trueopen1c5mpzp95cwm4syklatc07u2p2knan53rl38lmx"
	taskID := fill(0x11)
	revealHash := fill(0x22)
	proofHash := fill(0x33)

	got, err := nodewire.ResultCommitmentHash(nodewire.ResultCommitmentV2{
		ChainID:                 "chain-A",
		TaskID:                  taskID[:],
		TaskHash:                proofHash[:],
		VerifyRound:             1,
		VerifierOperatorAddress: verifier,
		ResultPayloadHash:       revealHash[:],
		Salt:                    proofHash[:],
	})
	if err != nil {
		t.Fatalf("ResultCommitmentHash returned error: %v", err)
	}

	verifierBytes, err := nodewire.CanonicalOperatorAddressBytes("verifier_operator_address", verifier)
	if err != nil {
		t.Fatalf("CanonicalOperatorAddressBytes returned error: %v", err)
	}
	want := specHFields(
		nodewire.DomainResultCommitmentV2,
		[]byte("chain-A"),
		taskID[:],
		proofHash[:],
		specU32(1),
		verifierBytes,
		revealHash[:],
		proofHash[:],
	)
	if got != want {
		t.Fatalf("production commit_hash %s disagrees with the independent §5.14 encoder %s", got, want)
	}
}

// TestAggregateProofAgreesWithItsDocumentedEncoding transcribes the byte layout
// written in BuildAggregateProof's own comment.
//
// This one is weaker than the three above and says so: the layout is Cortex's,
// not the protocol's, so agreement here only proves the code matches its
// documentation. It is still worth having - a blob whose comment and bytes
// disagree is the worst possible starting point for the protocol conversation
// this encoding still needs.
func TestAggregateProofAgreesWithItsDocumentedEncoding(t *testing.T) {
	binding := fixtureBinding()
	material, err := Build(binding, fixtureSamples())
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	summaryHash, err := nodewire.MetricSummaryHash(material.Summary)
	if err != nil {
		t.Fatalf("MetricSummaryHash returned error: %v", err)
	}
	want := specFrame(
		[]byte(AggregateProofVersionV1),
		[]byte(binding.ChainID),
		binding.TaskID[:],
		[]byte(binding.ModelID),
		specU32(binding.ProfileVersion),
		[]byte(binding.JudgmentFunctionVersion),
		[]byte(binding.CanonicalEncodingVersion),
		binding.EvidenceSchemaHash[:],
		binding.TokenizerHash[:],
		binding.GenerationParamsDigest[:],
		specU32(binding.RequiredTopK),
		specBool(binding.Spec.CompareLogprobDiff),
		specBool(binding.Spec.CompareRankDelta),
		specBool(binding.Spec.CompareTopKJaccard),
		specBool(binding.Spec.CompareUnionJS),
		specU32(binding.Spec.ComparedTopK),
		material.Root[:],
		specU32(uint32(material.LeafCount)),
		summaryHash[:],
	)
	if !bytes.Equal(material.AggregateProof.Bytes, want) {
		t.Fatalf("aggregate proof bytes disagree with the layout documented in BuildAggregateProof")
	}
	// And it carries no domain: a domain-framed blob would begin with the
	// length of a TRUEOPEN_* string, which §4.2 governs and which nothing has
	// registered for this value.
	if bytes.HasPrefix(material.AggregateProof.Bytes, []byte("TRUEOPEN_")) {
		t.Fatalf("aggregate proof bytes begin with a domain")
	}
}
