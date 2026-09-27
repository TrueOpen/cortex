package metric

import (
	"encoding/hex"
	"testing"

	"github.com/TrueOpen/cortex/internal/nodewire"
)

// wireMainAggregateProofHex is metric_aggregate_proof_v1 from
// testdata/v1/task/result_metric_v3.json at wire commit
// 3dec7cdb7595d8206cb430d4b10eeb28fccf8a4e (main, to be released as
// v0.3.0-rc.3). The pinned rc.2 set has no such vector, so the bytes are
// inlined here rather than copied into internal/wirevectors.
const wireMainAggregateProofHex = "000000000000002150524546494c4c5f4d45545249435f4147475245474154455f50524f4f465f56310000000000000011747275656f70656e2d676f6c64656e2d31000000000000002011111111111111111111111111111111111111111111111111111111111111110000000000000020c65241d19b257f935ddea99ea59a19175b4b29751e259853d403fe59f04f4e4f000000000000000400000002000000000000002250524546494c4c5f47454e4552415445445f544f4b454e5f4d4554524943535f5631000000000000001843414e4f4e4943414c5f4f55545055545f544558545f563100000000000000206666666666666666666666666666666666666666666666666666666666666666000000000000002044444444444444444444444444444444444444444444444444444444444444440000000000000020b9cc1d8c612df0db96bd365b24e2aa9db3f418775452b2106156922f8816a3140000000000000004000000020000000000000001010000000000000001010000000000000001000000000000000001000000000000000004000000020000000000000020c261e32222bab88b3ea110c865bb97a483d15968cbfe42317fc7c118e1568a9300000000000000040000000300000000000000209790987ab9c449018d2732afa71414d25fe268022f7566b6dac28dc80cbfd037"

const wireMainAggregateProofDigestHex = "fae247a0c474d717b1664551d73164995218c74f5a6e1490b38b290fbab6bb4c"

// The aggregate proof frames model_id as its raw 32 bytes and reproduces
// wire's published proof byte for byte.
func TestAggregateProofReproducesTheWireRawModelIDVector(t *testing.T) {
	binding := Binding{
		ChainID: "trueopen-golden-1", TaskID: fill(0x11), VerifyRound: 1,
		ModelID: "c65241d19b257f935ddea99ea59a19175b4b29751e259853d403fe59f04f4e4f", ProfileVersion: 2,
		JudgmentFunctionVersion: "PREFILL_GENERATED_TOKEN_METRICS_V1", CanonicalEncodingVersion: "CANONICAL_OUTPUT_TEXT_V1",
		EvidenceSchemaHash: fill(0x66), MetricAggregateProofVersion: AggregateProofVersionV1, TokenizerHash: fill(0x44),
		RequiredTopK: 2, Spec: Spec{CompareLogprobDiff: true, CompareRankDelta: true, ComparedTopK: 2},
	}
	digest, _ := hex.DecodeString("b9cc1d8c612df0db96bd365b24e2aa9db3f418775452b2106156922f8816a314")
	copy(binding.GenerationParamsDigest[:], digest)
	binding.TaskHash = fill(0x22)
	root, _ := hex.DecodeString("c261e32222bab88b3ea110c865bb97a483d15968cbfe42317fc7c118e1568a93")
	summary := nodewire.MetricSummaryV1{
		FiniteCount: 2, MissingComparedCount: 1,
		MeanAbsLogprobDiffFP1e6: 50000, AbsLogprobDiffP95FP1e6: 50000, AbsLogprobDiffP99FP1e6: 50000,
		ComparedRankCount: 2,
	}
	summaryHash, err := nodewire.MetricSummaryHash(summary)
	if err != nil || summaryHash.String() != "9790987ab9c449018d2732afa71414d25fe268022f7566b6dac28dc80cbfd037" {
		t.Fatalf("metric_summary_hash = %s, %v", summaryHash, err)
	}
	var metricRoot [32]byte
	copy(metricRoot[:], root)
	proof, err := BuildAggregateProof(binding, metricRoot, 3, summary)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(proof.Bytes) != wireMainAggregateProofHex || proof.Hash.String() != wireMainAggregateProofDigestHex {
		t.Fatalf("aggregate proof = %x (%s), want wire's raw model_id encoding", proof.Bytes, proof.Hash)
	}
}
