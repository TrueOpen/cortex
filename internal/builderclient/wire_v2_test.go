package builderclient

import (
	"bytes"
	"testing"

	"github.com/TrueOpen/cortex/internal/nodewire"
)

func TestResultReceiptProtoOptionalPresence(t *testing.T) {
	receipt := nodewire.ResultReceiptV3{
		SchemaVersion: nodewire.ResultReceiptSchemaVersionV3, ChainID: "chain-1", TaskID: bytes.Repeat([]byte{0xab}, 32),
		VerifyRound: 1, VerifierOperatorAddress: "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe",
		ServiceAuthorizationNonce:         2,
		GenerationParamsDigest:            bytes.Repeat([]byte{0x01}, 32),
		MetricRoot:                        bytes.Repeat([]byte{0x02}, 32),
		MetricSummary:                     nodewire.MetricSummaryV1{FiniteCount: 7},
		AggregateProofHash:                bytes.Repeat([]byte{0x03}, 32),
		VerifierEvidenceBundleHash:        bytes.Repeat([]byte{0x04}, 32),
		VerifierEvidenceManifestSizeBytes: 123,
		Salt:                              bytes.Repeat([]byte{0x06}, 32),
		ExpiryHeight:                      9,
		VerifierValueRoot:                 bytes.Repeat([]byte{0x07}, 32),
		MetricLeafCount:                   7,
		VerifierEvidenceKeyCommitment:     make([]byte, 32),
		ServiceSignature:                  bytes.Repeat([]byte{0x05}, 64),
	}
	message, err := ResultReceiptProto(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if message.GetMetricSummary().TopkJaccardMeanFp_1E6 != nil || message.GetMetricSummary().UnionJsP99Fp_1E6 != nil {
		t.Fatal("absent optional metrics must stay absent on the wire")
	}
	receipt.MetricSummary.TopkJaccardMeanFP1e6 = nodewire.PresentUint32(0)
	message, err = ResultReceiptProto(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if message.GetMetricSummary().TopkJaccardMeanFp_1E6 == nil || *message.GetMetricSummary().TopkJaccardMeanFp_1E6 != 0 {
		t.Fatal("a present zero optional metric must travel as present zero")
	}
}
