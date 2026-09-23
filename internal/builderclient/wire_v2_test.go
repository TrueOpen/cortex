package builderclient

import (
	"bytes"
	"testing"

	"github.com/TrueOpen/cortex/internal/nodewire"
)

// TestHandraiseProtoRoundTrip pins the nodewire <-> proto bridge: the digest
// recomputed from the wire message equals the digest of the source struct, so
// what travels is exactly what was signed.
func TestHandraiseProtoRoundTrip(t *testing.T) {
	handraise := nodewire.WorkerHandraiseV1{
		SchemaVersion: 1, ChainID: "chain-1",
		TaskID: bytes.Repeat([]byte{0xab}, 32), TaskHash: bytes.Repeat([]byte{0xcd}, 32),
		ModelID: "model-a", ProfileVersion: 2,
		Member: nodewire.CandidateMemberRefV1{
			CandidatePoolSnapshotID: bytes.Repeat([]byte{0x11}, 32),
			Slot:                    3, SlotVersion: 4, OperatorAddress: "trueopen1j7r6u8nwvw93l2tc0wd75v07vu89lxyfqf8fut",
		},
		Duty: nodewire.DutyWorker, ServiceAuthorizationNonce: 5, ExpiryHeight: 6,
		ServiceSignature: bytes.Repeat([]byte{0x22}, 64),
	}
	want, err := nodewire.WorkerHandraiseSigningDigest(handraise)
	if err != nil {
		t.Fatal(err)
	}
	message, err := WorkerHandraiseProto(handraise)
	if err != nil {
		t.Fatal(err)
	}
	back, err := WorkerHandraiseFromProto(message)
	if err != nil {
		t.Fatal(err)
	}
	got, err := nodewire.WorkerHandraiseSigningDigest(back)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("worker handraise digest did not survive the proto round trip")
	}
	if !bytes.Equal(back.ServiceSignature, handraise.ServiceSignature) {
		t.Fatal("service signature did not survive the proto round trip")
	}
}

func TestResultReceiptProtoOptionalPresence(t *testing.T) {
	receipt := nodewire.ResultReceiptV2{
		SchemaVersion: 2, ChainID: "chain-1", TaskID: bytes.Repeat([]byte{0xab}, 32),
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
