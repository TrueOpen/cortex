package txclient

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoregistry"

	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// The remote signer resolves each Msg by type URL and decodes the payload as
// ProtoJSON of that type (signer.CosmosMessage). A kind it cannot resolve, or
// a payload that does not decode strictly into the generated message, fails at
// signing time on a live node, so both are locked here for every Msg S6–S8
// added (S7 Q16).
func TestPhaseOneMsgKindsResolveForTheRemoteSigner(t *testing.T) {
	if len(PhaseOneMsgKinds) != 4 {
		t.Fatalf("PhaseOneMsgKinds = %v, want the four Phase 1 Msgs", PhaseOneMsgKinds)
	}
	for _, k := range PhaseOneMsgKinds {
		if !k.Valid() {
			t.Fatalf("%s is not a valid tx kind", k)
		}
		mt, err := protoregistry.GlobalTypes.FindMessageByURL(string(k))
		if err != nil || "/"+string(mt.Descriptor().FullName()) != string(k) {
			t.Fatalf("%s does not resolve to its generated type: %v", k, err)
		}
	}
	_ = &taskv1.MsgClaimDispatchCompensation{}
	// MsgReportDataUnavailable is the one hand-mirrored payload among them.
	payload, err := MarshalMessage(MsgReportDataUnavailable, ReportDataUnavailableMessage{
		TaskID: ProtoBytes32(strings.Repeat("11", 32)), VerifyRound: 1, UnavailableTaskBuilderBitmap: ProtoBytes("01"),
		SubmitterAddress: "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz",
		EvidenceKind:     EvidenceKindWorkerValueOpening, Reason: DataUnavailableReasonBuilderUnavailable,
	})
	if err != nil {
		t.Fatal(err)
	}
	var m taskv1.MsgReportDataUnavailable
	if err := (protojson.UnmarshalOptions{}).Unmarshal(payload, &m); err != nil {
		t.Fatalf("payload is not strict ProtoJSON of the generated Msg: %v\n%s", err, payload)
	}
	if m.GetVerifyRound() != 1 || len(m.GetTaskId()) != 32 || len(m.GetUnavailableTaskBuilderBitmap()) != 1 {
		t.Fatalf("decoded = %v", &m)
	}
}
