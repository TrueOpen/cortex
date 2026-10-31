package txclient

import (
	"strings"
	"testing"
)

func validReport() ReportDataUnavailableMessage {
	return ReportDataUnavailableMessage{
		TaskID: ProtoBytes32(strings.Repeat("ab", 32)), VerifyRound: 1, UnavailableTaskBuilderBitmap: ProtoBytes("0a05"),
		SubmitterAddress: "trueopen1service", EvidenceKind: EvidenceKindUnspecified, Reason: DataUnavailableReasonBuilderUnavailable,
	}
}

func TestReportDataUnavailableIsARegisteredKind(t *testing.T) {
	if !MsgReportDataUnavailable.Valid() {
		t.Fatal("MsgReportDataUnavailable is not a valid kind")
	}
	payload, err := MarshalMessage(MsgReportDataUnavailable, validReport())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRequest(Request{TaskID: "task-1", Kind: MsgReportDataUnavailable, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"unavailable_task_builder_bitmap":"CgU="`, `"evidence_kind":"EVIDENCE_KIND_UNSPECIFIED"`, `"reason":"DATA_UNAVAILABLE_REASON_V1_BUILDER_UNAVAILABLE"`} {
		if !strings.Contains(string(payload), want) {
			t.Fatalf("payload %s lacks %s", payload, want)
		}
	}
	b := validReport()
	b.EvidenceKind, b.Reason = EvidenceKindWorkerValueOpening, DataUnavailableReasonWorkerEvidenceInvalid
	if _, err := MarshalMessage(MsgReportDataUnavailable, b); err != nil {
		t.Fatalf("a B-level WORKER_EVIDENCE_INVALID report was refused: %v", err)
	}
}

func TestReportDataUnavailableRefusesMalformedReports(t *testing.T) {
	for name, mutate := range map[string]func(*ReportDataUnavailableMessage){
		"round zero":         func(m *ReportDataUnavailableMessage) { m.VerifyRound = 0 },
		"all-zero bitmap":    func(m *ReportDataUnavailableMessage) { m.UnavailableTaskBuilderBitmap = "0000" },
		"unknown kind":       func(m *ReportDataUnavailableMessage) { m.EvidenceKind = "EVIDENCE_KIND_WORKER_TOKEN_OPENING" },
		"unspecified reason": func(m *ReportDataUnavailableMessage) { m.Reason = "DATA_UNAVAILABLE_REASON_V1_UNSPECIFIED" },
		"no submitter":       func(m *ReportDataUnavailableMessage) { m.SubmitterAddress = "" },
		"short task id":      func(m *ReportDataUnavailableMessage) { m.TaskID = "abcd" },
	} {
		t.Run(name, func(t *testing.T) {
			m := validReport()
			mutate(&m)
			if _, err := MarshalMessage(MsgReportDataUnavailable, m); err == nil {
				t.Fatal("malformed report accepted")
			}
		})
	}
}
