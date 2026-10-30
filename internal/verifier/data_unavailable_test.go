package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/txclient"
	"github.com/TrueOpen/cortex/internal/txclient/txclienttest"
	"github.com/TrueOpen/cortex/internal/wirevectors"
)

// wireBitmapVector reads wire testdata/v1/task/task_keeper_domains_v1.json
// data_unavailable_bitmap_v1: the Task Builder count and the bitmap bytes.
func wireBitmapVector(t *testing.T) (int, string) {
	t.Helper()
	raw, err := wirevectors.File("task/task_keeper_domains_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			Name   string `json:"name"`
			Fields []struct {
				Name  string          `json:"name"`
				Hex   string          `json:"hex"`
				Value json.RawMessage `json:"value"`
			} `json:"fields"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	for _, v := range file.Vectors {
		if v.Name != "data_unavailable_bitmap_v1" {
			continue
		}
		count, bitmap := 0, ""
		for _, f := range v.Fields {
			switch f.Name {
			case "task_builder_count":
				if err := json.Unmarshal(f.Value, &count); err != nil {
					t.Fatal(err)
				}
			case "unavailable_task_builder_bitmap":
				bitmap = f.Hex
			}
		}
		return count, bitmap
	}
	t.Fatal("wire data_unavailable_bitmap_v1 vector is missing")
	return 0, ""
}

// S7 Q10: LSB-first within each byte, bit i in byte i/8, length ceil(n/8),
// pinned by the wire vector (12 Task Builders, bitmap 0a05 = Builders 1, 3,
// 8 and 10).
func TestUnavailableBuilderBitmapMatchesTheWireVector(t *testing.T) {
	count, want := wireBitmapVector(t)
	if count != 12 || want != "0a05" {
		t.Fatalf("wire vector = %d builders, bitmap %s; the fixture moved", count, want)
	}
	selected := make([]string, count)
	for i := range selected {
		selected[i] = fmt.Sprintf("b%02d", i)
	}
	got, err := UnavailableBuilderBitmap(selected, map[string]bool{"b01": true, "b03": true, "b08": true, "b10": true, "b05": false})
	if err != nil || fmt.Sprintf("%x", got) != want {
		t.Fatalf("bitmap = %x, %v; want %s", got, err, want)
	}
	if got, _ := UnavailableBuilderBitmap(selected, map[string]bool{"b01": true}); fmt.Sprintf("%x", got) != "0200" {
		t.Fatalf("bitmap = %x, want the fixed ceil(12/8) length 0200", got)
	}
	for name, tc := range map[string]struct {
		selected []string
		down     map[string]bool
	}{
		"empty selection": {nil, map[string]bool{"b00": true}},
		"duplicate":       {[]string{"b00", "b00"}, map[string]bool{"b00": true}},
		"outsider":        {selected, map[string]bool{"x": true}},
		"nothing marked":  {selected, map[string]bool{}},
	} {
		if _, err := UnavailableBuilderBitmap(tc.selected, tc.down); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestReportDataUnavailableSubmitsTheTypedReport(t *testing.T) {
	tx := txclienttest.NewFake()
	m := NewSettlementManager(SettlementConfig{Tx: tx, VerifierAddress: fixtureVerifierAddress, SubmitterAddress: "service-1", GasPayer: "service-1",
		FeeCap: txclient.Coin{Amount: 25, Denom: "utrueopen"}})
	taskID := strings.Repeat("ab", 32)
	if _, err := m.ReportDataUnavailable(context.Background(), DataUnavailableReport{
		SessionID: "s", TaskID: taskID, VerifyRound: 1, Level: DataLevelB, Invalid: true, Bitmap: []byte{0x05}, DeadlineHeight: 300,
	}); err != nil {
		t.Fatal(err)
	}
	requests := tx.Requests()
	if len(requests) != 1 || requests[0].Kind != txclient.MsgReportDataUnavailable || requests[0].DeadlineHeight != 300 {
		t.Fatalf("requests = %#v", requests)
	}
	var sent txclient.ReportDataUnavailableMessage
	if err := json.Unmarshal(requests[0].Payload, &sent); err != nil {
		t.Fatal(err)
	}
	if sent.EvidenceKind != txclient.EvidenceKindWorkerValueOpening || sent.Reason != txclient.DataUnavailableReasonWorkerEvidenceInvalid ||
		sent.UnavailableTaskBuilderBitmap.Hex() != "05" || sent.SubmitterAddress != "service-1" || sent.TaskID.Hex() != taskID {
		t.Fatalf("sent = %+v", sent)
	}
	tx.RejectNext(txclient.MsgReportDataUnavailable, "duplicate")
	if _, err := m.ReportDataUnavailable(context.Background(), DataUnavailableReport{TaskID: taskID, VerifyRound: 1, Level: DataLevelA, Bitmap: []byte{1}, DeadlineHeight: 300}); err == nil {
		t.Fatal("a rejected report was reported as landed")
	}
	if _, err := m.ReportDataUnavailable(context.Background(), DataUnavailableReport{TaskID: taskID, VerifyRound: 1, Level: DataLevelA, Bitmap: []byte{1}}); err == nil {
		t.Fatal("a report without its window's deadline was submitted")
	}
}
