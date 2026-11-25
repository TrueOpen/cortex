package chainclient

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func vfVarint(b []byte, num protowire.Number, v uint64) []byte {
	return protowire.AppendVarint(protowire.AppendTag(b, num, protowire.VarintType), v)
}

func vfBytes(b []byte, num protowire.Number, v []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(b, num, protowire.BytesType), v)
}

func TestDecodeWorkerQuota(t *testing.T) {
	var raw []byte
	for num, v := range map[protowire.Number]uint64{1: 7, 2: 1000, 3: 300, 4: 200, 5: 500, 6: 1, 7: 1, 8: 5} {
		raw = vfVarint(raw, num, v)
	}
	raw = vfBytes(raw, 99, []byte("a later field")) // unknown fields are skipped
	got, err := decodeWorkerQuota(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := WorkerQuotaSnapshot{Period: 7, Quota: 1000, ReservedValue: 300, SettledValue: 200, Remaining: 500,
		Enforced: true, DispatchPaused: true, PauseReasons: 5}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if empty, err := decodeWorkerQuota(nil); err != nil || empty != (WorkerQuotaSnapshot{}) {
		t.Fatalf("an empty response must be the zero snapshot, got %+v, %v", empty, err)
	}
	if _, err := decodeWorkerQuota([]byte{0x08}); err == nil {
		t.Fatal("a truncated response must fail")
	}
}

func TestPauseReasonNames(t *testing.T) {
	if got := PauseReasonNames(0); got != nil {
		t.Fatalf("no bits: %v", got)
	}
	if got, want := PauseReasonNames(1|4|8), []string{"late_submission", "jailed", "unknown(8)"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestDecodePanelAssignments(t *testing.T) {
	task := make([]byte, 32)
	task[0] = 0xab
	model := make([]byte, 32)
	model[31] = 0x01
	reg := make([]byte, 32)
	reg[1] = 0x02
	var row []byte
	row = vfBytes(row, 1, task)
	row = vfVarint(row, 2, 3)
	row = vfVarint(row, 3, 2)
	row = vfVarint(row, 4, 100)
	row = vfVarint(row, 5, 160)
	row = vfBytes(row, 6, []byte{0x0a, 0x01, 0x01})
	row = vfBytes(row, 7, model)
	row = vfVarint(row, 8, 4)
	row = vfBytes(row, 9, reg)
	var raw []byte
	raw = vfBytes(raw, 1, row)
	raw = vfBytes(raw, 2, task)
	rows, next, err := decodePanelAssignments(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || fmt.Sprintf("%x", next) != fmt.Sprintf("%x", task) {
		t.Fatalf("rows %d next %x", len(rows), next)
	}
	a := rows[0]
	if a.TaskID != fmt.Sprintf("%x", task) || a.PanelRound != 3 || a.Kind != 2 || a.AssignmentHeight != 100 ||
		a.VoteDeadlineHeight != 160 || a.ModelID != fmt.Sprintf("%x", model) || a.ProfileVersion != 4 ||
		a.RegistrationHash != fmt.Sprintf("%x", reg) || len(a.Audit) != 3 {
		t.Fatalf("decoded %+v", a)
	}
	// A row without a round number is refused, not voted on.
	if _, _, err := decodePanelAssignments(vfBytes(nil, 1, vfBytes(nil, 1, task))); err == nil {
		t.Fatal("a row without a round must fail")
	}
}

func TestUnsupportedQuery(t *testing.T) {
	for _, text := range []string{
		"Keeper /hub.v1.Query/WorkerQuota ABCI query failed (codespace \"sdk\" code 6): unknown query path",
		"rpc error: code = Unimplemented desc = method not implemented",
	} {
		if !unsupportedQuery(errors.New(text)) {
			t.Fatalf("%q must read as unsupported", text)
		}
	}
	if unsupportedQuery(errors.New("connection refused")) {
		t.Fatal("a transport failure is not an unsupported query")
	}
}
