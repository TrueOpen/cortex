package txclient

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/wirevectors"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

func vectorInto[T proto.Message](t *testing.T, name string, msg T) T {
	t.Helper()
	row, err := wirevectors.DispatchVectorByName(name)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := hex.DecodeString(row.ProtobufHex)
	if err := proto.Unmarshal(raw, msg); err != nil {
		t.Fatal(err)
	}
	return msg
}

func validClaim(t *testing.T) *taskv1.MsgClaimDispatchCompensation {
	ticket := vectorInto(t, "task_v1_dispatchticketv1", &taskv1.DispatchTicketV1{})
	accept := vectorInto(t, "task_v1_dispatchacceptv1", &taskv1.DispatchAcceptV1{})
	th, err := dispatchwire.Digest(ticket)
	if err != nil {
		t.Fatal(err)
	}
	accept.DispatchTicketHash, accept.TaskId, accept.TaskHash = th[:], bytes.Clone(ticket.TaskId), bytes.Clone(ticket.TaskHash)
	accept.Member = proto.Clone(ticket.Target).(*taskv1.CandidateMemberRefV1)
	return &taskv1.MsgClaimDispatchCompensation{Order: &taskv1.SignedOrderV2{Order: &taskv1.TaskOrderV3{SchemaVersion: 3, ChainId: ticket.ChainId}},
		Ticket: ticket, Accept: accept, SubmitterAddress: "trueopen1service"}
}

func TestClaimDispatchCompensationPayload(t *testing.T) {
	if !MsgClaimDispatchCompensation.Valid() {
		t.Fatal("not a valid kind")
	}
	m := validClaim(t)
	payload, err := MarshalDispatchMessage(MsgClaimDispatchCompensation, m)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRequest(Request{TaskID: "t", Kind: MsgClaimDispatchCompensation, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	again, _ := MarshalDispatchMessage(MsgClaimDispatchCompensation, m)
	if !bytes.Equal(payload, again) || !strings.Contains(string(payload), `"submitter_address":"trueopen1service"`) {
		t.Fatalf("payload %s: one message, one compact proto-named payload", payload)
	}
	var back taskv1.MsgClaimDispatchCompensation
	if err := protojson.Unmarshal(payload, &back); err != nil || !proto.Equal(&back, m) {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := MarshalMessage(MsgClaimDispatchCompensation, m); err == nil {
		t.Fatal("the struct path refuses dispatch kinds")
	}
}

func TestClaimDispatchCompensationRefusesMismatchedParts(t *testing.T) {
	for name, mutate := range map[string]func(*taskv1.MsgClaimDispatchCompensation){
		"no submitter": func(m *taskv1.MsgClaimDispatchCompensation) { m.SubmitterAddress = "" },
		"no order":     func(m *taskv1.MsgClaimDispatchCompensation) { m.Order = nil },
		"accept for another": func(m *taskv1.MsgClaimDispatchCompensation) {
			m.Accept.DispatchTicketHash = bytes.Repeat([]byte{9}, 32)
		},
		"another member":  func(m *taskv1.MsgClaimDispatchCompensation) { m.Accept.Member.Slot++ },
		"unsigned accept": func(m *taskv1.MsgClaimDispatchCompensation) { m.Accept.ServiceSignature = nil },
	} {
		m := validClaim(t)
		mutate(m)
		if _, err := MarshalDispatchMessage(MsgClaimDispatchCompensation, m); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if _, err := MarshalDispatchMessage(MsgClaimDispatchCompensation, &taskv1.MsgRecordDispatch{}); err == nil {
		t.Fatal("a payload of another type is refused")
	}
}
