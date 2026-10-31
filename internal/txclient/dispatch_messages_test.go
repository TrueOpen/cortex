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

func TestOmissionAndRosterReportPayloads(t *testing.T) {
	if !MsgChallengeDispatchOmission.Valid() || !MsgReportDispatchRosterUnavailable.Valid() {
		t.Fatal("not valid kinds")
	}
	member := &taskv1.DispatchRosterMemberV1{Slot: 1, SlotVersion: 1, OperatorAddress: "trueopen1a", CandidateWeight: 1}
	om := &taskv1.MsgChallengeDispatchOmission{TaskId: bytes.Repeat([]byte{3}, 32), DispatchRound: 0, ChallengerAddress: "trueopen1service",
		Roster:        &taskv1.DispatchRosterV1{TaskId: bytes.Repeat([]byte{3}, 32), Members: []*taskv1.DispatchRosterMemberV1{member}},
		HandraiseRoot: &taskv1.SignedHandraiseRootV1{RootHeight: 1}, InclusionProof: &taskv1.HandraiseInclusionProofV1{Leaf: &taskv1.HandraiseRootLeafV1{Admitted: true}},
		NonInclusionProof: &taskv1.DispatchRosterNonInclusionProofV1{Predecessor: member}}
	payload, err := MarshalDispatchMessage(MsgChallengeDispatchOmission, om)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRequest(Request{TaskID: "t", Kind: MsgChallengeDispatchOmission, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	again, _ := MarshalDispatchMessage(MsgChallengeDispatchOmission, om)
	var back taskv1.MsgChallengeDispatchOmission
	if !bytes.Equal(payload, again) || bytes.ContainsAny(payload, " \n") || protojson.Unmarshal(payload, &back) != nil || !proto.Equal(&back, om) {
		t.Fatalf("payload %s: one message, one compact payload that round-trips", payload)
	}
	if _, err := MarshalMessage(MsgChallengeDispatchOmission, om); err == nil {
		t.Fatal("the struct path refuses dispatch kinds")
	}
	if _, err := MarshalDispatchMessage(MsgReportDispatchRosterUnavailable, om); err == nil {
		t.Fatal("a payload of another type is refused")
	}
	om.DispatchRound = 1
	if _, err := MarshalDispatchMessage(MsgChallengeDispatchOmission, om); err == nil {
		t.Fatal("round != 0 needs first_round_roster")
	}
	om.DispatchRound, om.InclusionProof = 0, nil
	if _, err := MarshalDispatchMessage(MsgChallengeDispatchOmission, om); err == nil {
		t.Fatal("an omission needs the inclusion proof")
	}
	rep := &taskv1.MsgReportDispatchRosterUnavailable{TaskId: bytes.Repeat([]byte{3}, 32), DispatchRound: 2, ReporterAddress: "trueopen1service"}
	rp, err := MarshalDispatchMessage(MsgReportDispatchRosterUnavailable, rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateMessagePayload(MsgReportDispatchRosterUnavailable, rp); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMessagePayload(MsgReportDispatchRosterUnavailable, []byte(`{"task_id":"AwMD"}`)); err == nil {
		t.Fatal("an invalid payload is refused on the raw path too")
	}
	rep.ReporterAddress = ""
	if _, err := MarshalDispatchMessage(MsgReportDispatchRosterUnavailable, rep); err == nil {
		t.Fatal("a report needs its reporter")
	}
}
