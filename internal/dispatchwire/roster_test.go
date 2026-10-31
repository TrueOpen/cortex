package dispatchwire

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/TrueOpen/wire/dispatch"

	"github.com/TrueOpen/cortex/internal/wirevectors"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

const vChain, vAddr = "trueopen-phase1-vector-1", "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz"

// derivedDigest reads a derived-digest row (no message) of task/dispatch_v1.json.
func derivedDigest(t *testing.T, name string) string {
	t.Helper()
	data, err := wirevectors.File("task/dispatch_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Vectors []struct {
			Name      string `json:"name"`
			DigestHex string `json:"digest_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	for _, v := range f.Vectors {
		if v.Name == name {
			return v.DigestHex
		}
	}
	t.Fatalf("no vector %s", name)
	return ""
}

func vectorRoster() *taskv1.DispatchRosterV1 {
	return &taskv1.DispatchRosterV1{TaskId: bytes.Repeat([]byte{0x33}, 32), ReferenceHeight: 100, CandidatePoolSnapshotId: bytes.Repeat([]byte{0x66}, 32),
		Members: []*taskv1.DispatchRosterMemberV1{
			{Slot: 1, SlotVersion: 1, OperatorAddress: "trueopen1pu8q6rqtpgysspcxq5zqxqspqzsm9s7589fuc8", CandidateWeight: 1},
			{Slot: 3, SlotVersion: 1, OperatorAddress: "trueopen1zsf3yygspu8q6rqtpgysspcxq5zqxqsp050wj3", CandidateWeight: 5},
			{Slot: 7, SlotVersion: 1, OperatorAddress: vAddr, CandidateWeight: 2},
		}}
}

func TestRosterHashMatchesWire(t *testing.T) {
	h, err := RosterHash(vChain, vectorRoster())
	if err != nil || hex.EncodeToString(h[:]) != derivedDigest(t, "dispatch_roster") {
		t.Fatalf("roster hash %x, %v", h, err)
	}
	short := vectorRoster()
	short.CandidatePoolSnapshotId = []byte{1}
	if _, err := RosterHash(vChain, short); err == nil {
		t.Fatal("a roster without a 32-byte snapshot id is refused")
	}
}

func TestNonInclusionUsesTheAdjacentMembers(t *testing.T) {
	r := vectorRoster()
	p, err := NonInclusion(r, 4)
	if err != nil || p.GetPredecessor().GetSlot() != 3 || p.GetSuccessor().GetSlot() != 7 {
		t.Fatalf("slot 4: %+v, %v", p, err)
	}
	if p, _ := NonInclusion(r, 0); p.Predecessor != nil || p.GetSuccessor().GetSlot() != 1 {
		t.Fatal("below the first member: successor only")
	}
	if p, _ := NonInclusion(r, 9); p.Successor != nil || p.GetPredecessor().GetSlot() != 7 {
		t.Fatal("above the last member: predecessor only")
	}
	if _, err := NonInclusion(r, 3); !errors.Is(err, ErrInRoster) {
		t.Fatal("a member's slot cannot be proved absent")
	}
	r.Members[0], r.Members[1] = r.Members[1], r.Members[0]
	if _, err := NonInclusion(r, 4); err == nil {
		t.Fatal("a roster out of slot order is refused")
	}
}

func TestChallengeIDsMatchWire(t *testing.T) {
	task := [32]byte(bytes.Repeat([]byte{0x33}, 32))
	om, err := OmissionChallengeID(vChain, task, 1, vAddr, vAddr)
	if err != nil || hex.EncodeToString(om[:]) != derivedDigest(t, "dispatch_challenge_kind_1") {
		t.Fatalf("omission id %x, %v", om, err)
	}
	ru, err := RosterUnavailableChallengeID(vChain, task, 1, vAddr)
	if err != nil || hex.EncodeToString(ru[:]) != derivedDigest(t, "dispatch_challenge_kind_4") {
		t.Fatalf("roster-unavailable id %x, %v", ru, err)
	}
}

func TestSignRosterRequestReproducesWire(t *testing.T) {
	row := vectorByName(t, "nexus_v1_dispatchrosterrequestv1")
	m := vectorMessage(t, row).(*nexusv1.DispatchRosterRequestV1)
	m.ServiceSignature = bytes.Repeat([]byte{0xee}, 64)
	if err := SignRosterRequest(context.Background(), m, localSigner(fixtureKeyHex)); err != nil {
		t.Fatal(err)
	}
	d, _ := Digest(m)
	if err := dispatch.VerifyDigestSignature(mustHex(t, row.PublicKeyHex), d[:], m.ServiceSignature); err != nil || hex.EncodeToString(m.ServiceSignature) != row.SignatureHex {
		t.Fatalf("re-signed %x: %v", m.ServiceSignature, err)
	}
}
