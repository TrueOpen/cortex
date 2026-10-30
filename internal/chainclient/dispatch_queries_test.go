package chainclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/cosmos/gogoproto/proto"
	gproto "google.golang.org/protobuf/proto"

	hubv1 "github.com/TrueOpen/cortex/proto/hub/v1"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

func hubEpochParams(length uint64) *hubv1.QueryHubParamsResponse {
	return &hubv1.QueryHubParamsResponse{Params: &hubv1.HubParamsV2{SchemaVersion: 2, Epoch: &hubv1.EpochParamsV1{EpochLengthBlocks: length}}}
}

func TestDispatchEpochReadsTheEpochStartBeacon(t *testing.T) {
	r := bytes.Repeat([]byte{0xd8}, 32)
	beacon := func(tag string, verified bool) *hubv1.BeaconState {
		return &hubv1.BeaconState{Height: 800, RandomnessHex: hex.EncodeToString(r), SourceTag: tag, Verified: verified}
	}
	for _, c := range []struct {
		name       string
		earliest   uint64
		beacon     *hubv1.BeaconState
		notFound   bool
		wantQuery  bool
		wantHeight uint64
		verified   bool
	}{
		{"verified proposer VRF", 850, beacon("proposer_vrf_v1", true), false, true, 800, true},
		{"placeholder is never a seed", 850, beacon("placeholder_blockhash_v1", true), false, true, 800, false},
		{"unverified", 850, beacon("proposer_vrf_v1", false), false, true, 800, false},
		{"missing", 850, nil, true, true, 800, false},
		{"epoch zero", 99, nil, false, false, 0, false},
		{"epoch start not committed yet", 1_050, nil, false, false, 1_000, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			queried := false
			server := newABCITestServer(t, func(path, height string, data []byte) (proto.Message, uint32, string) {
				if height != "900" {
					t.Fatalf("height = %q, want the committed 900", height)
				}
				switch path {
				case hubQuery + "Params":
					return hubEpochParams(100), 0, ""
				case hubQuery + "Beacon":
					queried = true
					var req hubv1.QueryBeaconRequest
					if err := unmarshalTestProto(data, &req); err != nil {
						t.Fatal(err)
					}
					if req.Height != c.wantHeight {
						t.Fatalf("beacon height = %d, want %d", req.Height, c.wantHeight)
					}
					if c.notFound {
						return nil, 5, "rpc error: code = NotFound desc = no beacon"
					}
					return &hubv1.QueryBeaconResponse{Beacon: c.beacon}, 0, ""
				}
				t.Fatalf("ABCI path = %q", path)
				return nil, 0, ""
			})
			t.Cleanup(server.Close)
			got, err := NewKeeperABCIClient(server.URL).DispatchEpoch(context.Background(), c.earliest)
			if err != nil {
				t.Fatal(err)
			}
			if queried != c.wantQuery || got.EpochLengthBlocks != 100 || got.BeaconHeight != c.wantHeight || got.Verified != c.verified || got.Height != 900 {
				t.Fatalf("snapshot = %+v (queried %v)", got, queried)
			}
			if c.beacon != nil && !bytes.Equal(got.Randomness, r) {
				t.Fatalf("randomness = %x", got.Randomness)
			}
		})
	}
}

func TestDispatchEpochRefusesANonCanonicalBeacon(t *testing.T) {
	server := newABCITestServer(t, func(path, _ string, _ []byte) (proto.Message, uint32, string) {
		if path == hubQuery+"Params" {
			return hubEpochParams(100), 0, ""
		}
		return &hubv1.QueryBeaconResponse{Beacon: &hubv1.BeaconState{Height: 800, RandomnessHex: "ABCD", SourceTag: "proposer_vrf_v1", Verified: true}}, 0, ""
	})
	t.Cleanup(server.Close)
	if _, err := NewKeeperABCIClient(server.URL).DispatchEpoch(context.Background(), 850); err == nil {
		t.Fatal("a beacon whose randomness is not canonical 32-byte hex must be refused")
	}
}

func TestSessionReadsTheDispatchFields(t *testing.T) {
	sid := bytes.Repeat([]byte{0x5c}, 32)
	key := bytes.Repeat([]byte{0x11}, 20)
	stream := &taskv1.StreamState{
		SessionId: sid, OwnerUserAddress: "trueopen1owner", Status: taskv1.SessionStatus_SESSION_STATUS_ACTIVE,
		SessionKey: key, SessionKeySetHeight: 40, SessionKeyExpiryHeight: 2_000,
		BoundBuilder: "trueopen1builder", BoundChangeHeight: 105,
	}
	answer := func(s *taskv1.StreamState) *KeeperABCIClient {
		server := newABCITestServer(t, func(path, height string, data []byte) (proto.Message, uint32, string) {
			if path != taskQuery+"Session" || height != "900" {
				t.Fatalf("ABCI %s at %s", path, height)
			}
			var req taskv1.QuerySessionRequest
			if err := unmarshalTestProto(data, &req); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(req.SessionId, sid) {
				t.Fatalf("session_id = %x", req.SessionId)
			}
			if s == nil {
				return nil, 5, "rpc error: code = NotFound desc = compacted"
			}
			return &taskv1.QuerySessionResponse{Session: s}, 0, ""
		})
		t.Cleanup(server.Close)
		return NewKeeperABCIClient(server.URL)
	}
	got, err := answer(stream).Session(context.Background(), sid)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "ACTIVE" || got.BoundChangeHeight != 105 || !bytes.Equal(got.SessionKey, key) ||
		got.SessionKeySetHeight != 40 || got.SessionKeyExpiryHeight != 2_000 || got.BoundBuilder != "trueopen1builder" || got.Height != 900 {
		t.Fatalf("session = %+v", got)
	}
	if _, err := answer(nil).Session(context.Background(), sid); !errors.Is(err, ErrNotFound) {
		t.Fatalf("compacted session: err = %v, want ErrNotFound", err)
	}
	bad := gproto.Clone(stream).(*taskv1.StreamState)
	bad.SessionKey = []byte{1, 2, 3}
	if _, err := answer(bad).Session(context.Background(), sid); err == nil {
		t.Fatal("a session key that is not raw20 must be refused")
	}
	other := gproto.Clone(stream).(*taskv1.StreamState)
	other.SessionId = bytes.Repeat([]byte{1}, 32)
	if _, err := answer(other).Session(context.Background(), sid); err == nil {
		t.Fatal("an answer for another session must be refused")
	}
	if _, err := answer(stream).Session(context.Background(), []byte{1}); err == nil {
		t.Fatal("a session_id that is not 32 bytes must be refused before any query")
	}
}

func TestDispatchParamsAndWorkerLiabilityParams(t *testing.T) {
	server := newABCITestServer(t, func(path, _ string, _ []byte) (proto.Message, uint32, string) {
		switch path {
		case taskQuery + "Params":
			return &taskv1.QueryTaskParamsResponse{Params: &taskv1.TaskParamsV1{SchemaVersion: 1, Dispatch: &taskv1.DispatchParamsV1{
				RecordDeadlineBlocks: 50, DispatchCompensationClaimWindowBlocks: 60, DispatchCompensationRebuttalBlocks: 70,
				DispatchChallengeWindowBlocks: 80, DispatchChallengeResponseBlocks: 90, DispatchEvidenceRetentionBlocks: 1_000,
				MaxPrerecordOutputTokens: 32,
			}}}, 0, ""
		case hubQuery + "Params":
			return &hubv1.QueryHubParamsResponse{Params: &hubv1.HubParamsV2{SchemaVersion: 2, Service: &hubv1.ServiceParamsV1{
				MinTaskLiability: &sharedv1.Amount{AtomicUnits: "10"}, TaskLiabilityOrderCoverageBps: 2_500, ObjectiveForgerySlashBps: 500,
			}}}, 0, ""
		}
		t.Fatalf("ABCI path = %q", path)
		return nil, 0, ""
	})
	t.Cleanup(server.Close)
	c := NewKeeperABCIClient(server.URL)
	p, err := c.DispatchParams(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.RecordDeadlineBlocks != 50 || p.CompensationClaimWindowBlocks != 60 || p.CompensationRebuttalBlocks != 70 ||
		p.ChallengeWindowBlocks != 80 || p.ChallengeResponseBlocks != 90 || p.EvidenceRetentionBlocks != 1_000 || p.MaxPrerecordOutputTokens != 32 {
		t.Fatalf("dispatch params = %+v", p)
	}
	l, err := c.WorkerLiabilityParams(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if l.MinTaskLiability != 10 || l.OrderCoverageBps != 2_500 || l.ObjectiveForgerySlashBps != 500 {
		t.Fatalf("liability params = %+v", l)
	}
}

func TestDispatchParamsRefuseMissingOrMalformedValues(t *testing.T) {
	for name, answer := range map[string]proto.Message{
		"no record deadline": &taskv1.QueryTaskParamsResponse{Params: &taskv1.TaskParamsV1{SchemaVersion: 1, Dispatch: &taskv1.DispatchParamsV1{}}},
		"non-canonical min liability": &hubv1.QueryHubParamsResponse{Params: &hubv1.HubParamsV2{SchemaVersion: 2, Service: &hubv1.ServiceParamsV1{
			MinTaskLiability: &sharedv1.Amount{AtomicUnits: "010"}}}},
		"bps above 10000": &hubv1.QueryHubParamsResponse{Params: &hubv1.HubParamsV2{SchemaVersion: 2, Service: &hubv1.ServiceParamsV1{
			MinTaskLiability: &sharedv1.Amount{AtomicUnits: "10"}, TaskLiabilityOrderCoverageBps: 10_001}}},
	} {
		t.Run(name, func(t *testing.T) {
			server := newABCITestServer(t, func(string, string, []byte) (proto.Message, uint32, string) { return answer, 0, "" })
			t.Cleanup(server.Close)
			c := NewKeeperABCIClient(server.URL)
			var err error
			if _, ok := answer.(*taskv1.QueryTaskParamsResponse); ok {
				_, err = c.DispatchParams(context.Background())
			} else {
				_, err = c.WorkerLiabilityParams(context.Background())
			}
			if err == nil {
				t.Fatal("malformed params accepted")
			}
		})
	}
}

// Q18: the Dispatcher pins every read of one offer evaluation to one
// committed height, so the …At reads must query exactly that height and never
// read CommittedHeight themselves.
func TestDispatchReadsPinTheGivenHeight(t *testing.T) {
	sid := bytes.Repeat([]byte{0x5c}, 32)
	server := newABCITestServer(t, func(path, height string, data []byte) (proto.Message, uint32, string) {
		if height != "777" {
			t.Fatalf("%s read at height %q, want 777", path, height)
		}
		switch path {
		case hubQuery + "Params":
			return &hubv1.QueryHubParamsResponse{Params: &hubv1.HubParamsV2{SchemaVersion: 2, Epoch: &hubv1.EpochParamsV1{EpochLengthBlocks: 100},
				Service: &hubv1.ServiceParamsV1{MinTaskLiability: &sharedv1.Amount{AtomicUnits: "10"}}}}, 0, ""
		case hubQuery + "Beacon":
			return &hubv1.QueryBeaconResponse{Beacon: &hubv1.BeaconState{Height: 700, RandomnessHex: hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				SourceTag: "proposer_vrf_v1", Verified: true}}, 0, ""
		case taskQuery + "Session":
			return &taskv1.QuerySessionResponse{Session: &taskv1.StreamState{SessionId: sid, Status: taskv1.SessionStatus_SESSION_STATUS_IDLE}}, 0, ""
		case taskQuery + "Params":
			return &taskv1.QueryTaskParamsResponse{Params: &taskv1.TaskParamsV1{SchemaVersion: 1, Dispatch: &taskv1.DispatchParamsV1{RecordDeadlineBlocks: 5}}}, 0, ""
		}
		t.Fatalf("ABCI path = %q", path)
		return nil, 0, ""
	})
	t.Cleanup(server.Close)
	c := NewKeeperABCIClient(server.URL)
	ctx := context.Background()
	ep, err := c.DispatchEpochAt(ctx, 750, 777)
	if err != nil || ep.Height != 777 || ep.BeaconHeight != 700 || !ep.Verified {
		t.Fatalf("DispatchEpochAt = %+v, %v", ep, err)
	}
	if ep, err := c.DispatchEpochAt(ctx, 850, 777); err != nil || ep.BeaconHeight != 800 || ep.Verified {
		t.Fatalf("an epoch start above the pinned height is not committed there: %+v, %v", ep, err)
	}
	s, err := c.SessionAt(ctx, sid, 777)
	if err != nil || s.Height != 777 || s.Status != "IDLE" {
		t.Fatalf("SessionAt = %+v, %v", s, err)
	}
	p, err := c.DispatchParamsAt(ctx, 777)
	if err != nil || p.Height != 777 || p.RecordDeadlineBlocks != 5 {
		t.Fatalf("DispatchParamsAt = %+v, %v", p, err)
	}
	l, err := c.WorkerLiabilityParamsAt(ctx, 777)
	if err != nil || l.Height != 777 || l.MinTaskLiability != 10 {
		t.Fatalf("WorkerLiabilityParamsAt = %+v, %v", l, err)
	}
	for name, read := range map[string]func() error{
		"DispatchEpochAt":         func() error { _, err := c.DispatchEpochAt(ctx, 750, 0); return err },
		"SessionAt":               func() error { _, err := c.SessionAt(ctx, sid, 0); return err },
		"DispatchParamsAt":        func() error { _, err := c.DispatchParamsAt(ctx, 0); return err },
		"WorkerLiabilityParamsAt": func() error { _, err := c.WorkerLiabilityParamsAt(ctx, 0); return err },
		"BuilderSetAt":            func() error { _, err := c.BuilderSetAt(ctx, 0); return err },
	} {
		if read() == nil {
			t.Fatalf("%s: a pinned read needs a height", name)
		}
	}
}
