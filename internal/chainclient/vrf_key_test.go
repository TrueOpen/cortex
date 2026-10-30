package chainclient

import (
	"bytes"
	"context"
	"testing"

	"github.com/cosmos/gogoproto/proto"

	hubv1 "github.com/TrueOpen/cortex/proto/hub/v1"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
)

func TestBuilderVrfKeyReadsTheBuilderSelectorAtCommittedHeight(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	server := newABCITestServer(t, func(path, height string, data []byte) (proto.Message, uint32, string) {
		if path != hubQuery+"VrfKey" {
			t.Fatalf("ABCI path = %q", path)
		}
		if height != "900" {
			t.Fatalf("height = %q, want the committed 900", height)
		}
		var req hubv1.QueryVrfKeyRequest
		if err := unmarshalTestProto(data, &req); err != nil {
			t.Fatal(err)
		}
		if req.OperatorAddress != "trueopen1builder" || req.ParticipantType != sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER {
			t.Fatalf("request = %v", &req)
		}
		return &hubv1.QueryVrfKeyResponse{ActiveVrfPubkey: key, ActiveFromEpoch: 3, VrfAuthorizationNonce: 2}, 0, ""
	})
	t.Cleanup(server.Close)
	got, err := NewKeeperABCIClient(server.URL).BuilderVrfKey(context.Background(), "trueopen1builder")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.ActivePubkey, key) || got.ActiveFromEpoch != 3 || got.AuthorizationNonce != 2 || got.PendingPubkey != nil {
		t.Fatalf("VrfKeySnapshot = %+v", got)
	}
}

func TestBuilderVrfKeyRefusesAMalformedKey(t *testing.T) {
	server := newABCITestServer(t, func(string, string, []byte) (proto.Message, uint32, string) {
		return &hubv1.QueryVrfKeyResponse{ActiveVrfPubkey: []byte{1, 2, 3}}, 0, ""
	})
	t.Cleanup(server.Close)
	if _, err := NewKeeperABCIClient(server.URL).BuilderVrfKey(context.Background(), "trueopen1builder"); err == nil {
		t.Fatal("a VRF key that is not 32 bytes must be refused")
	}
}

func TestBuilderVrfKeyAtPinsTheGivenHeight(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	server := newABCITestServer(t, func(path, height string, data []byte) (proto.Message, uint32, string) {
		if path != hubQuery+"VrfKey" || height != "777" {
			t.Fatalf("query %q at height %q, want VrfKey at 777", path, height)
		}
		return &hubv1.QueryVrfKeyResponse{ActiveVrfPubkey: key}, 0, ""
	})
	t.Cleanup(server.Close)
	if _, err := NewKeeperABCIClient(server.URL).BuilderVrfKeyAt(context.Background(), "trueopen1builder", 777); err != nil {
		t.Fatal(err)
	}
}
