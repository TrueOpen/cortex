package chainclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/cosmos/gogoproto/proto"

	hubv1 "github.com/TrueOpen/cortex/proto/hub/v1"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
)

func TestCommittedCurrentServiceKeyExposesPendingRotation(t *testing.T) {
	pubkey := append([]byte{0x02}, bytes.Repeat([]byte{0xab}, 32)...)
	for _, pending := range []bool{false, true} {
		server := newABCITestServer(t, func(path, height string, data []byte) (proto.Message, uint32, string) {
			if path != hubQuery+"CurrentServiceKey" {
				t.Fatalf("ABCI path = %q", path)
			}
			view := &hubv1.CurrentServiceKeyViewV1{
				ParticipantType: sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX,
				OperatorAddress: "trueopen1operator", ServiceAddress: "trueopen1service",
				ServicePubkey: pubkey, ServiceAuthorizationNonce: 3,
				ParticipantStatus: &hubv1.CurrentServiceKeyViewV1_CortexServiceKeyStatus{
					CortexServiceKeyStatus: hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_ACTIVE,
				},
			}
			if pending {
				view.PendingRotation = &hubv1.PendingServiceKeyRotationState{
					ParticipantType: sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX, OperatorAddress: "trueopen1operator",
					CurrentServiceAuthorizationNonce: 3, NextServiceAuthorizationNonce: 4,
					RegisteredHeight: 880, EffectiveHeight: 1_200,
				}
			}
			return &hubv1.QueryCurrentServiceKeyResponse{Binding: view}, 0, ""
		})
		t.Cleanup(server.Close)
		binding, _, err := NewKeeperABCIClient(server.URL).CommittedCurrentServiceKey(context.Background(), ParticipantTypeCortexNode, "trueopen1operator")
		if err != nil {
			t.Fatalf("pending=%v: %v", pending, err)
		}
		if binding.HasPendingRotation != pending {
			t.Fatalf("HasPendingRotation = %v, want %v", binding.HasPendingRotation, pending)
		}
		if pending && (binding.PendingRotation.EffectiveHeight != 1_200 || binding.PendingRotation.NextAuthorizationNonce != 4 ||
			binding.PendingRotation.RegisteredHeight != 880) {
			t.Fatalf("PendingRotation = %+v", binding.PendingRotation)
		}
		if binding.Status != "ACTIVE" || binding.AuthorizationNonce.Uint64() != 3 {
			t.Fatalf("a pending rotation must not change the current binding: %+v", binding)
		}
	}
}

// wire b30fba8 retains one previous proof generation and an explicit
// emergency-revoke cutoff on the current binding; both are needed to verify a
// retained Builder message by the nonce it was signed with.
func TestCommittedCurrentServiceKeyExposesPreviousGenerationAndRevokeCutoff(t *testing.T) {
	pubkey := append([]byte{0x02}, bytes.Repeat([]byte{0xab}, 32)...)
	previous := append([]byte{0x03}, bytes.Repeat([]byte{0xcd}, 32)...)
	u64 := func(v uint64) *uint64 { return &v }
	cases := []struct {
		name    string
		edit    func(*hubv1.CurrentServiceKeyViewV1)
		wantErr bool
		check   func(t *testing.T, s ServiceKeySnapshot)
	}{
		{name: "no previous", edit: func(*hubv1.CurrentServiceKeyViewV1) {}, check: func(t *testing.T, s ServiceKeySnapshot) {
			if s.HasPrevious || s.RevokedHeight.Uint64() != 0 {
				t.Fatalf("snapshot = %+v", s)
			}
		}},
		{name: "previous", edit: func(v *hubv1.CurrentServiceKeyViewV1) {
			v.PreviousServicePubkey, v.PreviousServiceAuthorizationNonce, v.PreviousRetiredHeight = previous, u64(2), u64(1_000)
		}, check: func(t *testing.T, s ServiceKeySnapshot) {
			if !s.HasPrevious || s.Previous.ServicePubkey != hex.EncodeToString(previous) || s.Previous.AuthorizationNonce != 2 || s.Previous.RetiredHeight != 1_000 {
				t.Fatalf("previous = %+v", s.Previous)
			}
		}},
		{name: "revoked cutoff", edit: func(v *hubv1.CurrentServiceKeyViewV1) {
			v.ParticipantStatus = &hubv1.CurrentServiceKeyViewV1_BuilderServiceKeyStatus{BuilderServiceKeyStatus: hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_REVOKED}
			v.RevokedHeight = u64(1_500)
		}, check: func(t *testing.T, s ServiceKeySnapshot) {
			if s.Status != "REVOKED" || s.RevokedHeight.Uint64() != 1_500 {
				t.Fatalf("snapshot = %+v", s)
			}
		}},
		{name: "previous without retirement", edit: func(v *hubv1.CurrentServiceKeyViewV1) {
			v.PreviousServicePubkey, v.PreviousServiceAuthorizationNonce = previous, u64(2)
		}, wantErr: true},
		{name: "previous not older", edit: func(v *hubv1.CurrentServiceKeyViewV1) {
			v.PreviousServicePubkey, v.PreviousServiceAuthorizationNonce, v.PreviousRetiredHeight = previous, u64(3), u64(1_000)
		}, wantErr: true},
		{name: "active with revoke height", edit: func(v *hubv1.CurrentServiceKeyViewV1) { v.RevokedHeight = u64(9) }, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := newABCITestServer(t, func(path, height string, data []byte) (proto.Message, uint32, string) {
				view := &hubv1.CurrentServiceKeyViewV1{
					ParticipantType: sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER,
					OperatorAddress: "trueopen1operator", ServiceAddress: "trueopen1service",
					ServicePubkey: pubkey, ServiceAuthorizationNonce: 3,
					ParticipantStatus: &hubv1.CurrentServiceKeyViewV1_BuilderServiceKeyStatus{
						BuilderServiceKeyStatus: hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_ACTIVE,
					},
				}
				tc.edit(view)
				return &hubv1.QueryCurrentServiceKeyResponse{Binding: view}, 0, ""
			})
			t.Cleanup(server.Close)
			binding, err := NewKeeperABCIClient(server.URL).CurrentServiceKey(context.Background(), ParticipantTypeBuilder, "trueopen1operator", 7)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("CurrentServiceKey() = %+v, want an error", binding)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, binding)
		})
	}
}
