package chainclient

import (
	"bytes"
	"context"
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
					RegisteredHeight: 880, EffectiveHeight: 1_200, OldMaterialCloseHeight: 1_150,
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
			binding.PendingRotation.OldMaterialCloseHeight != 1_150 || binding.PendingRotation.RegisteredHeight != 880) {
			t.Fatalf("PendingRotation = %+v", binding.PendingRotation)
		}
		if binding.Status != "ACTIVE" || binding.AuthorizationNonce.Uint64() != 3 {
			t.Fatalf("a pending rotation must not change the current binding: %+v", binding)
		}
	}
}
