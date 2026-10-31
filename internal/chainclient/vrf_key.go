package chainclient

import (
	"context"
	"fmt"
	"strings"

	hubv1 "github.com/TrueOpen/cortex/proto/hub/v1"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
)

// VrfKeySnapshot is hub.v1.QueryVrfKeyResponse for one operator.
type VrfKeySnapshot struct {
	ActivePubkey       []byte
	ActiveFromEpoch    uint64
	PendingPubkey      []byte // nil unless a next-epoch key is registered
	PendingFromEpoch   uint64
	AuthorizationNonce uint64
}

// BuilderVrfKeyAt reads a Builder's registered dispatch VRF key at height,
// which must have come from CommittedHeight, so it can be read beside other
// facts at that height (hub.v1.Query/VrfKey, participant_type BUILDER: zero
// would select the Validator registry). Standing handraise gate H1 needs it to
// be readable, and dispatchwire.TicketContext.BuilderVRFPubKey is its active
// key. There is deliberately no by-epoch read: wire's PHASE1_CONTRACT has none.
func (c *KeeperABCIClient) BuilderVrfKeyAt(ctx context.Context, operatorAddress string, height uint64) (VrfKeySnapshot, error) {
	if height == 0 {
		return VrfKeySnapshot{}, fmt.Errorf("Builder VRF key query height is required")
	}
	request := &hubv1.QueryVrfKeyRequest{
		OperatorAddress: strings.TrimSpace(operatorAddress),
		ParticipantType: sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER,
	}
	var response hubv1.QueryVrfKeyResponse
	if err := c.query(ctx, hubQuery+"VrfKey", height, request, &response); err != nil {
		return VrfKeySnapshot{}, err
	}
	if len(response.ActiveVrfPubkey) != 32 {
		return VrfKeySnapshot{}, fmt.Errorf("Builder %s VRF key is %d bytes, want 32", operatorAddress, len(response.ActiveVrfPubkey))
	}
	snapshot := VrfKeySnapshot{
		ActivePubkey:       append([]byte(nil), response.ActiveVrfPubkey...),
		ActiveFromEpoch:    response.ActiveFromEpoch,
		AuthorizationNonce: response.VrfAuthorizationNonce,
	}
	if response.PendingVrfPubkey != nil {
		snapshot.PendingPubkey = append([]byte(nil), response.PendingVrfPubkey...)
		snapshot.PendingFromEpoch = response.GetPendingFromEpoch()
	}
	return snapshot, nil
}
