package chainclient

import (
	"bytes"
	"context"
	"testing"

	"github.com/cosmos/gogoproto/proto"

	hubv1 "github.com/TrueOpen/cortex/proto/hub/v1"
)

func TestCortexNodeAndServiceBondAtPinTheGivenHeight(t *testing.T) {
	const op = "trueopen1operator"
	server := newABCITestServer(t, func(path, height string, data []byte) (proto.Message, uint32, string) {
		if height != "777" {
			t.Fatalf("%s read at height %q, want 777", path, height)
		}
		switch path {
		case hubQuery + "CortexNode":
			return &hubv1.QueryCortexNodeResponse{Node: &hubv1.CortexNodeState{
				SchemaVersion: 1, OperatorAddress: op, CurrentServiceAddress: "trueopen1service",
				CurrentServicePubkey: append([]byte{2}, bytes.Repeat([]byte{1}, 32)...), ServiceAuthorizationNonce: 3,
				ServiceKeyStatus: hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_ACTIVE,
			}}, 0, ""
		case hubQuery + "ServiceBond":
			return &hubv1.QueryServiceBondResponse{Bond: &hubv1.ServiceBondState{
				OperatorAddress: op, ActiveBond: 10, BondVersion: 2, Status: hubv1.ServiceBondStatus_SERVICE_BOND_STATUS_ACTIVE,
			}}, 0, ""
		}
		t.Fatalf("unexpected path %q", path)
		return nil, 0, ""
	})
	t.Cleanup(server.Close)
	c := NewKeeperABCIClient(server.URL)
	node, err := c.CortexNodeAt(context.Background(), op, 777)
	if err != nil || node.AuthorizationNonce != 3 {
		t.Fatalf("CortexNodeAt = %+v %v", node, err)
	}
	bond, err := c.ServiceBondAt(context.Background(), op, 777)
	if err != nil || bond.ActiveBond != 10 || bond.Status != "ACTIVE" {
		t.Fatalf("ServiceBondAt = %+v %v", bond, err)
	}
	if _, err := c.CortexNodeAt(context.Background(), op, 0); err == nil {
		t.Fatal("a pinned read needs a height")
	}
	if _, err := c.ServiceBondAt(context.Background(), op, 0); err == nil {
		t.Fatal("a pinned read needs a height")
	}
}
