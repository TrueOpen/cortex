package builderclient

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	"github.com/TrueOpen/cortex/proto/nexus/v1/nexusv1connect"
)

// GetDispatchRoster asks one Builder's IngressAPI for every round's roster of
// a recorded task (NX §4.15). The caller signs the DispatchRosterRequestV1
// for this Builder (chain_id and builder_operator are signed).
func (c *ConnectTaskDataClient) GetDispatchRoster(ctx context.Context, endpoint string, req *nexusv1.GetDispatchRosterRequest) (*nexusv1.GetDispatchRosterResponse, error) {
	if req.GetRosterRequest() == nil {
		return nil, fmt.Errorf("GetDispatchRoster needs a signed DispatchRosterRequestV1")
	}
	client, err := c.ingress(endpoint)
	if err != nil {
		return nil, err
	}
	r := connect.NewRequest(req)
	c.authorize(r.Header())
	resp, err := client.GetDispatchRoster(ctx, r)
	if err != nil {
		return nil, classifyConnectError(nexusv1connect.IngressAPIGetDispatchRosterProcedure, err)
	}
	if resp == nil || resp.Msg == nil {
		return nil, fmt.Errorf("empty GetDispatchRoster response")
	}
	return resp.Msg, nil
}

// IsRosterNotFound: this Builder keeps no roster for the task (DATA_NOT_FOUND).
func IsRosterNotFound(err error) bool { return connect.CodeOf(err) == connect.CodeNotFound }
