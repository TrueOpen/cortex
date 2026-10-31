package builderclient

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	"github.com/TrueOpen/cortex/proto/nexus/v1/nexusv1connect"
)

type rosterHandler struct {
	nexusv1connect.UnimplementedIngressAPIHandler
	notFound bool
}

func (h *rosterHandler) GetDispatchRoster(_ context.Context, r *connect.Request[nexusv1.GetDispatchRosterRequest]) (*connect.Response[nexusv1.GetDispatchRosterResponse], error) {
	if h.notFound {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("DATA_NOT_FOUND"))
	}
	if r.Msg.GetRosterRequest().GetBuilderOperator() != "trueopen1builder" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("unsigned"))
	}
	return connect.NewResponse(&nexusv1.GetDispatchRosterResponse{Rounds: []*nexusv1.DispatchRosterRoundV1{{DispatchRound: 0}}}), nil
}

func TestGetDispatchRoster(t *testing.T) {
	req := &nexusv1.GetDispatchRosterRequest{TaskId: "0x03", Authentication: &nexusv1.GetDispatchRosterRequest_RosterRequest{
		RosterRequest: &nexusv1.DispatchRosterRequestV1{BuilderOperator: "trueopen1builder"}}}
	ok := newTaskDataTestServer(t, &rosterHandler{})
	resp, err := newTestTaskDataClient(ok.Client(), "").GetDispatchRoster(context.Background(), ok.URL, req)
	if err != nil || len(resp.GetRounds()) != 1 {
		t.Fatalf("roster = %v, %v", resp, err)
	}
	missing := newTaskDataTestServer(t, &rosterHandler{notFound: true})
	if _, err := newTestTaskDataClient(missing.Client(), "").GetDispatchRoster(context.Background(), missing.URL, req); connect.CodeOf(err) != connect.CodeNotFound || IsRetryable(err) {
		t.Fatalf("not found: %v", err)
	}
	if _, err := newTestTaskDataClient(ok.Client(), "").GetDispatchRoster(context.Background(), ok.URL, &nexusv1.GetDispatchRosterRequest{}); err == nil {
		t.Fatal("an unauthenticated request is refused before dialling")
	}
}
