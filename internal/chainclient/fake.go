package chainclient

type FakeClient struct {
	AcceptedAssignments  []AssignmentAccepted
	FinalizedAssignments []AssignmentFinalized
}

func NewFakeClient() *FakeClient {
	return &FakeClient{}
}

func (f *FakeClient) AddAssignmentFinalized(event AssignmentFinalized) {
	f.FinalizedAssignments = append(f.FinalizedAssignments, event)
}
