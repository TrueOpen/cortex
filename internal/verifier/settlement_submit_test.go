package verifier

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/txclient"
)

type settlementReaderFunc func(context.Context, string) (chainclient.SettlementContext, error)

func (f settlementReaderFunc) SettlementContext(ctx context.Context, task string) (chainclient.SettlementContext, error) {
	return f(ctx, task)
}

func readySettlementContext() chainclient.SettlementContext {
	return chainclient.SettlementContext{
		TaskID: testTaskID, SessionID: strings.Repeat("12", 32), Phase: 7,
		ObservedHeight: 100, UpdatedHeight: 90, PermissionlessHeight: 100, DeadlineHeight: 200,
	}
}

func TestSettlementSubmissionCarriesOnlyTaskAndCurrentSubmitter(t *testing.T) {
	client := txclient.NewFake()
	manager := NewSettlementManager(SettlementConfig{
		Tx: client, SubmitterAddress: "trueopen1service", GasPayer: "trueopen1service",
		FeeCap: txclient.Coin{Amount: 25, Denom: "utrueopen"},
		ContextReader: settlementReaderFunc(func(_ context.Context, taskID string) (chainclient.SettlementContext, error) {
			if taskID != testTaskID {
				t.Errorf("requested task=%s", taskID)
			}
			return readySettlementContext(), nil
		}),
	})
	obs, err := manager.HandleStage3BuilderFailure(context.Background(), SettlementInput{
		Message: txclient.SettleTaskMessage{TaskID: txclient.ProtoBytes32(testTaskID), SubmitterAddress: "trueopen1service"},
	})
	if err != nil || !obs.Submitted {
		t.Fatalf("settlement observation=%#v error=%v", obs, err)
	}
	requests := client.Requests()
	if len(requests) != 1 {
		t.Fatalf("requests=%d, want one MsgSettleTask", len(requests))
	}
	request := requests[0]
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(request.Payload, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 2 || fields["task_id"] == nil || fields["submitter_address"] == nil {
		t.Fatalf("payload=%s, want exactly the same two fields as Nexus SubmitSettle", request.Payload)
	}
	if request.Kind != txclient.MsgSettleTask || request.TaskID != testTaskID || request.SessionID != strings.Repeat("12", 32) || request.DeadlineHeight != 200 || request.GasPayer != "trueopen1service" || request.FeeCap.Amount != 25 {
		t.Fatalf("request=%#v, want authoritative scope, deadline and configured fee cap", request)
	}
	if obs.Closed {
		t.Fatal("an accepted fake submission without Keeper confirmation was reported closed")
	}
}

func TestSettlementSubmissionRefusesWrongIdentityAndUnsafeWindow(t *testing.T) {
	for _, test := range []struct {
		name      string
		submitter string
		mutate    func(*chainclient.SettlementContext)
		readerErr error
	}{
		{name: "wrong signer", submitter: "other-service"},
		{name: "wrong task", mutate: func(s *chainclient.SettlementContext) { s.TaskID = strings.Repeat("cd", 32) }},
		{name: "missing session", mutate: func(s *chainclient.SettlementContext) { s.SessionID = "" }},
		{name: "before public window", mutate: func(s *chainclient.SettlementContext) { s.ObservedHeight = 99 }},
		{name: "after deadline", mutate: func(s *chainclient.SettlementContext) { s.ObservedHeight = 201 }},
		{name: "deadline already committed", mutate: func(s *chainclient.SettlementContext) { s.ObservedHeight = 200 }},
		{name: "reveal still open", mutate: func(s *chainclient.SettlementContext) { s.Phase = 6 }},
		{name: "query failed", readerErr: errors.New("keeper unavailable")},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := txclient.NewFake()
			state := readySettlementContext()
			if test.mutate != nil {
				test.mutate(&state)
			}
			manager := NewSettlementManager(SettlementConfig{
				Tx: client, SubmitterAddress: "trueopen1service",
				ContextReader: settlementReaderFunc(func(context.Context, string) (chainclient.SettlementContext, error) { return state, test.readerErr }),
			})
			submitter := test.submitter
			if submitter == "" {
				submitter = "trueopen1service"
			}
			obs, err := manager.HandleStage3BuilderFailure(context.Background(), SettlementInput{
				Message: txclient.SettleTaskMessage{TaskID: txclient.ProtoBytes32(testTaskID), SubmitterAddress: submitter},
			})
			if err == nil || obs.Submitted || len(client.Requests()) != 0 {
				t.Fatalf("observation=%#v error=%v requests=%d, want rejection before spending", obs, err, len(client.Requests()))
			}
		})
	}
}

func TestSettlementSubmissionIsNoopForTerminalTask(t *testing.T) {
	client := txclient.NewFake()
	state := readySettlementContext()
	state.Phase = 8
	manager := NewSettlementManager(SettlementConfig{
		Tx: client, SubmitterAddress: "trueopen1service",
		ContextReader: settlementReaderFunc(func(context.Context, string) (chainclient.SettlementContext, error) { return state, nil }),
	})
	obs, err := manager.HandleStage3BuilderFailure(context.Background(), SettlementInput{
		Message: txclient.SettleTaskMessage{TaskID: txclient.ProtoBytes32(testTaskID), SubmitterAddress: "trueopen1service"},
	})
	if err != nil || !obs.Closed || obs.Submitted || len(client.Requests()) != 0 {
		t.Fatalf("observation=%#v error=%v, want terminal no-op", obs, err)
	}
}
