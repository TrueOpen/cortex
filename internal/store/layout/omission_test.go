package layout

import (
	"context"
	"errors"
	"testing"
)

func TestOmissionCaseLifecycle(t *testing.T) {
	ctx, s := context.Background(), openTestLayout(t)
	c := OmissionCase{TaskID: hash("task"), SessionID: hash("s"), OrderSequence: 7, Builder: "b", RecordHash: hash("r"), RecordedHeight: 200}
	if created, err := PutOmissionCase(ctx, s, c); err != nil || !created {
		t.Fatal(err)
	}
	if created, _ := PutOmissionCase(ctx, s, c); created {
		t.Fatal("a redelivered event changes nothing")
	}
	other := c
	other.Builder = "x"
	if _, err := PutOmissionCase(ctx, s, other); !errors.Is(err, ErrConflict) {
		t.Fatal("same task, another record: conflict")
	}
	if open, _ := OpenOmissionCases(ctx, s); len(open) != 1 || open[0].State != OmissionPending || open[0].SchemaVersion != 1 {
		t.Fatal("pending is open")
	}
	if _, err := UpdateOmissionCase(ctx, s, c.TaskID, func(x *OmissionCase) { x.Builder = "x" }); !errors.Is(err, ErrConflict) {
		t.Fatal("identity is immutable")
	}
	if _, err := UpdateOmissionCase(ctx, s, c.TaskID, func(x *OmissionCase) { x.State = OmissionClear }); !errors.Is(err, ErrConflict) {
		t.Fatal("a closed case needs RetainUntil")
	}
	if _, err := UpdateOmissionCase(ctx, s, c.TaskID, func(x *OmissionCase) { x.State, x.RetainUntil = OmissionClear, 280 }); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateOmissionCase(ctx, s, c.TaskID, func(x *OmissionCase) { x.State = OmissionChallenged }); !errors.Is(err, ErrConflict) {
		t.Fatal("closed is final")
	}
	if created, err := PutOmissionCase(ctx, s, c); err != nil || created {
		t.Fatal("a redelivered event never reopens a closed case")
	}
	if open, _ := OpenOmissionCases(ctx, s); len(open) != 0 {
		t.Fatal("closed leaves the open index")
	}
	if due, _ := DueOmissionGC(ctx, s, 279, 10); len(due) != 0 {
		t.Fatal("not due")
	}
	due, _ := DueOmissionGC(ctx, s, 280, 10)
	if len(due) != 1 || due[0] != c.TaskID {
		t.Fatal("due at RetainUntil")
	}
	if err := DeleteOmissionCase(ctx, s, c.TaskID); err != nil {
		t.Fatal(err)
	}
	if due, _ := DueOmissionGC(ctx, s, 1000, 10); len(due) != 0 {
		t.Fatal("gc key gone")
	}
	if err := DeleteOmissionCase(ctx, s, c.TaskID); err != nil {
		t.Fatal("deleting twice is a no-op")
	}
}

func TestOmissionStateTransitions(t *testing.T) {
	ctx, s := context.Background(), openTestLayout(t)
	c := OmissionCase{TaskID: hash("task"), Builder: "b", RecordHash: hash("r"), RecordedHeight: 200}
	if _, err := PutOmissionCase(ctx, s, c); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateOmissionCase(ctx, s, c.TaskID, func(x *OmissionCase) { x.State = OmissionChallenged }); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateOmissionCase(ctx, s, c.TaskID, func(x *OmissionCase) { x.State = OmissionReported }); !errors.Is(err, ErrConflict) {
		t.Fatal("a challenged case is never reported")
	}
	if _, err := UpdateOmissionCase(ctx, s, c.TaskID, func(x *OmissionCase) { x.State, x.RetainUntil = OmissionClear, 1 }); !errors.Is(err, ErrConflict) {
		t.Fatal("a challenged case is resolved or abandoned, never clear")
	}
}
