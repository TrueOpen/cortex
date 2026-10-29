package verifier

import (
	"context"
	"testing"

	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

type recordingSender struct {
	handraises []*taskv1.VerifierHandraiseV1
	events     *[]string
}

func (r *recordingSender) SendVerifierHandraise(_ context.Context, h *taskv1.VerifierHandraiseV1) error {
	r.handraises = append(r.handraises, h)
	if r.events != nil {
		*r.events = append(*r.events, "sender:verifier-handraise")
	}
	return nil
}

func TestNilFrameSenderIsRejectedAtConstruction(t *testing.T) {
	if _, err := NewFrameSenderGuard(nil); err == nil {
		t.Fatal("a Verifier without a frame sender must fail closed")
	}
	if _, err := NewFrameSenderGuard(&recordingSender{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
