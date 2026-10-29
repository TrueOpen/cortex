package verifier

import (
	"context"
	"errors"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
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

type failingSender struct{ err error }

func (f failingSender) SendVerifierHandraise(context.Context, *taskv1.VerifierHandraiseV1) error {
	return f.err
}

func TestHandraiseDeliveryFailureIsRetryableUnlessThePeerSaysPermanent(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		permanent bool
	}{
		{name: "transient", err: errors.New("stream not connected")},
		{name: "permanent", err: builderclient.Permanent(errors.New("builder refused the frame")), permanent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.verifier.cfg.Sender = failingSender{err: tc.err}
			state := h.validTask()
			state.OpenVerifyAccepted = false

			_, err := h.verifier.EvaluateAndHandraise(context.Background(), state)
			if !errors.Is(err, tc.err) {
				t.Fatalf("EvaluateAndHandraise error = %v, want it to wrap %v", err, tc.err)
			}
			if tc.permanent {
				if !builderclient.IsPermanent(err) || builderclient.IsRetryable(err) {
					t.Fatalf("error = %v, want it to stay Permanent", err)
				}
				return
			}
			if !builderclient.IsRetryable(err) {
				t.Fatalf("error = %v, want a transient delivery failure to be Retryable", err)
			}
		})
	}
}
