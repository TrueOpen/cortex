package daemon

import (
	"context"
	"fmt"
	"testing"
)

func TestIsContextShutdownRequiresOwningContextError(t *testing.T) {
	liveCtx := context.Background()
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	expiredCtx, expire := context.WithTimeout(context.Background(), 0)
	defer expire()

	tests := []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{name: "foreign deadline while live", ctx: liveCtx, err: fmt.Errorf("keeper request: %w", context.DeadlineExceeded)},
		{name: "foreign cancellation while live", ctx: liveCtx, err: fmt.Errorf("keeper request: %w", context.Canceled)},
		{name: "own cancellation", ctx: canceledCtx, err: fmt.Errorf("poll: %w", context.Canceled), want: true},
		{name: "own deadline", ctx: expiredCtx, err: fmt.Errorf("poll: %w", context.DeadlineExceeded), want: true},
		{name: "unrelated error during cancellation", ctx: canceledCtx, err: fmt.Errorf("database failed")},
		{name: "different context sentinel", ctx: canceledCtx, err: context.DeadlineExceeded},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isContextShutdown(test.ctx, test.err); got != test.want {
				t.Fatalf("isContextShutdown() = %t, want %t", got, test.want)
			}
		})
	}
}
