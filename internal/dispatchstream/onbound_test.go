package dispatchstream

import (
	"sync/atomic"
	"testing"
)

func TestOnBoundRunsOncePerBinding(t *testing.T) {
	var bound atomic.Int32
	h := startSession(t, func(c *Config) {
		c.OnBound = func(builder string) {
			if builder != testOperator {
				t.Errorf("OnBound for %s", builder)
			}
			bound.Add(1)
		}
	})
	c, _ := h.bind(t)
	eventually(t, "OnBound after the first binding", func() bool { return bound.Load() == 1 })
	c.disconnect()
	h.bind(t)
	eventually(t, "OnBound after the reconnect", func() bool { return bound.Load() == 2 })
}
