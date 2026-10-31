package dispatchstream

import (
	"testing"
	"time"
)

func TestSessionStateFollowsTheBinding(t *testing.T) {
	h := startSession(t, func(c *Config) { c.Backoff = func(int) time.Duration { return time.Hour } })
	c, _ := h.bind(t)
	eventually(t, "bound after the binding", func() bool { return h.current().State().Bound })
	if st := h.current().State(); st.LastError != "" || st.Since.IsZero() {
		t.Fatalf("bound state = %+v", st)
	}
	c.disconnect()
	eventually(t, "reconnecting after the Builder left", func() bool {
		st := h.current().State()
		return !st.Bound && st.LastError != ""
	})
}
