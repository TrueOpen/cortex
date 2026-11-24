package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/cortex/internal/store/layout"
)

// The C4 drop of an evaluated offer says where the accept window went, so an
// operator can tell a window that was short on arrival (the Builder's timeout
// against this link) from a slow answer (this node's reads).
func TestLateAcceptNamesTheWindowAndTheAnswerTime(t *testing.T) {
	x := newDispatchHarness(t, 1, nil)
	ticket := layout.StoredHash{7}
	deadline := x.d.noteReceipt(ticket, uint64(x.now.Add(2500*time.Millisecond).UnixMilli()), layout.DispatchRecord{}, false)
	got := x.d.lateAccept(ticket, deadline)
	if !strings.Contains(got, "(C4)") || !strings.Contains(got, "2500 ms of its accept window left") || !strings.Contains(got, "took 0 ms") {
		t.Fatalf("lateAccept = %q", got)
	}
	x.d.forgetDeadline(ticket)
	if got := x.d.lateAccept(ticket, deadline); got != "accept deadline passed before the accept was signed (C4)" {
		t.Fatalf("an offer this process did not time: %q", got)
	}
}
