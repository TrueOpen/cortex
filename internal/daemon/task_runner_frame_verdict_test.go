package daemon

import (
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// builderFrameVerdict is the one place a Builder frame's admission error is
// classified and reported, so its four outcomes are pinned together.
func TestBuilderFrameVerdict(t *testing.T) {
	taskID := []byte{0xab, 0xcd, 0x01}
	for _, testCase := range []struct {
		name            string
		err             error
		wantNil         bool
		wantPermanent   bool
		wantDiagnostics int
		wantWaiting     bool
	}{
		{name: "store conflict is permanent", err: fmt.Errorf("%w: f", layout.ErrConflict), wantPermanent: true, wantDiagnostics: 1},
		{name: "plain error is not permanent", err: errors.New("transient"), wantDiagnostics: 1},
		{name: "first chain-state wait is reported as waiting", err: fmt.Errorf("%w: window", errChainStateWaiting), wantDiagnostics: 1, wantWaiting: true},
		{name: "repeated chain-state wait is not reported again", err: fmt.Errorf("%w: %w", errRepeatedChainStateWait, fmt.Errorf("%w: window", errChainStateWaiting))},
		{name: "nil is admitted", err: nil, wantNil: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var diagnostics []TaskRunnerDiagnostic
			runner := &TaskRunner{cfg: TaskRunnerConfig{Diagnostic: func(d TaskRunnerDiagnostic) { diagnostics = append(diagnostics, d) }}}

			got := runner.builderFrameVerdict("nexus_test", taskID, testCase.err)
			if testCase.wantNil {
				if got != nil {
					t.Fatalf("builderFrameVerdict(nil) = %v, want nil", got)
				}
			} else if got == nil {
				t.Fatal("builderFrameVerdict() = nil, want the error back")
			}
			if builderclient.IsPermanent(got) != testCase.wantPermanent {
				t.Fatalf("IsPermanent(%v) = %v, want %v", got, builderclient.IsPermanent(got), testCase.wantPermanent)
			}
			if len(diagnostics) != testCase.wantDiagnostics {
				t.Fatalf("diagnostics = %#v, want %d", diagnostics, testCase.wantDiagnostics)
			}
			if testCase.wantDiagnostics == 0 {
				return
			}
			d := diagnostics[0]
			if d.Source != "nexus_test" || d.Record != hex.EncodeToString(taskID) || d.Error != got.Error() || d.Waiting != testCase.wantWaiting {
				t.Fatalf("diagnostic = %#v, want source nexus_test, record %s, waiting %v", d, hex.EncodeToString(taskID), testCase.wantWaiting)
			}
		})
	}
}
