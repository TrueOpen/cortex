package verifier

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/modelservice"
)

// detokenizingModel is a model client with the OutputDetokenizer capability:
// it answers DetokenizeCommitted from a canned result and records what it was
// asked to decode.
type detokenizingModel struct {
	modelservice.Client
	decoded []byte
	err     error

	gotModelID        string
	gotProfileVersion string
	gotGenerated      []uint32
}

func (m *detokenizingModel) DetokenizeCommitted(_ context.Context, modelID, profileVersion string, generated []uint32) ([]byte, error) {
	m.gotModelID, m.gotProfileVersion, m.gotGenerated = modelID, profileVersion, generated
	return m.decoded, m.err
}

// plainModel has no Detokenize capability, like the cortex.v1 gRPC client.
type plainModel struct{ modelservice.Client }

// checkOutputDecodesFromTokens faults a Worker whose confirmed output is not
// the decode of its committed token ids, skips model services that cannot
// decode and profiles that declare no decoding, and folds ill-formed output
// bytes to U+FFFD before comparing -- the same fold the decode side went
// through.
func TestCheckOutputDecodesFromTokens(t *testing.T) {
	state := TaskState{ModelID: "model-under-test", ProfileVersion: 7}
	generated := []uint32{10, 11, 151645}
	for _, test := range []struct {
		name    string
		model   modelservice.Client
		output  string
		wantErr string
	}{
		{"matching decode scores", &detokenizingModel{decoded: []byte("hello world")}, "hello world", ""},
		{"tampered output faults", &detokenizingModel{decoded: []byte("hello world")}, "hello world!", "WORKER_EVIDENCE_FAULT"},
		{"truncated tail folds to U+FFFD", &detokenizingModel{decoded: []byte("ok�")}, "ok\xE4\xB8", ""},
		{"no declared decoding skips", &detokenizingModel{err: fmt.Errorf("profile x: %w", modelservice.ErrNoOutputDecoding)}, "anything", ""},
		{"decode failure is not a fault", &detokenizingModel{err: errors.New("engine down")}, "hello world", "engine down"},
		{"undetokenizing model service skips", &plainModel{}, "anything", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			v := &Verifier{cfg: Config{Model: test.model}}
			err := v.checkOutputDecodesFromTokens(context.Background(), state, generated, []byte(test.output))
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("checkOutputDecodesFromTokens() error = %v, want nil", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("checkOutputDecodesFromTokens() error = %v, want it to contain %q", err, test.wantErr)
			}
			if m, ok := test.model.(*detokenizingModel); ok && m.gotModelID != "" {
				if m.gotModelID != state.ModelID || m.gotProfileVersion != "7" || len(m.gotGenerated) != len(generated) {
					t.Fatalf("decode asked for %s@%s over %d ids, want %s@7 over %d",
						m.gotModelID, m.gotProfileVersion, len(m.gotGenerated), state.ModelID, len(generated))
				}
			}
		})
	}
}
