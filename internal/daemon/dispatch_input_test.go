package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/store/layout"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
)

func TestDispatchInputIsStagedVerifiedAndStartsInference(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	in := x.fx.input
	half := len(in) / 2
	tail := x.fx.inputResponse(1, 2, in[half:])
	for i := 0; i < 2; i++ {
		if err := x.d.HandleInputResponse(ctx, hrBuilderA, tail); err != nil {
			t.Fatalf("chunk 1 delivery %d: %v", i, err)
		}
	}
	if len(x.infer.starts()) != 0 {
		t.Fatal("inference waits for every chunk")
	}
	err := x.d.HandleInputResponse(ctx, hrBuilderA, x.fx.inputResponse(1, 2, []byte("x")))
	if err == nil || builderclient.IsRetryable(err) {
		t.Fatalf("a chunk that changed bytes: err = %v, want permanent", err)
	}
	// The refused chunk reset the staging (N1): nothing staged survives it,
	// so the consistent re-send starts over.
	if chunks, _ := dispatchInputChunks(ctx, x.st, layout.StoredHash(x.fx.ticketHash())); len(chunks) != 0 {
		t.Fatalf("%d chunks survived a refused chunk", len(chunks))
	}
	if err := x.d.HandleInputResponse(ctx, hrBuilderA, tail); err != nil {
		t.Fatal(err)
	}
	// The last chunk comes through the stream Handler entry point.
	head := &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_InputResponse{InputResponse: x.fx.inputResponse(0, 2, in[:half])}}
	if err := x.d.HandleFrame(ctx, hrBuilderA, head); err != nil {
		t.Fatal(err)
	}
	starts := x.infer.starts()
	if len(starts) != 1 {
		t.Fatalf("starts = %d", len(starts))
	}
	e := starts[0]
	th, task := x.fx.ticketHash(), x.fx.taskHash()
	if e.TicketHash != layout.StoredHash(th) || e.TaskHash != layout.StoredHash(task) || e.TaskID != hex.EncodeToString(x.fx.ticket.TaskId) ||
		e.SessionID != hex.EncodeToString(x.fx.ticket.SessionId) || e.OrderSequence != 1 || e.ModelID != hrModelAB || e.ProfileVersion != 1 ||
		e.InputSizeBytes != uint64(len(in)) || e.BuilderOperator != hrBuilderA || e.WorkerAddress != hrCortex ||
		e.BuilderSetID != "7" || e.ClaimFromHeight != 109+dpRecordDeadline {
		t.Fatalf("entry = %+v", e)
	}
	got, err := x.ev.ReadTaskKind(ctx, codec.Hash(task), string(layout.ArtifactTaskInput))
	if err != nil || !bytes.Equal(got, in) {
		t.Fatalf("staged input = %q, %v", got, err)
	}
	rec := x.record(t)
	if !rec.InputCommitted {
		t.Fatal("input committed is recorded")
	}
	if open, _ := openDispatches(ctx, x.st); len(open) != 0 {
		t.Fatal("a ticket with committed input is no longer open")
	}
	if chunks, _ := dispatchInputChunks(ctx, x.st, rec.TicketHash); len(chunks) != 0 {
		t.Fatal("chunks are dropped once the input is committed")
	}
	if err := x.d.HandleInputResponse(ctx, hrBuilderA, tail); err != nil || len(x.infer.starts()) != 1 {
		t.Fatalf("input after the commit is a no-op: %v", err)
	}
}

func TestDispatchInputThatDoesNotMatchIsDiscardedAndAskedAgain(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	bad := bytes.Repeat([]byte{'z'}, len(x.fx.input))
	if err := x.d.HandleInputResponse(ctx, hrBuilderA, x.fx.inputResponse(0, 1, bad)); err == nil {
		t.Fatal("bytes that do not hash to input_hash are refused")
	}
	if len(x.infer.starts()) != 0 {
		t.Fatal("unverified bytes never reach the model")
	}
	rec := x.record(t)
	if rec.InputChunkCount != 0 || rec.InputRequestedAtUnixMs != 0 || rec.InputCommitted {
		t.Fatalf("record = %+v: the bad input is forgotten and asked for again", rec)
	}
	if chunks, _ := dispatchInputChunks(ctx, x.st, rec.TicketHash); len(chunks) != 0 {
		t.Fatal("bad chunks are deleted")
	}
	if _, err := x.ev.ReadTaskKind(ctx, codec.Hash(x.fx.taskHash()), string(layout.ArtifactTaskInput)); err == nil {
		t.Fatal("unverified bytes never reach the evidence store (TD §5.1)")
	}
	if err := x.d.HandleInputResponse(ctx, hrBuilderA, x.fx.inputResponse(0, 1, x.fx.input)); err != nil || len(x.infer.starts()) != 1 {
		t.Fatalf("the right bytes then start inference: %v", err)
	}
}

func TestDispatchInputOnlyForAnAcceptedTicketFromItsBuilder(t *testing.T) {
	ctx := context.Background()
	x := newDispatchHarness(t, 2, nil)
	if err := x.d.HandleInputResponse(ctx, hrBuilderA, x.fx.inputResponse(0, 1, x.fx.input)); err == nil {
		t.Fatal("input for an unknown ticket is refused")
	}
	if err := x.handle(ctx); err != nil {
		t.Fatal(err)
	}
	if err := x.d.HandleInputResponse(ctx, hrBuilderB, x.fx.inputResponse(0, 1, x.fx.input)); err == nil {
		t.Fatal("input from another Builder is refused")
	}
	y := newDispatchHarness(t, 2, nil)
	y.chain.with(func(f *fakeDispatchChain) { f.session.BoundChangeHeight = 106 })
	if err := y.handle(ctx); err != nil {
		t.Fatal(err)
	}
	if err := y.d.HandleInputResponse(ctx, hrBuilderA, y.fx.inputResponse(0, 1, y.fx.input)); err != nil || len(y.infer.starts()) != 0 {
		t.Fatalf("input for a rejected ticket is ignored: %v", err)
	}
}
