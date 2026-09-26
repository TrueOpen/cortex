package worker

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// recordedStream is one Builder's view of the stream: what it was sent, and
// what it answers with.
type recordedStream struct {
	chunks   []builderclient.OutputChunk
	fins     []builderclient.OutputFin
	closed   int
	result   builderclient.OutputStreamResult
	sendErr  error
	finErr   error
	closeErr error
}

func (s *recordedStream) SendChunk(chunk builderclient.OutputChunk) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.chunks = append(s.chunks, chunk)
	return nil
}

func (s *recordedStream) Finish(fin builderclient.OutputFin) (builderclient.OutputStreamResult, error) {
	if s.finErr != nil {
		return builderclient.OutputStreamResult{}, s.finErr
	}
	s.fins = append(s.fins, fin)
	return s.result, nil
}

func (s *recordedStream) Close() error {
	s.closed++
	return s.closeErr
}

func fanOutFixture(t *testing.T, streams ...*recordedStream) (*fanOutOutputStream, []string) {
	t.Helper()
	opened := make([]builderclient.TaskOutputStream, 0, len(streams))
	names := make([]string, 0, len(streams))
	for i, stream := range streams {
		opened = append(opened, stream)
		names = append(names, string(rune('A'+i)))
	}
	fanOut, err := newFanOutOutputStream(opened, names)
	if err != nil {
		t.Fatalf("newFanOutOutputStream() error = %v", err)
	}
	return fanOut, names
}

func agreedResult() builderclient.OutputStreamResult {
	return builderclient.OutputStreamResult{
		OutputMMRRoot: codec.HashBytes([]byte("agreed-root")), LeafCount: 2, LastSeq: 1,
	}
}

// TestFanOutOutputStreamReachesEveryTaskBuilder is the invariant issue #13 is
// about: with three Task Builders, all three receive every frame. Before this,
// two of them received nothing and could never become data-ready.
func TestFanOutOutputStreamReachesEveryTaskBuilder(t *testing.T) {
	builders := []*recordedStream{{result: agreedResult()}, {result: agreedResult()}, {result: agreedResult()}}
	fanOut, _ := fanOutFixture(t, builders...)

	first := builderclient.OutputChunk{Seq: 0, Text: []byte("hello "), MMRRoot: codec.HashBytes([]byte("r0"))}
	second := builderclient.OutputChunk{Seq: 1, Text: []byte("world"), MMRRoot: codec.HashBytes([]byte("r1"))}
	for _, chunk := range []builderclient.OutputChunk{first, second} {
		if err := fanOut.SendChunk(chunk); err != nil {
			t.Fatalf("SendChunk(%d) error = %v", chunk.Seq, err)
		}
	}
	fin := builderclient.OutputFin{FinishReason: nodewire.FinishReasonV1EosToken, WorkerSignature: []byte("sig")}
	result, err := fanOut.Finish(fin)
	if err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
	if result != agreedResult() {
		t.Fatalf("Finish() = %#v, want the agreed result", result)
	}
	for i, builder := range builders {
		if len(builder.chunks) != 2 || builder.chunks[0].Seq != 0 || builder.chunks[1].Seq != 1 {
			t.Fatalf("Task Builder %d received %d chunks, want both", i, len(builder.chunks))
		}
		// Byte-identical, not merely present: a chunk signature covers
		// (chain_id, task_hash, seq, mmr_root) and names no recipient, so every
		// Builder must hold the same signed frame.
		if string(builder.chunks[0].Text) != "hello " || string(builder.chunks[1].Text) != "world" ||
			builder.chunks[1].MMRRoot != second.MMRRoot {
			t.Fatalf("Task Builder %d received altered frames: %#v", i, builder.chunks)
		}
		if len(builder.fins) != 1 || builder.fins[0].FinishReason != nodewire.FinishReasonV1EosToken {
			t.Fatalf("Task Builder %d received %d Fins, want exactly one", i, len(builder.fins))
		}
	}
}

// TestFanOutOutputStreamRefusesDisagreeingBuilders guards the reason Finish
// compares results at all. Each Builder rebuilds the MMR from what it received,
// so a disagreement means at least one holds a different tree, and returning
// either answer would bind a receipt to a tree not every Builder has.
func TestFanOutOutputStreamRefusesDisagreeingBuilders(t *testing.T) {
	diverged := agreedResult()
	diverged.OutputMMRRoot = codec.HashBytes([]byte("other-root"))
	fanOut, _ := fanOutFixture(t, &recordedStream{result: agreedResult()}, &recordedStream{result: diverged})

	_, err := fanOut.Finish(builderclient.OutputFin{FinishReason: nodewire.FinishReasonV1EosToken})
	if err == nil || !strings.Contains(err.Error(), "finished the output stream at root") {
		t.Fatalf("Finish() error = %v, want disagreeing Builders refused", err)
	}
}

// TestFanOutOutputStreamNamesTheFailingBuilder matters operationally: with one
// Builder the failing party was implicit, with three it is not, and a failure
// that does not say which Builder caused it cannot be acted on.
func TestFanOutOutputStreamNamesTheFailingBuilder(t *testing.T) {
	boom := errors.New("builder refused")
	fanOut, names := fanOutFixture(t, &recordedStream{result: agreedResult()}, &recordedStream{sendErr: boom})

	err := fanOut.SendChunk(builderclient.OutputChunk{Seq: 0})
	if err == nil || !strings.Contains(err.Error(), names[1]) || !errors.Is(err, boom) {
		t.Fatalf("SendChunk() error = %v, want the second Builder named and the cause wrapped", err)
	}
}

// TestFanOutOutputStreamClosesEveryBuilder pins that Close does not stop at the
// first failure: giving up halfway would leak the remaining streams.
func TestFanOutOutputStreamClosesEveryBuilder(t *testing.T) {
	first := &recordedStream{closeErr: errors.New("first close failed")}
	second := &recordedStream{}
	fanOut, _ := fanOutFixture(t, first, second)

	err := fanOut.Close()
	if err == nil || !strings.Contains(err.Error(), "first close failed") {
		t.Fatalf("Close() error = %v, want the failure reported", err)
	}
	if first.closed != 1 || second.closed != 1 {
		t.Fatalf("closed first=%d second=%d, want every stream closed once", first.closed, second.closed)
	}
}

// TestFanOutOutputStreamRefusesAnEmptySet keeps a Worker with no Builder from
// getting a stream that silently discards frames, which would surface much later
// as a receipt whose output nobody holds.
func TestFanOutOutputStreamRefusesAnEmptySet(t *testing.T) {
	if _, err := newFanOutOutputStream(nil, nil); err == nil {
		t.Fatal("newFanOutOutputStream(nil, nil) accepted an empty Builder set")
	}
	if _, err := newFanOutOutputStream([]builderclient.TaskOutputStream{&recordedStream{}}, nil); err == nil {
		t.Fatal("newFanOutOutputStream accepted a stream without a Builder name")
	}
}

// TestReceivingBuildersRefusesAnEmptySelection pins the Worker-side check: a
// provider that answers with no Builders is a refusal, not an empty fan-out.
func TestReceivingBuildersRefusesAnEmptySelection(t *testing.T) {
	w := &Worker{cfg: Config{ReceivingBuilder: emptySelectionProvider{}}}
	if _, err := w.receivingBuilders(context.Background(), ReceivingBuilderRef{TaskID: "task-1"}); err == nil ||
		!strings.Contains(err.Error(), "no resolved Task Builders") {
		t.Fatalf("receivingBuilders() error = %v, want an empty selection refused", err)
	}
}

type emptySelectionProvider struct{}

func (emptySelectionProvider) ResolveReceivingBuilder(context.Context, ReceivingBuilderRef) (BuilderEndpoint, error) {
	return BuilderEndpoint{}, nil
}

func (emptySelectionProvider) ResolveReceivingBuilders(context.Context, ReceivingBuilderRef) ([]BuilderEndpoint, error) {
	return nil, nil
}
