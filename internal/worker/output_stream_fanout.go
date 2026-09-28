package worker

import (
	"errors"
	"fmt"

	"github.com/TrueOpen/cortex/internal/builderclient"
)

// fanOutOutputStream pushes every output frame to all of the task's Task
// Builders, as the protocol requires: the Cortex Node acting as the selected
// Worker pushes each frame to all Task Builders while it generates.
//
// Sending to one Builder made the task depend on it. The other Builders accept
// Verifier handraises but can never become data-ready, so they can never send
// OPEN_VERIFY or submit a proposal, and if the one Builder goes down nobody can
// drive the task forward. The 2/3 redundancy the protocol assumes was not there.
//
// It implements builderclient.TaskOutputStream so nothing downstream has to know
// how many Builders are behind it. The signed frames are identical for all of
// them -- a chunk signature covers (chain_id, task_hash, seq, mmr_root) and
// names no recipient -- so this fans out one frame rather than producing one
// per Builder.
//
// Failure policy here is deliberately the pre-existing one: any Builder's
// failure fails the send. The protocol requires more than that -- failures
// caused by the Worker itself and by a Builder are told apart, one Builder
// dropping must not stop the others, and dropping to zero Builders stops
// sending while generation continues and buffers -- but that
// is a per-Builder state machine and is tracked separately. Landing the fan-out
// first with unchanged failure semantics keeps this change reviewable and makes
// the Builder list available to the V7b remedy, which is blocked on the same
// read.
type fanOutOutputStream struct {
	streams  []builderclient.TaskOutputStream
	builders []string
}

// newFanOutOutputStream refuses an empty set: a Worker with no Builder to send
// to has nothing to stream, and returning a stream that silently discards frames
// would surface as a receipt whose output nobody holds.
func newFanOutOutputStream(streams []builderclient.TaskOutputStream, builders []string) (*fanOutOutputStream, error) {
	if len(streams) == 0 || len(streams) != len(builders) {
		return nil, fmt.Errorf("output stream fan-out requires one stream per Task Builder")
	}
	return &fanOutOutputStream{streams: streams, builders: builders}, nil
}

func (f *fanOutOutputStream) SendChunk(chunk builderclient.OutputChunk) error {
	for i, stream := range f.streams {
		if err := stream.SendChunk(chunk); err != nil {
			return fmt.Errorf("send output chunk %d to Task Builder %s: %w", chunk.Seq, f.builders[i], err)
		}
	}
	return nil
}

// Finish terminates every stream and requires them to agree.
//
// The agreement check is the point. Each Builder independently rebuilds the MMR
// from the frames it received, so three matching results mean three Builders
// hold the same tree; a disagreement means at least one holds something else,
// and returning either answer as "the" result would bind a receipt to a tree not
// every Builder has. The first result is the reference only because one has to
// be -- any mismatch fails.
func (f *fanOutOutputStream) Finish(fin builderclient.OutputFin) (builderclient.OutputStreamResult, error) {
	var reference builderclient.OutputStreamResult
	for i, stream := range f.streams {
		result, err := stream.Finish(fin)
		if err != nil {
			return builderclient.OutputStreamResult{}, fmt.Errorf("finish output stream to Task Builder %s: %w", f.builders[i], err)
		}
		if i == 0 {
			reference = result
			continue
		}
		if result.OutputMMRRoot != reference.OutputMMRRoot || result.LeafCount != reference.LeafCount || result.LastSeq != reference.LastSeq {
			return builderclient.OutputStreamResult{}, fmt.Errorf(
				"Task Builder %s finished the output stream at root %s leaves %d, but %s finished at root %s leaves %d",
				f.builders[i], result.OutputMMRRoot, result.LeafCount,
				f.builders[0], reference.OutputMMRRoot, reference.LeafCount)
		}
	}
	return reference, nil
}

// Close closes every stream and reports all failures. Unlike the send path it
// does not stop at the first error: a Close that gave up halfway would leak the
// remaining streams, and by this point there is nothing left to abort.
func (f *fanOutOutputStream) Close() error {
	var errs []error
	for i, stream := range f.streams {
		if err := stream.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close output stream to Task Builder %s: %w", f.builders[i], err))
		}
	}
	return errors.Join(errs...)
}
