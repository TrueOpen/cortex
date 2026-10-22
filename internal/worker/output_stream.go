package worker

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/tasktrace"
)

const OutputStreamFramePrefix = "worker-output-frame:"
const OutputStreamFinKind = "worker-output-fin"

func OutputStreamFrameKind(seq uint64) string {
	return fmt.Sprintf("%s%020d", OutputStreamFramePrefix, seq)
}

// maxFrameRampBytes is where the ramp below stops, and from there on it is the
// minimum size of every frame but the last. It is a protocol constant rather
// than a chain parameter because the chain carries the other end of the ramp,
// and both ends have to be stated somewhere for three implementations to agree
// on the same frame boundaries.
const maxFrameRampBytes = 256

// minFrameBytes is the smallest frame this node may commit at seq. The chain
// parameter min_output_stream_frame_bytes is the minimum of frame 0 rather than
// of every frame: a reader sees the start of an answer after a fraction of the
// generation a flat floor would have required, while the minimum doubles per
// frame until it reaches maxFrameRampBytes, where ADR-0017's floor against
// micro-frame inflation governs the bulk of the stream. The last frame keeps
// its separate exemption and never consults this.
func minFrameBytes(floor uint32, seq uint64) uint64 {
	minimum := uint64(floor)
	// The ramp only ever climbs to the cap. A chain carrying a floor at or above
	// it is asking for frames at least that large, and lowering them to the cap
	// would emit frames the Builder is entitled to reject.
	if minimum >= maxFrameRampBytes {
		return minimum
	}
	// seq is bounded only by max_output_mmr_leaves, so it reaches far past the
	// point the ramp flattens. Any floor of at least one byte is at the cap
	// within the cap's bit width, which keeps the shift below from overflowing.
	if seq >= uint64(bits.Len64(maxFrameRampBytes)) {
		return maxFrameRampBytes
	}
	return min(minimum<<seq, maxFrameRampBytes)
}

type outputStreamRecorder struct {
	w            *Worker
	ctx          context.Context
	event        chainclient.AssignmentFinalized
	taskHash     codec.Hash
	mmr          *codec.MMR
	stream       builderclient.TaskOutputStream
	frames       []builderclient.OutputChunk
	pending      []byte
	total        uint64
	err          error
	deferredErr  error
	transportErr error

	// inferStartedAt is set immediately before the generation request leaves for
	// the engine, so the two latencies an operator asks about are measured from
	// the same instant: the engine's first delta, and the first signed frame this
	// node puts on the wire. They are not the same number -- a frame is held back
	// until it reaches min_output_stream_frame_bytes -- and only the second one is
	// what a waiting reader actually sees.
	inferStartedAt time.Time
	// prepareStartedAt is the other baseline the two first-output milestones
	// publish. inferStartedAt deliberately excludes the preparation above, so a
	// reader with only that number attributes the whole preparation to the
	// engine -- and infer_completed publishes a field of the same name measured
	// from before it. Carrying both ends the ambiguity in the line itself.
	prepareStartedAt time.Time
	firstDeltaAt     time.Time
	firstFrameTraced bool

	// The fields below order a stream opened while the model generates (see
	// openStreamConcurrently) against the frames emit signs meanwhile.
	// streamMu guards stream, transportErr, openPending and the frames slice
	// whenever an open is pending; emit holds it across the frame append and
	// the send, and the opener holds it while it replays the frames already
	// signed, so every frame reaches the stream exactly once, in seq order.
	streamMu sync.Mutex
	// openPending is true while the concurrent open has not landed. Frames
	// signed meanwhile are journaled and kept in frames; the opener sends
	// them when the stream is up.
	openPending bool
	// openDone is closed when the concurrent open has landed; nil when the
	// stream was opened before generation.
	openDone chan struct{}
	// cancelOpen cancels the context the concurrent stream was opened under.
	// The stream lives as long as that context, so it is cancelled only when
	// the stream is released (release, or Worker.closeOutputStream once the
	// stream was handed over).
	cancelOpen context.CancelFunc
}

type deferredFrameError struct{ err error }

func (e deferredFrameError) Error() string { return e.err.Error() }
func (e deferredFrameError) Unwrap() error { return e.err }

// Retain the completed model response before fetching artifacts so a transient
// artifact failure can resume the same signed generation.
type completedModelInference struct {
	RequestDigest codec.Hash
	TaskHash      codec.Hash
	Response      modelservice.InferResponse
	FrameCount    uint64
	Pending       []byte
	ObservedBytes uint64
}

// signedOutputFin is journaled before the network Fin is sent. Signers are not
// required to use deterministic ECDSA, so recomputing a valid signature after
// a disconnect would not preserve the original frame bytes.
type signedOutputFin struct {
	TaskHash        codec.Hash
	FinalSeq        uint64
	OutputMMRRoot   codec.Hash
	FinishReason    nodewire.FinishReasonV1
	WorkerSignature []byte
}

func (w *Worker) resumeOutputRecorder(ctx context.Context, event chainclient.AssignmentFinalized, saved completedModelInference) (*outputStreamRecorder, error) {
	if w.cfg.StreamLimits == nil || w.cfg.StreamLimits.MinOutputStreamFrameBytes == 0 || w.cfg.StreamLimits.MaxOutputMMRLeaves == 0 {
		return nil, fmt.Errorf("committed output stream limits are required")
	}
	facts, err := w.taskFacts(ctx, event.TaskID)
	if err != nil {
		return nil, err
	}
	if saved.TaskHash != codec.Hash(facts.AcceptedTaskHash) {
		return nil, fmt.Errorf("completed model response task commitment differs from assignment")
	}
	frames, err := w.cfg.Persistence.OutputStreamFrames(ctx, event.TaskID)
	if err != nil {
		return nil, err
	}
	if uint64(len(frames)) < saved.FrameCount || uint64(len(frames)) > saved.FrameCount+1 {
		return nil, fmt.Errorf("completed model response and signed frame journal disagree")
	}
	mmr, err := codec.NewMMR(codec.DomainOutputMMRV1)
	if err != nil {
		return nil, err
	}
	var total uint64
	for index, frame := range frames {
		if frame.Seq != uint64(index) || !utf8.Valid(frame.Text) || len(frame.Attachment) != 0 || len(frame.AttachmentSignature) != 0 {
			return nil, fmt.Errorf("completed model signed frame is invalid")
		}
		if uint64(len(frame.Text)) > ^uint64(0)-total {
			return nil, fmt.Errorf("completed model output size overflows")
		}
		total += uint64(len(frame.Text))
		if err := mmr.Append(frame.Text); err != nil {
			return nil, err
		}
		if mmr.Root() != frame.MMRRoot {
			return nil, fmt.Errorf("completed model frame root mismatch")
		}
		digest, err := nodewire.OutputChunkSigningDigest(w.cfg.ChainID, saved.TaskHash[:], frame.Seq, frame.MMRRoot[:])
		if err != nil {
			return nil, err
		}
		if err := signer.VerifyDigestSignature(w.cfg.SignerPubkey, digest, frame.WorkerSignature); err != nil {
			return nil, err
		}
	}
	pending := append([]byte(nil), saved.Pending...)
	if uint64(len(frames)) == saved.FrameCount {
		if uint64(len(pending)) > ^uint64(0)-total || total+uint64(len(pending)) != saved.ObservedBytes {
			return nil, fmt.Errorf("completed model pending suffix is inconsistent")
		}
		total = saved.ObservedBytes
	} else {
		if saved.ObservedBytes != 0 && !bytes.Equal(frames[len(frames)-1].Text, pending) {
			return nil, fmt.Errorf("completed model final signed frame differs from retained suffix")
		}
		pending = nil
	}
	// A resumed task already streamed its first frame in an earlier run; there is
	// no first-frame latency left to measure, only frames to re-send.
	r := &outputStreamRecorder{w: w, ctx: ctx, event: event, taskHash: saved.TaskHash, mmr: mmr, frames: frames, pending: pending, total: total,
		firstFrameTraced: len(frames) > 0}
	r.stream, r.transportErr = w.openOutputStream(ctx, event, saved.TaskHash, frames)
	return r, nil
}

func (w *Worker) newOutputRecorder(ctx context.Context, event chainclient.AssignmentFinalized) (*outputStreamRecorder, error) {
	if w.cfg.StreamLimits == nil || w.cfg.StreamLimits.MinOutputStreamFrameBytes == 0 || w.cfg.StreamLimits.MaxOutputMMRLeaves == 0 {
		return nil, fmt.Errorf("committed output stream limits are required")
	}
	frames, err := w.cfg.Persistence.OutputStreamFrames(ctx, event.TaskID)
	if err != nil {
		return nil, err
	}
	if len(frames) > 0 {
		// Classified rather than left bare. This is the one refusal whose remedy
		// is definitively NOT another generation: the frames already carry this
		// node's signature over (task_hash, seq, mmr_root), so a second run would
		// sign a different prefix under one task hash. The scheduler must stop
		// here and say so, not spend a retry budget rediscovering it.
		return nil, modelservice.RegenerationForbidden(
			modelservice.FaultCodeOutputFramesAlreadySigned,
			fmt.Errorf("inference interrupted after signing output frames; cannot regenerate a different prefix for this task"),
			modelservice.FaultInt("signed_frames", len(frames)),
			modelservice.FaultStr("task", event.TaskID))
	}
	facts, err := w.taskFacts(ctx, event.TaskID)
	if err != nil {
		return nil, err
	}
	mmr, err := codec.NewMMR(codec.DomainOutputMMRV1)
	if err != nil {
		return nil, err
	}
	r := &outputStreamRecorder{w: w, ctx: ctx, event: event, taskHash: codec.Hash(facts.AcceptedTaskHash), mmr: mmr}
	r.openStreamConcurrently(ctx)
	return r, nil
}

// openStreamConcurrently opens the output stream while the model starts
// generating, instead of before it: resolving the Task Builders and the
// handshakes with each of them no longer delay the generation request.
//
// Nothing about the frames depends on the stream. A frame's seq, MMR root and
// signature depend only on the task hash, which is already known, and every
// frame is journaled before it is sent; the stream only carries them. A frame
// signed before the stream is up waits in frames, and the opener sends the
// waiting frames, in order, the moment the stream is up -- the same replay
// that already carries signed frames over a reopened stream.
//
// A failed open is what it was before: the transport error is kept, the model
// keeps generating, every frame is signed and journaled, and the stream is
// reopened with those frames as replay when the output is stored. Failing the
// attempt instead would forbid it from ever completing, because signed frames
// may not be regenerated.
func (r *outputStreamRecorder) openStreamConcurrently(ctx context.Context) {
	openCtx, cancel := context.WithCancel(ctx)
	r.cancelOpen = cancel
	r.openPending = true
	r.openDone = make(chan struct{})
	r.w.prepare.streamConcurrent = true
	prepareStartedAt := r.w.prepare.startedAt
	go func() {
		defer close(r.openDone)
		var timing streamOpenTiming
		stream, err := r.w.openOutputStreamTimed(openCtx, r.event, r.taskHash, nil, &timing)
		openedAt := time.Now()
		r.streamMu.Lock()
		r.stream, r.transportErr = stream, err
		queued := len(r.frames)
		for _, frame := range r.frames {
			if r.stream == nil {
				break
			}
			r.sendLocked(frame)
		}
		r.openPending = false
		attached := r.stream != nil
		r.streamMu.Unlock()
		since := tasktrace.Field{}
		if !prepareStartedAt.IsZero() {
			since = tasktrace.Millis("since_prepare_started_ms", openedAt.Sub(prepareStartedAt))
		}
		traceOpened := r.w.cfg.Trace.Event
		if err != nil {
			traceOpened = r.w.cfg.Trace.ErrorEvent
		}
		traceOpened("output_stream_opened",
			tasktrace.Str("task", r.event.TaskID),
			tasktrace.Millis("resolve_builders_ms", timing.resolveBuilders),
			tasktrace.Millis("open_stream_ms", timing.openStream),
			tasktrace.Int("builders", timing.builders),
			since,
			// Frames signed before the stream was up and sent on it right
			// after: non-zero means generation outran the handshakes.
			tasktrace.Int("frames_queued", queued),
			tasktrace.Bool("transport_attached", attached),
			tasktrace.Err("error", err))
	}()
}

// awaitOpen waits for a concurrent stream open to land. The open runs under a
// context derived from the attempt's, so it cannot outlive the attempt.
// Afterwards the stream fields are only used by the attempt's goroutine.
func (r *outputStreamRecorder) awaitOpen() {
	if r.openDone != nil {
		<-r.openDone
	}
}

// release closes a stream that was not handed over to the storing step and
// cancels the context it was opened under. A pending open is cancelled first
// and waited for, so nothing is left running.
func (r *outputStreamRecorder) release() {
	// cancelOpen is still set only when the stream was not handed over, so
	// whatever it opened is being discarded.
	if r.cancelOpen != nil {
		r.cancelOpen()
		r.cancelOpen = nil
	}
	r.awaitOpen()
	if r.stream != nil {
		_ = r.stream.Close()
		r.stream = nil
	}
}

// sendLocked sends one signed frame, dropping the stream on a transport
// failure; the frame stays journaled and is replayed on the next open.
// Callers hold streamMu or are the only user of the stream.
func (r *outputStreamRecorder) sendLocked(chunk builderclient.OutputChunk) {
	if err := r.stream.SendChunk(chunk); err != nil {
		r.transportErr = err
		_ = r.stream.Close()
		r.stream = nil
	}
}

// openOutputStream opens one stream per Task Builder and returns them as a
// single fan-out stream: the selected Worker must push every frame to every Builder.
//
// The request authorization is per Builder, not shared: SignRequest binds the
// recipient's operator address, so each Builder gets a token naming itself. The
// body digest and the replay frames are the same for all of them.
//
// A Builder that cannot be opened fails the whole open. The protocol allows sending to
// continue while at least one Builder receives, but acting on that needs the
// per-Builder liveness tracking this change does not add yet; failing here keeps
// the behaviour honest rather than silently streaming to a subset.
func (w *Worker) openOutputStream(ctx context.Context, event chainclient.AssignmentFinalized, taskHash codec.Hash, frames []builderclient.OutputChunk) (builderclient.TaskOutputStream, error) {
	var timing streamOpenTiming
	stream, err := w.openOutputStreamTimed(ctx, event, taskHash, frames, &timing)
	w.prepare.resolveBuilders += timing.resolveBuilders
	w.prepare.openStream += timing.openStream
	if timing.resolved {
		w.prepare.builders = timing.builders
	}
	return stream, err
}

// streamOpenTiming is one stream open's share of the preparation timing. It
// is kept apart from Worker.prepare so an open running beside the generation
// does not write the Worker's fields.
type streamOpenTiming struct {
	resolveBuilders time.Duration
	openStream      time.Duration
	builders        int
	resolved        bool
}

func (w *Worker) openOutputStreamTimed(ctx context.Context, event chainclient.AssignmentFinalized, taskHash codec.Hash, frames []builderclient.OutputChunk, timing *streamOpenTiming) (builderclient.TaskOutputStream, error) {
	resolveStartedAt := time.Now()
	endpoints, err := w.openReceivingBuilders(ctx, receivingBuilderRef(event))
	timing.resolveBuilders += time.Since(resolveStartedAt)
	if err != nil {
		return nil, err
	}
	// Reported beside open_stream_ms, because the loop below opens one stream
	// per Builder in turn: the count is what the duration has to be read against.
	timing.builders, timing.resolved = len(endpoints), true
	openStartedAt := time.Now()
	defer func() { timing.openStream += time.Since(openStartedAt) }()
	digest, err := builderclient.TaskDataOutputStreamBodyDigest(taskHash.String(), event.SessionID, event.TaskID)
	if err != nil {
		return nil, err
	}
	key := builderclient.TaskDataKey{TaskHash: taskHash.String(), SessionID: event.SessionID, TaskID: event.TaskID, Kind: builderclient.DataKindOutput}
	// The Worker signs the plaintext OutputStreamHeaderV2 once per stream with
	// the same service key that signs the frames and the fin; the published
	// header vector names that key.
	headerDigest, err := builderclient.OutputStreamHeaderDigest(w.cfg.ChainID, taskHash.String())
	if err != nil {
		return nil, err
	}
	headerSignature, err := w.signDigest(ctx, headerDigest)
	if err != nil {
		return nil, fmt.Errorf("sign output stream header: %w", err)
	}
	// Opened together rather than one after another. Each open is a TLS
	// handshake and a round trip for the header acknowledgement, and the
	// Builders share nothing that would order them: separate endpoints,
	// separate authorisation, the same header signature and the same replay
	// frames. In turn they cost the sum of the handshakes; together they cost
	// the slowest one, which on a node deployed away from the Builders is the
	// difference between most of the wait before the first token and a third of
	// it.
	//
	// Results are written by index, never appended. The fan-out pairs the two
	// slices by position and names a failing Builder by looking its address up
	// at the stream's index, so an open that finishes early must not take an
	// earlier slot.
	streams := make([]builderclient.TaskOutputStream, len(endpoints))
	builders := make([]string, len(endpoints))
	errs := make([]error, len(endpoints))
	closeOpened := func() {
		for _, opened := range streams {
			if opened != nil {
				_ = opened.Close()
			}
		}
	}
	var wg sync.WaitGroup
	for i, endpoint := range endpoints {
		wg.Go(func() {
			auth, err := w.cfg.TaskDataAuth.SignRequest(ctx, "UploadTaskOutputStream", key, endpoint.OperatorAddress, digest)
			if err != nil {
				errs[i] = err
				return
			}
			stream, err := w.cfg.TaskData.OpenTaskOutputStream(
				builderclient.WithTLSPubkeyHash(ctx, endpoint.TLSPubkeyHash), endpoint.Endpoint,
				builderclient.OutputStreamRequest{TaskHash: taskHash.String(), SessionID: event.SessionID, TaskID: event.TaskID, Auth: auth, HeaderSignature: headerSignature, ReplayChunks: frames})
			if err != nil {
				errs[i] = fmt.Errorf("open output stream to Task Builder %s: %w", endpoint.OperatorAddress, err)
				return
			}
			streams[i] = stream
			builders[i] = endpoint.OperatorAddress
		})
	}
	// Every open is waited for before any is judged, so a refusal cannot leave
	// a handshake still running against a Builder nobody will stream to. The
	// first failure in Builder order is reported, which is the one the serial
	// loop would have reached.
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			closeOpened()
			return nil, err
		}
	}
	fanOut, err := newFanOutOutputStream(streams, builders)
	if err != nil {
		closeOpened()
		return nil, err
	}
	return fanOut, nil
}

func (r *outputStreamRecorder) ObserveInferFrame(ctx context.Context, frame modelservice.InferStreamFrame) error {
	if r.err != nil {
		return r.err
	}
	if frame.TaskID != r.event.TaskID || frame.RequestID != "infer-"+r.event.TaskID {
		r.err = fmt.Errorf("model stream frame identity mismatch")
		return r.err
	}
	if frame.Done {
		return nil
	}
	if !utf8.ValidString(frame.TextDelta) {
		r.err = fmt.Errorf("model stream text is not UTF-8")
		return r.err
	}
	if len(frame.TextDelta) > 0 && r.firstDeltaAt.IsZero() {
		r.firstDeltaAt = time.Now()
		r.w.cfg.Trace.Event("output_first_delta",
			tasktrace.Str("task", r.event.TaskID),
			tasktrace.Millis("since_infer_started_ms", r.firstDeltaAt.Sub(r.inferStartedAt)),
			r.sincePrepareStarted(r.firstDeltaAt),
			tasktrace.Int("delta_bytes", len(frame.TextDelta)))
	}
	limit := r.w.cfg.MaxOutputBytes
	if limit == 0 {
		limit = 64 << 20
	}
	if uint64(len(frame.TextDelta)) > limit-r.total {
		r.err = fmt.Errorf("streamed output exceeds local byte limit")
		return r.err
	}
	r.total += uint64(len(frame.TextDelta))
	r.pending = append(r.pending, frame.TextDelta...)
	if r.deferredErr == nil && uint64(len(r.pending)) >= minFrameBytes(r.w.cfg.StreamLimits.MinOutputStreamFrameBytes, r.mmr.LeafCount()) {
		if err := r.emit(ctx, r.pending); err != nil {
			var deferred deferredFrameError
			if errors.As(err, &deferred) {
				r.deferredErr = deferred.err
			} else {
				r.err = err
			}
		} else {
			r.pending = nil
		}
	}
	return r.err
}

func (r *outputStreamRecorder) emit(ctx context.Context, text []byte) error {
	if r.mmr.LeafCount() >= r.w.cfg.StreamLimits.MaxOutputMMRLeaves {
		return fmt.Errorf("output MMR leaf limit exceeded")
	}
	seq := r.mmr.LeafCount()
	candidate := r.mmr.Clone()
	if err := candidate.Append(text); err != nil {
		return err
	}
	root := candidate.Root()
	digest, err := nodewire.OutputChunkSigningDigest(r.w.cfg.ChainID, r.taskHash[:], seq, root[:])
	if err != nil {
		return err
	}
	signature, err := r.w.signDigest(ctx, digest)
	if err != nil {
		if errors.Is(err, signer.ErrRetryable) || builderclient.IsRetryable(err) {
			return deferredFrameError{err: err}
		}
		return err
	}
	chunk := builderclient.OutputChunk{Seq: seq, Text: append([]byte(nil), text...), MMRRoot: root, WorkerSignature: signature}
	encoded, err := json.Marshal(chunk)
	if err != nil {
		return err
	}
	if err := r.w.cfg.Persistence.WriteEvidence(ctx, EvidenceRecord{TaskID: r.event.TaskID, Kind: OutputStreamFrameKind(seq), Data: encoded}); err != nil {
		return deferredFrameError{err: err}
	}
	// The append and the send are one step under streamMu, so a stream that
	// lands from a concurrent open in between either replays this frame or
	// lets it be sent here, never both and never neither.
	r.streamMu.Lock()
	r.mmr = candidate
	r.frames = append(r.frames, chunk)
	attached, pending := r.stream != nil, r.openPending
	// Keep collecting durable model output after a network failure. The same
	// signed frames can then resume without rerunning generation or rechunking.
	// While an open is pending the frame waits in frames and the opener sends it.
	sentAt := time.Now()
	if r.stream != nil && !r.openPending {
		r.sendLocked(chunk)
	}
	r.streamMu.Unlock()
	if !r.firstFrameTraced && !r.inferStartedAt.IsZero() {
		r.firstFrameTraced = true
		now := sentAt
		// since_first_delta_ms is the share of the wait that is this node's
		// chunking rather than the engine's time to think; it is absent when the
		// frame did not come from a stream this run observed -- a resumed task, or
		// the tail frame of a generation that never reached the minimum size.
		sinceDelta := tasktrace.Field{}
		if !r.firstDeltaAt.IsZero() {
			sinceDelta = tasktrace.Millis("since_first_delta_ms", now.Sub(r.firstDeltaAt))
		}
		// The latency is measured at sentAt, taken after the frame was signed
		// and journaled and before any send, so it is the commit instant: a
		// transport that is gone or still opening only means the frame is sent
		// later, never regenerated. The line itself is emitted after streamMu
		// is released, so the send (if any) has already happened.
		r.w.cfg.Trace.Event("output_first_frame",
			tasktrace.Str("task", r.event.TaskID), tasktrace.Uint("seq", seq),
			tasktrace.Int("frame_bytes", len(text)),
			tasktrace.Millis("since_infer_started_ms", now.Sub(r.inferStartedAt)),
			r.sincePrepareStarted(now),
			sinceDelta,
			tasktrace.Uint("min_frame_bytes", uint64(r.w.cfg.StreamLimits.MinOutputStreamFrameBytes)),
			// transport_attached and stream_pending describe the stream at
			// the moment the frame was committed. attached: the frame was
			// sent now. Not attached and pending: the concurrent open had not
			// landed; the frame is journaled and was sent the moment it did
			// (output_stream_opened reports when, and frames_queued). Not
			// attached and not pending: the open failed or the transport
			// dropped; the journaled frames are replayed when the stream is
			// reopened to store the output.
			tasktrace.Bool("transport_attached", attached),
			tasktrace.Bool("stream_pending", pending))
	}
	return nil
}

func (r *outputStreamRecorder) finish(ctx context.Context, output []byte) ([]uint64, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.deferredErr != nil {
		return nil, r.deferredErr
	}
	// The tail frame and the hand-over below need the stream settled: up with
	// every earlier frame sent on it, or failed.
	r.awaitOpen()
	if r.total == 0 && len(r.frames) == 0 && len(output) > 0 {
		// Unary model transports still deliver through the signed frame protocol.
		limit := r.w.cfg.MaxOutputBytes
		if limit == 0 {
			limit = 64 << 20
		}
		if uint64(len(output)) > limit || !utf8.Valid(output) {
			return nil, fmt.Errorf("model output exceeds byte limit or is not UTF-8")
		}
		r.pending = append([]byte(nil), output...)
		r.total = uint64(len(output))
	}
	var observed bytes.Buffer
	for _, frame := range r.frames {
		observed.Write(frame.Text)
	}
	observed.Write(r.pending)
	if !bytes.Equal(observed.Bytes(), output) {
		return nil, fmt.Errorf("model stream does not reassemble to final output")
	}
	if len(r.pending) > 0 || len(r.frames) == 0 {
		if err := r.emit(ctx, r.pending); err != nil {
			return nil, err
		}
		r.pending = nil
	}
	if r.stream != nil {
		// The signed receipt is relayed before waiting for the Builder's Fin
		// acknowledgement. Transfer this stream to that later finalization step.
		r.w.closeOutputStream()
		r.w.outputStream, r.w.outputStreamTaskID = r.stream, r.event.TaskID
		r.w.outputStreamCancel, r.cancelOpen = r.cancelOpen, nil
		r.stream = nil
	}
	lengths := make([]uint64, len(r.frames))
	for i, frame := range r.frames {
		lengths[i] = uint64(len(frame.Text))
	}
	return lengths, nil
}

func (w *Worker) ensureOutputStreamStored(ctx context.Context, event chainclient.AssignmentFinalized, receipt builderclient.SignedInferReceipt) error {
	frames, err := w.cfg.Persistence.OutputStreamFrames(ctx, event.TaskID)
	if err != nil {
		return err
	}
	if len(frames) == 0 || uint64(len(frames)) != receipt.OutputLeafCount || frames[len(frames)-1].MMRRoot.String() != receipt.OutputHash {
		return fmt.Errorf("retained output frames do not match receipt")
	}
	raw, err := hex.DecodeString(receipt.TaskHash)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("receipt task_hash is invalid")
	}
	taskHash := codec.Hash(raw)
	descriptor, err := w.loadOutputDescriptor(ctx, event.TaskID)
	if err != nil {
		return err
	}
	if descriptor.OutputHash.String() != receipt.OutputHash || descriptor.FinishReason == nodewire.FinishReasonV1Unspecified {
		return fmt.Errorf("output descriptor does not match receipt or carry a successful finish reason")
	}
	mmr, err := codec.NewMMR(codec.DomainOutputMMRV1)
	if err != nil {
		return err
	}
	var total uint64
	for index, frame := range frames {
		if frame.Seq != uint64(index) || !utf8.Valid(frame.Text) || len(frame.Attachment) != 0 || len(frame.AttachmentSignature) != 0 {
			return fmt.Errorf("retained output frame sequence, text, or attachment is invalid")
		}
		if uint64(len(frame.Text)) > receipt.OutputSizeBytes-total {
			return fmt.Errorf("retained output frames exceed receipt size")
		}
		total += uint64(len(frame.Text))
		if err := mmr.Append(frame.Text); err != nil {
			return err
		}
		if mmr.Root() != frame.MMRRoot {
			return fmt.Errorf("retained output frame MMR root mismatch")
		}
		digest, err := nodewire.OutputChunkSigningDigest(w.cfg.ChainID, taskHash[:], frame.Seq, frame.MMRRoot[:])
		if err != nil {
			return err
		}
		if err := signer.VerifyDigestSignature(w.cfg.SignerPubkey, digest, frame.WorkerSignature); err != nil {
			return fmt.Errorf("retained output frame signature: %w", err)
		}
	}
	if total != receipt.OutputSizeBytes {
		return fmt.Errorf("retained output frame byte count differs from receipt")
	}
	fin, err := w.loadOrCreateOutputFin(ctx, event.TaskID, taskHash, frames[len(frames)-1].Seq, mmr.Root(), descriptor.FinishReason)
	if err != nil {
		return err
	}
	if data, err := w.cfg.Persistence.ReadArtifact(ctx, event.TaskID, "worker-output-stream-stored"); err == nil {
		var saved storedOutputStream
		if err := json.Unmarshal(data, &saved); err != nil {
			return err
		}
		if saved.TaskHash != taskHash || saved.BuilderOperator != event.BuilderOperatorAddress || saved.Result.OutputMMRRoot.String() != receipt.OutputHash || saved.Result.LeafCount != receipt.OutputLeafCount || saved.Result.LastSeq+1 != receipt.OutputLeafCount {
			return fmt.Errorf("stored output stream acknowledgement differs from receipt")
		}
		return nil
	}
	stream := w.outputStream
	if stream != nil {
		if w.outputStreamTaskID != event.TaskID {
			return fmt.Errorf("active output stream belongs to another task")
		}
		w.outputStream, w.outputStreamTaskID = nil, ""
	} else {
		stream, err = w.openOutputStream(ctx, event, taskHash, frames)
		if err != nil {
			return err
		}
	}
	defer stream.Close()
	result, err := stream.Finish(fin)
	if err != nil {
		return err
	}
	if result.OutputMMRRoot.String() != receipt.OutputHash || result.LeafCount != receipt.OutputLeafCount || result.LastSeq != receipt.OutputLeafCount-1 {
		return fmt.Errorf("stored output stream differs from receipt")
	}
	return w.persistStoredStream(ctx, event, taskHash, result)
}

func (w *Worker) loadOrCreateOutputFin(ctx context.Context, taskID string, taskHash codec.Hash, finalSeq uint64, root codec.Hash, reason nodewire.FinishReasonV1) (builderclient.OutputFin, error) {
	validate := func(fin signedOutputFin) (builderclient.OutputFin, error) {
		if fin.TaskHash != taskHash || fin.FinalSeq != finalSeq || fin.OutputMMRRoot != root || fin.FinishReason != reason {
			return builderclient.OutputFin{}, fmt.Errorf("persisted output Fin differs from committed output")
		}
		digest, err := nodewire.OutputFinSigningDigest(w.cfg.ChainID, taskHash[:], finalSeq, root[:], reason)
		if err != nil {
			return builderclient.OutputFin{}, err
		}
		if err := signer.VerifyDigestSignature(w.cfg.SignerPubkey, digest, fin.WorkerSignature); err != nil {
			return builderclient.OutputFin{}, fmt.Errorf("persisted output Fin signature: %w", err)
		}
		return builderclient.OutputFin{FinishReason: reason, WorkerSignature: append([]byte(nil), fin.WorkerSignature...)}, nil
	}

	data, err := w.cfg.Persistence.ReadArtifact(ctx, taskID, OutputStreamFinKind)
	if err == nil {
		var saved signedOutputFin
		if err := json.Unmarshal(data, &saved); err != nil {
			return builderclient.OutputFin{}, err
		}
		return validate(saved)
	}
	if !errors.Is(err, ErrCheckpointNotFound) {
		return builderclient.OutputFin{}, err
	}
	digest, err := nodewire.OutputFinSigningDigest(w.cfg.ChainID, taskHash[:], finalSeq, root[:], reason)
	if err != nil {
		return builderclient.OutputFin{}, err
	}
	signature, err := w.signDigest(ctx, digest)
	if err != nil {
		return builderclient.OutputFin{}, err
	}
	saved := signedOutputFin{TaskHash: taskHash, FinalSeq: finalSeq, OutputMMRRoot: root, FinishReason: reason, WorkerSignature: append([]byte(nil), signature...)}
	if _, err := validate(saved); err != nil {
		return builderclient.OutputFin{}, fmt.Errorf("locally verify output Fin: %w", err)
	}
	encoded, err := json.Marshal(saved)
	if err != nil {
		return builderclient.OutputFin{}, err
	}
	if err := w.cfg.Persistence.WriteEvidence(ctx, EvidenceRecord{TaskID: taskID, Kind: OutputStreamFinKind, Data: encoded}); err != nil {
		return builderclient.OutputFin{}, err
	}
	return validate(saved)
}

func (w *Worker) closeOutputStream() {
	if w.outputStream != nil {
		_ = w.outputStream.Close()
		w.outputStream, w.outputStreamTaskID = nil, ""
	}
	if w.outputStreamCancel != nil {
		w.outputStreamCancel()
		w.outputStreamCancel = nil
	}
}

type storedOutputStream struct {
	TaskHash        codec.Hash
	BuilderOperator string
	Result          builderclient.OutputStreamResult
}

func (w *Worker) persistStoredStream(ctx context.Context, event chainclient.AssignmentFinalized, taskHash codec.Hash, result builderclient.OutputStreamResult) error {
	data, err := json.Marshal(storedOutputStream{TaskHash: taskHash, BuilderOperator: event.BuilderOperatorAddress, Result: result})
	if err != nil {
		return err
	}
	return w.cfg.Persistence.WriteEvidence(ctx, EvidenceRecord{TaskID: event.TaskID, Kind: "worker-output-stream-stored", Data: data})
}
