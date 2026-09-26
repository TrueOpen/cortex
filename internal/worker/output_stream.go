package worker

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/modelservice"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/signer"
)

const OutputStreamFramePrefix = "worker-output-frame:"
const OutputStreamFinKind = "worker-output-fin"

func OutputStreamFrameKind(seq uint64) string {
	return fmt.Sprintf("%s%020d", OutputStreamFramePrefix, seq)
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
	r := &outputStreamRecorder{w: w, ctx: ctx, event: event, taskHash: saved.TaskHash, mmr: mmr, frames: frames, pending: pending, total: total}
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
	r.stream, r.transportErr = w.openOutputStream(ctx, event, r.taskHash, nil)
	return r, nil
}

// openOutputStream opens one stream per Task Builder and returns them as a
// single fan-out stream, so every frame reaches every Builder (04-任务/02 §9.2).
//
// The request authorization is per Builder, not shared: SignRequest binds the
// recipient's operator address, so each Builder gets a token naming itself. The
// body digest and the replay frames are the same for all of them.
//
// A Builder that cannot be opened fails the whole open. §9.5 allows sending to
// continue while at least one Builder receives, but acting on that needs the
// per-Builder liveness tracking this change does not add yet; failing here keeps
// the behaviour honest rather than silently streaming to a subset.
func (w *Worker) openOutputStream(ctx context.Context, event chainclient.AssignmentFinalized, taskHash codec.Hash, frames []builderclient.OutputChunk) (builderclient.TaskOutputStream, error) {
	endpoints, err := w.receivingBuilders(ctx, receivingBuilderRef(event))
	if err != nil {
		return nil, err
	}
	digest, err := builderclient.TaskDataOutputStreamBodyDigest(taskHash.String(), event.SessionID, event.TaskID)
	if err != nil {
		return nil, err
	}
	key := builderclient.TaskDataKey{TaskHash: taskHash.String(), SessionID: event.SessionID, TaskID: event.TaskID, Kind: builderclient.DataKindOutput}
	// The Worker signs the plaintext OutputStreamHeaderV2 once per stream.
	// TODO(wire v0.3.0): rc.1 does not name the header's signing key; the
	// service key that signs the frames and the fin is used.
	headerDigest, err := builderclient.OutputStreamHeaderDigest(w.cfg.ChainID, taskHash.String())
	if err != nil {
		return nil, err
	}
	headerSignature, err := w.signDigest(ctx, headerDigest)
	if err != nil {
		return nil, fmt.Errorf("sign output stream header: %w", err)
	}
	streams := make([]builderclient.TaskOutputStream, 0, len(endpoints))
	builders := make([]string, 0, len(endpoints))
	closeOpened := func() {
		for _, opened := range streams {
			_ = opened.Close()
		}
	}
	for _, endpoint := range endpoints {
		auth, err := w.cfg.TaskDataAuth.SignRequest(ctx, "UploadTaskOutputStream", key, endpoint.OperatorAddress, digest)
		if err != nil {
			closeOpened()
			return nil, err
		}
		stream, err := w.cfg.TaskData.OpenTaskOutputStream(
			builderclient.WithTLSPubkeyHash(ctx, endpoint.TLSPubkeyHash), endpoint.Endpoint,
			builderclient.OutputStreamRequest{TaskHash: taskHash.String(), SessionID: event.SessionID, TaskID: event.TaskID, Auth: auth, HeaderSignature: headerSignature, ReplayChunks: frames})
		if err != nil {
			closeOpened()
			return nil, fmt.Errorf("open output stream to Task Builder %s: %w", endpoint.OperatorAddress, err)
		}
		streams = append(streams, stream)
		builders = append(builders, endpoint.OperatorAddress)
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
	if r.deferredErr == nil && len(r.pending) >= int(r.w.cfg.StreamLimits.MinOutputStreamFrameBytes) {
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
	r.mmr = candidate
	r.frames = append(r.frames, chunk)
	// Keep collecting durable model output after a network failure. The same
	// signed frames can then resume without rerunning generation or rechunking.
	if r.stream != nil {
		if err := r.stream.SendChunk(chunk); err != nil {
			r.transportErr = err
			_ = r.stream.Close()
			r.stream = nil
		}
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
