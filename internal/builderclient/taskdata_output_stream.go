package builderclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/hfields"
	"github.com/TrueOpen/cortex/internal/nodewire"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	nexusv1connect "github.com/TrueOpen/cortex/proto/nexus/v1/nexusv1connect"
	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

type OutputChunk struct {
	Seq                 uint64
	Text                []byte
	MMRRoot             codec.Hash
	WorkerSignature     []byte
	Attachment          []byte
	AttachmentSignature []byte
}

// ReplayChunks preserves the exact signed frame boundaries for reconnects.
// Open checks the Builder's persisted prefix before resending missing frames.
type OutputStreamRequest struct {
	TaskHash  string
	SessionID string
	TaskID    string
	Auth      TaskDataRequestAuth
	// HeaderSignature is the Worker's compact signature over
	// OutputStreamHeaderDigest for this task, independent of Auth.
	HeaderSignature []byte
	ReplayChunks    []OutputChunk
}

// OutputStreamHeaderDigest is the digest a Worker signs to open its output
// stream: the plaintext OutputStreamHeaderV2 for this task, with attempt 0,
// stream_instance 1, no recipient key and ZERO32 key slots.
func OutputStreamHeaderDigest(chainID, taskHash string) (codec.Hash, error) {
	raw, err := taskDataHash("task_hash", taskHash)
	if err != nil {
		return codec.Hash{}, err
	}
	zero := make([]byte, 32)
	return nodewire.OutputStreamHeaderSigningDigest(nodewire.OutputStreamHeaderV2{
		ChainID: chainID, TaskHash: raw, Attempt: 0, StreamInstance: 1,
		OutputKeyCommitment: zero, KeyPackageHash: zero,
	})
}

// OutputStreamResult proves STORED output only. FinalizeTaskResult publishes it.
type OutputStreamResult struct {
	LastSeq       uint64
	LeafCount     uint64
	OutputMMRRoot codec.Hash
}

// OutputFin is the Worker-authenticated terminal metadata. The stream derives
// final_seq and output_mmr_root from its accepted chunks so callers cannot send
// a signature beside different terminal coordinates.
type OutputFin struct {
	FinishReason    nodewire.FinishReasonV1
	WorkerSignature []byte
}

type TaskOutputStream interface {
	SendChunk(OutputChunk) error
	Finish(OutputFin) (OutputStreamResult, error)
	Close() error
}

// TaskDataOutputStreamBodyDigest is the TRUEOPEN_TASK_DATA_UPLOAD_BODY_V2
// body digest of an output stream, whose content hash and size are not known
// when the stream opens: the nine-field OUTPUT object reference with a ZERO32
// content_hash, no evidence producer, round or evidence kind, size 0 and an
// empty media type. The retired V1 domain lacked evidence_kind.
func TaskDataOutputStreamBodyDigest(taskHash, sessionID, taskID string) (codec.Hash, error) {
	fields, err := finalizeScope(taskHash, sessionID, taskID)
	if err != nil {
		return codec.Hash{}, err
	}
	fields = append(fields, hfields.Uint32(uint32(DataKindOutput)), hfields.Hash(codec.Hash{}), hfields.Uint32(0), hfields.Uint32(0),
		hfields.Optional(false, hfields.Bytes(nil)), hfields.Uint32(uint32(nodewire.EvidenceKindUnspecified)))
	return hfields.Digest("TRUEOPEN_TASK_DATA_UPLOAD_BODY_V2", hfields.Frame(fields...), hfields.Uint64(0), hfields.String(""))
}

func validateOutputStreamRequest(request OutputStreamRequest) error {
	digest, err := TaskDataOutputStreamBodyDigest(request.TaskHash, request.SessionID, request.TaskID)
	if err != nil {
		return err
	}
	if err := validateSignedTaskDataRequest(request.Auth, "UploadTaskOutputStream", digest); err != nil {
		return err
	}
	if _, err := OutputStreamHeaderDigest(request.Auth.ChainID, request.TaskHash); err != nil {
		return err
	}
	return validateCompactSignature(request.HeaderSignature)
}

type outputStreamState struct {
	mmr    *codec.MMR
	chunks []OutputChunk
	closed bool
	failed bool
}

func newOutputStreamState() (*outputStreamState, error) {
	mmr, err := codec.NewMMR("TRUEOPEN_OUTPUT_MMR_V1")
	return &outputStreamState{mmr: mmr}, err
}

func (s *outputStreamState) append(chunk OutputChunk) error {
	if s.closed || s.failed {
		return fmt.Errorf("output stream is closed")
	}
	if len(chunk.Attachment) != 0 || len(chunk.AttachmentSignature) != 0 {
		return fmt.Errorf("Phase 0 output attachments must be empty")
	}
	if chunk.Seq != s.mmr.LeafCount() || !utf8.Valid(chunk.Text) || uint64(len(chunk.Text)) > math.MaxUint32 {
		return fmt.Errorf("output chunk sequence or text is invalid")
	}
	if err := validateCompactSignature(chunk.WorkerSignature); err != nil {
		return err
	}
	if err := s.mmr.Append(chunk.Text); err != nil {
		return err
	}
	if chunk.MMRRoot != s.mmr.Root() {
		s.failed = true
		return fmt.Errorf("output chunk cumulative MMR root mismatch")
	}
	chunk.Text = append([]byte(nil), chunk.Text...)
	chunk.WorkerSignature = append([]byte(nil), chunk.WorkerSignature...)
	s.chunks = append(s.chunks, chunk)
	return nil
}

func outputStreamPrefix(progress *nexusv1.OutputStreamProgressV1, replay []OutputChunk) (uint64, error) {
	if progress == nil {
		return 0, fmt.Errorf("output stream requires a progress response after Header")
	}
	if progress.LastSeq == nil {
		empty, _ := codec.NewMMR(codec.DomainOutputMMRV1)
		root := empty.Root()
		if (len(progress.MmrRoot) != 0 && !bytes.Equal(progress.MmrRoot, root[:])) || progress.LastFrameShort {
			return 0, fmt.Errorf("empty output stream progress carries a root or short-frame flag")
		}
		return 0, nil
	}
	if *progress.LastSeq >= uint64(len(replay)) {
		return 0, fmt.Errorf("output stream progress exceeds retained replay frames")
	}
	count := *progress.LastSeq + 1
	if !bytes.Equal(progress.MmrRoot, replay[count-1].MMRRoot[:]) {
		return 0, fmt.Errorf("output stream resume MMR root mismatch")
	}
	if progress.LastFrameShort && count != uint64(len(replay)) {
		return 0, fmt.Errorf("output stream short-frame progress permits only Fin")
	}
	return count, nil
}

type connectOutputStream struct {
	*outputStreamState
	stream           *connect.BidiStreamForClient[nexusv1.UploadTaskOutputStreamRequest, nexusv1.UploadTaskOutputStreamResponse]
	short            bool
	ctx              context.Context
	cancel           context.CancelCauseFunc
	timeout          time.Duration
	stopCancellation func() bool
	cancellationDone chan struct{}
	chainID          string
	taskHash         string
	// heldOnOpen is how many leading frames the Builder reported holding when the
	// stream opened; outputStreamPrefix has checked its root against ours.
	heldOnOpen uint64
	// early is a Receive started right after opening a stream whose frames the
	// Builder already holds in full; see watchForSealedOnOpen.
	early    chan outputReply
	endpoint string
}

type outputReply struct {
	response *nexusv1.UploadTaskOutputStreamResponse
	err      error
}

// sealedOnOpenWait is how long Finish waits, before sending the Fin, for a
// Builder that holds every frame to end the stream as already sealed. It is
// only spent on a reconnect that finds every frame already held.
var sealedOnOpenWait = time.Second

var errOutputStreamIOTimeout = errors.New("output stream network I/O deadline exceeded")

func (c *ConnectTaskDataClient) OpenTaskOutputStream(ctx context.Context, endpoint string, request OutputStreamRequest) (TaskOutputStream, error) {
	if err := validateOutputStreamRequest(request); err != nil {
		return nil, err
	}
	state, err := newOutputStreamState()
	if err != nil {
		return nil, err
	}
	for _, chunk := range request.ReplayChunks {
		if err := state.append(chunk); err != nil {
			return nil, err
		}
	}
	client, err := c.outputIngress(endpoint)
	if err != nil {
		return nil, err
	}
	streamCtx, cancel := context.WithCancelCause(ctx)
	stream := client.UploadTaskOutputStream(streamCtx)
	c.authorize(stream.RequestHeader())
	s := &connectOutputStream{outputStreamState: state, stream: stream, ctx: streamCtx, cancel: cancel, timeout: c.outputIOTimeout, chainID: request.Auth.ChainID, taskHash: request.TaskHash, endpoint: endpoint}
	fail := func(err error) (TaskOutputStream, error) { _ = s.Close(); return nil, err }
	// Send(nil) starts Connect's HTTP request without writing a message. It
	// initializes the request-body pipe before a timer can close its write side.
	if err := stream.Send(nil); err != nil {
		return fail(classifyOutputStreamError(err))
	}
	s.cancellationDone = make(chan struct{})
	s.stopCancellation = context.AfterFunc(streamCtx, func() {
		_ = stream.CloseRequest()
		close(s.cancellationDone)
	})
	zero := make([]byte, 32)
	header := &nexusv1.OutputStreamHeaderV2{
		TaskHash: request.TaskHash, SessionId: request.SessionID, TaskId: request.TaskID, RequestAuth: taskDataRequestAuthToProto(request.Auth),
		Attempt: 0, StreamInstance: 1, OutputKeyCommitment: zero, KeyPackageHash: zero,
		WorkerSignature: append([]byte(nil), request.HeaderSignature...),
	}
	if err := s.send(&nexusv1.UploadTaskOutputStreamRequest{Frame: &nexusv1.UploadTaskOutputStreamRequest_Header{Header: header}}); err != nil {
		return fail(err)
	}
	response, err := s.receive("Header acknowledgement")
	if err != nil {
		return fail(classifyOutputStreamError(err))
	}
	count, err := outputStreamPrefix(response.GetProgress(), state.chunks)
	if err != nil {
		return fail(err)
	}
	s.short = response.GetProgress().LastFrameShort
	s.heldOnOpen = count
	for _, chunk := range state.chunks[count:] {
		if err := s.send(outputChunkFrame(chunk)); err != nil {
			return fail(err)
		}
	}
	if count > 0 && count == uint64(len(state.chunks)) {
		s.watchForSealedOnOpen()
	}
	return s, nil
}

// watchForSealedOnOpen starts the next Receive in the background when the
// Builder already holds every frame. A Builder that has sealed the output ends
// the stream right after its progress, before reading anything more; a Builder
// that has not waits for the Fin. Reading ahead lets Finish tell the two apart
// before it sends the Fin.
func (s *connectOutputStream) watchForSealedOnOpen() {
	early := make(chan outputReply, 1)
	stream := s.stream
	go func() {
		response, err := stream.Receive()
		early <- outputReply{response: response, err: err}
	}()
	s.early = early
}

// Bidirectional Connect requires HTTP/2. Use a separate pool so HTTP/1 unary
// calls retain their transport behavior; dialOrigin still gates plaintext.
func newOutputHTTPClient(base connect.HTTPClient) connect.HTTPClient {
	httpClient, ok := base.(*http.Client)
	if !ok {
		return base
	}
	client := *httpClient
	client.Timeout = 0
	configure := func(base *http.Transport) *http.Transport {
		t := base.Clone()
		t.Protocols = new(http.Protocols)
		t.Protocols.SetHTTP2(true)
		t.Protocols.SetUnencryptedHTTP2(true)
		return t
	}
	switch transport := httpClient.Transport.(type) {
	case *pinRouter:
		client.Transport = newPinRouter(configure(transport.base))
	case *http.Transport:
		client.Transport = configure(transport)
	case nil:
		client.Transport = configure(http.DefaultTransport.(*http.Transport))
	}
	return &client
}

func (c *ConnectTaskDataClient) outputIngress(endpoint string) (nexusv1connect.IngressAPIClient, error) {
	if c == nil || c.outputHTTPClient == nil {
		return nil, fmt.Errorf("output stream HTTP client is required")
	}
	baseURL, err := c.dialOrigin(endpoint)
	if err != nil {
		return nil, err
	}
	return nexusv1connect.NewIngressAPIClient(c.outputHTTPClient, baseURL, connect.WithReadMaxBytes(maxNexusResponseBytes)), nil
}

func (c *ConnectTaskDataClient) UploadTaskOutputStream(ctx context.Context, endpoint string, request OutputStreamRequest, fin OutputFin) (OutputStreamResult, error) {
	stream, err := c.OpenTaskOutputStream(ctx, endpoint, request)
	if err != nil {
		return OutputStreamResult{}, err
	}
	defer func() { _ = stream.Close() }()
	return stream.Finish(fin)
}

func outputChunkFrame(chunk OutputChunk) *nexusv1.UploadTaskOutputStreamRequest {
	return &nexusv1.UploadTaskOutputStreamRequest{Frame: &nexusv1.UploadTaskOutputStreamRequest_Chunk{Chunk: &nexusv1.OutputChunkV1{Seq: chunk.Seq, Text: chunk.Text, MmrRoot: chunk.MMRRoot[:], WorkerSignature: chunk.WorkerSignature}}}
}

func classifyOutputStreamError(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return Retryable(fmt.Errorf("output stream ended before its acknowledgement: %w", err))
	}
	return classifyConnectError(nexusv1connect.IngressAPIUploadTaskOutputStreamProcedure, err)
}

// Only active network operations are timed. The model may legitimately spend
// longer than this limit generating the next chunk between calls.
func (s *connectOutputStream) networkIO(operation string, call func() error) error {
	timeout := s.timeout
	if timeout <= 0 {
		timeout = nexusDataTimeout
	}
	timedOut := make(chan struct{})
	timer := time.AfterFunc(timeout, func() {
		s.cancel(fmt.Errorf("%w: %s exceeded %s", errOutputStreamIOTimeout, operation, timeout))
		close(timedOut)
	})
	err := call()
	// Stop does not join a callback that has started. Join it before touching
	// stream state so a completed operation cannot leave a late cancellation.
	if !timer.Stop() {
		<-timedOut
	}
	if cause := context.Cause(s.ctx); errors.Is(cause, errOutputStreamIOTimeout) {
		s.failed = true
		_ = s.Close()
		return Retryable(cause)
	}
	return err
}

func (s *connectOutputStream) receive(operation string) (*nexusv1.UploadTaskOutputStreamResponse, error) {
	if early := s.early; early != nil {
		s.early = nil
		var reply outputReply
		err := s.networkIO(operation, func() error {
			reply = <-early
			return reply.err
		})
		return reply.response, err
	}
	var response *nexusv1.UploadTaskOutputStreamResponse
	err := s.networkIO(operation, func() error {
		var err error
		response, err = s.stream.Receive()
		return err
	})
	return response, err
}

func (s *connectOutputStream) send(frame *nexusv1.UploadTaskOutputStreamRequest) error {
	if err := s.networkIO("send frame", func() error { return s.stream.Send(frame) }); err != nil {
		s.failed = true
		defer func() { _ = s.Close() }()
		if errors.Is(err, io.EOF) {
			if _, receiveErr := s.receive("send error response"); receiveErr != nil {
				return classifyOutputStreamError(receiveErr)
			}
		}
		return classifyOutputStreamError(err)
	}
	return nil
}

func (s *connectOutputStream) SendChunk(chunk OutputChunk) error {
	if s.short {
		return fmt.Errorf("output stream short-frame progress permits only Fin")
	}
	if err := s.append(chunk); err != nil {
		return err
	}
	return s.send(outputChunkFrame(chunk))
}

func outputFinFrame(chainID, taskHash string, root codec.Hash, count uint64, fin OutputFin) (*nexusv1.UploadTaskOutputStreamRequest, error) {
	parsedTaskHash, err := parseLowerHexHash(taskHash, "task_hash")
	if err != nil {
		return nil, err
	}
	if _, err := nodewire.OutputFinSigningDigest(chainID, parsedTaskHash[:], count-1, root[:], fin.FinishReason); err != nil {
		return nil, err
	}
	if err := validateCompactSignature(fin.WorkerSignature); err != nil {
		return nil, err
	}
	frame := &nexusv1.OutputFinV1{
		FinalSeq:        count - 1,
		OutputMmrRoot:   root[:],
		FinishReason:    taskv1.FinishReasonV1(fin.FinishReason),
		WorkerSignature: append([]byte(nil), fin.WorkerSignature...),
	}
	return &nexusv1.UploadTaskOutputStreamRequest{Frame: &nexusv1.UploadTaskOutputStreamRequest_Fin{Fin: frame}}, nil
}

func (s *connectOutputStream) Finish(fin OutputFin) (OutputStreamResult, error) {
	if s.closed || s.failed || s.mmr.LeafCount() == 0 {
		return OutputStreamResult{}, fmt.Errorf("output stream requires at least one leaf and an open stream")
	}
	defer func() { _ = s.Close() }()
	root, count := s.mmr.Root(), s.mmr.LeafCount()
	frame, err := outputFinFrame(s.chainID, s.taskHash, root, count, fin)
	if err != nil {
		return OutputStreamResult{}, err
	}
	if sealed, err := s.sealedOnOpen(count); err != nil {
		return OutputStreamResult{}, err
	} else if sealed {
		return s.alreadyDelivered(root, count), nil
	}
	if err := s.networkIO("send frame", func() error { return s.stream.Send(frame) }); err != nil {
		s.failed = true
		if !errors.Is(err, io.EOF) {
			return OutputStreamResult{}, classifyOutputStreamError(err)
		}
		// io.EOF: the Builder ended the stream before the Fin reached it.
		_, answer := s.receive("send error response")
		if answer == nil {
			return OutputStreamResult{}, classifyOutputStreamError(err)
		}
		answer = classifyOutputStreamError(answer)
		if connect.CodeOf(answer) == connect.CodeAlreadyExists && s.heldOnOpen == count {
			return s.alreadyDelivered(root, count), nil
		}
		return OutputStreamResult{}, answer
	}
	s.closed = true
	if err := s.networkIO("close request", s.stream.CloseRequest); err != nil {
		return OutputStreamResult{}, classifyOutputStreamError(err)
	}
	// An AlreadyExists read here came after the Fin and may mean the Fin was
	// refused (task data deleted, stream superseded, blob conflict), so it stays
	// an error; the reconnect finds out whether the Builder really sealed.
	response, err := s.receive("Fin acknowledgement")
	if err != nil {
		return OutputStreamResult{}, classifyOutputStreamError(err)
	}
	result := response.GetResult()
	if result == nil || !result.Accepted || result.LastSeq != count-1 || result.LeafCount != count || !bytes.Equal(result.OutputMmrRoot, root[:]) {
		return OutputStreamResult{}, fmt.Errorf("output stream final acknowledgement does not match uploaded MMR root and leaf count")
	}
	if _, err := s.receive("stream completion"); !errors.Is(err, io.EOF) {
		if err != nil {
			return OutputStreamResult{}, classifyOutputStreamError(err)
		}
		return OutputStreamResult{}, fmt.Errorf("output stream continued after final acknowledgement")
	}
	return OutputStreamResult{LastSeq: count - 1, LeafCount: count, OutputMMRRoot: root}, nil
}

// sealedOnOpen reports whether a Builder that held every frame of this stream
// on open ended it as already sealed before the Fin was sent.
//
// A Builder that has sealed a task's output answers a reopened stream with its
// progress and then ends it with AlreadyExists; the Worker is meant to decide
// from the root whether that is its own output (Nexus UploadTaskOutputStream).
// That happens whenever a Finish reached this Builder but not the Worker's
// bookkeeping: a lost Fin acknowledgement, or a fan-out Finish that sealed one
// Task Builder and then failed on another. Treating it as an error makes every
// retry fail on this Builder, so the Builders after it never receive the Fin.
//
// Only an end that arrives before the Fin counts. Nexus also answers
// AlreadyExists to a Fin it refuses, and a refused Fin has not sealed anything.
// The progress message carries no sealed flag, so "held every frame with our
// root, then ended before reading the Fin" is the test. A Builder holding fewer
// frames, or an OUTPUT committed by the whole-object path, which reports no
// frames, never gets here.
func (s *connectOutputStream) sealedOnOpen(count uint64) (bool, error) {
	early := s.early
	if early == nil || s.heldOnOpen != count {
		return false, nil
	}
	select {
	case reply := <-early:
		s.early = nil
		s.failed = true
		if reply.err == nil {
			return false, fmt.Errorf("output stream answered before the Fin")
		}
		err := classifyOutputStreamError(reply.err)
		if connect.CodeOf(err) == connect.CodeAlreadyExists {
			return true, nil
		}
		return false, err
	case <-time.After(sealedOnOpenWait):
		return false, nil
	}
}

// alreadyDelivered is the result for a Builder that already sealed this exact
// output.
//
// Known limit: if the Fin that Builder sealed with carries a different
// finish_reason, that Builder rejects the later FinalizeTaskResult, which
// recomputes the Worker commitment from its stored Fin, so the mismatch is
// refused there rather than passed; the other Builders are unaffected.
func (s *connectOutputStream) alreadyDelivered(root codec.Hash, count uint64) OutputStreamResult {
	slog.Info("output stream already sealed by the Builder with this output; treating it as delivered",
		"endpoint", s.endpoint, "task_hash", s.taskHash, "leaf_count", count, "output_mmr_root", root.String()[:16])
	return OutputStreamResult{LastSeq: count - 1, LeafCount: count, OutputMMRRoot: root}
}

func (s *connectOutputStream) Close() error {
	s.closed = true
	s.cancel(context.Canceled)
	if s.stopCancellation != nil {
		if !s.stopCancellation() {
			<-s.cancellationDone
		}
		s.stopCancellation = nil
	}
	_ = s.stream.CloseRequest()
	return s.stream.CloseResponse()
}
