package builderclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	nexusv1connect "github.com/TrueOpen/cortex/proto/nexus/v1/nexusv1connect"
	"google.golang.org/protobuf/proto"
)

func outputStreamFixture(t *testing.T, chunks ...string) OutputStreamRequest {
	t.Helper()
	pair := newTaskDataTestKeyPair(t)
	key := taskDataTestObjectKey()
	body, err := TaskDataOutputStreamBodyDigest(key.TaskHash, key.SessionID, key.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	request := OutputStreamRequest{TaskHash: key.TaskHash, SessionID: key.SessionID, TaskID: key.TaskID, Auth: taskDataTestRequestAuth(t, pair, "UploadTaskOutputStream", key, body)}
	mmr, _ := codec.NewMMR("TRUEOPEN_OUTPUT_MMR_V1")
	for i, text := range chunks {
		if err := mmr.Append([]byte(text)); err != nil {
			t.Fatal(err)
		}
		root := mmr.Root()
		digest, err := nodewire.OutputChunkSigningDigest(request.Auth.ChainID, mustDecodeHex(t, key.TaskHash), uint64(i), root[:])
		if err != nil {
			t.Fatal(err)
		}
		request.ReplayChunks = append(request.ReplayChunks, OutputChunk{Seq: uint64(i), Text: []byte(text), MMRRoot: root, WorkerSignature: pair.sign(t, digest)})
	}
	return request
}

func outputFinFixture(t *testing.T, request OutputStreamRequest, reason nodewire.FinishReasonV1) OutputFin {
	t.Helper()
	last := request.ReplayChunks[len(request.ReplayChunks)-1]
	digest, err := nodewire.OutputFinSigningDigest(request.Auth.ChainID, mustDecodeHex(t, request.TaskHash), last.Seq, last.MMRRoot[:], reason)
	if err != nil {
		t.Fatal(err)
	}
	return OutputFin{FinishReason: reason, WorkerSignature: newTaskDataTestKeyPair(t).sign(t, digest)}
}

func outputTestServer(t *testing.T, plaintext bool, handler nexusv1connect.IngressAPIHandler) *httptest.Server {
	t.Helper()
	path, h := nexusv1connect.NewIngressAPIHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	server := httptest.NewUnstartedServer(mux)
	server.EnableHTTP2 = true
	if plaintext {
		server.Config.Protocols = new(http.Protocols)
		server.Config.Protocols.SetUnencryptedHTTP2(true)
		server.Start()
	} else {
		server.StartTLS()
	}
	t.Cleanup(server.Close)
	return server
}

func TestOutputStreamUploadsResumesAndChecksFinalAcknowledgement(t *testing.T) {
	for _, plaintext := range []bool{false, true} {
		for _, mode := range []string{"fresh", "resume", "finished", "wrong prefix", "ahead", "short", "wrong root", "wrong count", "rejected", "transient"} {
			t.Run(mode+map[bool]string{true: " h2c", false: " TLS"}[plaintext], func(t *testing.T) {
				request := outputStreamFixture(t, "first long chunk", "last")
				finish := outputFinFixture(t, request, nodewire.FinishReasonV1EosToken)
				server := outputTestServer(t, plaintext, &taskDataTestHandler{output: func(_ context.Context, s *connect.BidiStream[nexusv1.UploadTaskOutputStreamRequest, nexusv1.UploadTaskOutputStreamResponse]) error {
					header, err := s.Receive()
					if err != nil {
						return err
					}
					if header.GetHeader() == nil || header.GetHeader().TaskHash != request.TaskHash || !proto.Equal(header.GetHeader().RequestAuth, taskDataRequestAuthToProto(request.Auth)) {
						t.Error("stream header changed signed identity")
					}
					progress := &nexusv1.OutputStreamProgressV1{}
					start := 0
					if mode == "resume" || mode == "wrong prefix" || mode == "short" {
						start = 1
					}
					if mode == "finished" {
						start = 2
					}
					if mode == "ahead" {
						seq := uint64(5)
						progress.LastSeq = &seq
					}
					if start > 0 {
						seq := uint64(start - 1)
						progress.LastSeq = &seq
						progress.MmrRoot = request.ReplayChunks[start-1].MMRRoot[:]
					}
					if mode == "wrong prefix" {
						progress.MmrRoot = make([]byte, 32)
					}
					if mode == "short" {
						progress.LastFrameShort = true
					}
					if err := s.Send(&nexusv1.UploadTaskOutputStreamResponse{Reply: &nexusv1.UploadTaskOutputStreamResponse_Progress{Progress: progress}}); err != nil {
						return err
					}
					if mode == "wrong prefix" || mode == "ahead" || mode == "short" {
						return nil
					}
					for i := start; i < len(request.ReplayChunks); i++ {
						frame, err := s.Receive()
						if err != nil {
							return err
						}
						if !proto.Equal(frame, outputChunkFrame(request.ReplayChunks[i])) {
							t.Error("wrong resumed chunk")
						}
					}
					if mode == "transient" {
						return connect.NewError(connect.CodeUnavailable, errors.New("stream interrupted"))
					}
					fin, err := s.Receive()
					if err != nil {
						return err
					}
					expectedFin, _ := outputFinFrame(request.Auth.ChainID, request.TaskHash, request.ReplayChunks[1].MMRRoot, 2, finish)
					if !proto.Equal(fin, expectedFin) {
						t.Error("invalid Fin")
					}
					root := request.ReplayChunks[1].MMRRoot
					result := &nexusv1.OutputStreamResultV1{Accepted: true, LastSeq: 1, OutputMmrRoot: root[:], LeafCount: 2}
					if mode == "wrong root" {
						result.OutputMmrRoot = make([]byte, 32)
					}
					if mode == "wrong count" {
						result.LeafCount++
					}
					if mode == "rejected" {
						result.Accepted = false
					}
					return s.Send(&nexusv1.UploadTaskOutputStreamResponse{Reply: &nexusv1.UploadTaskOutputStreamResponse_Result{Result: result}})
				}})
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				result, err := newTestTaskDataClient(server.Client(), "").UploadTaskOutputStream(ctx, server.URL, request, finish)
				wantOK := mode == "fresh" || mode == "resume" || mode == "finished"
				if (err == nil) != wantOK {
					t.Fatalf("result=%+v err=%v", result, err)
				}
				if mode == "transient" && !IsRetryable(err) {
					t.Fatalf("transient not retryable: %v", err)
				}
			})
		}
	}
}

func TestOutputStreamRejectsMalformedFramesBeforeDial(t *testing.T) {
	for _, mode := range []string{"attachment", "attachment signature", "signature", "root", "sequence", "auth body", "task", "no leaf"} {
		t.Run(mode, func(t *testing.T) {
			request := outputStreamFixture(t, "text")
			finish := outputFinFixture(t, request, nodewire.FinishReasonV1EosToken)
			switch mode {
			case "attachment":
				request.ReplayChunks[0].Attachment = []byte{1}
			case "attachment signature":
				request.ReplayChunks[0].AttachmentSignature = []byte{1}
			case "signature":
				request.ReplayChunks[0].WorkerSignature = nil
			case "root":
				request.ReplayChunks[0].MMRRoot = codec.Hash{}
			case "sequence":
				request.ReplayChunks[0].Seq = 1
			case "auth body":
				request.Auth.BodyDigest = codec.HashBytes([]byte("other"))
			case "task":
				request.TaskHash = strings.Repeat("88", 32)
			case "no leaf":
				request.ReplayChunks = nil
			}
			f := NewFakeClient()
			if _, err := f.UploadTaskOutputStream(context.Background(), "", request, finish); err == nil {
				t.Fatal("malformed stream accepted")
			}
			if len(f.TaskData) != 0 {
				t.Fatal("malformed stream stored output")
			}
		})
	}
}

func TestOutputStreamRejectsInvalidFin(t *testing.T) {
	for _, mode := range []string{"unspecified", "unknown", "signature"} {
		t.Run(mode, func(t *testing.T) {
			request := outputStreamFixture(t, "text")
			finish := outputFinFixture(t, request, nodewire.FinishReasonV1EosToken)
			switch mode {
			case "unspecified":
				finish.FinishReason = nodewire.FinishReasonV1Unspecified
			case "unknown":
				finish.FinishReason = nodewire.FinishReasonV1MaxOutputDuration + 1
			case "signature":
				finish.WorkerSignature = nil
			}
			client := NewFakeClient()
			if _, err := client.UploadTaskOutputStream(context.Background(), "", request, finish); err == nil {
				t.Fatal("invalid Fin accepted")
			}
			if len(client.TaskData) != 0 || len(client.UploadedOutputFins) != 0 {
				t.Fatal("invalid Fin changed stored state")
			}
		})
	}
}

func TestOutputStreamEmptyOutputIsOneLeafAndRemainsStored(t *testing.T) {
	f := NewFakeClient()
	request := outputStreamFixture(t, "")
	result, err := f.UploadTaskOutputStream(context.Background(), "", request, outputFinFixture(t, request, nodewire.FinishReasonV1EosToken))
	if err != nil || result.LeafCount != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	for _, metadata := range f.TaskDataMetadata {
		if metadata.Readiness != TaskDataStored || metadata.OutputLeafCount != 1 || metadata.SizeBytes != 0 {
			t.Fatalf("metadata=%+v", metadata)
		}
	}
	pair := newTaskDataTestKeyPair(t)
	receipt := taskDataTestReceipt(t, pair, "chain-A", nil)
	if err := f.SubmitInferReceipt(context.Background(), "", SubmitInferReceiptRequest{Receipt: receipt}); err != nil {
		t.Fatal(err)
	}
	for _, metadata := range f.TaskDataMetadata {
		if metadata.Readiness != TaskDataStored {
			t.Fatal("SubmitInferReceipt made output READY")
		}
	}
}

func TestWholeOutputUploadIsRefused(t *testing.T) {
	pair := newTaskDataTestKeyPair(t)
	request := taskDataTestUploadRequest(t, pair, []byte("output"))
	request.Key = taskDataTestObjectKey()
	denied := &countingTaskDataHTTPClient{}
	_, err := newTestTaskDataClient(denied, "").UploadTaskResultObject(context.Background(), "http://invalid", request)
	if err == nil || !strings.Contains(err.Error(), "UploadTaskOutputStream") || denied.calls != 0 {
		t.Fatalf("err=%v calls=%d", err, denied.calls)
	}
}

func TestOutputStreamLiveSendingUsesPinnedTLSHTTP2(t *testing.T) {
	request := outputStreamFixture(t, "first long chunk", "last")
	finish := outputFinFixture(t, request, nodewire.FinishReasonV1StopSequence)
	chunks := request.ReplayChunks
	request.ReplayChunks = nil
	server := outputTestServer(t, false, &taskDataTestHandler{output: func(_ context.Context, s *connect.BidiStream[nexusv1.UploadTaskOutputStreamRequest, nexusv1.UploadTaskOutputStreamResponse]) error {
		if _, err := s.Receive(); err != nil {
			return err
		}
		empty, _ := codec.NewMMR(codec.DomainOutputMMRV1)
		root := empty.Root()
		if err := s.Send(&nexusv1.UploadTaskOutputStreamResponse{Reply: &nexusv1.UploadTaskOutputStreamResponse_Progress{Progress: &nexusv1.OutputStreamProgressV1{MmrRoot: root[:]}}}); err != nil {
			return err
		}
		for _, chunk := range chunks {
			frame, err := s.Receive()
			if err != nil {
				return err
			}
			if !proto.Equal(frame, outputChunkFrame(chunk)) {
				t.Error("live chunk changed")
			}
		}
		if _, err := s.Receive(); err != nil {
			return err
		}
		root = chunks[1].MMRRoot
		return s.Send(&nexusv1.UploadTaskOutputStreamResponse{Reply: &nexusv1.UploadTaskOutputStreamResponse_Result{Result: &nexusv1.OutputStreamResultV1{Accepted: true, LastSeq: 1, OutputMmrRoot: root[:], LeafCount: 2}}})
	}})
	client := NewConnectTaskDataClientWithDefaults("", TaskDataTransport{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = WithTLSPubkeyHash(ctx, TLSPubkeyHash(server.Certificate()))
	stream, err := client.OpenTaskOutputStream(ctx, server.URL, request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	for _, chunk := range chunks {
		if err := stream.SendChunk(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if result, err := stream.Finish(finish); err != nil || result.LeafCount != 2 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if err := stream.SendChunk(chunks[1]); err == nil {
		t.Fatal("sent after Fin")
	}
	badCtx := WithTLSPubkeyHash(context.Background(), strings.Repeat("99", 32))
	if stream, err := client.OpenTaskOutputStream(badCtx, server.URL, request); err == nil {
		_ = stream.Close()
		t.Fatal("reused connection under wrong TLS pin")
	}
}

func TestOutputStreamTimesOutSilentAcknowledgementsAndBlockedWrites(t *testing.T) {
	for _, stage := range []string{"Header acknowledgement", "Fin acknowledgement", "send frame", "caller cancellation"} {
		t.Run(stage, func(t *testing.T) {
			text := "output"
			if stage == "send frame" || stage == "caller cancellation" {
				text = strings.Repeat("x", 8<<20)
			}
			request := outputStreamFixture(t, text)
			finish := outputFinFixture(t, request, nodewire.FinishReasonV1EosToken)
			chunk := request.ReplayChunks[0]
			request.ReplayChunks = nil
			handlerDone := make(chan struct{})
			server := outputTestServer(t, false, &taskDataTestHandler{output: func(ctx context.Context, s *connect.BidiStream[nexusv1.UploadTaskOutputStreamRequest, nexusv1.UploadTaskOutputStreamResponse]) error {
				defer close(handlerDone)
				if _, err := s.Receive(); err != nil {
					return err
				}
				if stage != "Header acknowledgement" {
					if err := s.Send(&nexusv1.UploadTaskOutputStreamResponse{Reply: &nexusv1.UploadTaskOutputStreamResponse_Progress{Progress: &nexusv1.OutputStreamProgressV1{}}}); err != nil {
						return err
					}
				}
				if stage == "Fin acknowledgement" {
					for i := 0; i < 2; i++ {
						if _, err := s.Receive(); err != nil {
							return err
						}
					}
				}
				<-ctx.Done()
				return ctx.Err()
			}})
			client := newTestTaskDataClient(server.Client(), "")
			client.outputIOTimeout = 50 * time.Millisecond
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if stage == "caller cancellation" {
				client.outputIOTimeout = 5 * time.Second
			}
			started := time.Now()
			stream, err := client.OpenTaskOutputStream(ctx, server.URL, request)
			if stage != "Header acknowledgement" {
				if err != nil {
					t.Fatal(err)
				}
				cancelDone := make(chan struct{})
				var cancelTimer *time.Timer
				if stage == "caller cancellation" {
					cancelTimer = time.AfterFunc(50*time.Millisecond, func() { cancel(); close(cancelDone) })
				}
				err = stream.SendChunk(chunk)
				if cancelTimer != nil && !cancelTimer.Stop() {
					<-cancelDone
				}
				if stage == "Fin acknowledgement" {
					if err != nil {
						t.Fatal(err)
					}
					_, err = stream.Finish(finish)
				}
				if err == nil {
					_ = stream.Close()
					t.Fatal("silent peer did not time out")
				}
				if nextErr := stream.SendChunk(chunk); nextErr == nil {
					t.Fatal("timed-out stream remained writable")
				}
			}
			if stage == "caller cancellation" {
				if !errors.Is(err, context.Canceled) || IsRetryable(err) {
					t.Fatalf("caller cancellation classification: %v", err)
				}
			} else if !IsRetryable(err) || !errors.Is(err, errOutputStreamIOTimeout) || !strings.Contains(err.Error(), stage) {
				t.Fatalf("timeout classification: %v", err)
			}
			if time.Since(started) > 2*time.Second {
				t.Fatal("network I/O deadline did not bound the call")
			}
			select {
			case <-handlerDone:
			case <-time.After(2 * time.Second):
				t.Fatal("timed-out stream did not cancel its handler")
			}
		})
	}
}

func TestOutputStreamNetworkDeadlineDoesNotTimeOutModelGeneration(t *testing.T) {
	request := outputStreamFixture(t, "output")
	finish := outputFinFixture(t, request, nodewire.FinishReasonV1MaxOutputTokens)
	chunk := request.ReplayChunks[0]
	request.ReplayChunks = nil
	server := outputTestServer(t, false, &taskDataTestHandler{output: func(_ context.Context, s *connect.BidiStream[nexusv1.UploadTaskOutputStreamRequest, nexusv1.UploadTaskOutputStreamResponse]) error {
		if _, err := s.Receive(); err != nil {
			return err
		}
		if err := s.Send(&nexusv1.UploadTaskOutputStreamResponse{Reply: &nexusv1.UploadTaskOutputStreamResponse_Progress{Progress: &nexusv1.OutputStreamProgressV1{}}}); err != nil {
			return err
		}
		for i := 0; i < 2; i++ {
			if _, err := s.Receive(); err != nil {
				return err
			}
		}
		return s.Send(&nexusv1.UploadTaskOutputStreamResponse{Reply: &nexusv1.UploadTaskOutputStreamResponse_Result{Result: &nexusv1.OutputStreamResultV1{Accepted: true, LastSeq: 0, OutputMmrRoot: chunk.MMRRoot[:], LeafCount: 1}}})
	}})
	client := newTestTaskDataClient(server.Client(), "")
	client.outputIOTimeout = 50 * time.Millisecond
	stream, err := client.OpenTaskOutputStream(context.Background(), server.URL, request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	time.Sleep(3 * client.outputIOTimeout)
	if err := stream.SendChunk(chunk); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * client.outputIOTimeout)
	if result, err := stream.Finish(finish); err != nil || result.LeafCount != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestOutputStreamUsesExistingClientTimeoutPerOperation(t *testing.T) {
	for _, timeout := range []time.Duration{0, 123 * time.Millisecond} {
		client := NewConnectTaskDataClient(&http.Client{Timeout: timeout}, "", TaskDataTransport{})
		want := timeout
		if want == 0 {
			want = nexusDataTimeout
		}
		if client.outputIOTimeout != want || client.outputHTTPClient.(*http.Client).Timeout != 0 {
			t.Fatalf("network timeout=%s, whole-stream timeout=%s", client.outputIOTimeout, client.outputHTTPClient.(*http.Client).Timeout)
		}
	}
}
