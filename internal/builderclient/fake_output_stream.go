package builderclient

import (
	"context"
	"fmt"

	nexusv1 "github.com/SingaXYZ/cortex/proto/nexus/v1"
)

type fakeOutputStream struct {
	*outputStreamState
	client  *FakeClient
	request OutputStreamRequest
	scope   string
}

func (f *FakeClient) OpenTaskOutputStream(_ context.Context, endpoint string, request OutputStreamRequest) (TaskOutputStream, error) {
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
	scope := endpoint + "|" + request.Auth.BuilderAddress + "|" + request.Auth.ChainID + "|" + request.TaskHash + "|" + request.SessionID + "|" + request.TaskID
	stored := f.outputStreams[scope]
	progress := &nexusv1.OutputStreamProgressV1{}
	if len(stored) > 0 {
		last := stored[len(stored)-1]
		progress.LastSeq = &last.Seq
		progress.MmrRoot = last.MMRRoot[:]
	}
	if _, err := outputStreamPrefix(progress, state.chunks); err != nil {
		return nil, err
	}
	if f.outputStreams == nil {
		f.outputStreams = map[string][]OutputChunk{}
	}
	f.outputStreams[scope] = append([]OutputChunk(nil), state.chunks...)
	f.UploadedOutputStreams = append(f.UploadedOutputStreams, request)
	f.record("open_task_output_stream")
	return &fakeOutputStream{outputStreamState: state, client: f, request: request, scope: scope}, nil
}

func (f *FakeClient) UploadTaskOutputStream(ctx context.Context, endpoint string, request OutputStreamRequest, fin OutputFin) (OutputStreamResult, error) {
	stream, err := f.OpenTaskOutputStream(ctx, endpoint, request)
	if err != nil {
		return OutputStreamResult{}, err
	}
	defer func() { _ = stream.Close() }()
	return stream.Finish(fin)
}

func (s *fakeOutputStream) SendChunk(chunk OutputChunk) error {
	if err := s.append(chunk); err != nil {
		return err
	}
	s.client.outputStreams[s.scope] = append([]OutputChunk(nil), s.chunks...)
	s.client.record("output_chunk")
	return nil
}

func (s *fakeOutputStream) Finish(fin OutputFin) (OutputStreamResult, error) {
	if s.closed || s.failed || s.mmr.LeafCount() == 0 {
		return OutputStreamResult{}, fmt.Errorf("output stream requires at least one leaf and an open stream")
	}
	s.closed = true
	root := s.mmr.Root()
	if _, err := outputFinFrame(s.request.Auth.ChainID, s.request.TaskHash, root, s.mmr.LeafCount(), fin); err != nil {
		return OutputStreamResult{}, err
	}
	fin.WorkerSignature = append([]byte(nil), fin.WorkerSignature...)
	s.client.UploadedOutputFins = append(s.client.UploadedOutputFins, fin)
	key := TaskDataKey{TaskHash: s.request.TaskHash, SessionID: s.request.SessionID, TaskID: s.request.TaskID, Kind: DataKindOutput, ContentHash: root.String()}
	var data []byte
	lengths := make([]uint32, 0, len(s.chunks))
	for _, chunk := range s.chunks {
		data = append(data, chunk.Text...)
		lengths = append(lengths, uint32(len(chunk.Text)))
	}
	if s.client.TaskData == nil {
		s.client.TaskData = map[TaskDataKey][]byte{}
	}
	if s.client.TaskDataMetadata == nil {
		s.client.TaskDataMetadata = map[TaskDataKey]TaskDataMetadata{}
	}
	for existing := range s.client.TaskDataMetadata {
		if existing.TaskHash == key.TaskHash && existing.SessionID == key.SessionID && existing.TaskID == key.TaskID && existing.Kind == DataKindOutput && existing != key {
			return OutputStreamResult{}, fmt.Errorf("output stream conflicts with stored output")
		}
	}
	s.client.TaskData[key] = data
	if existing, ok := s.client.TaskDataMetadata[key]; !ok || existing.Readiness != TaskDataReady {
		s.client.TaskDataMetadata[key] = TaskDataMetadata{Key: key, SizeBytes: uint64(len(data)), Readiness: TaskDataStored, ChunkLengths: lengths, OutputLeafCount: uint64(len(lengths))}
	}
	s.client.record("output_fin")
	return OutputStreamResult{LastSeq: s.mmr.LeafCount() - 1, LeafCount: s.mmr.LeafCount(), OutputMMRRoot: root}, nil
}

func (s *fakeOutputStream) Close() error { s.closed = true; return nil }
