package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/taskdataauth"
)

const (
	inputTestBuilder  = "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"
	inputTestOperator = "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc"
	inputTestKeyRef   = "worker.json"
	inputTestHeight   = uint64(100)
	inputTestExpiry   = uint64(20)
)

type inputServiceKeys struct {
	binding chainclient.ServiceKeySnapshot
	err     error
}

func (s *inputServiceKeys) CommittedCurrentServiceKey(_ context.Context, participantType, operatorAddress string) (chainclient.ServiceKeySnapshot, uint64, error) {
	if s.err != nil {
		return chainclient.ServiceKeySnapshot{}, 0, s.err
	}
	if participantType != chainclient.ParticipantTypeCortexNode || operatorAddress != inputTestOperator {
		return chainclient.ServiceKeySnapshot{}, 0, fmt.Errorf("unexpected current service-key query %s/%s", participantType, operatorAddress)
	}
	return s.binding, inputTestHeight, nil
}

type staticEndpoints struct {
	endpoint BuilderEndpoint
	err      error
}

func (s staticEndpoints) ResolveBuilderEndpoint(_ context.Context, operatorAddress string) (BuilderEndpoint, error) {
	if s.err != nil {
		return BuilderEndpoint{}, s.err
	}
	if operatorAddress != s.endpoint.OperatorAddress {
		return BuilderEndpoint{}, fmt.Errorf("unexpected Builder %q", operatorAddress)
	}
	return s.endpoint, nil
}

type inputTaskDataClient struct {
	*builderclient.FakeClient
	payload          []byte
	metadata         builderclient.TaskDataMetadata
	metadataErr      error
	fetch            func(builderclient.FetchTaskDataRequest, func(builderclient.TaskDataChunk) error) error
	metadataRequests []builderclient.GetTaskDataMetadataRequest
	ranges           []builderclient.FetchTaskDataRequest
	// verify commit relay: records the endpoint and the request; returns relayErr when set.
	commitEndpoints []string
	commitPins      []string
	commits         []builderclient.SubmitVerifyCommitRequest
	relayErr        error
}

func (c *inputTaskDataClient) SubmitVerifyCommit(ctx context.Context, endpoint string, request builderclient.SubmitVerifyCommitRequest) (builderclient.VerifyRelayAck, error) {
	c.commitEndpoints = append(c.commitEndpoints, endpoint)
	pin, _ := builderclient.TLSPubkeyHashFromContext(ctx)
	c.commitPins = append(c.commitPins, pin)
	c.commits = append(c.commits, request)
	if c.relayErr != nil {
		return builderclient.VerifyRelayAck{}, c.relayErr
	}
	return builderclient.VerifyRelayAck{CommitKey: codec.HashBytes([]byte("relay-commit"))}, nil
}

func (c *inputTaskDataClient) GetTaskDataMetadata(_ context.Context, _ string, request builderclient.GetTaskDataMetadataRequest) (builderclient.TaskDataMetadata, error) {
	c.metadataRequests = append(c.metadataRequests, request)
	return c.metadata, c.metadataErr
}

func (c *inputTaskDataClient) FetchTaskData(_ context.Context, _ string, request builderclient.FetchTaskDataRequest, receive func(builderclient.TaskDataChunk) error) error {
	if request.Range == nil {
		request.Range = &builderclient.TaskDataRange{Length: uint64(len(c.payload))}
	}
	c.ranges = append(c.ranges, request)
	if c.fetch != nil {
		return c.fetch(request, receive)
	}
	end := request.Range.Offset + request.Range.Length
	if end > uint64(len(c.payload)) {
		return fmt.Errorf("range end %d exceeds payload size %d", end, len(c.payload))
	}
	return receive(builderclient.TaskDataChunk{
		Offset: request.Range.Offset,
		Data:   c.payload[request.Range.Offset:end],
		EOF:    true,
	})
}

func (*inputTaskDataClient) UploadTaskResultData(context.Context, string, builderclient.UploadTaskResultRequest) (builderclient.StorageConfirmation, error) {
	return builderclient.StorageConfirmation{}, errors.New("unexpected upload")
}

func (*inputTaskDataClient) SubmitInferReceipt(context.Context, string, builderclient.SubmitInferReceiptRequest) error {
	return errors.New("unexpected receipt relay")
}

func localInputServiceSigner(t *testing.T) (signer.Signer, chainclient.ServiceKeySnapshot) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, inputTestKeyRef), []byte(runtimeTestKeystore), 0o600); err != nil {
		t.Fatalf("write keystore: %v", err)
	}
	signing, err := signer.NewLocalSigner(dir, []byte(runtimeTestKeystorePassword), "trueopen", []signer.KeyRef{{Ref: inputTestKeyRef}})
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	keys := signing.Keys()
	if len(keys) != 1 {
		t.Fatalf("Keys() = %#v", keys)
	}
	return signing, chainclient.ServiceKeySnapshot{
		ParticipantType:    chainclient.ParticipantTypeCortexNode,
		OperatorAddress:    inputTestOperator,
		ServiceAddress:     keys[0].Address,
		ServicePubkey:      keys[0].CompressedPubkey,
		AuthorizationNonce: chainclient.NewUint64String(1),
		Status:             "ACTIVE",
	}
}

func newInputResolver(t *testing.T, client *inputTaskDataClient, rangeBytes, maxBytes uint64) (*NexusTaskInputResolver, *inputServiceKeys) {
	t.Helper()
	signing, binding := localInputServiceSigner(t)
	serviceKeys := &inputServiceKeys{binding: binding}
	auth, err := taskdataauth.New(taskdataauth.Config{
		ServiceKeys: serviceKeys, Signer: signing,
		ChainID: "trueopen-devnet-1", OperatorAddress: inputTestOperator,
		ServiceAddress: binding.ServiceAddress, ServicePubkey: binding.ServicePubkey,
		ServiceKeyRef: inputTestKeyRef, ExpiryBlocks: inputTestExpiry,
	})
	if err != nil {
		t.Fatalf("taskdataauth.New: %v", err)
	}
	resolver, err := NewNexusTaskInputResolver(NexusTaskInputResolverConfig{
		TaskData: client,
		Endpoints: staticEndpoints{endpoint: BuilderEndpoint{
			OperatorAddress: inputTestBuilder,
			Endpoint:        "https://builder.example",
			Source:          BuilderEndpointSourceDescriptor,
		}},
		Auth: auth, RangeBytes: rangeBytes, MaxInputBytes: maxBytes,
	})
	if err != nil {
		t.Fatalf("NewNexusTaskInputResolver: %v", err)
	}
	return resolver, serviceKeys
}

func taskInputRef(payload []byte) TaskInputRef {
	return TaskInputRef{
		SessionID: strings.Repeat("11", 32), TaskID: strings.Repeat("22", 32), TaskHash: codec.HashBytes([]byte("accepted-task")),
		PayloadHash:            chainclient.HexHash(codec.HashBytes(payload)),
		BuilderOperatorAddress: inputTestBuilder,
	}
}

func taskDataMetadata(payload []byte) builderclient.TaskDataMetadata {
	digest := sha256.Sum256(payload)
	return builderclient.TaskDataMetadata{
		Readiness: builderclient.TaskDataReady, Key: builderclient.TaskDataKey{TaskHash: codec.HashBytes([]byte("accepted-task")).String(), SessionID: strings.Repeat("11", 32), TaskID: strings.Repeat("22", 32), Kind: builderclient.DataKindInput, ContentHash: hex.EncodeToString(digest[:])},
		SizeBytes: uint64(len(payload)), MediaType: "application/octet-stream",
	}
}

func TestNexusTaskInputResolverFetchesContiguousRanges(t *testing.T) {
	payload := []byte("0123456789")
	client := &inputTaskDataClient{payload: payload, metadata: taskDataMetadata(payload)}
	resolver, _ := newInputResolver(t, client, 4, 0)

	got, err := resolver.ResolveTaskInput(context.Background(), taskInputRef(payload))
	if err != nil {
		t.Fatalf("ResolveTaskInput: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("input = %q, want %q", got, payload)
	}
	wantRanges := [][2]uint64{{0, 4}, {4, 4}, {8, 2}}
	if len(client.ranges) != len(wantRanges) {
		t.Fatalf("ranges = %+v, want %v", client.ranges, wantRanges)
	}
	for i, want := range wantRanges {
		if client.ranges[i].Range.Offset != want[0] || client.ranges[i].Range.Length != want[1] {
			t.Fatalf("range %d = %d/%d, want %d/%d", i, client.ranges[i].Range.Offset, client.ranges[i].Range.Length, want[0], want[1])
		}
		if client.ranges[i].Auth.ExpiresAtHeight <= inputTestHeight || client.ranges[i].Auth.ExpiresAtHeight > inputTestHeight+inputTestExpiry {
			t.Fatalf("range %d expiry = %d, want (%d,%d]", i, client.ranges[i].Auth.ExpiresAtHeight, inputTestHeight, inputTestHeight+inputTestExpiry)
		}
	}
	if len(client.metadataRequests) != 1 {
		t.Fatalf("metadata requests = %d, want 1", len(client.metadataRequests))
	}
	auth := client.metadataRequests[0].Auth
	if auth.BuilderAddress != inputTestBuilder || auth.ExpiresAtHeight <= inputTestHeight || auth.ExpiresAtHeight > inputTestHeight+inputTestExpiry {
		t.Fatalf("metadata auth = %+v", auth)
	}
}

func TestNexusTaskInputResolverResumesAtLastConfirmedOffset(t *testing.T) {
	payload := []byte("abcdefgh")
	client := &inputTaskDataClient{payload: payload, metadata: taskDataMetadata(payload)}
	first := true
	client.fetch = func(request builderclient.FetchTaskDataRequest, receive func(builderclient.TaskDataChunk) error) error {
		if first {
			first = false
			if err := receive(builderclient.TaskDataChunk{Offset: request.Range.Offset, Data: payload[:2], EOF: false}); err != nil {
				return err
			}
			return builderclient.Retryable(errors.New("stream interrupted"))
		}
		end := request.Range.Offset + request.Range.Length
		return receive(builderclient.TaskDataChunk{Offset: request.Range.Offset, Data: payload[request.Range.Offset:end], EOF: true})
	}
	resolver, _ := newInputResolver(t, client, 4, 0)

	got, err := resolver.ResolveTaskInput(context.Background(), taskInputRef(payload))
	if err != nil {
		t.Fatalf("ResolveTaskInput: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("input = %q, want %q", got, payload)
	}
	want := [][2]uint64{{0, 4}, {2, 2}, {4, 4}}
	if len(client.ranges) != len(want) {
		t.Fatalf("ranges = %+v, want %v", client.ranges, want)
	}
	for i := range want {
		if client.ranges[i].Range.Offset != want[i][0] || client.ranges[i].Range.Length != want[i][1] {
			t.Fatalf("range %d = %d/%d, want %d/%d", i, client.ranges[i].Range.Offset, client.ranges[i].Range.Length, want[i][0], want[i][1])
		}
	}
}

func TestNexusTaskInputResolverUsesFreshNonceOnRetry(t *testing.T) {
	payload := []byte("abcdefgh")
	client := &inputTaskDataClient{payload: payload, metadata: taskDataMetadata(payload)}
	first := true
	client.fetch = func(request builderclient.FetchTaskDataRequest, receive func(builderclient.TaskDataChunk) error) error {
		if first {
			first = false
			if err := receive(builderclient.TaskDataChunk{Offset: 0, Data: payload[:2]}); err != nil {
				return err
			}
			return builderclient.Retryable(errors.New("retry me"))
		}
		end := request.Range.Offset + request.Range.Length
		return receive(builderclient.TaskDataChunk{Offset: request.Range.Offset, Data: payload[request.Range.Offset:end], EOF: true})
	}
	resolver, _ := newInputResolver(t, client, 4, 0)
	if _, err := resolver.ResolveTaskInput(context.Background(), taskInputRef(payload)); err != nil {
		t.Fatalf("ResolveTaskInput: %v", err)
	}
	if len(client.ranges) < 2 || bytes.Equal(client.ranges[0].Auth.RequestNonce, client.ranges[1].Auth.RequestNonce) {
		t.Fatalf("retry nonces = %x / %x, want fresh values", client.ranges[0].Auth.RequestNonce, client.ranges[1].Auth.RequestNonce)
	}
}

func TestNexusTaskInputResolverRejectsServiceKeyBindingMismatch(t *testing.T) {
	payload := []byte("input")
	client := &inputTaskDataClient{payload: payload, metadata: taskDataMetadata(payload)}
	resolver, keys := newInputResolver(t, client, 4, 0)
	keys.binding.ServiceAddress = "trueopen1rotated"

	_, err := resolver.ResolveTaskInput(context.Background(), taskInputRef(payload))
	if err == nil || builderclient.IsRetryable(err) || !strings.Contains(err.Error(), "runtime service") {
		t.Fatalf("ResolveTaskInput error = %v, want permanent runtime binding mismatch", err)
	}
	if len(client.metadataRequests) != 0 {
		t.Fatalf("metadata calls = %d, want zero before valid authentication", len(client.metadataRequests))
	}
}

func TestNexusTaskInputResolverRejectsMetadataHashOrSizeMismatch(t *testing.T) {
	payload := []byte("input")
	for name, mutate := range map[string]func(*builderclient.TaskDataMetadata){
		"missing":      func(metadata *builderclient.TaskDataMetadata) { metadata.Readiness = builderclient.TaskDataStored },
		"wrong hash":   func(metadata *builderclient.TaskDataMetadata) { metadata.Key.ContentHash = strings.Repeat("0", 64) },
		"invalid hash": func(metadata *builderclient.TaskDataMetadata) { metadata.Key.ContentHash = "ABC" },
		"zero size":    func(metadata *builderclient.TaskDataMetadata) { metadata.SizeBytes = 0 },
		"too large":    func(metadata *builderclient.TaskDataMetadata) { metadata.SizeBytes = 9 },
	} {
		t.Run(name, func(t *testing.T) {
			metadata := taskDataMetadata(payload)
			mutate(&metadata)
			client := &inputTaskDataClient{payload: payload, metadata: metadata}
			resolver, _ := newInputResolver(t, client, 4, 8)
			_, err := resolver.ResolveTaskInput(context.Background(), taskInputRef(payload))
			if err == nil || builderclient.IsRetryable(err) {
				t.Fatalf("ResolveTaskInput error = %v, want permanent metadata rejection", err)
			}
			if len(client.ranges) != 0 {
				t.Fatalf("fetch calls = %d, want zero after invalid metadata", len(client.ranges))
			}
		})
	}
}

func TestNexusTaskInputResolverRejectsGapOverlapAndPrematureEOF(t *testing.T) {
	payload := []byte("abcd")
	for name, frames := range map[string][]builderclient.TaskDataChunk{
		"gap":           {{Offset: 1, Data: []byte("abcd"), EOF: true}},
		"overlap":       {{Offset: 0, Data: []byte("ab")}, {Offset: 1, Data: []byte("cd"), EOF: true}},
		"premature EOF": {{Offset: 0, Data: []byte("ab"), EOF: true}},
		"missing EOF":   {{Offset: 0, Data: []byte("abcd"), EOF: false}},
	} {
		t.Run(name, func(t *testing.T) {
			client := &inputTaskDataClient{payload: payload, metadata: taskDataMetadata(payload)}
			client.fetch = func(_ builderclient.FetchTaskDataRequest, receive func(builderclient.TaskDataChunk) error) error {
				for _, frame := range frames {
					if err := receive(frame); err != nil {
						return err
					}
				}
				return nil
			}
			resolver, _ := newInputResolver(t, client, 4, 0)
			_, err := resolver.ResolveTaskInput(context.Background(), taskInputRef(payload))
			if err == nil || builderclient.IsRetryable(err) {
				t.Fatalf("ResolveTaskInput error = %v, want permanent frame rejection", err)
			}
		})
	}
}

func TestNexusTaskInputResolverUsesSignedSizeWithoutMetadata(t *testing.T) {
	payload := []byte("signed-size-payload")
	client := &inputTaskDataClient{payload: payload}
	resolver, _ := newInputResolver(t, client, 0, 0)

	ref := taskInputRef(payload)
	ref.InputSizeBytes = uint64(len(payload))
	got, err := resolver.ResolveTaskInput(context.Background(), ref)
	if err != nil {
		t.Fatalf("ResolveTaskInput: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
	if len(client.metadataRequests) != 0 {
		t.Fatalf("metadata requests = %d, want 0", len(client.metadataRequests))
	}
}

func TestNexusTaskInputResolverFallsBackToMetadataOnFetchFailure(t *testing.T) {
	payload := []byte("signed-size-payload")
	client := &inputTaskDataClient{
		payload: payload,
		fetch: func(r builderclient.FetchTaskDataRequest, receive func(builderclient.TaskDataChunk) error) error {
			return fmt.Errorf("transport error")
		},
		metadata: taskDataMetadata(payload),
	}
	resolver, _ := newInputResolver(t, client, 0, 0)

	ref := taskInputRef(payload)
	ref.InputSizeBytes = uint64(len(payload))
	_, err := resolver.ResolveTaskInput(context.Background(), ref)
	if err == nil {
		t.Fatalf("ResolveTaskInput: expected error")
	}
	if len(client.metadataRequests) != 1 {
		t.Fatalf("metadata requests = %d, want 1", len(client.metadataRequests))
	}
}

func TestNexusTaskInputResolverRejectsOversizedSignedSize(t *testing.T) {
	payload := []byte("small")
	client := &inputTaskDataClient{payload: payload}
	resolver, _ := newInputResolver(t, client, 0, 0)

	ref := taskInputRef(payload)
	ref.InputSizeBytes = defaultTaskDataMaxBytes + 1
	_, err := resolver.ResolveTaskInput(context.Background(), ref)
	if err == nil {
		t.Fatalf("ResolveTaskInput: expected error for oversized signed size")
	}
	if len(client.metadataRequests) != 0 {
		t.Fatalf("metadata requests = %d, want 0", len(client.metadataRequests))
	}
}
