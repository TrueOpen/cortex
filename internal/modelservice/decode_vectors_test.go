package modelservice

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/modelmanifest"
)

// countingVectorsSource hands out a fixed DECODE_VECTORS answer and counts how
// often it was asked, so the tests can see the pass being cached (or a failure
// deliberately not).
type countingVectorsSource struct {
	mu      sync.Mutex
	calls   int
	vectors []modelmanifest.DecodeVector
	err     error
}

func (s *countingVectorsSource) DecodeVectors(context.Context, chainclient.CurrentProfileSnapshot) ([]modelmanifest.DecodeVector, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return s.vectors, s.err
}

func (s *countingVectorsSource) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// conformingVectors are DECODE_VECTORS this stub engine reproduces: the
// trailing-EOS strip, a body special token rendered literally, and a T of
// nothing but an EOS whose committed output is empty (checked without any
// engine call).
func conformingVectors() []modelmanifest.DecodeVector {
	return []modelmanifest.DecodeVector{
		{TokenIDs: []uint32{10, 11, testEOSTokenID}, ExpectedBytes: []byte("hello world")},
		{TokenIDs: []uint32{10, testEOSTokenID, 11}, ExpectedBytes: append(append([]byte("hello"), eosBytes...), []byte(" world")...)},
		{TokenIDs: []uint32{testEOSTokenID}, ExpectedBytes: []byte{}},
	}
}

// A profile whose manifest declares DECODE_VECTORS gates every decode on
// reproducing them, once: the vectors run before the first DetokenizeCommitted
// and never again for the same manifest and engine.
func TestDecodeVectorsPassIsRequiredOnceThenCached(t *testing.T) {
	stub := &detokenizeStub{t: t, decode: decodeFromGenTokens([]genToken{hello, world, eos})}
	srv := stub.start()
	svc := chainBoundLocalService(srv.URL)
	source := &countingVectorsSource{vectors: conformingVectors()}
	svc.SetDecodeVectorsSource(source)
	for i := range 2 {
		decoded, err := svc.DetokenizeCommitted(context.Background(), testQwenModelID(), "1", []uint32{10, 11, testEOSTokenID})
		if err != nil || string(decoded) != "hello world" {
			t.Fatalf("DetokenizeCommitted() #%d = %q, %v", i, decoded, err)
		}
	}
	if source.callCount() != 1 {
		t.Fatalf("vectors were fetched %d times, want once (pass cached)", source.callCount())
	}
	// One calibration round trip, one decode per vector with a non-empty
	// committed prefix (the all-EOS vector costs no engine call), and one
	// decode per DetokenizeCommitted.
	if stub.detokenizeCalls != 1+2+2 {
		t.Fatalf("engine detokenize calls = %d, want 5", stub.detokenizeCalls)
	}
}

// A failed vector refuses both decode paths -- the Verifier's comparison and
// the Worker's corroborated commit -- and the failure is not cached, so a
// fixed engine is retried.
func TestDecodeVectorsFailureRefusesBothPaths(t *testing.T) {
	disagreeing := []modelmanifest.DecodeVector{{TokenIDs: []uint32{10, 11}, ExpectedBytes: []byte("goodbye")}}
	t.Run("verifier path", func(t *testing.T) {
		stub := &detokenizeStub{t: t, decode: decodeFromGenTokens([]genToken{hello, world, eos})}
		srv := stub.start()
		svc := chainBoundLocalService(srv.URL)
		source := &countingVectorsSource{vectors: disagreeing}
		svc.SetDecodeVectorsSource(source)
		for i := range 2 {
			_, err := svc.DetokenizeCommitted(context.Background(), testQwenModelID(), "1", []uint32{10, 11})
			if err == nil || !strings.Contains(err.Error(), "DECODE_VECTORS[0]") {
				t.Fatalf("DetokenizeCommitted() #%d error = %v, want the vector refusal", i, err)
			}
		}
		if source.callCount() != 2 {
			t.Fatalf("vectors were fetched %d times, want a failure retried, never cached", source.callCount())
		}
	})
	t.Run("worker path", func(t *testing.T) {
		tokens := []genToken{hello, world, eos}
		stub := &detokenizeStub{t: t, chat: chatGeneration(tokens, "stop"), decode: decodeFromGenTokens(tokens)}
		srv := stub.start()
		svc := chainBoundLocalService(srv.URL)
		svc.SetStreamInference(false)
		svc.SetDetokenizeCorroboration(true)
		svc.SetDecodeVectorsSource(&countingVectorsSource{vectors: disagreeing})
		_, err := svc.Infer(context.Background(), chatBoundWithLimit(t, InferRequest{
			RequestID: "gated", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1,
			Input: []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
		}, uint64(len(tokens))))
		if err == nil || !strings.Contains(err.Error(), "DECODE_VECTORS[0]") {
			t.Fatalf("Infer() error = %v, want the vector refusal", err)
		}
	})
}

// A manifest that declares no vectors (decode_vectors_path "") passes
// vacuously, and a transient source failure refuses the task without being
// cached.
func TestDecodeVectorsAbsenceAndSourceFailure(t *testing.T) {
	stub := &detokenizeStub{t: t, decode: decodeFromGenTokens([]genToken{hello, world, eos})}
	srv := stub.start()
	svc := chainBoundLocalService(srv.URL)
	source := &countingVectorsSource{err: errors.New("mirror unreachable")}
	svc.SetDecodeVectorsSource(source)
	if _, err := svc.DetokenizeCommitted(context.Background(), testQwenModelID(), "1", []uint32{10, 11}); err == nil || !strings.Contains(err.Error(), "obtain DECODE_VECTORS") {
		t.Fatalf("DetokenizeCommitted() error = %v, want the fetch refusal", err)
	}
	source.mu.Lock()
	source.err = nil // the source recovers, answering a declared absence
	source.mu.Unlock()
	for i := range 2 {
		if _, err := svc.DetokenizeCommitted(context.Background(), testQwenModelID(), "1", []uint32{10, 11}); err != nil {
			t.Fatalf("DetokenizeCommitted() #%d error = %v after the source recovered", i, err)
		}
	}
	if source.callCount() != 2 {
		t.Fatalf("vectors were fetched %d times, want the failure retried and the absence cached", source.callCount())
	}
}
