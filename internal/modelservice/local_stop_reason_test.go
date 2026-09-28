package modelservice

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
	"github.com/TrueOpen/cortex/internal/modelmanifest"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

// The testnet Qwen3.8-27B-FP8 manifest lists eos_token_ids [248044, 248046].
// vLLM stops on the primary EOS with a null stop_reason, but on the model's
// other EOS id with that id as a numeric stop_reason.
func testnetManifestBytes(t *testing.T) []byte {
	t.Helper()
	body, err := os.ReadFile("../modelmanifest/testdata/testnet_qwen3.8-27b-fp8.manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func testnetDecoding() modelmanifest.OutputDecoding {
	return modelmanifest.OutputDecoding{EOSTokenIDs: []uint32{248044, 248046}}
}

// testnetBoundLocalService is chainBoundLocalService with the testnet
// manifest as the profile's manifest.
func testnetBoundLocalService(t *testing.T, url string) *LocalService {
	t.Helper()
	manifest := testnetManifestBytes(t)
	hash := modelmanifest.Hash(manifest)
	snapshot := liveLikeProfileSnapshotWithTopK(defaultTopK)(testQwenModelID(), "1")
	snapshot.ManifestHash = chainclient.ProtoBytes32(hash[:])
	svc := newBoundLocalService(url, "local-svc", 4, 0, 0)
	svc.SetOutputDecodingSource(outputDecodingSourceFunc(func(_ context.Context, profile chainclient.CurrentProfileSnapshot) (modelmanifest.OutputDecoding, error) {
		return modelmanifest.VerifyOutputDecoding(manifest, profile.ManifestHash)
	}))
	svc.SetProfileResolver(staticLocalProfileResolver{profile: snapshot})
	return svc
}

func TestNumericStopReasonOnAnEOSIdIsAnEOSFinish(t *testing.T) {
	for _, test := range []struct {
		name  string
		stop  string
		stops []uint32
		want  nodewire.FinishReasonV1
		fails bool
	}{
		{name: "first eos id", stop: "248044", want: nodewire.FinishReasonV1EosToken},
		{name: "second eos id", stop: "248046", want: nodewire.FinishReasonV1EosToken},
		{name: "order stop token only", stop: "11", stops: []uint32{11}, want: nodewire.FinishReasonV1StopToken},
		// EOS wins when the order also lists an EOS id as a stop token.
		{name: "in both sets", stop: "248044", stops: []uint32{248044}, want: nodewire.FinishReasonV1EosToken},
		{name: "in neither set", stop: "11", fails: true},
		{name: "in neither set with other stops", stop: "12", stops: []uint32{11}, fails: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			g := localTestGeneration(testQwenModelID(), 1)
			g.Params.DecodingParams.StopTokenIDs = test.stops
			got, err := localGenerationFinishReason(g, testnetDecoding(), "stop", json.RawMessage(test.stop), 3)
			if test.fails {
				if err == nil {
					t.Fatalf("finish = %v, want a refusal", got)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("finish = %v, %v; want %v", got, err, test.want)
			}
		})
	}
	// Without an output_decoding (the dev path) nothing changes: an id the
	// order does not list is refused, as before.
	if _, err := localGenerationFinishReason(localTestGeneration(testQwenModelID(), 1), modelmanifest.OutputDecoding{}, "stop", json.RawMessage("248044"), 3); err == nil {
		t.Fatal("dev path accepted an unlisted numeric stop_reason")
	}
}

// A stop token that is not an EOS token stays in the committed output.
func TestAStopTokenIsNotStripped(t *testing.T) {
	stopToken := genToken{11, []byte("!")}
	resp := chatGeneration([]genToken{hello, stopToken}, "stop")
	text, err := decodeTokensFromLogprobs(resp.Choices[0].TokenIDs, resp.Choices[0].Logprobs, testnetDecoding())
	if err != nil || text != "hello!" {
		t.Fatalf("committed output = %q, %v; want the stop token kept", text, err)
	}
}

// A stop on either testnet EOS id reported as a numeric stop_reason is an EOS
// finish on both paths, the EOS is left out, and both paths commit the same
// bytes. An id in both the order's stop_token_ids and eos_token_ids is EOS
// too; an id in neither set fails locally.
func TestNumericEOSStopReasonCommitsTheSameBytesOnBothPaths(t *testing.T) {
	for _, eosID := range []int{248044, 248046} {
		stop := json.RawMessage(mustJSON(t, eosID))
		tokens := []genToken{hello, world, {eosID, []byte("<|eos|>")}}
		var outputs [][]byte

		// Raw text: the engine leaves the stopped-on token out of its text.
		for _, orderStops := range [][]uint32{nil, {uint32(eosID)}} {
			srv, _ := newVLLMStub(t, rawGeneration("hello world", "stop", string(stop), 10, 11, eosID), verifyResponse())
			svc := testnetBoundLocalService(t, srv.URL)
			svc.SetStreamInference(false)
			resp, err := svc.Infer(context.Background(), rawBound(t, 3, orderStops...))
			if err != nil {
				t.Fatalf("raw %d stops %v: Infer() = %v", eosID, orderStops, err)
			}
			if resp.FinishReason != nodewire.FinishReasonV1EosToken {
				t.Fatalf("raw %d stops %v: finish = %v, want EOS", eosID, orderStops, resp.FinishReason)
			}
			out, _ := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.OutputRef})
			outputs = append(outputs, out.Data)
		}

		// Chat, buffered and streamed.
		for _, streamed := range []bool{false, true} {
			var srv *httptest.Server
			if streamed {
				chunks := chatGenerationChunks(tokens, "stop")
				chunks[len(tokens)-1].Choices[0].StopReason = stop
				srv, _ = newChatVLLMStreamStub(t, chunks, []string{"Qwen/Qwen3-8B"})
			} else {
				gen := chatGeneration(tokens, "stop")
				gen.Choices[0].StopReason = stop
				srv, _ = newChatVLLMStub(t, gen, []string{"Qwen/Qwen3-8B"})
			}
			svc := testnetBoundLocalService(t, srv.URL)
			svc.SetStreamInference(streamed)
			obs := &recordingObserver{}
			resp, err := svc.Infer(WithInferStreamObserver(context.Background(), obs), chatBound(t, InferRequest{
				RequestID: "chat-stop-reason", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1,
				Input: []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
			}))
			if err != nil {
				t.Fatalf("chat %d streamed=%v: Infer() = %v", eosID, streamed, err)
			}
			if resp.FinishReason != nodewire.FinishReasonV1EosToken || resp.GeneratedTokenCount != 3 {
				t.Fatalf("chat %d streamed=%v: finish %v, %d tokens", eosID, streamed, resp.FinishReason, resp.GeneratedTokenCount)
			}
			out, _ := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: resp.OutputRef})
			if streamed {
				var concat []byte
				for _, frame := range obs.frames {
					concat = append(concat, frame.TextDelta...)
				}
				if len(obs.frames) == 0 || !bytes.Equal(concat, out.Data) {
					t.Fatalf("chat %d: streamed %q, committed %q", eosID, concat, out.Data)
				}
			}
			outputs = append(outputs, out.Data)
		}
		for i, out := range outputs {
			if string(out) != "hello world" {
				t.Fatalf("eos %d: output %d = %q, want %q on every path", eosID, i, out, "hello world")
			}
		}
	}

	// An id in neither set fails locally on both paths.
	srv, _ := newVLLMStub(t, rawGeneration("hello world", "stop", "99", 10, 11, 99), verifyResponse())
	raw := testnetBoundLocalService(t, srv.URL)
	raw.SetStreamInference(false)
	if _, err := raw.Infer(context.Background(), rawBound(t, 3)); err == nil {
		t.Fatal("raw text accepted a numeric stop_reason in neither set")
	}
	gen := chatGeneration([]genToken{hello, world, {99, []byte("?")}}, "stop")
	gen.Choices[0].StopReason = json.RawMessage("99")
	chatSrv, _ := newChatVLLMStub(t, gen, []string{"Qwen/Qwen3-8B"})
	chat := testnetBoundLocalService(t, chatSrv.URL)
	chat.SetStreamInference(false)
	if _, err := chat.Infer(context.Background(), chatBound(t, InferRequest{
		RequestID: "chat-stop-reason", ModelID: testQwenModelID(), Capability: CapabilityLLMTextV1,
		Input: []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
	})); err == nil || !strings.Contains(err.Error(), "stop_reason") {
		t.Fatalf("chat Infer() = %v, want a numeric stop_reason in neither set refused", err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
