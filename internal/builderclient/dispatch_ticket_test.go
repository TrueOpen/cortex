package builderclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

var testDispatchTicket = codec.HashBytes([]byte("builderclient dispatch ticket"))

func TestInferReceiptBindsTheDispatchTicket(t *testing.T) {
	facts := completeInferReceiptFacts(t)
	receipt, digest, err := BuildInferReceipt(facts)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.DispatchTicketHash != facts.DispatchTicketHash {
		t.Fatalf("receipt ticket = %q, want %q", receipt.DispatchTicketHash, facts.DispatchTicketHash)
	}
	other := receipt
	other.DispatchTicketHash = strings.Repeat("43", 32)
	if moved, err := InferReceiptSigningDigest(other); err != nil || moved == digest {
		t.Fatal("dispatch_ticket_hash must enter the signing projection (field 19)")
	}
	for name, v := range map[string]string{"absent": "", "zero": strings.Repeat("00", 32), "upper": strings.Repeat("AB", 32)} {
		bad := receipt
		bad.DispatchTicketHash = v
		if _, err := InferReceiptSigningDigest(bad); err == nil {
			t.Fatalf("%s ticket accepted", name)
		}
	}
	pair := newTaskDataTestKeyPair(t)
	receipt.ServiceSignature = hex.EncodeToString(pair.sign(t, digest))
	wire := signedInferReceiptToProto(receipt)
	if hex.EncodeToString(wire.GetDispatchTicketHash()) != facts.DispatchTicketHash {
		t.Fatal("InferReceiptV3.dispatch_ticket_hash (field 19) is not carried")
	}
	back, err := signedInferReceiptFromProto(wire)
	if err != nil || back.DispatchTicketHash != receipt.DispatchTicketHash {
		t.Fatalf("round trip = %q, %v", back.DispatchTicketHash, err)
	}
}

func TestOutputStreamFramesCarryTheTicketAndTokens(t *testing.T) {
	chunk := OutputChunk{Seq: 0, Text: []byte("a"), MMRRoot: codec.Hash{9}, WorkerSignature: []byte{1}, CumulativeGeneratedTokens: 5}
	f := outputChunkFrame(chunk, testDispatchTicket).GetChunk()
	if !bytes.Equal(f.GetDispatchTicketHash(), testDispatchTicket[:]) || f.GetCumulativeGeneratedTokens() != 5 {
		t.Fatalf("chunk frame = %v", f)
	}
	request := outputStreamFixture(t, "first long chunk", "last")
	if request.DispatchTicketHash != testDispatchTicket {
		t.Fatal("the fixture streams for the test ticket")
	}
	fin := outputFinFixture(t, request, nodewire.FinishReasonV1EosToken)
	last := request.ReplayChunks[1]
	frame, err := outputFinFrame(request.Auth.ChainID, request.TaskHash, request.DispatchTicketHash, last.MMRRoot, 2, fin)
	if err != nil || !bytes.Equal(frame.GetFin().GetDispatchTicketHash(), testDispatchTicket[:]) {
		t.Fatalf("fin frame = %v, %v", frame, err)
	}
	if _, err := OutputStreamHeaderDigest(request.Auth.ChainID, request.TaskHash, codec.Hash{}); err == nil {
		t.Fatal("a stream header without an accepted ticket is refused")
	}
	zero := request
	zero.DispatchTicketHash = codec.Hash{}
	if err := validateOutputStreamRequest(zero); err == nil {
		t.Fatal("an output stream request without a ticket is refused")
	}
}

func TestOutputStreamRefusesDecreasingGeneratedTokens(t *testing.T) {
	request := outputStreamFixture(t, "first long chunk", "last")
	request.ReplayChunks[0].CumulativeGeneratedTokens = 4
	request.ReplayChunks[1].CumulativeGeneratedTokens = 3
	if _, err := NewFakeClient().OpenTaskOutputStream(context.Background(), "https://builder.example", request); err == nil {
		t.Fatal("cumulative_generated_tokens is non-decreasing within an attempt (PHASE1_CONTRACT)")
	}
	request.ReplayChunks[1].CumulativeGeneratedTokens = 4
	if _, err := NewFakeClient().OpenTaskOutputStream(context.Background(), "https://builder.example", request); err != nil {
		t.Fatal(err)
	}
}
