package worker

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/signer"
)

var workerTestTicket = codec.HashWithDomain("TEST_DISPATCH_TICKET", []byte("ticket-7"))

func TestWorkerBindsItsDispatchTicketAndCountsTokens(t *testing.T) {
	h := newHarness(t)
	enableEvidenceSchema(&h)
	ctx := context.Background()
	event := finalizedTask()
	result, err := h.worker.HandleAssignmentFinalized(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	receipt := result.TaskDataReceipt
	if receipt.DispatchTicketHash != workerTestTicket.String() {
		t.Fatalf("receipt ticket = %q", receipt.DispatchTicketHash)
	}
	stream := h.taskData.UploadedOutputStreams[0]
	if stream.DispatchTicketHash != workerTestTicket {
		t.Fatal("the stream request carries the accepted ticket")
	}
	header, err := builderclient.OutputStreamHeaderDigest(h.worker.cfg.ChainID, stream.TaskHash, workerTestTicket)
	if err != nil || signer.VerifyDigestSignature(h.worker.cfg.SignerPubkey, header, stream.HeaderSignature) != nil {
		t.Fatalf("header is not signed for the ticket: %v", err)
	}
	raw, _ := hex.DecodeString(receipt.TaskHash)
	frames, err := h.persistence.OutputStreamFrames(ctx, event.TaskID)
	if err != nil || len(frames) == 0 {
		t.Fatalf("frames = %d, %v", len(frames), err)
	}
	var previous uint64
	for _, f := range frames {
		d, err := nodewire.OutputChunkSigningDigest(h.worker.cfg.ChainID, raw, workerTestTicket[:], f.Seq, f.MMRRoot[:])
		if err != nil || signer.VerifyDigestSignature(h.worker.cfg.SignerPubkey, d, f.WorkerSignature) != nil {
			t.Fatalf("frame %d is not signed for the ticket", f.Seq)
		}
		if f.CumulativeGeneratedTokens < previous {
			t.Fatal("cumulative_generated_tokens decreased")
		}
		previous = f.CumulativeGeneratedTokens
	}
	if previous != receipt.GeneratedTokenCount {
		t.Fatalf("last frame reports %d tokens, receipt %d", previous, receipt.GeneratedTokenCount)
	}
	fin := h.taskData.UploadedOutputFins[len(h.taskData.UploadedOutputFins)-1]
	last := frames[len(frames)-1]
	d, err := nodewire.OutputFinSigningDigest(h.worker.cfg.ChainID, raw, workerTestTicket[:], last.Seq, last.MMRRoot[:], fin.FinishReason)
	if err != nil || signer.VerifyDigestSignature(h.worker.cfg.SignerPubkey, d, fin.WorkerSignature) != nil {
		t.Fatal("the Fin is not signed for the ticket")
	}
}

type splitBuilders struct {
	dispatching BuilderEndpoint
	group       []BuilderEndpoint
}

func (p splitBuilders) ResolveReceivingBuilder(context.Context, ReceivingBuilderRef) (BuilderEndpoint, error) {
	return p.dispatching, nil
}

func (p splitBuilders) ResolveReceivingBuilders(context.Context, ReceivingBuilderRef) ([]BuilderEndpoint, error) {
	return p.group, nil
}

func TestWorkerStreamsOutputOnlyToTheDispatchingBuilder(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	event := finalizedTask()
	dispatching, err := h.worker.cfg.ReceivingBuilder.ResolveReceivingBuilder(ctx, receivingBuilderRef(event))
	if err != nil {
		t.Fatal(err)
	}
	other := dispatching
	other.OperatorAddress = workerTestOperatorAddress
	h.worker.cfg.ReceivingBuilder = splitBuilders{dispatching: dispatching, group: []BuilderEndpoint{dispatching, other}}
	stream, err := h.worker.openOutputStream(ctx, event, codec.HashBytes([]byte("task")), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if n := len(h.taskData.UploadedOutputStreams); n != 1 || h.taskData.UploadedOutputStreams[0].Auth.BuilderAddress != dispatching.OperatorAddress {
		t.Fatalf("opened %d streams; output frames go only to the dispatching Builder (CD W11, C1)", n)
	}
}

func TestWorkerRefusesToRunWithoutATicket(t *testing.T) {
	h := newHarnessWithConfig(t, func(c *Config) { c.DispatchTicketHash = codec.Hash{} })
	enableEvidenceSchema(&h)
	if _, err := h.worker.HandleAssignmentFinalized(context.Background(), finalizedTask()); err == nil || !strings.Contains(err.Error(), "dispatch_ticket_hash") {
		t.Fatal("a Worker responsibility without an accepted ticket cannot sign a single frame")
	}
}
