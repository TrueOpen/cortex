package daemon

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"sync"
	"testing"

	"github.com/TrueOpen/cortex/internal/builderclient"
	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/signer"
	"github.com/TrueOpen/cortex/internal/store/layout"
	"github.com/TrueOpen/cortex/internal/txclient"
)

type fakeRescueTx struct {
	mu   sync.Mutex
	reqs []txclient.Request
}

func (f *fakeRescueTx) Submit(_ context.Context, r txclient.Request) (txclient.Observation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, r)
	return txclient.Observation{TaskID: r.TaskID, Kind: r.Kind, TxHash: "AB12"}, nil
}

func (f *fakeRescueTx) requests() []txclient.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]txclient.Request(nil), f.reqs...)
}

func dpSignedReceipt(t *testing.T, rec layout.DispatchRecord) builderclient.SignedInferReceipt {
	t.Helper()
	receipt, digest, err := builderclient.BuildInferReceipt(builderclient.InferReceiptFacts{
		ChainID: dpChainID, TaskID: codec.Hash(rec.TaskID).String(), TaskHash: codec.Hash(rec.TaskHash).String(),
		WorkerOperatorAddress: hrCortex, ServiceAuthorizationNonce: 7, GenerationParamsDigest: strings.Repeat("33", 32),
		OutputHash: codec.HashBytes([]byte("output")), OutputSizeBytes: 6, OutputLeafCount: 1, GeneratedTokenCount: 2,
		RequiredEvidenceCommitments: []builderclient.EvidenceCommitment{
			{EvidenceKind: nodewire.EvidenceKindWorkerValueOpening, EvidenceHashOrRoot: codec.HashBytes([]byte("v")), EncodedSizeBytes: 5},
			{EvidenceKind: nodewire.EvidenceKindWorkerTokenOpening, EvidenceHashOrRoot: codec.HashBytes([]byte("t")), EncodedSizeBytes: 7},
		},
		ProfileEvidenceRequirements: builderclient.WorkerEvidenceRequirementsV3(), ExpiryHeight: rec.InferDeadlineHeight,
		DispatchTicketHash: codec.Hash(rec.TicketHash).String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.SignDigestWithPrivateKeyHex(hrCortexKey, digest)
	if err != nil {
		t.Fatal(err)
	}
	receipt.ServiceSignature = hex.EncodeToString(sig)
	return receipt
}

func TestRecordedReceiptIsSelfRescuedNearTheInferDeadline(t *testing.T) {
	ctx := context.Background()
	tx := &fakeRescueTx{}
	rescue := func(c *DispatcherConfig) { c.Tx, c.ServiceAddress, c.ReceiptRescueMarginBlocks = tx, hrCortex, 5 }
	x, _, _ := seedDispatchedInferWith(t, rescue)
	rec := x.record(t)
	receipt := dpSignedReceipt(t, rec)
	if err := (dispatchGate{st: x.st}).ReceiptSigned(ctx, codec.Hash(rec.TicketHash), receipt); err != nil {
		t.Fatal(err)
	}
	x.chain.with(func(f *fakeDispatchChain) { f.height = 140 })
	if err := x.d.Sweep(ctx); err != nil || len(tx.requests()) != 0 {
		t.Fatalf("140 + 5 < 150: not yet (%v, %d)", err, len(tx.requests()))
	}
	x.chain.with(func(f *fakeDispatchChain) { f.height = 145 })
	if err := x.d.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	reqs := tx.requests()
	if len(reqs) != 1 || reqs[0].Kind != txclient.MsgSubmitInferReceipt || reqs[0].DeadlineHeight != 150 {
		t.Fatalf("requests = %+v", reqs)
	}
	if err := txclient.ValidateMessagePayload(txclient.MsgSubmitInferReceipt, reqs[0].Payload); err != nil {
		t.Fatalf("the rescue payload is the frozen message: %v", err)
	}
	for _, field := range []string{receipt.ServiceSignature, receipt.DispatchTicketHash, receipt.OutputHash} {
		if !payloadCarriesHex(t, reqs[0].Payload, field) {
			t.Fatalf("the rescue carries the receipt exactly as signed; %s is missing", field)
		}
	}
	if err := x.d.Sweep(ctx); err != nil || len(tx.requests()) != 1 {
		t.Fatal("one rescue per receipt")
	}
	if got := x.record(t); got.RescueTxHash != "AB12" {
		t.Fatalf("record = %+v", got)
	}
	x.chain.with(func(f *fakeDispatchChain) { f.height = 151 })
	if err := x.d.Sweep(ctx); err != nil || len(tx.requests()) != 1 {
		t.Fatal("past the infer deadline nothing is submitted")
	}

	y, _, _ := seedDispatchedInferWith(t, rescue)
	yr := y.record(t)
	if err := (dispatchGate{st: y.st}).ReceiptSigned(ctx, codec.Hash(yr.TicketHash), dpSignedReceipt(t, yr)); err != nil {
		t.Fatal(err)
	}
	y.chain.with(func(f *fakeDispatchChain) { f.height, f.assignment.ReceiptAccepted = 145, true })
	if err := y.d.Sweep(ctx); err != nil || len(tx.requests()) != 1 {
		t.Fatal("an accepted receipt is not rescued")
	}
	if got := y.record(t); !got.ReceiptAccepted {
		t.Fatal("acceptance is recorded")
	}
	if c, _ := layout.ReceiptRescueCandidates(ctx, y.st); len(c) != 0 {
		t.Fatal("an accepted receipt leaves the rescue index")
	}
}

// payloadCarriesHex reports whether the base64 ProtoJSON payload carries the
// bytes of a hex field.
func payloadCarriesHex(t *testing.T, payload []byte, hexValue string) bool {
	t.Helper()
	raw, err := hex.DecodeString(hexValue)
	if err != nil {
		return false
	}
	return strings.Contains(string(payload), base64.StdEncoding.EncodeToString(raw))
}

func TestRescueNeedsAMargin(t *testing.T) {
	x := newDispatchHarness(t, 2, nil)
	cfg := x.d.cfg
	cfg.Tx, cfg.ServiceAddress = &fakeRescueTx{}, hrCortex
	if _, err := NewDispatcher(context.Background(), cfg); err == nil {
		t.Fatal("a Tx without ReceiptRescueMarginBlocks is refused (CD §15.3: no built-in margin)")
	}
	cfg.ReceiptRescueMarginBlocks, cfg.ServiceAddress = 5, ""
	if _, err := NewDispatcher(context.Background(), cfg); err == nil {
		t.Fatal("a Tx without the submitter's ServiceAddress is refused")
	}
}
