package daemon

import (
	"encoding/hex"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/builderclient"
	busv1 "github.com/TrueOpen/cortex/proto/bus/v1"
	bustaskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

// TestOrderBroadcastAcceptsACarriedSignatureChainID covers signature_chain_id
// beside the user signature in SignedOrderV2. The field rides inside the nested
// signed_order, where the envelope's guard does not look -- DecodePayload
// refuses unknown TOP-level payload fields only -- so the strict carrier
// decoder is the single thing standing between such an order and this node.
// While it refused the field, every broadcast carrying one was rejected and the
// node took no work at all.
//
// It was written as an upgrade gate, building the carrier the way the field
// arrived from a signer ahead of the pinned descriptor: appended as an unknown
// field that the generated type carried through verbatim. The descriptor now
// has it, so the fixture sets it directly; what is being checked is unchanged,
// and the unknown-field path it used to prove is no longer the one real
// carriers take.
func TestOrderBroadcastAcceptsACarriedSignatureChainID(t *testing.T) {
	const (
		chainID       = "trueopen-localnet-1"
		modelID       = "ad410b3157d13dbfb8263e92914cfe5a75868ce68fd722d2f73c75ff8cc7378b"
		walletChainID = 11155111
	)
	sessionID := strings.Repeat("12", 32)
	signed, wantHash := testSignedOrderProto(t, chainID, modelID, sessionID, 1, 200)

	raw, err := proto.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	var received bustaskv1.SignedOrderV2
	if err := proto.Unmarshal(raw, &received); err != nil {
		t.Fatal(err)
	}
	received.SignatureChainId = walletChainID

	// The bus guard sees nothing: the field is nested, so the carrier reaches
	// the decoder rather than being refused at the envelope.
	broadcast := &busv1.OrderBroadcastV1{SignedOrder: &received}
	envelope, err := builderclient.NewUnsignedBusEnvelope(builderclient.UnsignedEnvelopeInput{
		Kind: builderclient.KindOrderBroadcast, ChainID: chainID,
		Subject:                   builderclient.NATSTaskOpenSubject(modelID),
		SenderOperatorAddress:     "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc",
		SenderParticipantType:     builderclient.ParticipantBuilder,
		ServiceAuthorizationNonce: 1,
	}, broadcast)
	if err != nil {
		t.Fatal(err)
	}
	var decoded busv1.OrderBroadcastV1
	if err := envelope.DecodePayload(&decoded); err != nil {
		t.Fatalf("DecodePayload() error = %v, want the nested field to pass the envelope guard", err)
	}

	taskHash, facts, carrier, err := validateNexusOrderBroadcast(&decoded, envelope, true)
	if err != nil {
		t.Fatalf("validateNexusOrderBroadcast() error = %v, want a v0.5.0 order admitted", err)
	}
	if facts.SignatureChainID != walletChainID {
		t.Fatalf("facts.SignatureChainID = %d, want the carried %d", facts.SignatureChainID, walletChainID)
	}
	// Identity is derived from the order, not from what the wallet signed under:
	// the same order broadcast with and without the field opens one task.
	if taskHash != wantHash {
		t.Fatalf("task_hash = %x, want the same order's %x", taskHash, wantHash)
	}
	if !strings.Contains(hex.EncodeToString(carrier), hex.EncodeToString(protowire.AppendVarint(protowire.AppendTag(nil, 4, protowire.VarintType), walletChainID))) {
		t.Fatal("the stored carrier dropped signature_chain_id; it must be kept exactly as received")
	}
}
