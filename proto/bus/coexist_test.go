// Package bus_test verifies the shared Task binding used by both transports.
package bus_test

import (
	"testing"

	nexusv1 "github.com/TrueOpen/cortex/proto/nexus/v1"
	"google.golang.org/protobuf/proto"

	busv1 "github.com/TrueOpen/cortex/proto/bus/v1"
	bustaskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

func TestBusAndIngressShareOneTaskBinding(t *testing.T) {
	receipt := &bustaskv1.ResultReceiptV3{SchemaVersion: 3, ChainId: "trueopen-localnet-1"}
	raw, err := proto.Marshal(receipt)
	if err != nil {
		t.Fatalf("marshal mirror message: %v", err)
	}
	envelope := &busv1.BusEnvelopeV1{SchemaVersion: 1, Payload: raw}
	if _, err := proto.Marshal(envelope); err != nil {
		t.Fatalf("marshal mirror envelope: %v", err)
	}
	ingress := &nexusv1.SubmitVerifyResultRequest{Receipt: receipt}
	if ingress.Receipt.ProtoReflect().Descriptor() != receipt.ProtoReflect().Descriptor() {
		t.Fatal("ingress and bus use different Task descriptors")
	}
}
