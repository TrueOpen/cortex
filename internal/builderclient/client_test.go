package builderclient

import (
	"bytes"
	"testing"

	"github.com/SingaXYZ/cortex/internal/codec"
)

func TestInferReceiptMaterialUsesCanonicalBinaryEncoding(t *testing.T) {
	material := InferReceiptMaterial{
		TaskID:              "task-1",
		OutputRef:           "cortex-artifact://model/output",
		OutputHash:          codec.HashWithDomain("OUTPUT", []byte("output")),
		PackageHash:         codec.HashWithDomain("PACKAGE", []byte("package")),
		ReceiptResultHash:   codec.HashWithDomain("RECEIPT", []byte("receipt")),
		ActualOutputSummary: "12 bytes output",
	}

	encoded, err := EncodeInferReceiptMaterial(material)
	if err != nil {
		t.Fatalf("EncodeInferReceiptMaterial returned error: %v", err)
	}
	if bytes.HasPrefix(encoded, []byte("{")) {
		t.Fatalf("receipt material encoded as JSON: %q", encoded)
	}
	decoded, err := DecodeInferReceiptMaterial(encoded)
	if err != nil {
		t.Fatalf("DecodeInferReceiptMaterial returned error: %v", err)
	}
	if decoded != material {
		t.Fatalf("decoded material = %#v, want %#v", decoded, material)
	}
}
