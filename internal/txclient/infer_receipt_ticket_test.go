package txclient

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestSubmitInferReceiptCarriesTheDispatchTicket(t *testing.T) {
	m := validSubmitInferReceiptMessage()
	payload, err := MarshalMessage(MsgSubmitInferReceipt, m)
	if err != nil {
		t.Fatal(err)
	}
	want := `"dispatch_ticket_hash":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)) + `"`
	if !strings.Contains(string(payload), want) {
		t.Fatalf("payload %s lacks field 19", payload)
	}
	if err := ValidateMessagePayload(MsgSubmitInferReceipt, payload); err != nil {
		t.Fatal(err)
	}
	for _, v := range []ProtoBytes32{"", ProtoBytes32(strings.Repeat("00", 32))} {
		bad := m
		bad.Receipt.DispatchTicketHash = v
		if _, err := MarshalMessage(MsgSubmitInferReceipt, bad); err == nil {
			t.Fatalf("ticket %q accepted", v)
		}
	}
}
