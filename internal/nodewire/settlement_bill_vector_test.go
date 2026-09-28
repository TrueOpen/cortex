package nodewire_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/wirevectors"
)

// TestSettlementBillReproducesTheRoundSettlementVector binds SettlementBillHash
// to wire's settlement_bill_v1 vector: domain, preimage, digest, and the digest
// of every published field mutation.
func TestSettlementBillReproducesTheRoundSettlementVector(t *testing.T) {
	raw, err := wirevectors.File("task/round_settlement_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			Name        string `json:"name"`
			Domain      string `json:"domain"`
			Producer    string `json:"producer"`
			PreimageHex string `json:"preimage_hex"`
			DigestHex   string `json:"digest_hex"`
			Fields      []struct {
				Name   string  `json:"name"`
				Hex    string  `json:"hex"`
				Bech32 string  `json:"bech32"`
				Value  *uint64 `json:"value"`
			} `json:"fields"`
			Mutations []struct {
				FieldPath string `json:"field_path"`
				Expect    string `json:"expect"`
				DigestHex string `json:"digest_hex"`
			} `json:"mutations"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range file.Vectors {
		if v.Name != "settlement_bill_v1" {
			continue
		}
		found = true
		if v.Domain != nodewire.DomainSettlementBillV1 || v.Producer != "SettlementBillHash" || len(v.Fields) != 5 {
			t.Fatalf("vector shape: domain %q, producer %q, %d fields", v.Domain, v.Producer, len(v.Fields))
		}
		address, err := hex.DecodeString(v.Fields[0].Hex)
		if err != nil {
			t.Fatal(err)
		}
		receiptRef, err := hex.DecodeString(v.Fields[1].Hex)
		if err != nil {
			t.Fatal(err)
		}
		base := nodewire.SettlementBillV1{
			WorkerOperatorAddress: v.Fields[0].Bech32, InferReceiptRef: receiptRef,
			FeeRuleVersion: *v.Fields[2].Value, GeneratedTokenCount: *v.Fields[3].Value, WorkUnit: *v.Fields[4].Value,
		}
		preimage, err := nodewire.SettlementBillPreimage(base)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(preimage) != v.PreimageHex {
			t.Fatalf("preimage = %x, published %s", preimage, v.PreimageHex)
		}
		digest, err := nodewire.SettlementBillHash(base)
		if err != nil || digest.String() != v.DigestHex {
			t.Fatalf("digest = %s (%v), published %s", digest, err, v.DigestHex)
		}
		mutations := map[string]func(*nodewire.SettlementBillV1){
			"worker_operator_address": func(b *nodewire.SettlementBillV1) {
				flipped := append([]byte(nil), address...)
				flipped[len(flipped)-1] ^= 1
				encoded, err := nodewire.CanonicalOperatorAddressString("trueopen", flipped)
				if err != nil {
					t.Fatal(err)
				}
				b.WorkerOperatorAddress = encoded
			},
			"infer_receipt_ref": func(b *nodewire.SettlementBillV1) {
				b.InferReceiptRef = append([]byte(nil), b.InferReceiptRef...)
				b.InferReceiptRef[len(b.InferReceiptRef)-1] ^= 1
			},
			"fee_rule_version":      func(b *nodewire.SettlementBillV1) { b.FeeRuleVersion++ },
			"generated_token_count": func(b *nodewire.SettlementBillV1) { b.GeneratedTokenCount++ },
			"work_unit":             func(b *nodewire.SettlementBillV1) { b.WorkUnit++ },
		}
		if len(v.Mutations) != len(mutations) {
			t.Fatalf("%d published mutations, want %d", len(v.Mutations), len(mutations))
		}
		for _, m := range v.Mutations {
			mutate, ok := mutations[m.FieldPath]
			if !ok || m.Expect != "digest_changes" {
				t.Fatalf("unexpected mutation %s (%s)", m.FieldPath, m.Expect)
			}
			changed := base
			mutate(&changed)
			got, err := nodewire.SettlementBillHash(changed)
			if err != nil || got.String() != m.DigestHex {
				t.Errorf("%s: digest = %s (%v), published %s", m.FieldPath, got, err, m.DigestHex)
			}
		}
	}
	if !found {
		t.Fatal("round_settlement_v1.json publishes no settlement_bill_v1 vector")
	}
}
