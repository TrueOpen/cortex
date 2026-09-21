package nodewire_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/SingaXYZ/cortex/internal/codec"
	"github.com/SingaXYZ/cortex/internal/hfields"
	"github.com/SingaXYZ/cortex/internal/nodewire"
	"github.com/SingaXYZ/cortex/internal/wirevectors"
)

func TestTokenIDsPublishedVectors(t *testing.T) {
	raw, err := wirevectors.File("task/token_ids_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Name     string   `json:"name"`
			Domain   string   `json:"domain"`
			IDs      []uint32 `json:"token_ids"`
			Raw      string   `json:"token_ids_raw_hex"`
			Size     uint64   `json:"token_ids_raw_size_bytes"`
			Preimage string   `json:"preimage_hex"`
			Digest   string   `json:"digest_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, tc := range fixture.Vectors {
		t.Run(tc.Name, func(t *testing.T) {
			encoded, err := nodewire.EncodeTokenIDs(tc.IDs)
			if err != nil || hex.EncodeToString(encoded) != tc.Raw || uint64(len(encoded)) != tc.Size {
				t.Fatalf("raw encoding %x: %v", encoded, err)
			}
			decoded, err := nodewire.DecodeTokenIDs(encoded)
			if err != nil || !reflect.DeepEqual(decoded, tc.IDs) {
				t.Fatalf("decode %v: %v", decoded, err)
			}
			var digest codec.Hash
			if tc.Domain == nodewire.DomainInputTokenIDsV1 {
				digest, err = nodewire.InputTokenIDsHash(tc.IDs)
			} else {
				digest, err = nodewire.GeneratedTokenIDsHash(tc.IDs)
			}
			if err != nil || digest.String() != tc.Digest {
				t.Fatalf("digest %s: %v", digest, err)
			}
			preimage, err := hfields.Preimage(tc.Domain, hfields.Bytes(encoded))
			if err != nil || hex.EncodeToString(preimage) != tc.Preimage {
				t.Fatal("raw token field preimage differs")
			}
			wrong, _ := hfields.Digest(tc.Domain, hfields.Uint32(uint32(len(tc.IDs))), hfields.Bytes(encoded))
			if wrong == digest {
				t.Fatal("second count does not change digest")
			}
			wrong, _ = hfields.Digest(tc.Domain, hfields.Bytes(encoded[4:]))
			if wrong == digest {
				t.Fatal("count omission does not change digest")
			}
			fields := []hfields.Field{hfields.Uint32(uint32(len(tc.IDs)))}
			for _, id := range tc.IDs {
				fields = append(fields, hfields.Uint32(id))
			}
			wrong, _ = hfields.Digest(tc.Domain, hfields.Frame(fields...))
			if wrong == digest {
				t.Fatal("repeated-container encoding does not change digest")
			}
		})
	}
}

func TestTokenIDsRejectInvalidCountsAndLengths(t *testing.T) {
	oversize := make([]byte, 4)
	binary.BigEndian.PutUint32(oversize, nodewire.MaxTokenIDCountV1+1)
	for _, raw := range [][]byte{nil, {0, 0, 0}, {0, 0, 0, 1}, {0, 0, 0, 0, 1}, oversize} {
		if _, err := nodewire.DecodeTokenIDs(raw); err == nil {
			t.Fatalf("malformed artifact %x accepted", raw)
		}
	}
	if _, err := nodewire.EncodeTokenIDs(make([]uint32, nodewire.MaxTokenIDCountV1+1)); err == nil {
		t.Fatal("oversized token vector accepted")
	}
	encoded, err := nodewire.EncodeTokenIDs(nil)
	if err != nil || !bytes.Equal(encoded, []byte{0, 0, 0, 0}) {
		t.Fatal("empty token vector is not a single raw zero count")
	}
	ids := []uint32{7, 1, 7}
	encoded, _ = nodewire.EncodeTokenIDs(ids)
	decoded, err := nodewire.DecodeTokenIDs(encoded)
	if err != nil || !reflect.DeepEqual(ids, decoded) {
		t.Fatal("token order or duplication changed")
	}
	input, _ := nodewire.InputTokenIDsHash(ids)
	generated, _ := nodewire.GeneratedTokenIDsHash(ids)
	if input == generated {
		t.Fatal("token domains collide")
	}
}
