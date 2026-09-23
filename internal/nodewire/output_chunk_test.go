package nodewire_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/wirevectors"
)

func TestOutputMMRAndChunkSigningPublishedVectors(t *testing.T) {
	raw, err := wirevectors.File("task/output_mmr_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		MMR struct {
			ChainID     string   `json:"chain_id"`
			TaskHash    string   `json:"task_hash_hex"`
			Chunks      []string `json:"chunks_utf8"`
			PrefixRoots []string `json:"prefix_roots_hex"`
			OutputHash  string   `json:"output_hash_hex"`
		} `json:"mmr"`
		ChunkSigning struct {
			Cases []struct {
				Seq      uint64 `json:"seq"`
				Root     string `json:"mmr_root_hex"`
				Digest   string `json:"digest_hex"`
				Preimage string `json:"preimage_hex"`
			} `json:"cases"`
		} `json:"chunk_signing"`
		Negative []struct {
			Name       string   `json:"name"`
			Chunks     []string `json:"chunks_utf8"`
			OutputHash string   `json:"output_hash_hex"`
			Seq        uint64   `json:"seq"`
			Root       string   `json:"mmr_root_hex"`
			ChainID    string   `json:"chain_id"`
			TaskHash   string   `json:"task_hash_hex"`
			Digest     string   `json:"digest_hex"`
		} `json:"negative"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	decode := func(s string) []byte {
		t.Helper()
		raw, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	chunks := func(items []string) [][]byte {
		out := make([][]byte, len(items))
		for i, item := range items {
			out[i] = []byte(item)
		}
		return out
	}
	mmr, _ := codec.NewMMR(codec.DomainOutputMMRV1)
	for i, chunk := range fixture.MMR.Chunks {
		if err := mmr.Append([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
		root, err := codec.OutputMMRRoot(chunks(fixture.MMR.Chunks[:i+1]))
		if err != nil || root != mmr.Root() || root.String() != fixture.MMR.PrefixRoots[i] {
			t.Fatalf("prefix %d = %s: %v", i, root, err)
		}
		if root == codec.OutputHash([]byte(chunk)) {
			t.Fatal("single chunk blob hash used as output root")
		}
	}
	for _, tc := range fixture.ChunkSigning.Cases {
		preimage, err := nodewire.OutputChunkSigningPreimage(fixture.MMR.ChainID, decode(fixture.MMR.TaskHash), tc.Seq, decode(tc.Root))
		if err != nil {
			t.Fatal(err)
		}
		if tc.Preimage != "" && hex.EncodeToString(preimage) != tc.Preimage {
			t.Fatal("chunk preimage differs")
		}
		digest, err := nodewire.OutputChunkSigningDigest(fixture.MMR.ChainID, decode(fixture.MMR.TaskHash), tc.Seq, decode(tc.Root))
		if err != nil || digest.String() != tc.Digest {
			t.Fatalf("chunk %d digest %s: %v", tc.Seq, digest, err)
		}
	}
	for _, tc := range fixture.Negative {
		t.Run(tc.Name, func(t *testing.T) {
			if len(tc.Chunks) > 0 {
				root, err := codec.OutputMMRRoot(chunks(tc.Chunks))
				if err != nil || root.String() != tc.OutputHash || root.String() == fixture.MMR.OutputHash {
					t.Fatalf("mutated root %s: %v", root, err)
				}
				return
			}
			if tc.Digest == "" {
				root, _ := codec.OutputMMRRoot([][]byte{{}})
				if root.String() == tc.OutputHash {
					t.Fatal("empty tree accepted as empty output")
				}
				return
			}
			chainID, taskHash, root := fixture.MMR.ChainID, fixture.MMR.TaskHash, fixture.MMR.PrefixRoots[tc.Seq]
			if tc.ChainID != "" {
				chainID = tc.ChainID
			}
			if tc.TaskHash != "" {
				taskHash = tc.TaskHash
			}
			if tc.Root != "" {
				root = tc.Root
			}
			digest, err := nodewire.OutputChunkSigningDigest(chainID, decode(taskHash), tc.Seq, decode(root))
			if err != nil || digest.String() != tc.Digest || digest.String() == fixture.ChunkSigning.Cases[tc.Seq].Digest {
				t.Fatalf("mutated digest %s: %v", digest, err)
			}
		})
	}
}

func TestOutputChunkSigningRejectsMalformedFields(t *testing.T) {
	for _, tc := range []struct {
		chain      string
		task, root []byte
	}{
		{"chain", []byte("short"), make([]byte, 32)},
		{"chain", make([]byte, 32), []byte("short")},
		{string([]byte{0xff}), make([]byte, 32), make([]byte, 32)},
	} {
		if _, err := nodewire.OutputChunkSigningDigest(tc.chain, tc.task, 0, tc.root); err == nil {
			t.Fatal("malformed chunk signing input accepted")
		}
	}
}

func TestOutputFinSigningWireVectors(t *testing.T) {
	raw, err := wirevectors.File("task/output_mmr_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Fin struct {
			ChainID  string `json:"chain_id"`
			TaskHash string `json:"task_hash_hex"`
			FinalSeq uint64 `json:"final_seq"`
			Root     string `json:"output_mmr_root_hex"`
			Reasons  []struct {
				Value  int32  `json:"value"`
				Digest string `json:"digest_hex"`
			} `json:"accepted_finish_reasons"`
			Rejected []struct {
				Value int32 `json:"value"`
			} `json:"rejected_finish_reason_values"`
			Preimage  string `json:"eos_token_preimage_hex"`
			Mutations []struct {
				Field    string `json:"field"`
				Value    any    `json:"value"`
				ValueHex string `json:"value_hex"`
				Digest   string `json:"digest_hex"`
			} `json:"mutation_digests"`
		} `json:"fin_signing"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	decode := func(value string) []byte {
		t.Helper()
		decoded, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	for _, reason := range fixture.Fin.Reasons {
		preimage, err := nodewire.OutputFinSigningPreimage(fixture.Fin.ChainID, decode(fixture.Fin.TaskHash), fixture.Fin.FinalSeq, decode(fixture.Fin.Root), nodewire.FinishReasonV1(reason.Value))
		if err != nil {
			t.Fatal(err)
		}
		if reason.Value == int32(nodewire.FinishReasonV1EosToken) && hex.EncodeToString(preimage) != fixture.Fin.Preimage {
			t.Fatal("Fin preimage differs")
		}
		digest, err := nodewire.OutputFinSigningDigest(fixture.Fin.ChainID, decode(fixture.Fin.TaskHash), fixture.Fin.FinalSeq, decode(fixture.Fin.Root), nodewire.FinishReasonV1(reason.Value))
		if err != nil || digest.String() != reason.Digest {
			t.Fatalf("Fin reason %d digest %s: %v", reason.Value, digest, err)
		}
	}
	for _, rejected := range fixture.Fin.Rejected {
		if _, err := nodewire.OutputFinSigningDigest(fixture.Fin.ChainID, decode(fixture.Fin.TaskHash), fixture.Fin.FinalSeq, decode(fixture.Fin.Root), nodewire.FinishReasonV1(rejected.Value)); err == nil {
			t.Fatalf("rejected finish reason %d accepted", rejected.Value)
		}
	}
	base := fixture.Fin.Reasons[0].Digest
	for _, mutation := range fixture.Fin.Mutations {
		chainID, taskHash, finalSeq, root, reason := fixture.Fin.ChainID, fixture.Fin.TaskHash, fixture.Fin.FinalSeq, fixture.Fin.Root, nodewire.FinishReasonV1EosToken
		switch mutation.Field {
		case "chain_id":
			chainID = mutation.Value.(string)
		case "task_hash":
			taskHash = mutation.ValueHex
		case "final_seq":
			finalSeq = uint64(mutation.Value.(float64))
		case "output_mmr_root":
			root = mutation.ValueHex
		case "finish_reason":
			reason = nodewire.FinishReasonV1(int32(mutation.Value.(float64)))
		default:
			t.Fatalf("unknown mutation field %q", mutation.Field)
		}
		digest, err := nodewire.OutputFinSigningDigest(chainID, decode(taskHash), finalSeq, decode(root), reason)
		if err != nil || digest.String() != mutation.Digest || digest.String() == base {
			t.Fatalf("Fin mutation %s digest %s: %v", mutation.Field, digest, err)
		}
	}
}
