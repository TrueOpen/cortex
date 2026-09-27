package keepercontract

import (
	"encoding/hex"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
)

// A local regression pin over this repository's own inputs. The support
// digests are pinned by wire's vectors in hub_domain_agreement_test.go.
func TestSigningDigestsMatchKeeperGoldenVectors(t *testing.T) {
	tests := []struct {
		name string
		got  codec.Hash
		want string
	}{
		{"worker", WorkerReveal("trueopen-devnet-1", "task-1", 1, "sample-seed", "sampled-hash", "schema-v1"), "123b3a91e409ac8287521fb8e435c79e055469c59a0e4c5822a6bb9bbf513ca1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hex.EncodeToString(tt.got[:]); got != tt.want {
				t.Fatalf("digest = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestWorkerRevealMatchesKeeperCanonicalTrimming(t *testing.T) {
	canonical := WorkerReveal("chain", "task", 1, "seed", "sampled", "schema")
	withWhitespace := WorkerReveal("chain", "task", 1, "seed", " sampled ", " schema ")
	if withWhitespace != canonical {
		t.Fatalf("WorkerReveal must trim sampled hash and schema like Keeper")
	}
}
