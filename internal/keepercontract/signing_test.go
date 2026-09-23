package keepercontract

import (
	"encoding/hex"
	"testing"

	"github.com/TrueOpen/cortex/internal/codec"
)

// These are local regression pins over this repository's own inputs, not
// upstream vectors: the SupportedProfilesHash and DailySupportConfirmation
// values moved when the repeated profile list was corrected from a flattened
// field list to the single nested frame the frozen contract specifies. The
// authority for that correction is TestSupportProfilesHashAgreesWithWireVector
// and TestDailySupportConfirmationAgreesWithWireVector, which drive the same two
// functions with github.com/TrueOpen/wire's own published inputs and digests.
// WorkerReveal is untouched by that change and its value is unchanged.
func TestSigningDigestsMatchKeeperGoldenVectors(t *testing.T) {
	profiles := []ProfileRef{{ModelID: "model-a", ProfileVersion: 1}}
	profilesHash, err := SupportedProfilesHash(profiles)
	if err != nil {
		t.Fatalf("SupportedProfilesHash error = %v", err)
	}
	if got, want := hex.EncodeToString(profilesHash[:]), "189c183323cfe4d56136c04c3977494159bbea8d5fd60d60fa45380620e1131f"; got != want {
		t.Fatalf("SupportedProfilesHash = %s, want %s", got, want)
	}
	daily, err := DailySupportConfirmation(
		"chain-1", "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc", 7, 3, 101, profiles,
	)
	if err != nil {
		t.Fatalf("DailySupportConfirmation error = %v", err)
	}
	tests := []struct {
		name string
		got  codec.Hash
		want string
	}{
		{"daily", daily, "6e8627ede266fd85085fdb4bb8e28f84c5288088deb5a1d81a9e840d508113b9"},
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
