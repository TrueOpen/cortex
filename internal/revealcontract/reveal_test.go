package revealcontract

import (
	"encoding/hex"
	"testing"
)

func TestLocalCommitHashGolden(t *testing.T) {
	const reveal = "p1=10|p2=20|salt=a"
	commit, err := CommitHash("task-fixture", 1, "verifier-a", "sample-seed-fixture", reveal)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(commit[:]), "6ca2de7bb4eed84e1a849aafd4026d9e2b10b59d726c569de4f6f2ddf89e9362"; got != want {
		t.Fatalf("CommitHash() = %q, want %q", got, want)
	}
}

func TestParseCompactRejectsNonCanonicalReveals(t *testing.T) {
	for _, reveal := range []string{
		"", " p1=1|salt=a", "p1=01|salt=a", "p2=2|p1=1|salt=a",
		"p1=1|p1=2|salt=a", "p1=1|salt=a|p2=2", "salt=a",
	} {
		if _, err := ParseCompact(reveal); err == nil {
			t.Fatalf("ParseCompact(%q) error = nil", reveal)
		}
	}
}
