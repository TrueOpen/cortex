package modelservice

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Artifacts used to stay in memory for the life of the process. They are now
// dropped once stored longer ago than the retention; one stored again (the
// same bytes, so the same ref) counts from the newer store, and one inside the
// retention stays fetchable.
func TestArtifactsAreDroppedAfterTheRetention(t *testing.T) {
	svc := newBoundLocalService("http://127.0.0.1:1", "local", 4, 0, 0)
	svc.SetArtifactRetention(time.Hour)
	old := svc.putArtifact([]byte("old artifact"))
	kept := svc.putArtifact([]byte("stored again"))
	age := func(ref string, by time.Duration) {
		parsed, err := ParseArtifactRef(ref)
		if err != nil {
			t.Fatal(err)
		}
		svc.mu.Lock()
		svc.artifactAt[parsed.ArtifactID] = svc.artifactAt[parsed.ArtifactID].Add(-by)
		svc.artifactsPrunedAt = time.Time{} // let the next store sweep
		svc.mu.Unlock()
	}
	age(old, 2*time.Hour)
	age(kept, 2*time.Hour)
	if got := svc.putArtifact([]byte("stored again")); got != kept {
		t.Fatalf("the same bytes got another ref: %s != %s", got, kept)
	}
	fresh := svc.putArtifact([]byte("fresh artifact"))
	fetch := func(ref string) error {
		_, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: ref})
		return err
	}
	if err := fetch(old); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatalf("an artifact past the retention is still served: %v", err)
	}
	if err := fetch(kept); err != nil {
		t.Fatalf("an artifact stored again inside the retention was dropped: %v", err)
	}
	if err := fetch(fresh); err != nil {
		t.Fatalf("a fresh artifact is not served: %v", err)
	}
	svc.mu.RLock()
	n, m := len(svc.artifacts), len(svc.artifactAt)
	svc.mu.RUnlock()
	if n != 2 || m != 2 {
		t.Fatalf("the store holds %d artifacts and %d times, want 2 and 2", n, m)
	}
}

// A sweep runs at most once per interval, so a store does not walk the whole
// map every time.
func TestArtifactSweepIsRateLimited(t *testing.T) {
	svc := newBoundLocalService("http://127.0.0.1:1", "local", 4, 0, 0)
	svc.SetArtifactRetention(time.Hour)
	old := svc.putArtifact([]byte("old artifact")) // this store swept
	parsed, err := ParseArtifactRef(old)
	if err != nil {
		t.Fatal(err)
	}
	svc.mu.Lock()
	svc.artifactAt[parsed.ArtifactID] = svc.artifactAt[parsed.ArtifactID].Add(-2 * time.Hour)
	svc.mu.Unlock()
	svc.putArtifact([]byte("another")) // inside the interval: no sweep
	if _, err := svc.FetchArtifact(context.Background(), FetchArtifactRequest{Ref: old}); err != nil {
		t.Fatalf("swept inside the interval: %v", err)
	}
}
