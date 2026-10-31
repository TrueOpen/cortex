package dispatchstream

import "testing"

func TestKeepaliveEchoRules(t *testing.T) {
	var k keepalive
	probe, ok := k.probe(100)
	if !ok || probe != 100 {
		t.Fatalf("first probe: %d %v", probe, ok)
	}
	if _, ok := k.probe(200); ok {
		t.Fatal("only one local probe may be outstanding")
	}
	if k.missed != 1 {
		t.Fatalf("a tick with a probe outstanding is a miss, got %d", k.missed)
	}
	if echo, reply := k.received(100); reply {
		t.Fatalf("our own echo must be consumed, not replied (%d)", echo)
	}
	if k.missed != 0 {
		t.Fatalf("an echo clears misses, got %d", k.missed)
	}
	if echo, reply := k.received(7); !reply || echo != 7 {
		t.Fatal("a peer probe is echoed once")
	}
	if _, reply := k.received(7); reply {
		t.Fatal("a repeated peer probe is not echoed again")
	}
	if p, ok := k.probe(90); !ok || p <= 100 {
		t.Fatalf("probe values must increase per direction, got %d", p)
	}
}

// Both peers probing at once: the peer's probe equal in value to ours is
// still our echo (the contract's rule is value-based), anything else is theirs.
func TestKeepaliveSimultaneousProbes(t *testing.T) {
	var k keepalive
	p, _ := k.probe(50)
	if echo, reply := k.received(40); !reply || echo != 40 {
		t.Fatal("peer probe while ours is outstanding is echoed")
	}
	if _, reply := k.received(p); reply {
		t.Fatal("our echo is consumed")
	}
	if _, ok := k.probe(51); !ok {
		t.Fatal("after the echo a new probe may go out")
	}
}

func TestKeepaliveEchoesPeerZeroOnce(t *testing.T) {
	var k keepalive
	if echo, reply := k.received(0); !reply || echo != 0 {
		t.Fatal("a peer probe of 0 is still a probe and is echoed")
	}
	if _, reply := k.received(0); reply {
		t.Fatal("a repeated 0 is not echoed again")
	}
}

func TestKeepaliveLocalProbesAreEvenAndStrictlyIncreasing(t *testing.T) {
	var k keepalive
	var last uint64
	for _, now := range []uint64{0, 1, 101, 101, 100, 7, 1_000_001, 1_000_002, 1_000_003} {
		p, ok := k.probe(now)
		if !ok {
			t.Fatalf("probe(%d) refused", now)
		}
		if p%2 != 0 || p <= last {
			t.Fatalf("probe(%d) = %d after %d: local probes must be even and strictly increasing", now, p, last)
		}
		last = p
		if _, reply := k.received(p); reply {
			t.Fatalf("our echo %d was not consumed", p)
		}
	}
}

// Nexus probes with odd values (ms|1). A peer probe carrying exactly the odd
// value our own clock reading would have produced must be echoed, never taken
// as the echo of our outstanding probe.
func TestKeepalivePeerOddProbeCollidingWithOurClockIsEchoed(t *testing.T) {
	var k keepalive
	ours, _ := k.probe(10_001) // our clock reads odd
	if ours != 10_000 {
		t.Fatalf("probe = %d, want the even 10000", ours)
	}
	// ours+1 is 10001, the odd value our clock read; ours-1 is the other
	// odd neighbour.
	for _, peer := range []uint64{ours + 1, ours - 1} {
		echo, reply := k.received(peer)
		if !reply || echo != peer {
			t.Fatalf("peer probe %d was consumed as our echo", peer)
		}
		if k.outstanding != ours {
			t.Fatalf("peer probe %d cleared our outstanding probe", peer)
		}
	}
	if _, reply := k.received(ours); reply || k.outstanding != 0 {
		t.Fatal("our real echo must still be consumed")
	}
}

func TestKeepalivePeerOddValueNeverMatchesOutstanding(t *testing.T) {
	for now := uint64(0); now < 2_000; now++ {
		var k keepalive
		k.lastLocal = now / 3 * 2 // vary the bump path
		ours, ok := k.probe(now)
		if !ok {
			t.Fatal("probe refused")
		}
		for _, peer := range []uint64{now | 1, ours | 1, ours + 1, ours - 1} {
			if peer == ours {
				t.Fatalf("now=%d: odd peer value %d equals our outstanding %d", now, peer, ours)
			}
			if _, reply := k.received(peer); !reply && k.outstanding == 0 {
				t.Fatalf("now=%d: odd peer value %d consumed our probe %d", now, peer, ours)
			}
		}
	}
}
