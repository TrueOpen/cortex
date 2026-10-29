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
