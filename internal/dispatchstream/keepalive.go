package dispatchstream

// keepalive implements the single-outstanding-probe rule from wire's
// PHASE1_CONTRACT. Timing and liveness thresholds are deployment settings
// held by Session, not here. State is per binding.
//
// The contract tells an echo from a peer probe by value alone, so the two
// directions must never pick the same value. Nexus probes with odd values
// (ms|1); this side probes with even values only, so a peer probe can never
// be mistaken for the echo of ours (wire issue #83; the convention is
// proposed on wire PR #49).
type keepalive struct {
	outstanding uint64 // 0: none
	lastLocal   uint64
	lastPeer    uint64
	peerSeen    bool // a peer probe of 0 is still a probe
	missed      int  // ticks that found the previous probe still unanswered
}

// probe returns the value to send, or false while one is outstanding (which
// counts as a miss). nowMs only seeds the value: it is rounded down to even
// and bumped by 2 when needed, so values stay even and strictly increasing.
// Being even, a probe is never 0, which marks "none outstanding".
func (k *keepalive) probe(nowMs uint64) (uint64, bool) {
	if k.outstanding != 0 {
		k.missed++
		return 0, false
	}
	v := nowMs &^ 1
	if v <= k.lastLocal {
		v = k.lastLocal + 2
	}
	k.lastLocal, k.outstanding = v, v
	return v, true
}

// received handles a peer keepalive. It returns the value to echo and whether
// to echo at all.
func (k *keepalive) received(v uint64) (uint64, bool) {
	if k.outstanding != 0 && v == k.outstanding {
		k.outstanding, k.missed = 0, 0
		return 0, false
	}
	if k.peerSeen && v == k.lastPeer {
		return 0, false
	}
	k.lastPeer, k.peerSeen = v, true
	return v, true
}
