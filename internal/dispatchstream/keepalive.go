package dispatchstream

// keepalive implements the single-outstanding-probe rule from wire's
// PHASE1_CONTRACT. Timing and liveness thresholds are deployment settings
// held by Session, not here. State is per binding.
type keepalive struct {
	outstanding uint64 // 0: none
	lastLocal   uint64
	lastPeer    uint64
	peerSeen    bool // a peer probe of 0 is still a probe
	missed      int  // ticks that found the previous probe still unanswered
}

// probe returns the value to send, or false while one is outstanding (which
// counts as a miss). nowMs only seeds the value; it is bumped to stay
// strictly increasing.
func (k *keepalive) probe(nowMs uint64) (uint64, bool) {
	if k.outstanding != 0 {
		k.missed++
		return 0, false
	}
	v := nowMs
	if v <= k.lastLocal {
		v = k.lastLocal + 1
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
