package daemon

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/TrueOpen/cortex/internal/config"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// ADR-0040 audit admission gate.
//
// A Worker that takes a task under a Profile requiring WORKER_ANCHOR_OPENING
// commits an anchor in its receipt. The chain may then sample the task, and
// the Worker must open it (and prove the opening) before the deadlines or be
// slashed. Opening is far slower than serving, so a Worker that takes every
// offer its engine has a slot for accumulates openings it cannot finish in
// time. The anchor sidecar knows how many such obligations it can still
// discharge and publishes the answer in a small JSON file:
//
//	{"accept": bool, "reason": string, "updated": unix seconds}
//
// While dispatch.anchor_admission.file names that file and the signal says
// no, the node takes no new task under such a Profile: the standing handraise
// leaves the Profile out, and an offer that still arrives is refused
// NO_CAPACITY. A signal that is missing, unreadable, malformed or older than
// max_age_s refuses as well: a sidecar that is not running cannot open
// anything. The refusal describes a moment, like a full engine, and ends when
// the sidecar says yes again.
//
// A read that fails or cannot be parsed is not a signal, though: a sidecar
// that replaces the file without a rename is caught mid-write now and then.
// While the last signal that was parsed is itself inside max_age_s, its
// verdict stands, so the gate (and with it the standing handraise) does not
// close and reopen between two good writes. Every parsed signal is taken as
// it is, except one whose read was overtaken by a later read of a newer
// signal (see adopt).
//
// What the gate cannot see. The signal is the sidecar's estimate, written
// every 15 s, and the sidecar only learns of a task when its receipt is on
// chain. A task this node accepted since the last write, or is still
// generating, is not in the sidecar's count of openings owed. The sidecar
// covers that lag by adding a configured upper bound on such in-flight tasks
// to the openings it plans for, so "accept" already means "there is room for
// the tasks that may be on their way and for one more". The bound is the
// sidecar operator's to set, at or above model_management.max_concurrency;
// the gate itself keeps no count. It is the same class of lag as the bond
// check, which does not count accepted but unrecorded offers in
// reserved_liability either. max_age_s (default 45 s, three write periods)
// bounds the other lag: how long the last "accept" of a sidecar that died
// goes on admitting.
//
// The slot protocol. "accept" does not say how many: the sidecar learns of a
// task only once its commitment exists, so between two writes of the signal
// a node could take any number of tasks against headroom the sidecar counted
// once. A sidecar that also publishes
//
//	"slots": n      tasks this node may have in flight beyond those in "seen"
//	"seen":  [...]  the tasks the sidecar accounts for or has settled, each by
//	                the first 16 lowercase hex characters of its task id (a
//	                longer id, 0x or upper case is read the same way)
//
// is read by those instead of "accept". The node takes a slot when it
// accepts an offer (Reserve, in the same step as the lease) and holds it
// until the sidecar lists the task as seen, the ticket ends without a signed
// receipt (rejected, revoked, superseded, lost, task ended), or a TTL runs
// out. It accepts only while the slots it holds number fewer than "slots".
// The sidecar computes the slots against the tasks it has seen and the node
// adds exactly those it has not, so no task is counted twice or missed,
// whatever the age of the signal inside max_age_s; a task that became
// visible after the signal was written stays reserved until the next one,
// which errs on the safe side. The standing handraise advertises what is
// left (see handraiseGates.applyAnchorAdmission). A signal without "slots"
// is the boolean gate described above.
//
// The table of slots held is in memory. After a restart it is rebuilt from
// the dispatch records and leases (every ticket that would hold a slot had
// the node not stopped, see Dispatcher.recoverAnchorSlots), and the TTL is
// the net under every path that might forget to give a slot back.
//
// Accepted tasks are not affected, Profiles without kind 5 are not affected,
// and Verifier duty is not gated (verifying creates no anchor obligation).
// Without the setting there is no gate at all.

// anchorAdmissionLogEvery spaces the log line of a gate that keeps refusing.
const anchorAdmissionLogEvery = time.Minute

// AnchorAdmission reads the anchor sidecar's admission signal. A nil
// *AnchorAdmission is the unconfigured gate and never refuses.
type AnchorAdmission struct {
	path   string
	maxAge time.Duration
	now    func() time.Time
	log    *slog.Logger

	mu            sync.Mutex
	last          *parsedAnchorAdmission // the last signal that was parsed
	refusing      bool
	loggedAt      time.Time
	refusedOffers uint64
	// reserved holds, by ticket, the tasks this node took on that the sidecar
	// does not list as seen yet (see the slot protocol above).
	reserved   map[layout.StoredHash]anchorReservation
	reserveTTL time.Duration
	// seenWarnedAt is when malformed "seen" entries were last logged.
	seenWarnedAt time.Time
	// reads counts the reads of the file, to order them (see adopt).
	reads uint64
}

// anchorReservation is one slot held by a ticket this node accepted.
type anchorReservation struct {
	task string    // the task id as the sidecar lists it (anchorAdmissionKey)
	at   time.Time // when the slot was taken, for the TTL
}

// anchorAdmissionKey is the form task ids take in the sidecar's "seen" list:
// the first 16 lowercase hex characters.
func anchorAdmissionKey(taskID layout.StoredHash) string {
	return hex.EncodeToString(taskID[:8])
}

// NewAnchorAdmission returns the gate cfg describes, or nil when cfg names no
// file. now and logger may be nil.
func NewAnchorAdmission(cfg config.AnchorAdmissionConfig, now func() time.Time, logger *slog.Logger) *AnchorAdmission {
	if !cfg.Enabled() {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &AnchorAdmission{path: cfg.File, maxAge: cfg.MaxAge(), now: now, log: logger.With("component", "anchor-admission"),
		reserved: map[layout.StoredHash]anchorReservation{}, reserveTTL: cfg.ReserveTTL()}
}

// anchorAdmissionSignal is the sidecar's file. Fields it does not know are
// ignored, so the sidecar may publish its own diagnostics next to them.
type anchorAdmissionSignal struct {
	Accept  *bool   `json:"accept"`
	Reason  string  `json:"reason"`
	Updated float64 `json:"updated"`
	// Slots, when present, makes this a slot signal: how many tasks beyond
	// those listed in Seen this node may have in flight. Seen lists the tasks
	// the sidecar accounts for or has settled, by anchorAdmissionKey (read
	// by anchorAdmissionSeenKey). A
	// sidecar that does not publish Slots is read by Accept alone.
	Slots *int     `json:"slots"`
	Seen  []string `json:"seen"`
}

// Refusal is nil when a new audit obligation may be taken, and otherwise says
// why not: the signal says no, is missing or stale, or it is a slot signal
// and every slot is reserved. The file is read on every call: it is small,
// local, and replaced by the sidecar every few seconds.
func (a *AnchorAdmission) Refusal() error {
	return a.RefusalForTask(layout.StoredHash{})
}

// RefusalForTask is Refusal for an offer of taskID: a task that already
// holds a slot here, or that the sidecar already lists as seen, needs no
// further slot. It reserves nothing; Reserve does, under the same rule.
func (a *AnchorAdmission) RefusalForTask(taskID layout.StoredHash) error {
	if a == nil {
		return nil
	}
	verdict := a.read()
	a.note(verdict)
	if verdict != nil {
		return verdict
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.fullLocked(layout.StoredHash{}, taskID)
}

// Capacity reads the signal for the standing handraise. refusal is the
// signal saying no (or being missing or stale). Otherwise limited reports a
// slot signal and free the slots not reserved; a boolean signal is not
// limited.
func (a *AnchorAdmission) Capacity() (free int, limited bool, refusal error) {
	if a == nil {
		return 0, false, nil
	}
	verdict := a.read()
	a.note(verdict)
	if verdict != nil {
		return 0, false, verdict
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	slots, limited := a.slotsLocked()
	return max(0, slots-len(a.reserved)), limited, nil
}

// Reserve takes a slot for ticket, an offer of taskID this node is about to
// accept, and reports whether it took a new one. It is the one place a slot
// is taken, and it checks and takes under one lock, so the tickets holding a
// slot never outnumber the slots of the signal they were taken against. A
// ticket that already holds a slot, and a task the sidecar already lists as
// seen, take none. Against a boolean signal nothing is reserved and the
// answer is the signal's.
func (a *AnchorAdmission) Reserve(ticket, taskID layout.StoredHash) (taken bool, err error) {
	if a == nil {
		return false, nil
	}
	verdict := a.read()
	a.note(verdict)
	if verdict != nil {
		return false, verdict
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, limited := a.slotsLocked(); !limited {
		return false, nil
	}
	if _, held := a.reserved[ticket]; held {
		return false, nil
	}
	if err := a.fullLocked(ticket, taskID); err != nil {
		return false, err
	}
	key := anchorAdmissionKey(taskID)
	if _, seen := a.last.seen[key]; seen {
		return false, nil
	}
	a.reserved[ticket] = anchorReservation{task: key, at: a.now()}
	return true, nil
}

// slotsLocked prunes the reservations and returns the slots of the last
// parsed signal; limited is false for a boolean signal. A reservation ends
// when the sidecar lists its task as seen (the sidecar counts it from then
// on) or at the TTL. The caller holds mu and has just read the signal.
func (a *AnchorAdmission) slotsLocked() (slots int, limited bool) {
	last := a.last
	if last == nil || last.slots == nil {
		return 0, false
	}
	now := a.now()
	for ticket, r := range a.reserved {
		_, seen := last.seen[r.task]
		if expired := now.Sub(r.at) > a.reserveTTL; seen || expired {
			delete(a.reserved, ticket)
			if expired && !seen {
				a.log.Warn("anchor admission slot released at its TTL: the sidecar never listed the task as seen",
					"ticket", ticket.String(), "task", r.task, "held", now.Sub(r.at).Round(time.Second).String())
			}
		}
	}
	return max(0, *last.slots), true
}

// fullLocked is the slot rule for one more task: nil against a boolean
// signal, for a ticket or task that already holds a slot, for a task the
// sidecar lists as seen, and while a slot is free. The caller holds mu.
func (a *AnchorAdmission) fullLocked(ticket, taskID layout.StoredHash) error {
	slots, limited := a.slotsLocked()
	if !limited {
		return nil
	}
	if !taskID.IsZero() {
		key := anchorAdmissionKey(taskID)
		if _, seen := a.last.seen[key]; seen {
			return nil
		}
		for held, r := range a.reserved {
			if held == ticket || (ticket.IsZero() && r.task == key) {
				return nil
			}
		}
	}
	if len(a.reserved) < slots {
		return nil
	}
	why := a.last.reason
	if why == "" {
		why = "no free audit slot"
	}
	return fmt.Errorf("the anchor sidecar has %d audit slots and %d tasks of this node are in flight: %s", slots, len(a.reserved), why)
}

// Release gives back the slot ticket holds, if any: the ticket will create
// no audit obligation here (it was rejected, revoked, superseded, lost, or
// its task ended before a receipt was signed).
func (a *AnchorAdmission) Release(ticket layout.StoredHash) {
	if a == nil {
		return
	}
	a.mu.Lock()
	delete(a.reserved, ticket)
	a.mu.Unlock()
}

// ReleaseTask gives back every slot held for taskID.
func (a *AnchorAdmission) ReleaseTask(taskID layout.StoredHash) {
	if a == nil {
		return
	}
	key := anchorAdmissionKey(taskID)
	a.mu.Lock()
	for ticket, r := range a.reserved {
		if r.task == key {
			delete(a.reserved, ticket)
		}
	}
	a.mu.Unlock()
}

// restore re-takes, after a restart, the slot of a ticket that held one:
// a task in flight, or a signed receipt the sidecar may not list as seen
// yet. The table is in memory only, so it is rebuilt from the dispatch
// records; it is rebuilt without a limit, because the tasks are in flight
// whatever the signal says now. received is when the offer arrived, from
// which the slot's TTL ran while the node was up: a slot whose TTL has run
// out since is not taken again (restored is false), and the others expire
// when they would have. A zero received (a record older than the field) is
// taken as now, and one ahead of the gate's clock is clamped to it.
func (a *AnchorAdmission) restore(ticket, taskID layout.StoredHash, received time.Time) (restored bool) {
	if a == nil {
		return false
	}
	now := a.now()
	if received.IsZero() || received.After(now) {
		received = now
	}
	if now.Sub(received) >= a.reserveTTL {
		return false
	}
	a.mu.Lock()
	a.reserved[ticket] = anchorReservation{task: anchorAdmissionKey(taskID), at: received}
	a.mu.Unlock()
	return true
}

// parsedAnchorAdmission is a signal that was parsed and the verdict it gave.
type parsedAnchorAdmission struct {
	updated time.Time
	verdict error
	// read orders the reads: it is taken before the file is opened.
	read uint64
	// slots is nil for a boolean signal.
	slots  *int
	seen   map[string]struct{}
	reason string
}

// read returns the verdict of the signal, or of the last parsed one while the
// file cannot be read or parsed and that signal is inside max_age.
func (a *AnchorAdmission) read() error {
	a.mu.Lock()
	a.reads++
	seq := a.reads
	a.mu.Unlock()
	sig, err := a.parse()
	if err != nil {
		a.mu.Lock()
		last := a.last
		a.mu.Unlock()
		if last != nil && a.fresh(last.updated) == nil {
			return last.verdict
		}
		return err
	}
	parsed := &parsedAnchorAdmission{updated: time.Unix(0, int64(sig.Updated*float64(time.Second))), read: seq}
	parsed.verdict = a.judge(sig, parsed.updated)
	if sig.Slots != nil {
		n := *sig.Slots
		parsed.slots, parsed.reason = &n, sig.Reason
		parsed.seen = make(map[string]struct{}, len(sig.Seen))
		var bad []string
		for _, id := range sig.Seen {
			key, ok := anchorAdmissionSeenKey(id)
			if !ok {
				bad = append(bad, id)
				continue
			}
			parsed.seen[key] = struct{}{}
		}
		if len(bad) > 0 {
			a.noteMalformedSeen(bad)
		}
	}
	return a.adopt(parsed)
}

// adopt makes parsed the last parsed signal and returns its verdict. read
// parses outside the lock, so two reads may finish out of order: a read
// that started before the one that gave the last signal, and found an older
// signal, keeps the last one, which is judged instead (its "seen" may have
// released slots the older one still counts). A read that started later is
// taken as it is, even if its signal is older: the file was rewritten.
func (a *AnchorAdmission) adopt(parsed *parsedAnchorAdmission) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if last := a.last; last != nil && parsed.read < last.read && parsed.updated.Before(last.updated) {
		if err := a.fresh(last.updated); err != nil {
			return err
		}
		return last.verdict
	}
	a.last = parsed
	return parsed.verdict
}

// anchorAdmissionSeenKey reads one entry of "seen" as anchorAdmissionKey: a
// task id in hex, in either case, with or without 0x, of at least 16
// characters (a full 64-character id included), of which the first 16
// count. ok is false for anything else; such an entry matches no task, and
// the slot it was meant to release waits for the TTL.
func anchorAdmissionSeenKey(id string) (key string, ok bool) {
	id = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(id)), "0x")
	if len(id) < 16 {
		return "", false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", false
		}
	}
	return id[:16], true
}

// noteMalformedSeen logs the entries of "seen" that are not task ids, at
// most once per anchorAdmissionLogEvery: the sidecar rewrites the file every
// few seconds and would repeat them.
func (a *AnchorAdmission) noteMalformedSeen(bad []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if !a.seenWarnedAt.IsZero() && now.Sub(a.seenWarnedAt) < anchorAdmissionLogEvery {
		return
	}
	a.seenWarnedAt = now
	a.log.Warn("anchor admission signal lists malformed seen entries: they release no slot (want the task id in hex, at least its first 16 characters)",
		"entries", len(bad), "first", bad[0], "signal", a.path)
}

func (a *AnchorAdmission) parse() (anchorAdmissionSignal, error) {
	var sig anchorAdmissionSignal
	raw, err := os.ReadFile(a.path)
	if err != nil {
		return sig, fmt.Errorf("anchor admission signal is unreadable (is the anchor sidecar running?): %w", err)
	}
	if err := json.Unmarshal(raw, &sig); err != nil {
		return sig, fmt.Errorf("anchor admission signal %s is malformed: %w", a.path, err)
	}
	if sig.Accept == nil {
		return sig, fmt.Errorf("anchor admission signal %s is malformed: no \"accept\"", a.path)
	}
	return sig, nil
}

// fresh refuses a signal written at updated that is older than max_age.
func (a *AnchorAdmission) fresh(updated time.Time) error {
	// A signal from the future is as untrustworthy as an old one: either the
	// clocks disagree or the file was not written by a live sidecar.
	age := a.now().Sub(updated)
	if age > a.maxAge || age < -a.maxAge {
		return fmt.Errorf("anchor admission signal is %.0fs old (limit %.0fs): the anchor sidecar is not updating it", age.Seconds(), a.maxAge.Seconds())
	}
	return nil
}

func (a *AnchorAdmission) judge(sig anchorAdmissionSignal, updated time.Time) error {
	if err := a.fresh(updated); err != nil {
		return err
	}
	if sig.Slots != nil {
		// A slot signal is read by its slots: "accept" is the sidecar's
		// answer for a service that does not know them.
		return nil
	}
	if !*sig.Accept {
		if sig.Reason == "" {
			sig.Reason = "no reason given"
		}
		return fmt.Errorf("the anchor sidecar is draining its audit backlog: %s", sig.Reason)
	}
	return nil
}

// note logs the gate closing, at most once per anchorAdmissionLogEvery while
// it stays closed, and once when it opens again.
func (a *AnchorAdmission) note(refusal error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	switch {
	case refusal != nil && (!a.refusing || now.Sub(a.loggedAt) >= anchorAdmissionLogEvery):
		a.log.Warn("anchor admission gate closed: no new task is taken under a Profile requiring WORKER_ANCHOR_OPENING",
			"why", refusal.Error(), "signal", a.path)
		a.loggedAt = now
	case refusal == nil && a.refusing:
		a.log.Info("anchor admission gate open again", "signal", a.path)
	}
	a.refusing = refusal != nil
}

// noteRefusedOffer counts one offer refused because the gate was closed.
func (a *AnchorAdmission) noteRefusedOffer() {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.refusedOffers++
	a.mu.Unlock()
}

// AnchorAdmissionStatus is the gate as /metrics reports it.
type AnchorAdmissionStatus struct {
	Accepting     bool   // the signal, read now, admits one more audit obligation
	RefusedOffers uint64 // offers refused by the gate since this process started
	// Limited reports a slot signal; Slots, Reserved and Free are then the
	// sidecar's slots, the slots tickets of this node hold, and the rest.
	Limited               bool
	Slots, Reserved, Free int
}

// Status reads the signal and reports the gate; ok is false for the
// unconfigured gate. It does not log.
func (a *AnchorAdmission) Status() (status AnchorAdmissionStatus, ok bool) {
	if a == nil {
		return AnchorAdmissionStatus{}, false
	}
	verdict := a.read()
	a.mu.Lock()
	defer a.mu.Unlock()
	status = AnchorAdmissionStatus{Accepting: verdict == nil, RefusedOffers: a.refusedOffers}
	if verdict == nil {
		if slots, limited := a.slotsLocked(); limited {
			status.Limited, status.Slots, status.Reserved = true, slots, len(a.reserved)
			status.Free = max(0, slots-len(a.reserved))
			status.Accepting = status.Free > 0
		}
	}
	return status, true
}
