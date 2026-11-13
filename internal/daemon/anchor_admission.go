package daemon

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/TrueOpen/cortex/internal/config"
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
	refusing      bool
	loggedAt      time.Time
	refusedOffers uint64
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
	return &AnchorAdmission{path: cfg.File, maxAge: cfg.MaxAge(), now: now, log: logger.With("component", "anchor-admission")}
}

// anchorAdmissionSignal is the sidecar's file. Fields it does not know are
// ignored, so the sidecar may publish its own diagnostics next to them.
type anchorAdmissionSignal struct {
	Accept  *bool   `json:"accept"`
	Reason  string  `json:"reason"`
	Updated float64 `json:"updated"`
}

// Refusal is nil when a new audit obligation may be taken, and otherwise says
// why not. The file is read on every call: it is small, local, and replaced
// by the sidecar every few seconds.
func (a *AnchorAdmission) Refusal() error {
	if a == nil {
		return nil
	}
	err := a.read()
	a.note(err)
	return err
}

func (a *AnchorAdmission) read() error {
	raw, err := os.ReadFile(a.path)
	if err != nil {
		return fmt.Errorf("anchor admission signal is unreadable (is the anchor sidecar running?): %w", err)
	}
	var sig anchorAdmissionSignal
	if err := json.Unmarshal(raw, &sig); err != nil {
		return fmt.Errorf("anchor admission signal %s is malformed: %w", a.path, err)
	}
	if sig.Accept == nil {
		return fmt.Errorf("anchor admission signal %s is malformed: no \"accept\"", a.path)
	}
	// A signal from the future is as untrustworthy as an old one: either the
	// clocks disagree or the file was not written by a live sidecar.
	age := a.now().Sub(time.Unix(0, int64(sig.Updated*float64(time.Second))))
	if age > a.maxAge || age < -a.maxAge {
		return fmt.Errorf("anchor admission signal is %.0fs old (limit %.0fs): the anchor sidecar is not updating it", age.Seconds(), a.maxAge.Seconds())
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
	Accepting     bool   // the signal, read now, admits new audit obligations
	RefusedOffers uint64 // offers refused by the gate since this process started
}

// Status reads the signal and reports the gate; ok is false for the
// unconfigured gate. It does not log.
func (a *AnchorAdmission) Status() (status AnchorAdmissionStatus, ok bool) {
	if a == nil {
		return AnchorAdmissionStatus{}, false
	}
	accepting := a.read() == nil
	a.mu.Lock()
	defer a.mu.Unlock()
	return AnchorAdmissionStatus{Accepting: accepting, RefusedOffers: a.refusedOffers}, true
}
