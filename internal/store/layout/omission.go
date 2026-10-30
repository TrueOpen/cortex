package layout

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/TrueOpen/cortex/internal/store"
)

// Omission discovery (S8, CD §8.7), one case per recorded task:
//
//	omission-case/<task_id>              OmissionCase
//	omission-open/<task_id>              "" while open
//	omission-gc/<%020d retain>/<task_id> "" once closed
const (
	omissionCasePrefix = "omission-case/"
	omissionOpenPrefix = "omission-open/"
	omissionGCPrefix   = "omission-gc/"
)

var errOmissionStop = errors.New("omission scan stop")

func OmissionCaseKey(taskID StoredHash) []byte { return join([]byte(omissionCasePrefix), taskID[:]) }
func omissionOpenKey(taskID StoredHash) []byte { return join([]byte(omissionOpenPrefix), taskID[:]) }
func omissionGCKey(at uint64, taskID StoredHash) []byte {
	return join(fmt.Appendf(nil, "%s%020d/", omissionGCPrefix, at), taskID[:])
}

type OmissionState string

const (
	OmissionPending    OmissionState = "pending"    // recorded while this node held an admitted leaf; not decided
	OmissionReported   OmissionState = "reported"   // MsgReportDispatchRosterUnavailable landed; the roster is still sought
	OmissionChallenged OmissionState = "challenged" // MsgChallengeDispatchOmission landed
	OmissionResolved   OmissionState = "resolved"   // the chain closed the challenge (Outcome)
	OmissionClear      OmissionState = "clear"      // not omitted, or not eligible
	OmissionAbandoned  OmissionState = "abandoned"  // window closed, or the chain refused the proof
)

func (s OmissionState) Open() bool {
	return s == OmissionPending || s == OmissionReported || s == OmissionChallenged
}

var omissionTransitions = map[OmissionState][]OmissionState{
	OmissionPending:    {OmissionReported, OmissionChallenged, OmissionResolved, OmissionClear, OmissionAbandoned},
	OmissionReported:   {OmissionChallenged, OmissionResolved, OmissionClear, OmissionAbandoned},
	OmissionChallenged: {OmissionResolved, OmissionAbandoned},
}

// OmissionCase is one order a configured Builder recorded while this node
// may have been left out of its roster.
type OmissionCase struct {
	SchemaVersion   uint16        `json:"schema_version"`
	TaskID          StoredHash    `json:"task_id"`
	SessionID       StoredHash    `json:"session_id"`
	OrderSequence   uint64        `json:"order_sequence"`
	Builder         string        `json:"builder"`
	RecordHash      StoredHash    `json:"record_hash"`
	RecordedHeight  uint64        `json:"recorded_height"`
	State           OmissionState `json:"state"`
	Reason          string        `json:"reason,omitempty"`
	Round           uint32        `json:"round,omitempty"`
	ChallengeID     StoredHash    `json:"challenge_id"`
	ChallengeTx     string        `json:"challenge_tx,omitempty"`
	ReportID        StoredHash    `json:"report_id"`
	ReportRound     uint32        `json:"report_round,omitempty"`
	ReportTx        string        `json:"report_tx,omitempty"`
	RosterMissSince uint64        `json:"roster_miss_since,omitempty"`
	NextCheckHeight uint64        `json:"next_check_height,omitempty"`
	Outcome         int32         `json:"outcome,omitempty"`
	RetainUntil     uint64        `json:"retain_until,omitempty"`
}

func putOmission(b *store.Batch, c OmissionCase) error {
	if err := putBatchJSON(b, OmissionCaseKey(c.TaskID), c); err != nil {
		return err
	}
	if c.State.Open() {
		return b.Set(omissionOpenKey(c.TaskID), []byte{})
	}
	if err := b.Delete(omissionOpenKey(c.TaskID)); err != nil {
		return err
	}
	return b.Set(omissionGCKey(c.RetainUntil, c.TaskID), []byte{})
}

// PutOmissionCase opens a pending case once per task. created=false: it
// exists (open or closed) for the same record. A different record is
// ErrConflict.
func PutOmissionCase(ctx context.Context, s *store.Store, c OmissionCase) (bool, error) {
	c.SchemaVersion, c.State = 1, OmissionPending
	created := false
	err := s.ApplyBatch(ctx, func(b *store.Batch) error {
		var cur OmissionCase
		err := getBatchJSON(b, OmissionCaseKey(c.TaskID), &cur)
		switch {
		case err == nil:
			if cur.RecordHash != c.RecordHash || cur.Builder != c.Builder {
				return fmt.Errorf("%w: omission case for task %s names another record", ErrConflict, c.TaskID)
			}
			return nil
		case !errors.Is(err, store.ErrNotFound):
			return err
		}
		created = true
		return putOmission(b, c)
	})
	return created, err
}

func GetOmissionCase(ctx context.Context, s *store.Store, taskID StoredHash) (OmissionCase, error) {
	var c OmissionCase
	return c, getJSON(ctx, s, OmissionCaseKey(taskID), &c)
}

// UpdateOmissionCase applies fn atomically: identity is immutable, states
// move along omissionTransitions, a closed case carries RetainUntil and
// never changes again.
func UpdateOmissionCase(ctx context.Context, s *store.Store, taskID StoredHash, fn func(*OmissionCase)) (OmissionCase, error) {
	var out OmissionCase
	err := s.ApplyBatch(ctx, func(b *store.Batch) error {
		var cur OmissionCase
		if err := getBatchJSON(b, OmissionCaseKey(taskID), &cur); err != nil {
			return err
		}
		if !cur.State.Open() {
			return fmt.Errorf("%w: omission case %s is closed", ErrConflict, taskID)
		}
		next := cur
		fn(&next)
		switch {
		case next.TaskID != cur.TaskID || next.RecordHash != cur.RecordHash || next.Builder != cur.Builder ||
			next.SessionID != cur.SessionID || next.OrderSequence != cur.OrderSequence || next.RecordedHeight != cur.RecordedHeight:
			return fmt.Errorf("%w: omission case identity is immutable", ErrConflict)
		case next.State != cur.State && !slices.Contains(omissionTransitions[cur.State], next.State):
			return fmt.Errorf("%w: omission %s cannot become %s", ErrConflict, cur.State, next.State)
		case !next.State.Open() && next.RetainUntil == 0:
			return fmt.Errorf("%w: a closed omission case needs RetainUntil", ErrConflict)
		}
		out = next
		return putOmission(b, next)
	})
	return out, err
}

// OpenOmissionCases lists every open case.
func OpenOmissionCases(ctx context.Context, s *store.Store) ([]OmissionCase, error) {
	tasks, err := scanHashes(ctx, s, []byte(omissionOpenPrefix))
	if err != nil {
		return nil, err
	}
	out := make([]OmissionCase, 0, len(tasks))
	for _, t := range tasks {
		c, err := GetOmissionCase(ctx, s, t)
		if err != nil {
			return nil, fmt.Errorf("omission case %s: %w", t, err)
		}
		out = append(out, c)
	}
	return out, nil
}

// DueOmissionGC lists up to limit closed cases with RetainUntil <= height.
func DueOmissionGC(ctx context.Context, s *store.Store, height uint64, limit int) ([]StoredHash, error) {
	prefix := []byte(omissionGCPrefix)
	var out []StoredHash
	err := s.ScanPrefix(ctx, prefix, func(key, _ []byte) error {
		rest := key[len(prefix):]
		if len(rest) != 21+32 {
			return fmt.Errorf("malformed key under %q", prefix)
		}
		at, err := strconv.ParseUint(string(rest[:20]), 10, 64)
		if err != nil {
			return err
		}
		if at > height || len(out) == limit {
			return errOmissionStop
		}
		var h StoredHash
		copy(h[:], rest[21:])
		out = append(out, h)
		return nil
	})
	if errors.Is(err, errOmissionStop) {
		err = nil
	}
	return out, err
}

// DeleteOmissionCase removes a case and its index keys; an absent case is a
// no-op.
func DeleteOmissionCase(ctx context.Context, s *store.Store, taskID StoredHash) error {
	return s.ApplyBatch(ctx, func(b *store.Batch) error {
		var c OmissionCase
		err := getBatchJSON(b, OmissionCaseKey(taskID), &c)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, k := range [][]byte{OmissionCaseKey(taskID), omissionOpenKey(taskID), omissionGCKey(c.RetainUntil, taskID)} {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}
