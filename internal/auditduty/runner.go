package auditduty

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

// AssignmentSource lists the open panel rounds the operator is a member of
// and has not voted in.
type AssignmentSource interface {
	PanelAssignments(ctx context.Context, operatorAddress string) ([]chainclient.PanelAssignment, error)
}

// VoteSubmitter sends a panel vote to the chain on the Verifier's behalf. A
// Runner without one leaves broadcasting to the Verifier program and only
// records what the program decided.
type VoteSubmitter interface {
	SubmitPanelVote(ctx context.Context, vote VoteFile) error
}

// Config is what a Runner needs.
type Config struct {
	ChainID  string
	Operator string
	Source   AssignmentSource
	Spool    *Spool
	// Submitter may be nil.
	Submitter VoteSubmitter
	PollEvery time.Duration
	Logger    *slog.Logger
}

// DefaultPollEvery paces the assignment poll.
const DefaultPollEvery = 10 * time.Second

// ledgerLimit bounds the rounds remembered after they closed.
const ledgerLimit = 4096

// Runner moves assignments into the spool and votes out of it.
type Runner struct {
	cfg Config
	log *slog.Logger

	mu          sync.Mutex
	ledger      ledger
	unsupported bool // the last poll found a chain without the query
}

type ledgerEntry struct {
	// Issued is set once the assignment was written for the program.
	Issued bool `json:"issued"`
	// Vote is the first valid vote read for the round; it is final.
	Vote *VoteFile `json:"vote,omitempty"`
	// Submitted is set once a Submitter accepted the vote.
	Submitted bool `json:"submitted,omitempty"`
	// Seq orders entries for pruning.
	Seq uint64 `json:"seq"`
}

type ledger struct {
	Next   uint64                  `json:"next"`
	Rounds map[string]*ledgerEntry `json:"rounds"`
}

// NewRunner loads the ledger kept in the spool directory, so a vote stays
// final across restarts.
func NewRunner(cfg Config) (*Runner, error) {
	if cfg.Source == nil || cfg.Spool == nil || cfg.Operator == "" {
		return nil, errors.New("audit duty needs an assignment source, a spool and the operator address")
	}
	if cfg.PollEvery <= 0 {
		cfg.PollEvery = DefaultPollEvery
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	r := &Runner{cfg: cfg, log: cfg.Logger.With("component", "audit-duty"), ledger: ledger{Rounds: map[string]*ledgerEntry{}}}
	body, err := os.ReadFile(r.ledgerPath())
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("audit duty ledger: %w", err)
	default:
		if err := json.Unmarshal(body, &r.ledger); err != nil {
			return nil, fmt.Errorf("audit duty ledger %s is unreadable; a vote is final, so it is not rebuilt silently: %w", r.ledgerPath(), err)
		}
		if r.ledger.Rounds == nil {
			r.ledger.Rounds = map[string]*ledgerEntry{}
		}
	}
	return r, nil
}

func (r *Runner) ledgerPath() string { return filepath.Join(r.cfg.Spool.dir, "ledger.json") }

// Run polls until ctx ends. A failed step is logged and retried; it never
// ends the node.
func (r *Runner) Run(ctx context.Context) error {
	r.log.Info("audit capability is on: this node takes panel assignments and hands them to the local Verifier program",
		"spool_dir", r.cfg.Spool.dir, "votes_broadcast_by", map[bool]string{true: "cortex", false: "verifier program"}[r.cfg.Submitter != nil])
	t := time.NewTicker(r.cfg.PollEvery)
	defer t.Stop()
	for {
		if err := r.Step(ctx); err != nil && ctx.Err() == nil {
			r.log.Warn("audit duty step failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// Step runs one poll: new assignments in, closed rounds out, votes read.
func (r *Runner) Step(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rows, err := r.cfg.Source.PanelAssignments(ctx, r.cfg.Operator)
	if errors.Is(err, chainclient.ErrQueryUnsupported) {
		if !r.unsupported {
			r.unsupported = true
			r.log.Warn("this chain does not serve panel assignments; the audit capability is idle until it does")
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read panel assignments: %w", err)
	}
	r.unsupported = false
	changed := false
	open := map[string]chainclient.PanelAssignment{}
	for _, row := range rows {
		key := roundKey(row.TaskID, row.PanelRound)
		open[key] = row
		written, err := r.cfg.Spool.PutAssignment(AssignmentFile{
			Version: ProtocolVersion, ChainID: r.cfg.ChainID, VerifierOperator: r.cfg.Operator,
			TaskID: row.TaskID, PanelRound: row.PanelRound, Kind: row.Kind,
			AssignmentHeight: row.AssignmentHeight, VoteDeadlineHeight: row.VoteDeadlineHeight,
			ModelID: row.ModelID, ProfileVersion: row.ProfileVersion, RegistrationHash: row.RegistrationHash,
			AuditB64: EncodeAudit(row.Audit),
		})
		if err != nil {
			return err
		}
		e := r.entry(key)
		if !e.Issued {
			e.Issued, changed = true, true
		}
		if written {
			r.log.Info("panel assignment handed to the Verifier program", "task_id", row.TaskID, "panel_round", row.PanelRound,
				"vote_deadline_height", row.VoteDeadlineHeight)
		}
	}
	// A round the chain no longer lists is voted, closed or past its deadline.
	keys, err := r.cfg.Spool.AssignmentKeys()
	if err != nil {
		return err
	}
	for _, key := range keys {
		if _, ok := open[key]; !ok {
			if err := r.cfg.Spool.RemoveAssignment(key); err != nil {
				return err
			}
		}
	}
	votes, bad, err := r.cfg.Spool.Votes()
	if err != nil {
		return err
	}
	for key, problem := range bad {
		r.log.Error("vote file from the Verifier program refused", "file", key+".json", "error", problem)
	}
	var voteKeys []string
	for key := range votes {
		voteKeys = append(voteKeys, key)
	}
	sort.Strings(voteKeys)
	for _, key := range voteKeys {
		vote := votes[key]
		e, known := r.ledger.Rounds[key]
		if !known || !e.Issued {
			r.log.Error("vote for a round this node was never assigned refused", "task_id", vote.TaskID, "panel_round", vote.PanelRound)
			continue
		}
		if e.Vote == nil {
			v := vote
			e.Vote, changed = &v, true
			r.log.Info("vote received from the Verifier program", "task_id", vote.TaskID, "panel_round", vote.PanelRound, "vote", vote.Vote)
		} else if !reflect.DeepEqual(*e.Vote, vote) {
			r.log.Error("a different vote for a round that already has one refused: a vote is final",
				"task_id", vote.TaskID, "panel_round", vote.PanelRound, "kept", e.Vote.Vote, "refused", vote.Vote)
			continue
		}
		if r.cfg.Submitter == nil || e.Submitted {
			continue
		}
		if _, stillOpen := open[key]; !stillOpen {
			continue // voted already, or the round closed: nothing to send
		}
		if err := r.cfg.Submitter.SubmitPanelVote(ctx, *e.Vote); err != nil {
			r.log.Warn("panel vote not submitted; it is retried at the next poll", "task_id", vote.TaskID, "panel_round", vote.PanelRound, "error", err)
			continue
		}
		e.Submitted, changed = true, true
	}
	if changed {
		r.prune(open)
		return r.save()
	}
	return nil
}

func (r *Runner) entry(key string) *ledgerEntry {
	e := r.ledger.Rounds[key]
	if e == nil {
		r.ledger.Next++
		e = &ledgerEntry{Seq: r.ledger.Next}
		r.ledger.Rounds[key] = e
	}
	return e
}

// prune drops the oldest closed rounds above the limit.
func (r *Runner) prune(open map[string]chainclient.PanelAssignment) {
	if len(r.ledger.Rounds) <= ledgerLimit {
		return
	}
	type aged struct {
		key string
		seq uint64
	}
	var closed []aged
	for key, e := range r.ledger.Rounds {
		if _, ok := open[key]; !ok {
			closed = append(closed, aged{key, e.Seq})
		}
	}
	sort.Slice(closed, func(i, j int) bool { return closed[i].seq < closed[j].seq })
	for i := 0; i < len(closed) && len(r.ledger.Rounds) > ledgerLimit; i++ {
		delete(r.ledger.Rounds, closed[i].key)
	}
}

func (r *Runner) save() error {
	body, err := json.Marshal(r.ledger)
	if err != nil {
		return err
	}
	tmp := r.ledgerPath() + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return fmt.Errorf("audit duty ledger: %w", err)
	}
	return os.Rename(tmp, r.ledgerPath())
}

// Recorded returns the vote kept for a round, if any.
func (r *Runner) Recorded(taskID string, round uint32) (VoteFile, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.ledger.Rounds[roundKey(taskID, round)]
	if e == nil || e.Vote == nil {
		return VoteFile{}, false
	}
	return *e.Vote, true
}
