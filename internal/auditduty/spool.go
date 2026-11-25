package auditduty

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The local protocol between Cortex and the Verifier program is a spool
// directory with two sub-directories:
//
//	assignments/<task_id>-<panel_round>.json   written by Cortex, read by the program
//	votes/<task_id>-<panel_round>.json         written by the program, read by Cortex
//
// Every file is written under a temporary name and renamed into place, so a
// reader never sees half a file. Cortex removes an assignment file when its
// round is no longer open for this Verifier. A vote file is final: the first
// vote read for a round is kept and a later, different file for the same
// round is refused.

// Vote values of the local protocol; they are the chain's AnchorVerdictV1 names
// a panel member may cast.
const (
	VotePass        = "PASS"
	VoteReject      = "REJECT"
	VoteUnavailable = "UNAVAILABLE"
)

// ProtocolVersion is written into every assignment file.
const ProtocolVersion = 1

// AssignmentFile is assignments/<task_id>-<panel_round>.json.
type AssignmentFile struct {
	Version            int    `json:"version"`
	ChainID            string `json:"chain_id"`
	VerifierOperator   string `json:"verifier_operator"`
	TaskID             string `json:"task_id"`     // 64 lowercase hex
	PanelRound         uint32 `json:"panel_round"` // 1, 2, 3 ... per task, never reused
	Kind               uint32 `json:"kind"`        // AnchorPanelRoundKindV1
	AssignmentHeight   uint64 `json:"assignment_height"`
	VoteDeadlineHeight uint64 `json:"vote_deadline_height"`
	ModelID            string `json:"model_id"`
	ProfileVersion     uint32 `json:"profile_version"`
	RegistrationHash   string `json:"registration_hash"`
	// AuditB64 is the chain's AnchorAuditState row, protobuf, base64.
	AuditB64 string `json:"audit_b64"`
}

// PositionVerdict is one sampled position of a PASS or REJECT vote.
type PositionVerdict struct {
	Position uint64 `json:"position"`
	Verdict  string `json:"verdict"` // PASS or REJECT
}

// VoteFile is votes/<task_id>-<panel_round>.json.
type VoteFile struct {
	TaskID     string `json:"task_id"`
	PanelRound uint32 `json:"panel_round"`
	Vote       string `json:"vote"`
	// OpeningHash and ProofHash are the hashes the program audited (64 lowercase
	// hex); the chain refuses a vote whose hashes are not the recorded ones.
	OpeningHash string `json:"opening_hash,omitempty"`
	ProofHash   string `json:"proof_hash,omitempty"`
	// Positions lists exactly the sampled positions for PASS and REJECT and is
	// empty for UNAVAILABLE.
	Positions []PositionVerdict `json:"positions,omitempty"`
}

var (
	hash32Text = regexp.MustCompile(`^[0-9a-f]{64}$`)
	spoolName  = regexp.MustCompile(`^([0-9a-f]{64})-([0-9]{1,10})\.json$`)
)

// maxVoteFileBytes bounds what Cortex reads from the program.
const maxVoteFileBytes = 1 << 20

// Validate checks a vote against the protocol; it does not judge the audit.
func (v VoteFile) Validate() error {
	if !hash32Text.MatchString(v.TaskID) {
		return errors.New("task_id is not 64 lowercase hex characters")
	}
	if v.PanelRound == 0 {
		return errors.New("panel_round is zero")
	}
	switch v.Vote {
	case VotePass, VoteReject:
		if !hash32Text.MatchString(v.OpeningHash) || !hash32Text.MatchString(v.ProofHash) {
			return fmt.Errorf("a %s vote names the opening and proof hashes it audited", v.Vote)
		}
		if len(v.Positions) == 0 {
			return fmt.Errorf("a %s vote lists the sampled positions", v.Vote)
		}
		rejects := 0
		for _, p := range v.Positions {
			switch p.Verdict {
			case VotePass:
			case VoteReject:
				rejects++
			default:
				return fmt.Errorf("position %d has verdict %q, not PASS or REJECT", p.Position, p.Verdict)
			}
		}
		if v.Vote == VotePass && rejects != 0 {
			return errors.New("a PASS vote has a rejected position")
		}
		if v.Vote == VoteReject && rejects == 0 {
			return errors.New("a REJECT vote has no rejected position")
		}
	case VoteUnavailable:
		if len(v.Positions) != 0 {
			return errors.New("an UNAVAILABLE vote lists no positions")
		}
	default:
		return fmt.Errorf("vote %q is not PASS, REJECT or UNAVAILABLE", v.Vote)
	}
	return nil
}

// Spool is the directory pair.
type Spool struct{ dir string }

// OpenSpool creates the two sub-directories, private to the node's user.
func OpenSpool(dir string) (*Spool, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, errors.New("verifier.audit.spool_dir is empty")
	}
	for _, sub := range []string{"assignments", "votes"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, fmt.Errorf("audit spool: %w", err)
		}
	}
	return &Spool{dir: dir}, nil
}

func roundKey(taskID string, round uint32) string { return fmt.Sprintf("%s-%d", taskID, round) }

// PutAssignment writes the assignment unless a file for the round is already
// there (the program may be reading it).
func (s *Spool) PutAssignment(a AssignmentFile) (written bool, err error) {
	path := filepath.Join(s.dir, "assignments", roundKey(a.TaskID, a.PanelRound)+".json")
	if _, err := os.Stat(path); err == nil {
		return false, nil
	}
	body, err := json.Marshal(a)
	if err != nil {
		return false, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return false, fmt.Errorf("audit spool: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return false, fmt.Errorf("audit spool: %w", err)
	}
	return true, nil
}

// AssignmentKeys lists the rounds that have an assignment file.
func (s *Spool) AssignmentKeys() ([]string, error) { return s.keys("assignments") }

// RemoveAssignment drops the assignment file of a round that is over.
func (s *Spool) RemoveAssignment(key string) error {
	err := os.Remove(filepath.Join(s.dir, "assignments", key+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *Spool) keys(sub string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, sub))
	if err != nil {
		return nil, fmt.Errorf("audit spool: %w", err)
	}
	var out []string
	for _, e := range entries {
		if m := spoolName.FindStringSubmatch(e.Name()); m != nil && !e.IsDir() {
			out = append(out, strings.TrimSuffix(e.Name(), ".json"))
		}
	}
	return out, nil
}

// Votes reads every vote file. A file that does not parse, fails Validate or
// is named for another round than it carries is returned in bad, keyed by
// file name, and never as a vote.
func (s *Spool) Votes() (votes map[string]VoteFile, bad map[string]error, err error) {
	keys, err := s.keys("votes")
	if err != nil {
		return nil, nil, err
	}
	votes, bad = map[string]VoteFile{}, map[string]error{}
	for _, key := range keys {
		path := filepath.Join(s.dir, "votes", key+".json")
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.Size() > maxVoteFileBytes {
			bad[key] = fmt.Errorf("vote file is %d bytes, above the %d limit", info.Size(), maxVoteFileBytes)
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			bad[key] = err
			continue
		}
		var v VoteFile
		if err := json.Unmarshal(body, &v); err != nil {
			bad[key] = fmt.Errorf("vote file is not JSON: %w", err)
			continue
		}
		if err := v.Validate(); err != nil {
			bad[key] = err
			continue
		}
		if roundKey(v.TaskID, v.PanelRound) != key {
			bad[key] = errors.New("vote file is named for another round than it carries")
			continue
		}
		votes[key] = v
	}
	return votes, bad, nil
}

// EncodeAudit is the audit_b64 form of an audit row.
func EncodeAudit(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }
