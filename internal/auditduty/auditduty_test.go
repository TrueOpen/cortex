package auditduty

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

const (
	taskA = "aa00000000000000000000000000000000000000000000000000000000000000"
	taskB = "bb00000000000000000000000000000000000000000000000000000000000000"
	hashO = "0100000000000000000000000000000000000000000000000000000000000000"
	hashP = "0200000000000000000000000000000000000000000000000000000000000000"
)

func host(env map[string]string, files ...string) Host {
	set := map[string]bool{}
	for _, f := range files {
		set[f] = true
	}
	return Host{Env: func(k string) string { return env[k] }, Exists: func(p string) bool { return set[p] }}
}

func TestBlockProducerKeyMaterialIsRefused(t *testing.T) {
	for name, h := range map[string]Host{
		"well-known home":  host(map[string]string{"HOME": "/h/u"}, "/h/u/.node/config/priv_validator_key.json"),
		"DAEMON_HOME":      host(map[string]string{"DAEMON_HOME": "/d"}, "/d/config/priv_validator_key.json"),
		"NODE_HOME state":  host(map[string]string{"NODE_HOME": "/n"}, "/n/data/priv_validator_state.json"),
		"key env variable": host(map[string]string{"PRIV_VALIDATOR_KEY_FILE": "/somewhere/key.json"}),
	} {
		if err := RefuseIfBlockProducer(nil, h); err == nil || !strings.Contains(err.Error(), "block producer") {
			t.Errorf("%s: want a refusal, got %v", name, err)
		}
	}
	if err := RefuseIfBlockProducer([]string{"/srv/n"}, host(nil, "/srv/n/priv_validator_key.json")); err == nil {
		t.Error("a configured node home with a key must be refused")
	}
	if err := RefuseIfBlockProducer([]string{"/srv/n"}, host(map[string]string{"HOME": "/h/u"}, "/h/u/.node/config/app.toml")); err != nil {
		t.Errorf("a plain full node's files are not key material: %v", err)
	}
}

func TestVoteValidation(t *testing.T) {
	pos := func(v ...string) []PositionVerdict {
		var out []PositionVerdict
		for i, x := range v {
			out = append(out, PositionVerdict{Position: uint64(i), Verdict: x})
		}
		return out
	}
	good := []VoteFile{
		{TaskID: taskA, PanelRound: 1, Vote: VotePass, OpeningHash: hashO, ProofHash: hashP, Positions: pos("PASS", "PASS")},
		{TaskID: taskA, PanelRound: 2, Vote: VoteReject, OpeningHash: hashO, ProofHash: hashP, Positions: pos("PASS", "REJECT")},
		{TaskID: taskA, PanelRound: 3, Vote: VoteUnavailable},
	}
	for _, v := range good {
		if err := v.Validate(); err != nil {
			t.Errorf("%+v: %v", v, err)
		}
	}
	bad := []VoteFile{
		{TaskID: taskA, PanelRound: 1, Vote: "NO_VERDICT"},
		{TaskID: taskA, PanelRound: 1, Vote: ""},
		{TaskID: "xyz", PanelRound: 1, Vote: VoteUnavailable},
		{TaskID: taskA, PanelRound: 0, Vote: VoteUnavailable},
		{TaskID: taskA, PanelRound: 1, Vote: VotePass, OpeningHash: hashO, ProofHash: hashP},
		{TaskID: taskA, PanelRound: 1, Vote: VotePass, Positions: pos("PASS")},
		{TaskID: taskA, PanelRound: 1, Vote: VotePass, OpeningHash: hashO, ProofHash: hashP, Positions: pos("PASS", "REJECT")},
		{TaskID: taskA, PanelRound: 1, Vote: VoteReject, OpeningHash: hashO, ProofHash: hashP, Positions: pos("PASS")},
		{TaskID: taskA, PanelRound: 1, Vote: VoteUnavailable, Positions: pos("PASS")},
		{TaskID: taskA, PanelRound: 1, Vote: VotePass, OpeningHash: hashO, ProofHash: hashP, Positions: pos("MAYBE")},
	}
	for _, v := range bad {
		if err := v.Validate(); err == nil {
			t.Errorf("%+v must be refused", v)
		}
	}
}

type fakeSource struct {
	rows []chainclient.PanelAssignment
	err  error
}

func (f *fakeSource) PanelAssignments(context.Context, string) ([]chainclient.PanelAssignment, error) {
	return f.rows, f.err
}

type fakeSubmitter struct {
	sent []VoteFile
	err  error
}

func (f *fakeSubmitter) SubmitPanelVote(_ context.Context, v VoteFile) error {
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, v)
	return nil
}

func assignment(task string, round uint32) chainclient.PanelAssignment {
	return chainclient.PanelAssignment{TaskID: task, PanelRound: round, Kind: 1, AssignmentHeight: 10, VoteDeadlineHeight: 70,
		Audit: []byte{1, 2, 3}, ModelID: hashO, ProfileVersion: 2, RegistrationHash: hashP}
}

func writeVote(t *testing.T, dir string, v VoteFile) {
	t.Helper()
	body, _ := json.Marshal(v)
	if err := os.WriteFile(filepath.Join(dir, "votes", roundKey(v.TaskID, v.PanelRound)+".json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func newRunner(t *testing.T, dir string, src AssignmentSource, sub VoteSubmitter) *Runner {
	t.Helper()
	spool, err := OpenSpool(dir)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRunner(Config{ChainID: "chain-1", Operator: "op", Source: src, Spool: spool, Submitter: sub})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAssignmentInVoteOut(t *testing.T) {
	dir := t.TempDir()
	src := &fakeSource{rows: []chainclient.PanelAssignment{assignment(taskA, 1)}}
	sub := &fakeSubmitter{}
	r := newRunner(t, dir, src, sub)
	ctx := context.Background()
	if err := r.Step(ctx); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "assignments", taskA+"-1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var a AssignmentFile
	if err := json.Unmarshal(body, &a); err != nil {
		t.Fatal(err)
	}
	if a.Version != ProtocolVersion || a.ChainID != "chain-1" || a.VerifierOperator != "op" || a.TaskID != taskA || a.PanelRound != 1 ||
		a.VoteDeadlineHeight != 70 || a.RegistrationHash != hashP || a.AuditB64 != "AQID" {
		t.Fatalf("assignment file %+v", a)
	}
	if len(sub.sent) != 0 {
		t.Fatal("nothing is sent before the program votes")
	}
	vote := VoteFile{TaskID: taskA, PanelRound: 1, Vote: VoteUnavailable}
	writeVote(t, dir, vote)
	if err := r.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if len(sub.sent) != 1 || sub.sent[0].Vote != VoteUnavailable {
		t.Fatalf("submitted %+v", sub.sent)
	}
	if err := r.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if len(sub.sent) != 1 {
		t.Fatal("a vote is submitted once")
	}
	// The chain stops listing a voted round: the assignment file goes.
	src.rows = nil
	if err := r.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "assignments", taskA+"-1.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a closed round's assignment file must be removed")
	}
}

func TestAVoteIsFinalAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	src := &fakeSource{rows: []chainclient.PanelAssignment{assignment(taskA, 1)}}
	sub := &fakeSubmitter{err: errors.New("node unreachable")}
	r := newRunner(t, dir, src, sub)
	ctx := context.Background()
	if err := r.Step(ctx); err != nil {
		t.Fatal(err)
	}
	first := VoteFile{TaskID: taskA, PanelRound: 1, Vote: VoteUnavailable}
	writeVote(t, dir, first)
	if err := r.Step(ctx); err != nil {
		t.Fatal(err)
	}
	// The program (or anything else) rewrites the file with another vote.
	writeVote(t, dir, VoteFile{TaskID: taskA, PanelRound: 1, Vote: VotePass, OpeningHash: hashO, ProofHash: hashP,
		Positions: []PositionVerdict{{Position: 0, Verdict: VotePass}}})
	sub2 := &fakeSubmitter{}
	r2 := newRunner(t, dir, src, sub2) // restart
	if err := r2.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if got, ok := r2.Recorded(taskA, 1); !ok || got.Vote != VoteUnavailable {
		t.Fatalf("the first vote must be kept, got %+v %v", got, ok)
	}
	if len(sub2.sent) != 0 {
		t.Fatal("a changed vote is never submitted")
	}
	// Restoring the original file lets the retry go through.
	writeVote(t, dir, first)
	if err := r2.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if len(sub2.sent) != 1 || sub2.sent[0].Vote != VoteUnavailable {
		t.Fatalf("the kept vote is retried, got %+v", sub2.sent)
	}
}

func TestVotesForUnassignedOrMalformedRoundsAreRefused(t *testing.T) {
	dir := t.TempDir()
	src := &fakeSource{rows: []chainclient.PanelAssignment{assignment(taskA, 1)}}
	sub := &fakeSubmitter{}
	r := newRunner(t, dir, src, sub)
	ctx := context.Background()
	if err := r.Step(ctx); err != nil {
		t.Fatal(err)
	}
	writeVote(t, dir, VoteFile{TaskID: taskB, PanelRound: 1, Vote: VoteUnavailable}) // never assigned
	if err := os.WriteFile(filepath.Join(dir, "votes", taskA+"-1.json"), []byte(`{"task_id":"`+taskA+`","panel_round":1,"vote":"ABSTAIN"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if len(sub.sent) != 0 {
		t.Fatalf("nothing may be submitted, got %+v", sub.sent)
	}
	if _, ok := r.Recorded(taskA, 1); ok {
		t.Fatal("a vote outside the three values is not recorded")
	}
}

func TestWithoutASubmitterTheVoteIsOnlyRecorded(t *testing.T) {
	dir := t.TempDir()
	r := newRunner(t, dir, &fakeSource{rows: []chainclient.PanelAssignment{assignment(taskA, 2)}}, nil)
	if err := r.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	writeVote(t, dir, VoteFile{TaskID: taskA, PanelRound: 2, Vote: VoteUnavailable})
	if err := r.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, ok := r.Recorded(taskA, 2); !ok || got.Vote != VoteUnavailable {
		t.Fatalf("recorded %+v %v", got, ok)
	}
}

func TestAChainWithoutPanelsLeavesTheSpoolAlone(t *testing.T) {
	dir := t.TempDir()
	r := newRunner(t, dir, &fakeSource{err: chainclient.ErrQueryUnsupported}, nil)
	for i := 0; i < 3; i++ {
		if err := r.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "assignments"))
	if len(entries) != 0 {
		t.Fatal("no assignment can appear")
	}
	if _, err := os.Stat(filepath.Join(dir, "ledger.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("nothing is recorded")
	}
	// A transport failure is an error for the caller to log, not a silent pass.
	r2 := newRunner(t, t.TempDir(), &fakeSource{err: errors.New("connection refused")}, nil)
	if err := r2.Step(context.Background()); err == nil {
		t.Fatal("a failed read must be reported")
	}
}
