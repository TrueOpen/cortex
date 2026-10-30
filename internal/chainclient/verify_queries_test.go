package chainclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/cosmos/gogoproto/proto"

	taskv1 "github.com/TrueOpen/cortex/proto/task/v1"
)

func TestVerifyCommitReadsThisVerifiersCommitRow(t *testing.T) {
	taskID := bytes.Repeat([]byte{0x11}, 32)
	commitHash := bytes.Repeat([]byte{0x22}, 32)
	row := func(round uint32, operator string, hash []byte) *taskv1.CommitState {
		return &taskv1.CommitState{CommitKey: bytes.Repeat([]byte{0x33}, 32), TaskId: taskID, VerifyRound: round, VerifierOperatorAddress: operator, CommitHash: hash}
	}
	for _, c := range []struct {
		name     string
		row      *taskv1.CommitState
		notFound bool
		wantErr  bool
	}{
		{"found", row(1, "trueopen1verifier", commitHash), false, false},
		{"not found", nil, true, true},
		{"another round", row(2, "trueopen1verifier", commitHash), false, true},
		{"another operator", row(1, "trueopen1other", commitHash), false, true},
		{"short hash", row(1, "trueopen1verifier", []byte{1}), false, true},
		{"empty answer", nil, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			server := newABCITestServer(t, func(path, _ string, data []byte) (proto.Message, uint32, string) {
				if path != taskQuery+"VerifyCommit" {
					t.Fatalf("ABCI path = %q", path)
				}
				var req taskv1.QueryVerifyCommitRequest
				if err := unmarshalTestProto(data, &req); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(req.TaskId, taskID) || req.VerifyRound != 1 || req.VerifierOperatorAddress != "trueopen1verifier" {
					t.Fatalf("request = %+v", &req)
				}
				if c.notFound {
					return nil, 5, "rpc error: code = NotFound desc = no commit"
				}
				return &taskv1.QueryVerifyCommitResponse{Commit: c.row}, 0, ""
			})
			t.Cleanup(server.Close)
			got, err := NewKeeperABCIClient(server.URL).VerifyCommit(context.Background(), hex.EncodeToString(taskID), 1, "trueopen1verifier")
			if c.notFound && !errors.Is(err, ErrNotFound) {
				t.Fatalf("error = %v, want ErrNotFound", err)
			}
			if c.wantErr != (err != nil) {
				t.Fatalf("error = %v, wantErr %v", err, c.wantErr)
			}
			if err == nil && (!bytes.Equal(got.CommitHash, commitHash) || got.VerifyRound != 1 || got.Height == 0) {
				t.Fatalf("snapshot = %+v", got)
			}
		})
	}
}

func TestVerifyCommitRefusesAMalformedRequest(t *testing.T) {
	client := NewKeeperABCIClient("http://127.0.0.1:1")
	for name, call := range map[string]func() error{
		"short task id": func() error { _, err := client.VerifyCommit(context.Background(), "abcd", 1, "v"); return err },
		"round zero": func() error {
			_, err := client.VerifyCommit(context.Background(), hex.EncodeToString(bytes.Repeat([]byte{1}, 32)), 0, "v")
			return err
		},
		"no operator": func() error {
			_, err := client.VerifyCommit(context.Background(), hex.EncodeToString(bytes.Repeat([]byte{1}, 32)), 1, " ")
			return err
		},
	} {
		if err := call(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
