package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestAssignmentUsesExplicitAcceptedTaskHash(t *testing.T) {
	id, hash := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	notify, err := assignmentNotify(id, hash, "worker", 90, 100)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(notify.TaskId) != id || hex.EncodeToString(notify.TaskHash) != hash {
		t.Fatalf("notify = %+v", notify)
	}
	for _, invalid := range []string{"", strings.Repeat("AB", 32), strings.Repeat("ab", 31)} {
		if _, err := assignmentNotify(id, invalid, "worker", 90, 100); err == nil {
			t.Fatalf("accepted task hash %q", invalid)
		}
	}
	if _, err := assignmentNotify(id, hash, "worker", 100, 90); err == nil {
		t.Fatal("accepted reversed assignment deadlines")
	}
}
