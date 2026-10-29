package layout

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestKeyEncodings(t *testing.T) {
	taskHash := StoredHash{}
	copy(taskHash[:], bytes.Repeat([]byte{0xab}, 32))

	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, 0x0102030405060708)

	cases := []struct {
		name string
		key  []byte
		want []byte
	}{
		{
			name: "verify-candidate",
			key:  VerifyCandidateKey(taskHash, 0x0102030405060708),
			want: append(append([]byte("verify-candidate/"), taskHash[:]...), append([]byte("/"), seq...)...),
		},
		{
			name: "task",
			key:  TaskKey(taskHash),
			want: append([]byte("task/"), taskHash[:]...),
		},
		{
			name: "infer",
			key:  InferKey(taskHash),
			want: append([]byte("infer/"), taskHash[:]...),
		},
		{
			name: "verify",
			key:  VerifyKey(taskHash),
			want: append([]byte("verify/"), taskHash[:]...),
		},
		{
			name: "delivery output",
			key:  DeliveryKey(taskHash, "OUTPUT"),
			want: append(append([]byte("delivery/"), taskHash[:]...), "/OUTPUT"...),
		},
		{
			name: "delivery evidence selector",
			key:  DeliveryKey(taskHash, "EVIDENCE", "DESCRIPTOR"),
			want: append(append([]byte("delivery/"), taskHash[:]...), "/EVIDENCE/DESCRIPTOR"...),
		},
		{
			name: "evidence",
			key:  EvidenceKey(taskHash),
			want: append([]byte("evidence/"), taskHash[:]...),
		},
		{
			name: "challenge",
			key:  ChallengeKey(taskHash, "challenge-1"),
			want: append(append([]byte("challenge/"), taskHash[:]...), "/challenge-1"...),
		},
		{
			name: "task-id/infer",
			key:  TaskIDInferKey("task-1"),
			want: []byte("task-id/infer/task-1"),
		},
		{
			name: "task-id/verify",
			key:  TaskIDVerifyKey("task-1"),
			want: []byte("task-id/verify/task-1"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(tc.key); got != string(tc.want) {
				t.Fatalf("key = %q, want %q", tc.key, tc.want)
			}
		})
	}
}

func TestPrefixesDoNotCollide(t *testing.T) {
	prefixes := [][]byte{
		[]byte(verifyCandidatePrefix),
		[]byte(taskPrefix),
		[]byte(inferPrefix),
		[]byte(verifyPrefix),
		[]byte(deliveryPrefix),
		[]byte(evidencePrefix),
		[]byte(challengePrefix),
		[]byte(taskIDInferPrefix),
		[]byte(taskIDVerifyPrefix),
	}
	for i := range prefixes {
		for j := range prefixes {
			if i == j {
				continue
			}
			if bytes.HasPrefix(prefixes[i], prefixes[j]) {
				t.Fatalf("prefix collision: %q is a prefix of %q", prefixes[j], prefixes[i])
			}
		}
	}
}

func TestVerifyCandidateRoundTrip(t *testing.T) {
	taskHash := StoredHash{}
	copy(taskHash[:], bytes.Repeat([]byte{0xcd}, 32))
	key := VerifyCandidateKey(taskHash, 0x0102030405060708)
	round := make([]byte, 8)
	binary.BigEndian.PutUint64(round, 0x0102030405060708)
	expected := append(append([]byte("verify-candidate/"), taskHash[:]...), append([]byte("/"), round...)...)
	if !bytes.Equal(key, expected) {
		t.Fatalf("key = %x, want %x", key, expected)
	}
}
