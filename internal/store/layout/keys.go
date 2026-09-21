package layout

import (
	"encoding/binary"
)

// Key prefix constants for the new task storage layout.
// See docs/specs/task-storage-layout.md
const (
	candidateCurrentPrefix = "candidate-current/"
	candidatePrefix        = "candidate/"
	verifyCandidatePrefix  = "verify-candidate/"
	taskPrefix             = "task/"
	inferPrefix            = "infer/"
	verifyPrefix           = "verify/"
	taskIDInferPrefix      = "task-id/infer/"
	taskIDVerifyPrefix     = "task-id/verify/"
	deliveryPrefix         = "delivery/"
	evidencePrefix         = "evidence/"
	challengePrefix        = "challenge/"
)

// CandidateCurrentKey returns the candidate-current locator key:
// candidate-current/<sessionID>/<orderSequence:8 BE>
func CandidateCurrentKey(sessionID string, orderSequence uint64) []byte {
	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, orderSequence)
	return join([]byte(candidateCurrentPrefix), []byte(sessionID), slash(), seq)
}

// CandidateKey returns the candidate admission key: candidate/<taskHash:32>
func CandidateKey(taskHash StoredHash) []byte {
	return join([]byte(candidatePrefix), taskHash[:])
}

// VerifyCandidateKey returns the verifier admission key:
// verify-candidate/<taskHash:32>/<verifyRound:8 BE>
func VerifyCandidateKey(taskHash StoredHash, verifyRound uint64) []byte {
	round := make([]byte, 8)
	binary.BigEndian.PutUint64(round, verifyRound)
	return join([]byte(verifyCandidatePrefix), taskHash[:], slash(), round)
}

// TaskKey returns the task/ key: task/<taskHash:32>
func TaskKey(taskHash StoredHash) []byte {
	return join([]byte(taskPrefix), taskHash[:])
}

// InferKey returns the infer/ key: infer/<taskHash:32>
func InferKey(taskHash StoredHash) []byte {
	return join([]byte(inferPrefix), taskHash[:])
}

// VerifyKey returns the verify/ key: verify/<taskHash:32>
func VerifyKey(taskHash StoredHash) []byte {
	return join([]byte(verifyPrefix), taskHash[:])
}

// TaskIDInferKey returns the task-id/infer/<taskID> key.
func TaskIDInferKey(taskID string) []byte {
	return []byte(taskIDInferPrefix + taskID)
}

// TaskIDVerifyKey returns the task-id/verify/<taskID> key.
func TaskIDVerifyKey(taskID string) []byte {
	return []byte(taskIDVerifyPrefix + taskID)
}

// DeliveryKey returns a delivery/ key. For INPUT/OUTPUT there is no selector.
// For EVIDENCE a selector is appended: delivery/<taskHash>/<dataKind>[/<selector>]
func DeliveryKey(taskHash StoredHash, dataKind string, selector ...string) []byte {
	parts := [][]byte{[]byte(deliveryPrefix), taskHash[:], slash(), []byte(dataKind)}
	for _, s := range selector {
		parts = append(parts, slash(), []byte(s))
	}
	return join(parts...)
}

// EvidenceKey returns the evidence/ key: evidence/<taskHash:32>
func EvidenceKey(taskHash StoredHash) []byte {
	return join([]byte(evidencePrefix), taskHash[:])
}

// ChallengeKey returns a challenge/ key: challenge/<taskHash:32>/<challengeID>
func ChallengeKey(taskHash StoredHash, challengeID string) []byte {
	return join([]byte(challengePrefix), taskHash[:], slash(), []byte(challengeID))
}

func verifyCandidatePrefixForTask(taskHash StoredHash) []byte {
	return join([]byte(verifyCandidatePrefix), taskHash[:], slash())
}

func deliveryPrefixForTask(taskHash StoredHash) []byte {
	return join([]byte(deliveryPrefix), taskHash[:], slash())
}

func challengePrefixForTask(taskHash StoredHash) []byte {
	return join([]byte(challengePrefix), taskHash[:], slash())
}

func slash() []byte { return []byte("/") }

func join(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
