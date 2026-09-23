package identity

import (
	"fmt"
	"strings"

	"github.com/TrueOpen/cortex/internal/codec"
)

type SignedEnvelope struct {
	Domain                string
	ChainID               string
	SessionID             string
	OrderSequence         uint64
	OrderDigest           codec.Hash
	TaskID                codec.Hash
	Role                  string
	MessageType           string
	MessageVersion        string
	ValidFromHeight       uint64
	ValidUntilHeight      uint64
	SourceSnapshotHeight  uint64
	SignerSequenceOrNonce string
	CanonicalMessageHash  codec.Hash
	SignerAddress         string
	Signature             []byte
}

func (e SignedEnvelope) Validate() error {
	if err := e.validateSigningMaterial(); err != nil {
		return err
	}
	if len(e.Signature) != 64 {
		return fmt.Errorf("signature must be 64 bytes")
	}
	allZero := true
	for _, value := range e.Signature {
		if value != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("signature must not be zero")
	}
	return nil
}

func (e SignedEnvelope) validateSigningMaterial() error {
	if strings.TrimSpace(e.Domain) == "" {
		return fmt.Errorf("domain is required")
	}
	if strings.TrimSpace(e.ChainID) == "" {
		return fmt.Errorf("chain_id is required")
	}
	if strings.TrimSpace(e.SessionID) == "" {
		return fmt.Errorf("session_id is required")
	}
	if e.OrderDigest == (codec.Hash{}) {
		return fmt.Errorf("order_digest is required")
	}
	if e.TaskID == (codec.Hash{}) {
		return fmt.Errorf("task_id is required")
	}
	if e.TaskID != TaskID(e.SessionID, e.OrderSequence) {
		return fmt.Errorf("task_id does not match session_id and order_sequence")
	}
	if strings.TrimSpace(e.Role) == "" {
		return fmt.Errorf("role is required")
	}
	if strings.TrimSpace(e.MessageType) == "" {
		return fmt.Errorf("message_type is required")
	}
	if strings.TrimSpace(e.MessageVersion) == "" {
		return fmt.Errorf("message_version is required")
	}
	if e.ValidUntilHeight == 0 {
		return fmt.Errorf("valid_until_height is required")
	}
	if e.ValidFromHeight > e.ValidUntilHeight {
		return fmt.Errorf("valid height window is inconsistent")
	}
	if e.SourceSnapshotHeight == 0 {
		return fmt.Errorf("source_snapshot_height is required")
	}
	if strings.TrimSpace(e.SignerSequenceOrNonce) == "" {
		return fmt.Errorf("signer_sequence_or_nonce is required")
	}
	if e.CanonicalMessageHash == (codec.Hash{}) {
		return fmt.Errorf("canonical_message_hash is required")
	}
	if strings.TrimSpace(e.SignerAddress) == "" {
		return fmt.Errorf("signer_address is required")
	}
	return nil
}

func (e SignedEnvelope) SigningHash() (codec.Hash, error) {
	if err := e.validateSigningMaterial(); err != nil {
		return codec.Hash{}, err
	}
	return codec.HashWithDomain(
		"TRUEOPEN_SIGNED_ENVELOPE_V2",
		[]byte(e.Domain),
		[]byte(e.ChainID),
		[]byte(e.SessionID),
		codec.Uint64Bytes(e.OrderSequence),
		e.OrderDigest[:],
		e.TaskID[:],
		[]byte(e.Role),
		[]byte(e.MessageType),
		[]byte(e.MessageVersion),
		codec.Uint64Bytes(e.ValidFromHeight),
		codec.Uint64Bytes(e.ValidUntilHeight),
		codec.Uint64Bytes(e.SourceSnapshotHeight),
		[]byte(e.SignerSequenceOrNonce),
		e.CanonicalMessageHash[:],
		[]byte(e.SignerAddress),
	), nil
}
