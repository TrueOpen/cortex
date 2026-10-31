package daemon

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/sha3"

	"github.com/TrueOpen/cortex/internal/nodewire"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/layout"
)

// Test-only reads of the dispatch rows layout keeps; production never asks.

func hasRawKey(ctx context.Context, st *store.Store, key []byte) (bool, error) {
	_, err := st.GetRaw(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// hasWorkerLease reports whether ticket holds a pre-record lease.
func hasWorkerLease(ctx context.Context, st *store.Store, ticket layout.StoredHash) (bool, error) {
	return hasRawKey(ctx, st, layout.WorkerTicketLeaseKey(ticket))
}

// hasWorkerTaskLease reports whether taskID holds a post-record lease.
func hasWorkerTaskLease(ctx context.Context, st *store.Store, taskID layout.StoredHash) (bool, error) {
	return hasRawKey(ctx, st, layout.WorkerTaskLeaseKey(taskID))
}

// dispatchInputChunks returns ticket's staged input chunks by index.
func dispatchInputChunks(ctx context.Context, st *store.Store, ticket layout.StoredHash) (map[uint32][]byte, error) {
	k := layout.DispatchInputChunkKey(ticket, 0)
	prefix := k[:len(k)-4]
	out := map[uint32][]byte{}
	err := st.ScanPrefix(ctx, prefix, func(key, value []byte) error {
		out[binary.BigEndian.Uint32(key[len(prefix):])] = bytes.Clone(value)
		return nil
	})
	return out, err
}

// openDispatches returns the records whose input is not committed yet.
func openDispatches(ctx context.Context, st *store.Store) ([]layout.DispatchRecord, error) {
	k := layout.DispatchOpenKey(layout.StoredHash{})
	prefix := k[:len(k)-len(layout.StoredHash{})]
	var tickets []layout.StoredHash
	if err := st.ScanPrefix(ctx, prefix, func(key, _ []byte) error {
		var h layout.StoredHash
		copy(h[:], key[len(prefix):])
		tickets = append(tickets, h)
		return nil
	}); err != nil {
		return nil, err
	}
	out := make([]layout.DispatchRecord, 0, len(tickets))
	for _, t := range tickets {
		rec, err := layout.GetDispatchRecord(ctx, st, t)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}

// evmAccountAddress is the Bech32 account of an EVM-style secp256k1 key: the
// last 20 bytes of keccak256 over the 64-byte uncompressed point, which is
// what nodewire.SignedOrderSigner recovers.
func evmAccountAddress(hrp string, uncompressedPubkey []byte) (string, error) {
	if len(uncompressedPubkey) != 65 || uncompressedPubkey[0] != 0x04 {
		return "", errors.New("EVM account derivation needs a 65-byte uncompressed secp256k1 point")
	}
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(uncompressedPubkey[1:])
	return nodewire.CanonicalOperatorAddressString(hrp, h.Sum(nil)[12:])
}
