package nodewire_test

import (
	"testing"

	"github.com/TrueOpen/wire/dispatch"

	"github.com/TrueOpen/cortex/internal/codec"
	"github.com/TrueOpen/cortex/internal/nodewire"
)

func TestPlaintextOutputStreamHeaderDigestIsWireOutputTestFraming(t *testing.T) {
	v := prereleaseGolden(t, "task/output_stream_header_v1.json", "output_stream_header_v2_plaintext")
	chain := fieldString(t, v, 0, "chain_id")
	var task, ticket [32]byte
	copy(task[:], fieldBytes(t, v, 1, "task_hash"))
	copy(ticket[:], fieldBytes(t, v, 2, "dispatch_ticket_hash"))
	got, err := nodewire.PlaintextOutputStreamHeaderDigest(chain, task, ticket)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != v.DigestHex {
		t.Fatalf("header digest = %s, published %s", got, v.DigestHex)
	}
	zero := make([]byte, 32)
	// wire dispatch/output_test.go:39-49, field for field. proto task_hash is a
	// string on the header frame; the signature is over raw32.
	want := dispatch.HashFields(nodewire.DomainOutputStreamHeaderV1, []byte(chain), task[:], ticket[:], dispatch.Uint32(1), nil, zero, zero)
	if got != codec.Hash(want) {
		t.Fatal("header digest is not wire's HashFields projection")
	}
	if _, err := nodewire.PlaintextOutputStreamHeaderDigest(chain, task, [32]byte{}); err == nil {
		t.Fatal("ZERO32 is the retired S0 placeholder, never an accepted ticket")
	}
}

func TestOutputChunkAndFinDigestsAreWireDispatch(t *testing.T) {
	task, ticket, root := [32]byte{1}, [32]byte{2}, [32]byte{3}
	chunk, err := nodewire.OutputChunkSigningDigest("chain", task[:], ticket[:], 7, root[:])
	if err != nil || chunk != codec.Hash(dispatch.OutputChunkDigest("chain", task, ticket, 7, root)) {
		t.Fatalf("chunk digest = %s, %v", chunk, err)
	}
	fin, err := nodewire.OutputFinSigningDigest("chain", task[:], ticket[:], 7, root[:], nodewire.FinishReasonV1EosToken)
	want, werr := dispatch.OutputFinDigest("chain", task, ticket, 7, root, uint32(nodewire.FinishReasonV1EosToken))
	if err != nil || werr != nil || fin != codec.Hash(want) {
		t.Fatalf("fin digest = %s, %v / %v", fin, err, werr)
	}
	if _, err := nodewire.OutputChunkSigningDigest("chain", task[:], ticket[:31], 7, root[:]); err == nil {
		t.Fatal("a short ticket is refused before it reaches wire")
	}
}
