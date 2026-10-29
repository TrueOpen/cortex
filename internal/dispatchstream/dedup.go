package dispatchstream

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/TrueOpen/cortex/internal/dispatchwire"
	"github.com/TrueOpen/cortex/internal/store"
	"github.com/TrueOpen/cortex/internal/store/once"
)

// DefaultDedupRetention bounds how long a delivered message's claim is kept.
// A Builder only replays a message it has not seen acked, and an ack is lost
// only with the connection it was on, so a replay follows within one
// reconnect backoff; a day is orders of magnitude past that while keeping
// the claim set bounded by one day of inbound traffic per Builder. Business
// state machines downstream must still treat a message as a hint (the chain
// is authoritative), so a replay arriving after retention is harmless.
const DefaultDedupRetention = 24 * time.Hour

// dedupPruneLimit caps one prune pass; prune runs on every binding.
const dedupPruneLimit = 4096

// dedup records which Builder business messages reached the Handler.
//
// Cursors restart at 1 on every binding and the Builder replays unacked
// messages under new cursors, so cursor tracking alone cannot stop a message
// whose ack was lost from being handled twice. The key is (builder operator,
// frame variant, message digest): the digest excludes the signature, so a
// re-signed copy of the same content is still the same message.
type dedup struct {
	once      *once.Store
	builder   string
	retention time.Duration
}

func newDedup(st *store.Store, builder string, retention time.Duration) *dedup {
	if retention <= 0 {
		retention = DefaultDedupRetention
	}
	return &dedup{once: once.New(st), builder: builder, retention: retention}
}

// messageDigest is dispatchwire.Digest for signed messages. Builder-sent
// containers without their own signature (DispatchOfferV1,
// HandraiseRootNoticeV1) have no signing domain; they are identified by a
// domain-separated hash of their deterministic encoding, which is canonical
// for frames that already passed wire's strict decoder.
func messageDigest(msg proto.Message) ([32]byte, error) {
	fields := msg.ProtoReflect().Descriptor().Fields()
	if fields.ByName("builder_service_signature") != nil || fields.ByName("service_signature") != nil {
		return dispatchwire.Digest(msg)
	}
	raw, err := dispatchwire.Raw(msg)
	if err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	h.Write([]byte("TRUEOPEN_CORTEX_DISPATCHSTREAM_DEDUP_V1\x00"))
	h.Write([]byte(dispatchwire.Name(msg)))
	h.Write([]byte{0})
	h.Write(raw)
	var d [32]byte
	copy(d[:], h.Sum(nil))
	return d, nil
}

func (d *dedup) key(v variant, msg proto.Message) (string, error) {
	digest, err := messageDigest(msg)
	if err != nil {
		return "", fmt.Errorf("dispatchstream: dedup digest: %w", err)
	}
	return fmt.Sprintf("dispatchstream/%s/%d/%s", d.builder, v, hex.EncodeToString(digest[:])), nil
}

// claim durably records the message as delivered. first is false when an
// unexpired claim already exists. The once store compares expiries against
// the wall clock, so retention is wall-clock time.
func (d *dedup) claim(ctx context.Context, key string) (bool, error) {
	return d.once.Claim(ctx, key, time.Now().Add(d.retention))
}

// release forgets a claim so a retryable failure can be redelivered.
func (d *dedup) release(ctx context.Context, key string) error {
	return d.once.Release(ctx, key)
}

func (d *dedup) prune(ctx context.Context) error {
	_, err := d.once.Prune(ctx, time.Now(), dedupPruneLimit)
	return err
}
