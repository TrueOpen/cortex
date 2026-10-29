// Package dispatchstream runs the Cortex end of one nexus.v1 DispatchStream:
// binding, per-direction business cursors, cumulative acks, keepalive and
// reconnect. Business handling lives behind Handler.
//
// Inbound delivery is at least once: each Builder business message is
// strictly decoded, signature-checked and durably recorded as received before
// the Handler runs, and recorded done (then acked) after it finishes. Only a
// done record suppresses a replay, so a crash in between, or a replay after
// the dedup retention, reaches the Handler again; Handlers must be idempotent.
//
// Outbound business messages are persisted before they are first sent and are
// replayed with their original bytes on every new binding until acked or
// expired.
package dispatchstream
