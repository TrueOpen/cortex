# testassign

Publish one diagnostic `WorkerAssignmentNotifyV1` on the devnet Nexus bus using
the payload and bus envelope of the pinned wire release. The envelope is unsigned, so the
receiving node must use `nexus.envelope_auth_mode: trusted_nats_dev`.

```sh
go run ./scripts/testassign \
  -nats-url "$NEXUS_NATS_URL" \
  -chain-id trueopen-devnet-1 \
  -task-id "$TASK_ID" \
  -task-hash "$ACCEPTED_TASK_HASH" \
  -winner "$WORKER_OPERATOR" \
  -finalized-height 123456 \
  -deadline 123556 \
  -builder "$BUILDER_OPERATOR" \
  -authorization-nonce 4
```

Both hashes must be canonical 32-byte lowercase hex. `-task-hash` is the accepted
task hash from Keeper; a BuilderSet hash is not a substitute. The finalized and
inference deadline heights must match Keeper state, with the deadline after
finalization. The payload contains no session ID, payload CID, or BuilderSet
reference.

The receiving Worker checks task identity, winner, and assignment heights
against the authoritative Keeper snapshot. Publishing this notification cannot
create an on-chain assignment or make an unassigned node execute a task. Check
the task ID in the node logs to observe acceptance or refusal.

`-chain-id` must match the receiving node. `-ttl` controls the envelope lifetime
and must fit the node's configured maximum. The tool flushes the NATS publish
before exiting and redacts NATS URL credentials from reported errors.

Exit codes: `2` for invalid flags, `1` for encoding or transport failure, and `0`
after publishing and flushing the notification.
