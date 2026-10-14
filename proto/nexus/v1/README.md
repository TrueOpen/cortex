# Nexus Ingress Bindings

Generated from the TrueOpen/wire v0.5.0 release descriptor, commit
`ebeeb84f640c035d7761ac818ccf4ab79ae254d2`. See `proto/CHAIN_BINDINGS.md` for
the checksum, tools and reproduction instructions.

Task receipts are imported from the same canonical `task.v1` graph used by
the Bus and chain clients. Upload stores objects; `FinalizeTaskResult` and
`FinalizeVerifierEvidence` establish readiness and produce storage confirmations.
