# Nexus Ingress Bindings

Generated from the TrueOpen/wire v0.4.0 release descriptor, commit
`586ea8f2f1664b9a8fd625dfc8c6eb612a445a36`. See `proto/CHAIN_BINDINGS.md` for
the checksum, tools and reproduction instructions.

Task receipts are imported from the same canonical `task.v1` graph used by
the Bus and chain clients. Upload stores objects; `FinalizeTaskResult` and
`FinalizeVerifierEvidence` establish readiness and produce storage confirmations.
