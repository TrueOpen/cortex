# Nexus Ingress Bindings

Generated from the TrueOpen/wire v0.2.0 release descriptor, commit
`5d59051ebbd54727158d12583fb7241db402a7ca`. See `proto/CHAIN_BINDINGS.md` for
the checksum, tools and reproduction instructions.

Task receipts are imported from the same canonical `task.v1` graph used by
the Bus and chain clients. Upload stores objects; `FinalizeTaskResult` and
`FinalizeVerifierEvidence` establish readiness and produce storage confirmations.
