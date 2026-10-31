# Nexus Ingress Bindings

Generated from the TrueOpen/wire descriptor of commit
`916e3936355cb787f6e82509619f55c6b5aad7e2` (the Phase 1 candidate contract). See `proto/CHAIN_BINDINGS.md` for
the checksum, tools and reproduction instructions.

Task receipts are imported from the same canonical `task.v1` graph used by
the chain clients. Upload stores objects; `FinalizeTaskResult` and
`FinalizeVerifierEvidence` establish readiness and produce storage confirmations.
