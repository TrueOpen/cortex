# Nexus Ingress Bindings

Generated from the TrueOpen/wire v0.5.1 release descriptor, commit
`1c9db9b8d45baf28f2963357a963b1403cb4886c`. See `proto/CHAIN_BINDINGS.md` for
the checksum, tools and reproduction instructions.

Task receipts are imported from the same canonical `task.v1` graph used by
the Bus and chain clients. Upload stores objects; `FinalizeTaskResult` and
`FinalizeVerifierEvidence` establish readiness and produce storage confirmations.
