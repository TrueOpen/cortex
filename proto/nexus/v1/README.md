# Nexus Ingress Bindings

Generated from the TrueOpen/wire descriptor of commit
`b30fba873bd5b7553947f0ad32731fdd6e6ae93b` (the Phase 1 contract the devnet Node and Builder run). See `proto/CHAIN_BINDINGS.md` for
the checksum, tools and reproduction instructions.

Task receipts are imported from the same canonical `task.v1` graph used by
the chain clients. Upload stores objects; `FinalizeTaskResult` and
`FinalizeVerifierEvidence` establish readiness and produce storage confirmations.
