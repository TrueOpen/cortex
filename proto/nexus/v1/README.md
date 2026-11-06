# Nexus Ingress Bindings

Generated from the TrueOpen/wire descriptor of commit
`e365a4850d5276508aa3ec5cee0307b4ce5e6590` (the Phase 1 contract the devnet Node and Builder run, plus the model support confirmation relay). See `proto/CHAIN_BINDINGS.md` for
the checksum, tools and reproduction instructions.

Task receipts are imported from the same canonical `task.v1` graph used by
the chain clients. Upload stores objects; `FinalizeTaskResult` and
`FinalizeVerifierEvidence` establish readiness and produce storage confirmations.
