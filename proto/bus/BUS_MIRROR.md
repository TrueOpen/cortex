# Bus Bindings

`proto/bus/v1` is generated from the pinned TrueOpen/wire v0.2.0 release
descriptor. Bus payloads import the same `task.v1`,
`shared.v1` and `hub.v1` Go types used by chain and Nexus clients.
There is no separate pruned source tree or duplicate Task registry.

See `proto/CHAIN_BINDINGS.md` for provenance and regeneration. The package tests
pin payload fields and prove Bus/Nexus share the canonical Task descriptor.
`github.com/TrueOpen/wire/bus` defines envelope signing and payload hashing;
`internal/nodewire` defines the chain-bound material digests.
