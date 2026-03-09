# Dexios-Core

`dexios-core` is the reusable cryptographic and format layer behind Dexios.

It is responsible for:

- header parsing and serialization
- password hashing and key derivation
- stream and memory-mode cipher helpers
- protected secret handling through `Protected<>`

The current CLI uses `dexios-core` primarily through `dexios-domain`, but the crate can also be embedded directly in other Rust applications.

The current latest writable header format is **V5**.
