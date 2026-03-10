# Dexios-Core

`dexios-core` is the reusable cryptographic and format layer behind Dexios.

It is responsible for:

- V1 header parsing and serialization
- password hashing and key derivation
- single-suite stream and wrapping-key helpers
- protected secret handling through `Protected<>`

The current CLI uses `dexios-core` primarily through `dexios-domain`, but the crate can also be embedded directly in other Rust applications. The normal writable header format is **V1**.
