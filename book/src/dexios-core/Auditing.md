## Auditing

Dexios does not currently document a full-project external audit for the current workspace.

The practical audit surface for Dexios lives in:

- `dexios-core/src/header.rs`
- `dexios-core/src/key.rs`
- `dexios-core/src/stream.rs`
- `dexios-core/src/cipher.rs`
- `dexios-core/src/primitives.rs`
- `dexios-core/src/protected.rs`

If you are auditing end-to-end file workflows rather than only the primitives, also review:

- `dexios-domain/src/encrypt.rs`
- `dexios-domain/src/decrypt.rs`
- `dexios-domain/src/pack.rs`
- `dexios-domain/src/unpack.rs`
- `dexios-domain/src/storage.rs`

The repository currently relies heavily on Rust's type system, explicit error handling, compatibility tests, and CI checks, but that is not a substitute for a dedicated independent audit.
