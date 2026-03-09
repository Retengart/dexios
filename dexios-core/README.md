<p align="center">
  <img src="https://github.com/brxken128/dexios/raw/master/assets/long-logo.png" width="320" />
</p>

## Dexios-Core

Dexios-Core is the reusable cryptographic and format crate behind Dexios.

It provides:

- versioned header parsing and serialization
- stream and memory-mode cipher helpers
- key derivation helpers
- protected secret handling through `Protected<>`

The current latest writable format is V5.

## Security Notes

Dexios-Core uses modern AEAD-backed encryption primitives from the Rust ecosystem. The current CLI writes new files with `XChaCha20-Poly1305` by default and optionally `AES-256-GCM`.

`Deoxys-II-256` is still represented in the core format for compatibility with older files, but the current CLI does not expose it for new encryption.

## Documentation

- crate API docs: <https://docs.rs/dexios-core/latest/dexios_core/>
- project book: <https://brxken128.github.io/dexios/>
