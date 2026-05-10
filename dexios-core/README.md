<p align="center">
  <img src="https://github.com/brxken128/dexios/raw/master/assets/long-logo.png" width="320" />
</p>

## Dexios-Core

Dexios-Core is the reusable cryptographic and format crate behind Dexios.

It provides:

- V1 header parsing and serialization
- single-suite XChaCha20-Poly1305 helpers
- key derivation helpers
- protected secret handling through `Protected<>`

The supported format is V1-only.

## Security Notes

Dexios-Core uses modern AEAD-backed encryption primitives from the Rust ecosystem. The supported path is built around one suite: `XChaCha20-Poly1305` with LE31 stream encryption.

Legacy Dexios formats are intentionally unsupported after the Phase 2 refactor.

## Documentation

- crate API docs: <https://docs.rs/dexios-core/latest/dexios_core/>
- project book: <https://brxken128.github.io/dexios/>
