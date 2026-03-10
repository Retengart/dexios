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

The current normal writable format is V1.

## Security Notes

Dexios-Core uses modern AEAD-backed encryption primitives from the Rust ecosystem. The normal write path is built around one suite: `XChaCha20-Poly1305` with LE31 stream encryption.

Legacy parsing and compatibility helpers still exist internally under explicit legacy boundaries, but they are no longer the normal product surface.

## Documentation

- crate API docs: <https://docs.rs/dexios-core/latest/dexios_core/>
- project book: <https://brxken128.github.io/dexios/>
