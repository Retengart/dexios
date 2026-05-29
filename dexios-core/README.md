<p align="center">
  <img src="https://github.com/brxken128/dexios/raw/master/assets/long-logo.png" width="320" />
</p>

## Dexios-Core

Dexios-Core is the reusable cryptographic and format crate behind Dexios.

It provides:

- V1 header parsing and serialization
- single-suite XChaCha20-Poly1305 helpers
- Argon2id key derivation helpers for new V1 keyslots
- protected secret handling through `Protected<>`

The supported format is V1-only.

## KDF Contract

Normal V1 key derivation is Argon2id only. The frozen canonical parameters are
m_cost `262_144` KiB (256 MiB), t_cost `4` passes, p_cost `4` lanes, output
length `32` bytes, salt length `16` bytes, and Argon2 version `0x13`.

The V1 keyslot tag `[0xDF, 0x02]` is still recognized as an unsupported
historical Argon2id tag so old headers can be diagnosed explicitly. New core
construction paths do not emit that tag.

## Security Notes

Dexios-Core uses modern AEAD-backed encryption primitives from the Rust ecosystem. The supported path is built around one suite: `XChaCha20-Poly1305` with LE31 stream encryption.

The normal V1 payload API is the typed `V1PayloadStream` boundary. It derives
AAD from the V1 header, requires the final block marker, and treats plaintext
written before a decrypt error as uncommitted scratch until final authentication
succeeds. The deterministic stream matrix lives in
`dexios-core/tests/stream_v1.rs`.

Legacy Dexios formats are intentionally unsupported after the Phase 2 refactor.

## Documentation

- crate API docs: <https://docs.rs/dexios-core/latest/dexios_core/>
- project book: <https://brxken128.github.io/dexios/>
