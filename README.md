<p align="center">
  <img src="https://github.com/brxken128/dexios/raw/master/assets/long-logo.png" width="320" />
</p>

[![Dexios Tests](https://img.shields.io/github/actions/workflow/status/brxken128/dexios/dexios-tests.yml?branch=master&label=tests&style=flat-square)](https://github.com/brxken128/dexios/actions/workflows/dexios-tests.yml)
[![Dexios Crate](https://img.shields.io/crates/v/dexios.svg?style=flat-square)](https://lib.rs/crates/dexios)
[![BSD-2-Clause](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg?style=flat-square)](https://opensource.org/licenses/BSD-2-Clause)

## Dexios

Dexios is a Rust command-line file encryption utility built around a small, versioned file format and modern authenticated encryption.

Current defaults for new encryption:

- `XChaCha20-Poly1305`
- `BLAKE3-Balloon` as the only normal KDF for new V1 writes
- V1 headers
- LE31 stream encryption

Current V1 stream behavior:

- normal encryption and decryption go through the typed `V1PayloadStream`
  boundary
- payload authentication uses header-derived AAD from the V1 header
- exact-block plaintext emits an authenticated empty final block
- plaintext written during failed decryption is uncommitted scratch until final
  authentication succeeds

The workspace is split into:

- `dexios/` for the CLI
- `dexios-core/` for cryptographic primitives and header handling
- `dexios-domain/` for higher-level workflows such as pack/unpack and key operations
- `dexios-gui/` for an experimental GUI crate

## Installation

Dexios currently requires Rust `1.88` or newer.

```bash
cargo install dexios --locked
```

Prebuilt binaries are also published on the releases page.

## Development

```bash
cargo check --workspace --all-targets --release
cargo build --workspace
cargo test --workspace --all-features --release --verbose
```

## Documentation

The mdBook source for the project documentation lives in `book/src/`.

- generated site output lives in `docs/`
- crate API docs are published separately on docs.rs
- the whitepaper-style format reference lives in `spec/dexios-paper.typ`

For user-facing and technical docs, see:

- [Dexios CLI notes](dexios/README.md)
- [Dexios-Core](dexios-core/README.md)
- [Dexios-Domain](dexios-domain/README.md)
- [Published documentation site](https://brxken128.github.io/dexios/)

## Notes

- New V1 output does not expose user-configurable KDF parameters or an
  alternate KDF selector.
- Historical V1 files may contain the unsupported Argon2id keyslot tag `[0xDF, 0x02]`;
  Dexios recognizes that tag as unsupported historical metadata rather than
  using it for new writes.
- delete-after-success flags are available for `encrypt`, `decrypt`, `pack`, and `unpack`
- the supported file format is V1-only
- legacy Dexios formats are intentionally unsupported after the Phase 2 refactor
