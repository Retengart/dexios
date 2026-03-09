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
- `BLAKE3-Balloon`
- V5 headers
- stream-mode encryption

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

- `AES-256-GCM` is available via `--aes`.
- `argon2id` is available for new output via `--argon`.
- `Deoxys-II-256` remains part of format compatibility in `dexios-core`, but the current CLI does not offer it for new encryption.
