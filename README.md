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
- `Argon2id` as the only normal KDF for new V1 writes
- 512-byte canonical V1 headers
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

Archive workflows:

- `pack` writes a Dexios-owned manifest-first archive payload with a `DXAR`
  manifest and ordered `DXBF` body frames.
- `unpack` validates archive paths, collisions, selected body frames, and output
  targets before committing extracted files.
- ZIP bytes and ZIP crate types are not canonical V1 archive format surface.
- `pack --delete-source` and `unpack --delete-input` are ordinary delete-after-success cleanup flags that run only after commit and requested hash success.

## Installation

Dexios currently requires Rust `1.88` or newer.

```bash
cargo install dexios --locked
```

Prebuilt binaries are also published on the releases page.

### Verifying a release download

Release binaries are built with `cargo auditable`, so the dependency tree is
embedded in each binary. The release pipeline signs every artifact with
keyless Sigstore cosign and attaches a build-provenance attestation.

**Cosign verification** (authenticity — strict, pins the producing workflow):

```bash
cosign verify-blob dexios-vX.Y.Z-linux-amd64 \
  --bundle dexios-vX.Y.Z-linux-amd64.sigstore.json \
  --certificate-identity 'https://github.com/brxken128/dexios/.github/workflows/release.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

**GitHub provenance** (strict):

```bash
gh attestation verify dexios-vX.Y.Z-linux-amd64 \
  --repo brxken128/dexios \
  --signer-workflow brxken128/dexios/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z
```

See [SIGNING.md](SIGNING.md) for full verification details.

Read the dependency list embedded in a binary with `rust-audit-info` (from the
`rust-audit-info` crate, installable via `cargo install rust-audit-info`):

```bash
rust-audit-info dexios-vX.Y.Z-linux-amd64
```

Each release also ships a CycloneDX SBOM per platform, named
`dexios-vX.Y.Z-<platform>.cdx.json`, alongside the binaries. Each artifact has
a `.sigstore.json` cosign bundle.

## Development

```bash
cargo check --workspace --all-targets --release
cargo build --workspace
cargo test --workspace --all-features --release --verbose
```

Safety-sensitive changes use the Maintainer Verification Gate in
`book/src/Safety-Contract.md`. That contract is the authority for required focused
checks, broad workspace checks, dependency/security checks, documentation
checks, and release-note triggers.

## Documentation

The mdBook source for the project documentation lives in `book/src/`.

- generated site output is not committed; `mdbook build --dest-dir target/mdbook`
  writes it under the ignored `target/` tree
- crate API docs are published separately on docs.rs
- the whitepaper-style format source lives in `spec/dexios-paper.typ`
- the current PDF `spec/dexios-paper.pdf` is generated from that Typst source
  and checked by the maintainer gate with
  `typst compile --creation-timestamp 0 spec/dexios-paper.typ spec/dexios-paper.pdf`
- `spec/specification-v1.pdf` is historical comparison input only, not current release-critical authority
- the Maintainer Verification Gate is tracked in `book/src/Safety-Contract.md`

Release-facing metadata is source-backed:

- release manifest wording lives in `scripts/generate_release_manifest.sh`
- release workflow asset-name construction lives in `.github/workflows/release.yml`
- source-backed docs/spec locations are `book/src/` and `spec/dexios-paper.typ`
- manifest asset entries record supplied basenames and SHA256 values only, and
  this wording does not claim a complete platform asset set

For user-facing and technical docs, see:

- [Dexios CLI notes](dexios/README.md)
- [Dexios-Core](dexios-core/README.md)
- [Dexios-Domain](dexios-domain/README.md)
- [Published documentation site](https://brxken128.github.io/dexios/)

## Notes

- New V1 output does not expose user-configurable KDF parameters or an
  alternate KDF selector.
- Historical V1 files may contain the historical Argon2id tag `[0xDF, 0x02]`;
  Dexios recognizes that tag as unsupported historical metadata rather than
  using it for new writes.
- delete-after-success flags are available for `encrypt`, `decrypt`, `pack`, and `unpack`
- the supported file format is V1-only
- legacy Dexios formats are intentionally unsupported after the Phase 2 refactor
