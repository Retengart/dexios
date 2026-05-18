## Installing

Dexios currently requires Rust `1.88` or newer when building from source.

The recommended Cargo install command is:

```bash
cargo install dexios --locked
```

Prebuilt binaries are also published on the GitHub releases page.

### Linux and FreeBSD

Install a C toolchain before building. In practice, `gcc` is required by the current dependency set.

```bash
cargo install dexios --locked
```

### Windows

Dexios can be installed with Cargo on Windows as well:

```bash
cargo install dexios --locked
```

### Android

Dexios can be built in Termux. The project has historically been tested on Android through Termux, but you should still treat mobile support as more environment-sensitive than desktop builds.

```bash
AR=llvm-ar cargo install dexios --locked
```

## Building the Workspace

From the repository root:

```bash
cargo check --workspace --all-targets --release
cargo build --release
cargo test --workspace --all-features --release --verbose
```

## Maintainer Verification Gate

For safety-sensitive maintenance work, `book/src/Safety-Contract.md` is the
authoritative gate. Run the focused invariant checks for the area being changed,
then run the broad gate:

```bash
bash scripts/verify_phase_gate.sh
```

Before running the Cargo and mdBook command set, the script verifies the
no-unsafe crate-root check for `dexios/src/main.rs`, `dexios-core/src/lib.rs`,
and `dexios-domain/src/lib.rs`.

The command set is:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --no-deps
cargo test --workspace --all-features --release --verbose
cargo audit --deny warnings
cargo deny check
cargo build -p dexios --profile release-lto
bash scripts/verify_cli_surface.sh
mdbook build
git diff --exit-code -- docs
bash scripts/verify_repo_hygiene.sh
git diff --check
```

`mdbook build` writes the generated documentation site to `docs/` because
`book.toml` sets `build-dir = "docs"`.

The gate checks for required tools before running the long workspace commands.
Missing `cargo-audit`, `cargo-deny`, or `mdbook` fails with an install hint:

```bash
cargo install cargo-audit --locked --version 0.22.1
cargo install cargo-deny --locked --version 0.19.6
cargo install mdbook --locked
```

The gate does not auto-install tools or otherwise mutate the maintainer
environment.

`scripts/measure_performance_gate.sh` is a focused release gate for KDF,
stream, archive, and temp-space changes. It is not part of the default
maintainer gate.

## Release Evidence Manifest

Release candidates can record the local evidence used for a build:

```bash
cargo build -p dexios --profile release-lto
bash scripts/generate_release_manifest.sh \
  --output target/release-evidence/release-manifest.md \
  --asset target/release-lto/dexios
```

For release use, run the manifest command from a clean tracked working tree.
Untracked local files are ignored by the dirty check. `--tag <tag>` requires the
tag to point at the current commit. `--allow-dirty` is only for local dry runs
where the manifest must explicitly record that tracked changes were present.

The manifest records commit and tag status, tracked dirty state, `Cargo.lock`
SHA256, `cargo metadata --format-version=1 --locked` evidence, tool versions,
verification commands, and asset SHA256 hashes. That evidence is intentionally
narrow: it does not claim bit-for-bit reproducibility, signing trust, SBOM
completeness, SBOM protection, supply-chain prevention, or runtime safety beyond
the checks that were actually run. Future SBOM, signing, attestation, or
reproducibility work needs its own trust model and verification command before
public claims are made.

The CLI binary is produced at:

```text
target/release/dexios
```

## Building Notes

- Linux and FreeBSD builds require `gcc`.
- The workspace currently uses Rust edition `2024`.
- The workspace MSRV is `1.88`.
- Release workflows also use a dedicated `release-lto` profile for shipping artifacts.

## Precompiled Binaries

The releases page contains CI-built binaries. You should still verify any published hashes before trusting a downloaded artifact.
