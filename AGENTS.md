# Repository Guidelines

## Project Structure & Module Organization
This repository is a Cargo workspace rooted at `Cargo.toml` with four members:

- `dexios/`: the CLI application. Argument parsing lives in `src/cli.rs`, subcommands live under `src/subcommands/`, and shared process helpers live under `src/global/`.
- `dexios-core/`: low-level cryptographic primitives, header handling, protected buffers, and stream logic. Integration tests live in `dexios-core/tests/`.
- `dexios-domain/`: higher-level encryption, decryption, packing, unpacking, erasure, and storage workflows. Integration tests live in `dexios-domain/tests/`.
- `dexios-gui/`: GUI crate with a small `src/main.rs`; the crate exists but is still a work in progress.

Repository-level documentation and packaging assets live outside the crates:

- `book/src/` holds the mdBook source for the documentation site.
- `docs/` contains the generated documentation site assets.
- `assets/` contains branding and image assets.
- `spec/specification-v1.pdf` is the file format reference.
- `default.nix`, `flake.nix`, and `shell.nix` define the Nix workflows.

## Build, Test, and Development Commands
Run Cargo commands from the repository root so workspace settings and shared dependencies apply consistently.

- `cargo check --workspace --all-targets --release`: matches the stable CI compile check.
- `cargo check --workspace --all-targets`: matches the MSRV verification job.
- `cargo build --release`: builds the workspace and produces the CLI binary at `target/release/dexios`.
- `cargo run -p dexios -- --help`: inspect CLI behavior during development.
- `cargo test --workspace --all-features --release --verbose`: matches the main test workflow.
- `cargo clippy --workspace --all-targets --all-features --no-deps`: matches the lint workflow.
- `cargo fmt --all`: apply formatting.
- `cargo fmt --all --check`: verify formatting in CI-style mode.
- `nix-build . -A defaultPackage.x86_64-linux`: verify the legacy Nix package on Linux.

## Coding Style & Naming Conventions
The workspace inherits Rust edition `2024` and `rust-version = "1.88"` from `[workspace.package]`. Use default `rustfmt` output with 4-space indentation. Follow standard Rust naming: `snake_case` for modules, files, and functions; `PascalCase` for types and traits; `SCREAMING_SNAKE_CASE` for constants.

Keep security-critical code explicit and easy to audit. Prefer narrowly scoped helpers over clever abstractions in crypto, header, key, and erase paths. Add brief comments only where file-format compatibility, zeroization, or erase semantics would otherwise be unclear.

## Testing Guidelines
Add regression coverage in the crate that owns the behavior. Existing examples include `dexios-core/tests/key_derivation.rs`, `dexios-domain/tests/storage.rs`, and `dexios-domain/tests/unpack.rs`.

For CLI-facing changes, add or update tests where practical and run a manual smoke test with `cargo run -p dexios -- ...` against disposable data. For header, KDF, pack/unpack, or erase changes, add focused coverage for compatibility-sensitive paths and cross-crate flows. Before finishing substantive work, run the targeted tests you touched and then the workspace test and clippy commands above.

## Commit & Pull Request Guidelines
The active integration branch is `main`, and GitHub Actions run on pushes and pull requests targeting `main`. Recent commit subjects use short conventional prefixes such as `fix:`, `test:`, `build:`, and `ci:`; follow that style and keep each commit scoped to one logical change.

Pull requests should summarize user-visible impact, note any security or compatibility implications, and mention documentation updates when behavior changes. Include command output for CLI changes and screenshots only when GUI behavior changes.

Do not commit ad hoc planning artifacts from `docs/plans/`. Those files are local working notes, not mergeable project documentation.

## Security & Configuration Notes
Treat changes to headers, algorithms, KDF selection, pack/unpack behavior, and secure erase logic as compatibility-sensitive. Review `spec/specification-v1.pdf`, `book/src/`, and `SECURITY.md` before changing on-disk format behavior or cryptographic defaults.

Never commit real secrets, decrypted fixtures, or long-lived keys. Keep any manual test data disposable, and do not check generated artifacts from `target/` or ad hoc test output into the repository.
