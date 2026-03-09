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
