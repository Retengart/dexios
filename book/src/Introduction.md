# Welcome!

Welcome to the Dexios Book. This book is the user-facing and technical guide for the current `dexios` workspace.

## What is Dexios?

Dexios is a command-line file encryption utility written in Rust. It is aimed at encrypting files and packed directories for storage or transfer, especially when you want modern authenticated encryption without a large feature surface.

The current workspace is split into four crates:

- `dexios`: the CLI application
- `dexios-core`: the cryptographic primitives, header format, and protected memory wrapper
- `dexios-domain`: the higher-level workflows used by the CLI
- `dexios-gui`: an experimental GUI crate

For new encryption, Dexios currently writes V5 headers and uses stream mode. The default encryption algorithm is `XChaCha20-Poly1305`, with `AES-256-GCM` available via `--aes`. The default password hashing algorithm for new files is `BLAKE3-Balloon`; `argon2id` can be selected with `--argon`.

## Security Notices

The RustCrypto `aes-gcm` and `chacha20poly1305` implementations used by Dexios are based on audited upstream crates. Dexios itself does not claim a full-project external audit.

`Deoxys-II-256` is still recognized by the format and supported for decrypting older files, but the current CLI does not offer it as a choice for new encryption.

Dexios uses authenticated encryption and authenticates header data through AEAD AAD. Integrity of encrypted payloads does not depend on the optional checksum output.

Secure erase support is best effort only. On flash storage and SSDs, wear leveling means no software tool can guarantee physical erasure of previous contents.

## The Defaults

Running:

```bash
dexios encrypt input.txt output.enc
```

uses the following defaults:

- `XChaCha20-Poly1305`
- `BLAKE3-Balloon` password hashing
- V5 headers
- stream encryption with 1 MiB blocks
- protected in-memory handling of secret material
- an embedded header unless `--header` is specified

## Platform Notes

Dexios targets Linux, macOS, Windows, FreeBSD, and Android via Termux. The current repository automation tests Linux and macOS most directly, while release workflows also build shipping binaries for Windows.

## Privacy

Dexios is a local tool. It does not implement telemetry, remote processing, or cloud integration.

## Thank You

Dexios relies heavily on the RustCrypto ecosystem and related libraries. If you are reviewing the implementation, most of the security-sensitive behavior lives in `dexios-core` and `dexios-domain`.
