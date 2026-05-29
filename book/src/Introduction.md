# Welcome!

Welcome to the Dexios Book. This book is the user-facing and technical guide for the current `dexios` workspace.

## What is Dexios?

Dexios is a command-line file encryption utility written in Rust. It is aimed at encrypting files and packed directories for storage or transfer, especially when you want modern authenticated encryption without a large feature surface.

The current workspace is split into four crates:

- `dexios`: the CLI application
- `dexios-core`: the cryptographic primitives, header format, and protected memory wrapper
- `dexios-domain`: the higher-level workflows used by the CLI
- `dexios-gui`: an experimental GUI crate

For normal encryption, Dexios writes V1 headers and uses one suite:
`XChaCha20-Poly1305` with LE31 stream encryption. The normal KDF for new V1
writes is Argon2id only (256 MiB / t=4 / p=4). The historical unsupported
Argon2id keyslot tag remains recognized as unsupported historical metadata so
old headers can fail with a specific diagnosis.

## Security Notices

The RustCrypto `chacha20poly1305` implementation used by Dexios is based on audited upstream crates. Dexios itself does not claim a full-project external audit.

Dexios uses authenticated encryption and authenticates header data through AEAD AAD. Integrity of encrypted payloads does not depend on the optional checksum output.

For V1 payloads, the stream layer uses typed header-derived AAD. Decryption may
write plaintext bytes before it has seen the final block; those bytes are
uncommitted scratch until final authentication succeeds.

The current product surface does not offer secure-erase behavior. Instead, selected workflows can delete their source inputs after successful completion.

## The Defaults

Running:

```bash
dexios encrypt input.txt output.enc
```

uses the following defaults:

- `XChaCha20-Poly1305`
- `Argon2id` password hashing with frozen canonical parameters (256 MiB / t=4 / p=4)
- V1 headers
- stream encryption with 1 MiB blocks
- an authenticated final block, including an empty final marker for exact-block plaintext
- protected in-memory handling of secret material
- an embedded header unless `--header` is specified

## Platform Notes

Dexios targets Linux, macOS, Windows, FreeBSD, and Android via Termux. The current repository automation tests Linux and macOS most directly, while release workflows also build shipping binaries for Windows.

## Privacy

Dexios is a local tool. It does not implement telemetry, remote processing, or cloud integration.

## Thank You

Dexios relies heavily on the RustCrypto ecosystem and related libraries. If you are reviewing the implementation, most of the security-sensitive behavior lives in `dexios-core` and `dexios-domain`.
