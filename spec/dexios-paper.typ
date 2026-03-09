#set page(paper: "a4", margin: 25mm)
#set par(justify: true)
#set heading(numbering: "1.1")

#align(center)[
  #text(size: 18pt, weight: "bold")[Dexios: A Format for Encrypting and Storing Sensitive Data]

  brxken128

  March 10, 2026
]

#v(1.5em)

*Abstract*

Dexios is an open-source file encryption tool written in Rust. Its current format combines versioned headers, authenticated encryption, memory-hard password hashing, and a compact layout designed for efficient streaming encryption and long-term compatibility.

= Introduction

Dexios is aimed at encrypting files and packed directory archives for storage or transfer. The project separates the user-facing CLI, the workflow layer, and the low-level cryptographic primitives into different crates so that the format-critical code remains explicit and auditable.

= Modes of Operation

This section describes the current Dexios workflows, including encryption, decryption, packing, unpacking, erasure, and hashing.

== Encryption

New encryption uses the LE31 stream object provided by the `aead` crate. Payloads are processed in `1 MiB` blocks.

For new files, Dexios:

- generates a random 32-byte master key,
- generates a stream/data nonce,
- generates one or more salts and wrapping nonces for keyslots,
- hashes the user-provided key material with the selected KDF,
- wraps the master key inside the header,
- serializes the header,
- encrypts the payload in stream mode.

The current CLI writes V5 headers and uses stream mode for new encryption. The first 32 bytes of a V5 header are authenticated as AAD with each encrypted block.

=== File-size Edge Cases

If the plaintext size is exactly divisible by the `1 MiB` block size, Dexios still emits a final authenticated "last block". This avoids ambiguity at the end of the stream and is part of the current stream-mode behavior.

=== Detached Mode

Dexios can store the header separately from the encrypted payload. In this mode, the header is written to another file and the ciphertext itself starts immediately with encrypted data.

Detached mode is useful when the user wants to keep the header under separate control, but it also means header restoration is generally unsupported unless the target file already contains enough zero bytes at the beginning to hold the header.

== Decryption

Decryption reads and deserializes the header first.

For V5 files, Dexios iterates through the available keyslots and attempts to derive a wrapping key from the supplied key material and the keyslot salt. If one of the derived keys successfully decrypts the wrapped master key, that master key is used to decrypt the payload stream.

Legacy headers remain supported for decryption. Older versions use earlier header layouts and earlier KDF parameter versions, but they are still parsed by the current code.

== Packing

Packing is an extension of encryption.

The current implementation accepts one or more input directories, derives unique archive roots for them, creates a temporary `zip` archive, and then encrypts that archive with the normal Dexios file workflow. Recursive traversal is the default behavior; the `--recursive` flag is retained for compatibility.

ZSTD compression is available but must be explicitly enabled.

The packed payload is still just an encrypted `zip` archive. Users may decrypt it normally and handle the zip archive externally if they want.

Current implementation note: the temporary plaintext archive created during `pack` is cleaned up with two random overwrite passes followed by a zero pass.

== Unpacking

Unpacking is an extension of decryption.

The source file is first decrypted into a temporary `zip` archive. Dexios then normalizes archive paths, rejects traversal attempts, rejects duplicate output paths after normalization, rejects unsafe output symlink escapes, and extracts the archive into the chosen directory.

Current implementation note: the temporary plaintext archive created during `unpack` is cleaned up with one random overwrite pass followed by a zero pass.

== Erasing

Erasure performs `n` random overwrite passes followed by a final zero pass before the file is removed.

The current user-facing default is `1` random pass. More passes may be requested explicitly.

This is a best-effort approach only. It must not be treated as guaranteed physical erasure on SSDs or other flash-backed storage.

== Hashing

BLAKE3 is the only hashing algorithm exposed by Dexios' checksum mode.

This mode is useful for manual or out-of-band verification of files, but it is not the primary integrity mechanism of the Dexios format. Ciphertext and header integrity are already enforced by authenticated encryption and AAD validation.

= Key Operations

Dexios can modify the V5 keyslots attached to a file because the payload AAD covers only the first 32 bytes of the V5 header, not the keyslot area.

== Key Changing

Changing a key decrypts the wrapped master key with the old credential, derives a new wrapping key from the replacement credential, and rewrites the first matching keyslot with a new salt and nonce.

== Key Addition

Adding a key decrypts the wrapped master key and appends a new V5 keyslot containing a new wrapped copy of that same master key.

The current V5 format allows up to 4 keyslots.

== Key Deletion

Key deletion identifies the first keyslot that can be opened with the supplied old credential and removes that keyslot from the header.

All current V5 key-manipulation operations act on the first matching keyslot rather than all matching keyslots.

= GitHub and Pull Requests

The current Dexios repository uses GitHub Actions to run workspace checks, tests, release builds, and documentation-related validation. Pushes and pull requests target the `main` integration branch.

== Automatically Compiled Binaries

GitHub Actions are also used to build release artifacts. Users should still verify published hashes before trusting downloaded binaries.

= Cryptography

== Password Hashing

Dexios uses memory-hard password hashing to derive 32-byte wrapping keys from user-supplied key material.

All current KDFs use a 16-byte salt.

=== Hashing Algorithms

The current code supports:

- `Argon2id`
- `BLAKE3-Balloon`

For new files:

- the default is `Blake3Balloon(5)`
- `--argon` selects `Argon2id(3)`

Older files may use earlier parameter versions such as `Argon2id(1)`, `Argon2id(2)`, or `Blake3Balloon(4)`. The current implementation keeps those mappings for compatibility.

=== Performance

The KDF parameters are intentionally expensive compared to a general-purpose password hash, but still chosen to remain practical on normal user hardware. In most real workflows, storage I/O dominates total runtime once the key has been derived.

== Encryption Algorithms

The current CLI supports new encryption with:

- XChaCha20-Poly1305
- AES-256-GCM

Deoxys-II-256 remains part of the recognized header format for decrypting older files, but is not exposed by the current CLI for new encryption.

== Threat Model

Dexios is designed to protect file contents and format integrity at rest and in transit. It does not attempt to defend against a fully compromised host that can observe the running process directly.

== Key Inputs

Dexios currently accepts key material from:

- an interactively entered passphrase,
- a keyfile,
- a generated passphrase,
- or the `DEXIOS_KEY` environment variable.

The current CLI resolves these sources in this order:

1. explicit keyfile,
2. explicit generated passphrase request,
3. environment variable,
4. interactive prompt.

=== Passphrase Autogeneration

The current implementation generates `n` random words from a bundled wordlist and joins them with `-`.

The default is `7` words:

```text
word-word-word-word-word-word-word
```

== Cryptographic Hygiene

Dexios uses the `zeroize` crate and a `Protected` wrapper to reduce accidental exposure of secrets in memory.

=== Protected Wrapper

The `Protected` wrapper provides explicit access through `.expose()`, redacts debug output, forbids implicit copying, and zeroizes the wrapped value on drop.

== RNGs

Random values are generated through the current `rand` API, which draws from the operating system's entropy sources.

= Dependencies

Dexios keeps the core dependency set relatively small. The critical dependencies are the AEAD crates, KDF crates, `zeroize`, `rand`, and `zip` for pack/unpack workflows.

= Supported Hardware and Operating Systems

As a Rust workspace, Dexios targets a range of mainstream desktop platforms. The current project targets Linux, macOS, Windows, FreeBSD, and Android via Termux. Automated testing currently covers Linux and macOS most directly, while release automation also builds Windows binaries.

= Headers

The current V5 header length is `416` bytes.

The format still supports legacy headers V1-V4 for compatibility, but new files are written as V5.

== Header Structure

The V5 layout is:

```text
{VersionTag | AlgorithmTag | ModeTag | DataNonce | Padding | KeyslotArea}
```

The 2-byte version tag is `[0xDE, 0x05]`.

The algorithm tag is:

- `[0x0E, 0x01]` for XChaCha20-Poly1305
- `[0x0E, 0x02]` for AES-256-GCM
- `[0x0E, 0x03]` for Deoxys-II-256

The mode tag is:

- `[0x0C, 0x01]` for stream mode
- `[0x0C, 0x02]` for memory mode

Only the first 32 bytes of the V5 header are authenticated as AAD.

== Keyslots

The V5 keyslot area contains space for 4 keyslots at 96 bytes each.

Each keyslot contains:

```text
{Identifier | WrappedMasterKey | Nonce | Padding1 | Salt | Padding2}
```

The wrapped master key is 48 bytes long.

The identifier encodes both "this is a keyslot" and the KDF/parameter-version family used for that keyslot. Current identifiers include:

- `[0xDF, 0xA1]`
- `[0xDF, 0xA2]`
- `[0xDF, 0xA3]`
- `[0xDF, 0xB4]`
- `[0xDF, 0xB5]`

== AAD

For V5, the first 32 bytes of the header are authenticated as AAD. This protects the version, algorithm, mode, data nonce, and static padding, while still allowing keyslot updates without re-encrypting the payload.

Legacy header versions use different AAD behavior:

- V1-V2: no AAD
- V3: full serialized header
- V4: the static region plus trailing nonce padding

== Header Operations

Dexios supports:

- stripping headers by zeroing the serialized header region,
- dumping valid headers,
- restoring headers only when the target starts with enough zero bytes.

Files created in detached-header mode generally do not reserve enough zero space for restoration.

= Conclusion

Dexios' current design favors a compact versioned header, explicit compatibility handling, modern authenticated encryption, and a relatively small implementation surface. The project is best understood as a practical at-rest file-encryption format rather than a general-purpose secure messaging or secret-management system.

*References*

1. https://csrc.nist.gov/projects/block-cipher-techniques/bcm
2. https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/
3. https://www.eff.org/document/passphrase-wordlists
4. https://eprint.iacr.org/2016/027.pdf
