## Encryption

The current Dexios format uses a random 32-byte master key for new encryption. User key material is hashed and used to wrap that master key inside the header.

The current CLI supports new encryption with:

- `XChaCha20-Poly1305` (default)
- `AES-256-GCM` (`--aes`)

`Deoxys-II-256` is still recognized by the core format for backward compatibility, but the current CLI does not expose it for new encryption.

## Stream Mode

New encryption uses stream mode.

Dexios reads and writes payloads in **1 MiB** blocks. The stream helper is based on LE31 stream encryption from the `aead` ecosystem.

Stored stream nonces are shorter than their memory-mode equivalents because LE31 appends a 31-bit little-endian counter and a last-block flag internally:

- `XChaCha20-Poly1305`: 20-byte stored nonce, 24-byte effective AEAD nonce
- `AES-256-GCM`: 8-byte stored nonce, 12-byte effective AEAD nonce
- `Deoxys-II-256`: 11-byte stored nonce, 15-byte effective AEAD nonce

For new V5 files, the stream/data nonce is stored in the static header region. The wrapped master key uses a separate memory-mode nonce inside each keyslot.

## Stream Mode Edge Case

If a file length is exactly divisible by the 1 MiB block size, Dexios still emits a final authenticated last block. This avoids truncation ambiguity and is covered by the current stream implementation and tests.

## Memory Mode

Memory mode still exists in `dexios-core`, but it is effectively a legacy compatibility path for decryption and old headers.

The current CLI encrypt path does not select memory mode for new files; it always routes new encryption through stream mode.

Memory mode uses the full AEAD nonce length:

- 24 bytes for `XChaCha20-Poly1305`
- 12 bytes for `AES-256-GCM`
- 15 bytes for `Deoxys-II-256`

## Header and Payload Authentication

Payload authentication is provided by the AEAD itself, and header authentication is provided through the version-dependent AAD rules described in [Headers](Headers.md).
