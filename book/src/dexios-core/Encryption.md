## Encryption

The current Dexios product surface uses one suite for new output:

- `XChaCha20-Poly1305`
- LE31 stream encryption for payloads
- a separate wrapping nonce for the encrypted master key inside each keyslot

## Stream Encryption

Dexios reads and writes payloads in **1 MiB** blocks.

Stored payload nonces are shorter than their full AEAD counterparts because LE31 appends a 31-bit little-endian counter and a last-block flag internally:

- payload nonce: 20 bytes
- keyslot nonce: 24 bytes

For new V1 files, the payload nonce is stored in the static header region. Each wrapped master key uses its own 24-byte nonce inside a keyslot.

## Stream Edge Case

If the plaintext length is exactly divisible by the 1 MiB block size, Dexios still emits a final authenticated last block. This avoids end-of-stream ambiguity.

## Header and Payload Authentication

Payload authentication is provided by the AEAD itself.

Header authentication is provided through V1 AAD: the first 32 bytes of the header are authenticated with every encrypted block.

## Legacy Notes

Older compatibility paths still exist internally, but the normal public surface no longer exposes alternate cipher selection or memory-mode encryption for new output.
