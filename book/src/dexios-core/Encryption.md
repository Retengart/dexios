## Encryption

The current Dexios product surface uses one suite for new output:

- `XChaCha20-Poly1305`
- LE31 stream encryption for payloads
- a separate wrapping nonce for the encrypted master key inside each keyslot

## Stream Encryption

Dexios reads and writes payloads in **1 MiB** blocks through the typed
`V1PayloadStream` boundary. Normal callers pass a typed master key plus either a
V1 header for encryption or a parsed V1 payload bundle for decryption.

Stored payload nonces are shorter than their full AEAD counterparts because LE31 appends a 31-bit little-endian counter and a last-block flag internally:

- payload nonce: 20 bytes
- keyslot nonce: 24 bytes

For new V1 files, the payload nonce is stored in the static header region. Each wrapped master key uses its own 24-byte nonce inside a keyslot.

## Header-Derived AAD

Normal V1 stream APIs do not accept arbitrary caller-provided AAD. Encryption
derives AAD from the V1 header, and decryption uses the parsed V1 payload bundle
that binds the header to its matching AAD.

The deterministic regression matrix in `dexios-core/tests/stream_v1.rs` covers
wrong keys, mismatched header-derived AAD, wrong payload nonce, truncated
ciphertext, reordered chunks, tampered middle chunks, tampered final chunks, and
missing final blocks.

## Final Block Semantics

If the plaintext length is exactly divisible by the 1 MiB block size, Dexios still emits a final authenticated last block. This avoids end-of-stream ambiguity.

For exact-block plaintext, that final block is an authenticated empty marker.
Decryption requires the marker; ciphertext without the final block fails instead
of returning committed plaintext success.

## Header and Payload Authentication

Payload authentication is provided by the AEAD itself.

Header authentication is provided through V1 AAD: the first 32 bytes of the header are authenticated with every encrypted block.

## Decryption Output State

`V1PayloadStream::decrypt_file` writes plaintext to its writer as uncommitted
scratch. Callers must treat the plaintext as accepted only after the function
returns `Ok(())`, which means the final block authenticated successfully. This
core contract does not implement storage transactions; final output commit
semantics belong to the storage workflow layer.

## Legacy Notes

Older compatibility paths still exist internally, but the normal public surface no longer exposes alternate cipher selection or memory-mode encryption for new output.
