## Encryption

The current Dexios product surface uses one suite for new output:

- `XChaCha20-Poly1305`
- LE31 stream encryption for raw-file payloads
- a separate wrapping nonce for the encrypted master key inside each keyslot

## Stream Encryption

Dexios reads and writes payloads in **1 MiB** blocks through the typed
`V1PayloadStream` boundary. Normal callers pass a typed master key plus either a
canonical V1 header for encryption or a parsed V1 payload bundle for
decryption.

Stored payload nonces are shorter than their full AEAD counterparts because
LE31 appends a 31-bit little-endian counter and a last-block flag internally:

- payload nonce: 20 bytes
- keyslot nonce: 24 bytes

For new canonical V1 files, the payload nonce is immutable payload context in
the 64-byte static header. Each wrapped master key uses its own 24-byte keyslot
nonce inside a physical keyslot record.

Changing the payload nonce changes the payload AAD and fails payload stream
authentication. Changing a keyslot nonce changes the slot-scoped wrapping AAD
and fails wrapped master-key authentication for that slot.

## Payload AAD and Keyslot AAD

Normal V1 stream APIs do not accept arbitrary caller-provided AAD. Encryption
derives payload AAD from the immutable canonical V1 static header, and
decryption uses the parsed V1 payload bundle that binds the header to its
matching AAD.

Payload AAD excludes mutable keyslot table state. Slot occupancy, active slot
count, keyslot salts, keyslot nonces, KDF profile bytes, and wrapped master-key
bytes are not part of payload AAD.

Wrapped master keys use separate slot-scoped AAD. The slot-scoped AAD binds the
immutable static header context, physical slot index, KDF profile id, KDF
parameter profile id, salt, and keyslot nonce. This lets `key add`, `key
change`, and `key del` mutate keyslot records without re-encrypting the payload
or invalidating unrelated physical slots.

The deterministic regression matrix in `dexios-core/tests/stream_v1.rs` covers
wrong keys, mismatched header-derived AAD, wrong payload nonce, truncated
ciphertext, reordered chunks, tampered middle chunks, tampered final chunks, and
missing final blocks. The keyslot workflow tests cover keyslot nonce and slot
metadata authentication.

## Final Block Semantics

If the plaintext length is exactly divisible by the 1 MiB block size, Dexios
still emits a final authenticated last block. This avoids end-of-stream
ambiguity.

For exact-block plaintext, that final block is an authenticated empty marker.
Decryption requires the marker; ciphertext without the final block fails instead
of returning committed plaintext success.

## Final Authentication Receipt

`V1PayloadStream::decrypt_file` writes plaintext to its writer as uncommitted
scratch. Callers must treat the plaintext as accepted only after the function
returns a `V1FinalAuth` receipt. The receipt is created only after the final
block authenticates and the plaintext writer flushes successfully.
This is the final authentication boundary for payload acceptance.

Domain transactional decrypt commit observes that receipt before publishing the
final output. A final-authentication failure after scratch plaintext exists must
leave existing final outputs uncommitted.

## Payload Framing

Canonical V1 stores payload kind and payload framing bytes in the static header.
The bytes are interpreted by the shared core `PayloadKind` and
`PayloadFramingProfile` contract:

- `PayloadKind::RawFile` with `PayloadFramingProfile::RawLe31` for normal file
  encryption
- `PayloadKind::ManifestArchive` with
  `PayloadFramingProfile::ManifestFirst` for Dexios-owned archive framing

The manifest-first archive framing starts with a Dexios `DXAR` manifest and then
ordered `DXBF` body frames. This is canonical V1 payload structure, not ZIP
crate surface. ZIP implementation bytes, ZIP central-directory metadata, ZIP
crate types, compression selectors, and broad metadata knobs are not canonical
V1 format surface. Manifest-first framing is not ZIP crate surface. ZIP
implementation details are not canonical V1 format surface.

## Header and Payload Authentication

Payload authentication is provided by the AEAD itself. Header authentication for
payload bytes is provided through immutable canonical V1 payload AAD. Wrapped
master-key authentication is provided separately through slot-scoped AAD for
each physical keyslot.

## Legacy Notes

The normal public surface no longer exposes alternate cipher selection or
memory-mode encryption for new output. Retired old current-V1 layout handling is
an explicit parser rejection path, not a compatibility decrypt path.
