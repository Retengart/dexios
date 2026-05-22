## Headers

The supported Dexios format is **canonical V1**. The product format name and
version bytes remain V1, but canonical V1 is a redesigned byte contract with an
explicit discriminator. Old current-V1 artifacts using the retired 416-byte
layout are rejected by the normal parser and decrypt paths as obsolete retired
layout, not silently migrated or treated as supported input.
The phrase obsolete retired layout means the old bytes are retained only for
typed rejection evidence.

Legacy Dexios formats are intentionally unsupported after the safety refactor.

## Canonical V1 Layout

The canonical V1 layout is a **512-byte canonical V1 header**:

- 64-byte immutable static header
- four fixed physical keyslot records, each 112 bytes

The static header begins with:

- 4-byte magic: `DXIO`
- 2-byte product version field: `0x0001`
- 4-byte canonical discriminator: `CV1\0`
- 1-byte schema profile
- 1-byte payload kind from `PayloadKind`
- 1-byte payload framing profile from `PayloadFramingProfile`
- 1-byte canonical KDF parameter profile
- 1-byte fixed keyslot capacity
- 1 reserved byte
- 20-byte payload nonce
- zeroed reserved bytes through the end of the 64-byte static header

Together, the canonical V1 prefix is `DXIO 00 01 CV1\0`.

Those 64 static bytes are the payload AAD; the payload AAD covers the 64-byte immutable static header.
Payload AAD is immutable payload context: it includes
the canonical discriminator, schema, payload kind, payload framing profile, KDF
parameter profile, fixed slot capacity, and payload nonce.
It excludes mutable keyslot table state such as slot occupancy, active slot
count, salts, keyslot nonces, and wrapped master-key bytes.

Detached headers are exact 512-byte canonical V1 header bytes. They are parsed
by the same canonical parser as embedded headers; there is no detached metadata
wrapper.

## Keyslot Records

Canonical V1 has four physical keyslot positions. Empty slots serialize as
all-zero 112-byte records. Active slots serialize their physical slot index and
must remain in that physical position; add, change, delete, and verify do not
compact or reorder later slots.
Canonical keyslot operations do not compact or reorder physical slots.

Each 112-byte physical keyslot contains:

- active-slot state byte
- physical slot index
- KDF profile id
- KDF parameter profile id
- 16-byte salt
- 24-byte keyslot nonce
- 48-byte encrypted master key
- zeroed padding through the end of the 112-byte record

The wrapped master key is authenticated with slot-scoped AAD. That AAD binds
the immutable static header context, physical slot index, KDF profile id, KDF
parameter profile id, salt, and keyslot nonce. Changing the payload nonce fails
payload authentication; changing the keyslot nonce, salt, physical index, or KDF
metadata fails keyslot unwrap authentication.

## KDF Identifiers

Canonical V1 normal writes use one KDF profile:

- BLAKE3-Balloon with the canonical profile ids defined in `dexios-core/src/kdf.rs`

New canonical V1 writes do not expose alternate KDF selection or
user-configurable KDF parameters. The historical Argon2id tag may still be
recognized as unsupported metadata for explicit diagnostics, but it is not a
normal write policy and is not used for derivation.

## Key Manipulation

`key add`, `key change`, `key del`, and `key verify` operate on canonical V1
headers and fixed physical slots.

Important behavior:

- up to four physical slots may be populated
- matching is determined by successfully decrypting a slot-scoped wrapped
  master key
- `key add` proves an existing supported key before reading the new key source
  and writes the new key into the first empty physical slot
- `key change` replaces only the proven physical slot
- `key add` and `key change` generate and persist a fresh keyslot wrapping
  nonce for the changed physical slot
- the fresh keyslot wrapping nonce is part of the authenticated slot metadata
- `key del` clears only the proven physical slot and rejects deletion of the
  final supported decrypting keyslot
- unsupported keyslot metadata does not count as a supported recovery key
- `key verify` is read-only and must not normalize, compact, or mutate slots

## Retired and Legacy Layouts

The retired old current-V1 416-byte layout used `DXIO 00 01` without the
`CV1\0` discriminator. Canonical V1 rejects that layout on normal parser and
decrypt paths. Migration tooling is out of scope unless a future requirement
approves it.

Inputs beginning with legacy `[DE,01]` through `[DE,05]` prefixes are rejected
as unsupported format.

## Header Operations

Dexios supports V1-only header maintenance operations over encrypted artifacts:

- `header dump` accepts an embedded encrypted artifact with payload bytes after
  the canonical V1 header. It writes exactly 512 serialized canonical header
  bytes to the detached header output.
- `header strip` accepts an embedded encrypted artifact with a valid canonical
  V1 header and payload bytes. It transactionally replaces only the first 512
  bytes with zeroes and preserves the payload bytes.
- `header restore` accepts a detached header file only when it is exactly 512
  bytes and parses as a canonical V1 header. The restore target must be a
  stripped embedded artifact: it must contain a zeroed 512-byte header prefix
  and at least one payload byte after that prefix.

Header-only files are not embedded encrypted artifacts. Dump and strip reject
them because there are no payload bytes after the header. Restore rejects short
detached headers, detached headers with trailing bytes, short restore targets,
and targets whose first 512 bytes are not all zero before it stages any
replacement.

Detached-header encryption outputs usually do not reserve a zeroed 512-byte
prefix in the payload file, so restore remains a recovery operation for
previously stripped embedded artifacts rather than a normal detached-header
workflow.
