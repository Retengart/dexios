## Headers

The normal writable Dexios format is **V1**.

`dexios-core` still contains explicit legacy parsing helpers, but new encryption, new key management, and the normal CLI surface are centered on V1.

## V1 Layout

The V1 header is **416 bytes** long.

Its first **32 bytes** are the static header region and also the payload AAD:

- 4-byte magic: `DXIO`
- 2-byte version field: `0x0001`
- 1-byte keyslot count
- 1 reserved byte
- 20-byte payload nonce
- 4 reserved trailing bytes

Those first 32 bytes are authenticated as AAD during payload encryption and decryption.

After the static region comes space for up to **4 keyslots**, each **96 bytes** long.

Each V1 keyslot contains:

- a 2-byte KDF identifier
- a 48-byte encrypted master key
- a 24-byte keyslot nonce
- a 16-byte salt
- 6 reserved zero bytes

Unused keyslot regions are serialized as all-zero 96-byte blocks.

## KDF Identifiers

The current V1 format recognizes:

- `[0xDF, 0x01]` = `Blake3Balloon`
- `[0xDF, 0x02]` = `Argon2id`

## Key Manipulation

`key add`, `key change`, `key del`, and `key verify` now operate on V1 headers.

Important behavior:

- up to 4 keyslots may be populated
- matching is determined by successfully decrypting the wrapped master key
- `change` and `del` affect the first matching keyslot

## Legacy Notes

Legacy header parsing still exists as an explicit compatibility path. It is mainly relevant for inspection and migration-adjacent code, not for the normal product surface.

`header details` is V1-first and only falls back to legacy parsing when the input is not a V1 header.

## Header Operations

Dexios still supports:

- dumping headers
- stripping headers by zeroing the serialized header region
- restoring headers when the target file already begins with enough zero bytes

Detached-header outputs usually do not reserve enough zero bytes for restoration, so restore remains a specialized operation rather than a normal workflow.
