## Headers

Dexios uses versioned headers. `dexios-core` can deserialize legacy headers from V1 through V5, while current write paths target **V5**.

## Version Tags and Sizes

Each header starts with a 2-byte version tag:

- V1: `[0xDE, 0x01]`
- V2: `[0xDE, 0x02]`
- V3: `[0xDE, 0x03]`
- V4: `[0xDE, 0x04]`
- V5: `[0xDE, 0x05]`

Current header sizes:

- V1-V3: 64 bytes
- V4: 128 bytes
- V5: 416 bytes

The next fields after the version tag are:

- a 2-byte algorithm tag
- a 2-byte mode tag

## Current Format: V5

V5 is the current format used for new encryption.

The first 32 bytes are the static header region:

- 2-byte version tag
- 2-byte algorithm tag
- 2-byte mode tag
- stream/data nonce
- zero padding up to 32 bytes total

Those first 32 bytes are also the AAD used for V5 payload encryption/decryption.

After the static region comes space for up to **4 keyslots**, each exactly **96 bytes** long.

Each V5 keyslot contains:

- a 2-byte keyslot identifier
- a 48-byte encrypted master key
- a memory-mode nonce for the wrapped master key
- zero padding up to byte 74 of the keyslot
- a 16-byte salt
- 6 trailing zero bytes

Unused keyslot regions are serialized as zero-filled 96-byte blocks.

### Keyslot Identifiers

The keyslot identifier does more than say "this is a keyslot". It also encodes the hashing algorithm and parameter version used to derive the wrapping key.

Current identifiers recognized by the code:

- `[0xDF, 0xA1]` = `Argon2id(1)`
- `[0xDF, 0xA2]` = `Argon2id(2)`
- `[0xDF, 0xA3]` = `Argon2id(3)`
- `[0xDF, 0xB4]` = `Blake3Balloon(4)`
- `[0xDF, 0xB5]` = `Blake3Balloon(5)`

## Legacy Formats

### V1-V3

V1-V3 are legacy 64-byte headers. They derive the data key directly from the user's key material instead of storing a wrapped random master key in keyslots.

- V1 and V3 store a salt, mode, algorithm, nonce, and padding
- V2 also includes a legacy truncated HMAC field
- V3 authenticates the full header bytes as AAD during modern deserialization

### V4

V4 is the transitional master-key format. It stores:

- the static header fields
- a single wrapped master key
- a memory-mode nonce for that wrapped master key
- a salt associated with `Blake3Balloon(4)`

V4 has one effective keyslot, but not the full 4-slot V5 layout.

## AAD

AAD behavior depends on the header version:

- V1-V2: no AAD
- V3: the full serialized header
- V4: the static header bytes plus the trailing padding after the wrapped-key nonce
- V5: the first 32 bytes only

V5 intentionally excludes keyslots from AAD so key management operations can rewrite keyslots without re-encrypting the file payload.

## Key Manipulation

`key add`, `key change`, and `key del` operate on V5 headers only.

Important behavior:

- `key add` appends a new keyslot and fails if 4 keyslots already exist
- `key change` rewrites the first matching keyslot
- `key del` removes the first matching keyslot
- matching is determined by successfully decrypting the master key with the supplied old key material

If multiple keyslots correspond to equivalent credentials, `change` and `del` affect the first match only.

## Header Operations

### Stripping

`header strip` deserializes the header, rewinds the file, and overwrites the header region with zeroes. The number of zeroed bytes depends on the detected header version.

### Dumping

`header dump` deserializes a valid Dexios header and writes the canonical serialized bytes to the output.

### Restoring

`header restore` only works if the target file begins with enough zero bytes to hold the header being restored. Detached-header outputs usually do not reserve that space, so restoration is intentionally limited.
