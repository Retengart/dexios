## Password Hashing

Dexios derives 32-byte wrapping keys from user-provided key material and a 16-byte salt.

The current code supports two hashing families:

- `Argon2id`
- `BLAKE3-Balloon`

## Current Defaults

For new files:

- the default is `Blake3Balloon`
- `--argon` switches new encryption to `Argon2id`

For decryption and key manipulation, Dexios reads the required KDF family from the current keyslot metadata.

## Handling the Hash

Derived keys are wrapped in `Protected<>` and exposed only when initializing the cipher layer.

The implementation is intentionally explicit:

- raw key material is read into owned byte buffers
- the selected KDF derives a 32-byte value
- the raw input is dropped
- the derived key is only exposed to the encrypt/decrypt primitives
