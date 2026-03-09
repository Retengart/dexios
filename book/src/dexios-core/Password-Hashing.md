## Password Hashing

Dexios derives 32-byte wrapping keys from user-provided key material and a 16-byte salt.

The current code supports two hashing families:

- `Argon2id`
- `BLAKE3-Balloon`

## Current Defaults

For new files:

- the default is `Blake3Balloon(5)`
- `--argon` switches new encryption to `Argon2id(3)`

For decryption and key manipulation, Dexios reads the required algorithm/version from the header or keyslot metadata.

## Legacy Mapping

Supported parameter-version mapping in the current code:

- `Argon2id(1)` for V1
- `Argon2id(2)` for V2
- `Argon2id(3)` for V3 and new `--argon` output
- `Blake3Balloon(4)` for V4
- `Blake3Balloon(5)` for V5 and current default output

## Handling the Hash

Derived keys are wrapped in `Protected<>` and exposed only when initializing the cipher layer.

The implementation is intentionally explicit:

- raw key material is read into owned byte buffers
- the selected KDF derives a 32-byte value
- the raw input is dropped
- the derived key is only exposed to the encrypt/decrypt primitives
