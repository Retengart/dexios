# My Dexios - Modified Version

This is a modified version of the Dexios encryption utility with the following changes:

## What's Different

This version has been simplified to use only one encryption algorithm and one password hashing algorithm:

- **Encryption**: Only XChaCha20-Poly1305 (removed AES-256-GCM and Deoxys-II-256)
- **Password Hashing**: Only BLAKE3-Balloon (removed Argon2id)

## Why These Changes?

- **Simplicity**: Having only one algorithm for each purpose reduces complexity and potential attack surface
- **Security**: XChaCha20-Poly1305 is a modern, secure, and audited AEAD cipher
- **Performance**: BLAKE3-Balloon provides excellent security with good performance

## Building

To build this modified version:

```bash
cargo build --release
```

The binary will be available in `target/release/dexios`.

## Usage

Usage remains the same as the original Dexios, except:
- The `--aes` flag has been removed (XChaCha20-Poly1305 is always used)
- The `--argon` flag has been removed (BLAKE3-Balloon is always used)

### Examples

Encrypt a file:
```bash
dexios -e input.txt output.enc
```

Decrypt a file:
```bash
dexios -d output.enc input.txt
```

## Compatibility

**Important**: This version is NOT compatible with files encrypted using the original Dexios with AES or Argon2. It can only:
- Encrypt new files using XChaCha20-Poly1305 and BLAKE3-Balloon
- Decrypt files that were originally encrypted with XChaCha20-Poly1305 and BLAKE3-Balloon

## Security

This modified version maintains the high security standards of the original Dexios:
- XChaCha20-Poly1305 is audited and widely trusted
- BLAKE3-Balloon provides strong key derivation
- All sensitive data is securely erased from memory
- No unsafe code is used

## Credits

This is based on the original [Dexios](https://github.com/brxken128/dexios) project by brxken128.