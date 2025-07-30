# Changes Made to Create My Dexios

This document summarizes all the modifications made to the original Dexios codebase to remove AES, Argon2, and Deoxys support.

## Core Library Changes (dexios-core)

### 1. Cargo.toml
- Removed dependencies: `aes-gcm`, `argon2`, `deoxys`

### 2. primitives.rs
- Removed `Algorithm::Aes256Gcm` and `Algorithm::DeoxysII256` enum variants
- Updated `ALGORITHMS_LEN` from 3 to 1
- Updated `ALGORITHMS` array to only contain `XChaCha20Poly1305`
- Updated `get_nonce_len()` to only handle `XChaCha20Poly1305`

### 3. cipher.rs
- Removed imports for `aes_gcm::Aes256Gcm` and `deoxys::DeoxysII256`
- Removed `Ciphers::Aes256Gcm` and `Ciphers::DeoxysII` enum variants
- Updated `initialize()` to only handle `XChaCha20Poly1305`
- Updated all encrypt/decrypt methods to only handle `XChaCha20Poly1305`

### 4. stream.rs
- Removed imports for `aes_gcm::Aes256Gcm` and `deoxys::DeoxysII256`
- Removed stream encryption/decryption variants for AES and Deoxys
- Updated `EncryptionStreams` and `DecryptionStreams` enums

### 5. key.rs
- Removed the entire `argon2id_hash()` function
- Updated documentation to only reference `balloon_hash()`
- Modified `decrypt_master_key()` to reject V1-V3 headers (which used Argon2)

### 6. header.rs
- Removed import of `argon2id_hash`
- Removed `ARGON2ID_LATEST` constant
- Removed `HashingAlgorithm::Argon2id` enum variant
- Updated `HashingAlgorithm::hash()` to only handle BLAKE3-Balloon
- Updated algorithm parsing to only recognize XChaCha20-Poly1305
- Updated serialization methods

### 7. lib.rs
- Updated documentation to mention only XChaCha20-Poly1305

## CLI Changes (dexios)

### 1. cli.rs
- Removed all `--aes` flag definitions from all subcommands
- Removed all `--argon` flag definitions from all subcommands

### 2. global/parameters.rs
- Removed import of `ARGON2ID_LATEST`
- Updated `hashing_algorithm()` to always return BLAKE3-Balloon
- Updated `algorithm()` to always return XChaCha20-Poly1305

### 3. subcommands/header.rs
- Updated header details display to show BLAKE3-Balloon for all versions

## Domain Library Changes (dexios-domain)

### 1. lib.rs
- Updated documentation to remove references to AES and Deoxys

## Documentation Updates

### 1. README.md (root)
- Updated to mention only XChaCha20-Poly1305 AEAD
- Removed references to AES-256-GCM and Deoxys-II

### 2. dexios-core/README.md
- Updated features list to mention only XChaCha20-Poly1305
- Removed references to multiple AEADs and Argon2id
- Updated code examples

### 3. dexios/README.md
- Updated to mention only XChaCha20-Poly1305

### 4. dexios-domain/README.md
- Updated to mention only XChaCha20-Poly1305
- Added example code

## Key Points

1. **Single Algorithm**: The modified version uses only XChaCha20-Poly1305 for encryption
2. **Single Hashing**: Only BLAKE3-Balloon is used for password hashing
3. **Backwards Compatibility**: Can still decrypt files that were originally encrypted with XChaCha20-Poly1305 and BLAKE3-Balloon
4. **No Compatibility**: Cannot decrypt files encrypted with AES, Deoxys, or using Argon2id hashing
5. **Simplified Codebase**: Removed complexity of supporting multiple algorithms
6. **Security**: Maintains high security with audited cryptographic primitives