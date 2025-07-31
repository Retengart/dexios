# BLAKE3-Balloon

A Rust implementation of the Balloon password hashing algorithm using BLAKE3 as the underlying hash function.

## Overview

BLAKE3-Balloon combines the speed and security of BLAKE3 with the memory-hardness properties of Balloon hashing, providing a modern and efficient password hashing solution.

## Features

- **Memory-hard**: Resistant to GPU and ASIC attacks through configurable memory requirements
- **Fast**: Leverages BLAKE3's optimized implementation
- **Secure**: Automatic memory zeroing for sensitive data
- **Flexible**: Support for custom parameters and versioned parameter sets
- **Simple API**: Easy to use with sensible defaults

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
blake3-balloon = "0.1"
```

## Usage

### Basic Usage

```rust
use blake3_balloon::{hash_password, verify_password, Version};

fn main() -> anyhow::Result<()> {
    let password = b"my secure password";
    let salt = [0u8; 16]; // Use a random salt in production!
    
    // Hash the password
    let hash = hash_password(password, &salt, Version::V1)?;
    
    // Verify the password
    let is_valid = verify_password(password, &salt, &hash, Version::V1)?;
    assert!(is_valid);
    
    Ok(())
}
```

### Custom Parameters

```rust
use blake3_balloon::{hash_password_with_params, Params};

fn main() -> anyhow::Result<()> {
    let password = b"my secure password";
    let salt = [0u8; 16];
    
    // Create custom parameters: 256 MB memory, 3 iterations, 1 thread
    let params = Params::new(65536, 3, 1)?;
    
    let hash = hash_password_with_params(password, &salt, params)?;
    
    Ok(())
}
```

### Generating Random Salts

With the `rand` feature enabled (default):

```rust
use blake3_balloon::generate_salt;

let salt = generate_salt();
```

### Secure Password Handling

For automatic memory zeroing:

```rust
use blake3_balloon::{hash_password_secure, Version};

fn main() -> anyhow::Result<()> {
    let password = "sensitive password".to_string().into_bytes();
    let salt = [0u8; 16];
    
    // The password vector will be automatically zeroed after use
    let hash = hash_password_secure(password, &salt, Version::V1)?;
    
    Ok(())
}
```

## Parameter Versions

The crate supports different parameter versions:

- **Version::V1**: 272 MB memory cost, 1 time cost, 1 parallelism (recommended for most uses)
- **Version::Custom**: Use with `hash_password_with_params()` for custom parameters

## Security Considerations

1. **Always use a random salt**: Never reuse salts between passwords
2. **Choose appropriate parameters**: Higher memory and time costs provide better security but slower hashing
3. **Store salts alongside hashes**: You'll need the salt to verify passwords
4. **Use constant-time comparison**: The `verify_password` function uses constant-time comparison to prevent timing attacks

## Performance

The performance characteristics depend on the chosen parameters:

- **Memory cost**: Specified in 4KB blocks
- **Time cost**: Number of mixing iterations
- **Parallelism**: Currently only supports single-threaded operation (parallelism = 1)

## Algorithm Details

BLAKE3-Balloon combines:
- **BLAKE3**: A fast cryptographic hash function
- **Balloon Hashing**: A memory-hard construction proven secure in the random oracle model

The algorithm provides configurable memory-hardness while maintaining good performance on standard CPUs.

## License

This project is licensed under the BSD-2-Clause License - see the LICENSE file for details.

## Acknowledgments

- Based on the [Balloon Hashing](https://crypto.stanford.edu/balloon/) paper
- Uses the [blake3](https://github.com/BLAKE3-team/BLAKE3) and [balloon-hash](https://github.com/RustCrypto/password-hashes/tree/master/balloon-hash) crates
- Inspired by the implementation in [Dexios](https://github.com/brxken128/dexios)