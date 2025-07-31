# BLAKE3-Balloon Password Hashing

A Rust implementation of the BLAKE3-Balloon password hashing algorithm, combining the security of the Balloon hashing algorithm with the speed and security of the BLAKE3 cryptographic hash function.

## Features

- **Secure**: Uses the Balloon hashing algorithm with BLAKE3 for memory-hard password hashing
- **Memory Protection**: Sensitive data is automatically zeroized from memory
- **Version Support**: Supports multiple parameter versions for compatibility and upgrades
- **Easy to Use**: Simple API with both high-level and low-level interfaces
- **No-std Support**: Can be used in no-std environments (with some limitations)

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
blake3-balloon = { version = "0.1", features = ["salt-generation"] }
```

Basic usage:

```rust
use blake3_balloon::{hash_password, verify_password, generate_salt};

// Generate a random salt
let salt = generate_salt();

// Hash a password
let password = b"my-secure-password";
let hash = hash_password(password, &salt).unwrap();

// Verify the password
let is_valid = verify_password(password, &salt, &hash).unwrap();
assert!(is_valid);
```

## Advanced Usage

For more control over the hashing process:

```rust
use blake3_balloon::{Blake3BalloonHasher, ParameterVersion, Protected};

// Create a hasher with specific parameters
let hasher = Blake3BalloonHasher::new(ParameterVersion::V5);

// Use protected memory for the password
let password = Protected::new(b"my-secure-password".to_vec());
let salt = [0u8; 16]; // Use generate_salt() in practice

// Hash with protected memory
let hash = hasher.hash_protected_password(password, &salt).unwrap();
```

## Memory Protection

The crate provides a `Protected` wrapper for sensitive data:

```rust
use blake3_balloon::{Protected, protected_string};

// Wrap sensitive data
let password = protected_string("my-secret");

// Data is hidden from debug output
println!("{:?}", password); // Prints: [REDACTED]

// Access data explicitly
let password_ref = password.expose();

// Data is automatically zeroized when dropped
```

## Parameter Versions

This crate supports multiple parameter versions:

- **V4**: Legacy parameters (256KB memory cost)
- **V5**: Current recommended parameters (272KB memory cost)

```rust
use blake3_balloon::{Blake3BalloonHasher, ParameterVersion};

// Use latest recommended parameters
let hasher = Blake3BalloonHasher::recommended();

// Use specific version
let hasher_v4 = Blake3BalloonHasher::new(ParameterVersion::V4);
let hasher_v5 = Blake3BalloonHasher::new(ParameterVersion::V5);

// Use legacy parameters for compatibility
let legacy_hasher = Blake3BalloonHasher::legacy_v4();
```

## Salt Generation

The crate provides utilities for generating cryptographically secure salts:

```rust
use blake3_balloon::{generate_salt, generate_salts, salt_to_hex, salt_from_hex};

// Generate a single salt
let salt = generate_salt();

// Generate multiple salts
let salts = generate_salts(5);

// Convert salt to/from hex for storage
let hex = salt_to_hex(&salt);
let recovered_salt = salt_from_hex(&hex).unwrap();
```

## Security Considerations

- **Always use a unique, random salt for each password**
- **Store salts alongside password hashes**
- **Consider using `Protected` types for handling sensitive data**
- **Use the latest parameter version unless compatibility is required**

## Error Handling

The crate provides comprehensive error handling:

```rust
use blake3_balloon::{Blake3BalloonError, hash_password};

let result = hash_password(&[], &[0u8; 16]);
match result {
    Ok(hash) => println!("Hash: {:?}", hash),
    Err(Blake3BalloonError::EmptyPassword) => println!("Password cannot be empty"),
    Err(e) => println!("Other error: {}", e),
}
```

## Features

- `default`: Enables std support
- `std`: Standard library support (enabled by default)
- `salt-generation`: Enables salt generation functions (requires `rand`)

## Performance

BLAKE3-Balloon is designed to be memory-hard, making it resistant to hardware attacks while maintaining reasonable performance for legitimate use cases. The V5 parameters provide approximately 272KB memory usage per hash operation.

## Compatibility

This implementation is compatible with the BLAKE3-Balloon implementation used in the [Dexios](https://github.com/brxken128/dexios) project and follows the same parameter specifications.

## License

This project is licensed under the BSD-2-Clause License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.