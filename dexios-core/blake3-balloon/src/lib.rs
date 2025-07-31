//! # BLAKE3-Balloon Password Hashing
//!
//! This crate provides a Rust implementation of the BLAKE3-Balloon password hashing algorithm,
//! which combines the security of the Balloon hashing algorithm with the speed and security
//! of the BLAKE3 cryptographic hash function.
//!
//! ## Features
//!
//! - **Secure**: Uses the Balloon hashing algorithm with BLAKE3 for memory-hard password hashing
//! - **Memory Protection**: Sensitive data is automatically zeroized from memory
//! - **Version Support**: Supports multiple parameter versions for compatibility and upgrades
//! - **Easy to Use**: Simple API with both high-level and low-level interfaces
//! - **No-std Support**: Can be used in no-std environments (with some limitations)
//!
//! ## Quick Start
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! blake3-balloon = { version = "0.1", features = ["salt-generation"] }
//! ```
//!
//! Basic usage:
//!
//! ```rust
//! use blake3_balloon::{hash_password, verify_password, generate_salt};
//!
//! // Generate a random salt
//! let salt = generate_salt();
//!
//! // Hash a password
//! let password = b"my-secure-password";
//! let hash = hash_password(password, &salt).unwrap();
//!
//! // Verify the password
//! let is_valid = verify_password(password, &salt, &hash).unwrap();
//! assert!(is_valid);
//! ```
//!
//! ## Advanced Usage
//!
//! For more control over the hashing process:
//!
//! ```rust
//! use blake3_balloon::{Blake3BalloonHasher, ParameterVersion, Protected};
//!
//! // Create a hasher with specific parameters
//! let hasher = Blake3BalloonHasher::new(ParameterVersion::V5);
//!
//! // Use protected memory for the password
//! let password = Protected::new(b"my-secure-password".to_vec());
//! let salt = [0u8; 16]; // Use generate_salt() in practice
//!
//! // Hash with protected memory
//! let hash = hasher.hash_protected_password(password, &salt).unwrap();
//! ```
//!
//! ## Security Considerations
//!
//! - Always use a unique, random salt for each password
//! - Store salts alongside password hashes
//! - Consider using `Protected` types for handling sensitive data
//! - Use the latest parameter version unless compatibility is required
//!
//! ## Parameter Versions
//!
//! This crate supports multiple parameter versions:
//!
//! - **V4**: Legacy parameters (256KB memory cost)
//! - **V5**: Current recommended parameters (272KB memory cost)
//!
//! The default and recommended version is V5, which provides good security
//! while maintaining reasonable performance.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

// Public modules
pub mod error;
pub mod hasher;
pub mod params;
pub mod protected;
pub mod salt;

// Re-export main types and functions for convenience
pub use error::{Blake3BalloonError, Result};
pub use hasher::{
    hash_password, hash_protected_password, verify_password, Blake3BalloonHasher,
};
pub use params::{Blake3BalloonConfig, ParameterVersion, OUTPUT_LEN, SALT_LEN};
pub use protected::{protected_bytes, protected_string, Protected};
pub use salt::{salt_from_hex, salt_to_hex};

#[cfg(feature = "salt-generation")]
pub use salt::{generate_salt, generate_salts};

/// Current version of the BLAKE3-Balloon crate
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Latest parameter version (alias for `ParameterVersion::latest()`)
pub const LATEST_VERSION: ParameterVersion = ParameterVersion::V5;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_hashing() {
        let password = b"test-password";
        let salt = [0u8; SALT_LEN];

        let hash = hash_password(password, &salt).unwrap();
        assert_eq!(hash.len(), OUTPUT_LEN);

        let is_valid = verify_password(password, &salt, &hash).unwrap();
        assert!(is_valid);

        let wrong_password = b"wrong-password";
        let is_invalid = verify_password(wrong_password, &salt, &hash).unwrap();
        assert!(!is_invalid);
    }

    #[test]
    fn test_protected_hashing() {
        let password = Protected::new(b"test-password".to_vec());
        let salt = [0u8; SALT_LEN];

        let hash = hash_protected_password(password, &salt).unwrap();
        assert_eq!(hash.expose().len(), OUTPUT_LEN);
    }

    #[test]
    fn test_hasher_versions() {
        let password = b"test-password";
        let salt = [0u8; SALT_LEN];

        let hasher_v4 = Blake3BalloonHasher::new(ParameterVersion::V4);
        let hasher_v5 = Blake3BalloonHasher::new(ParameterVersion::V5);

        let hash_v4 = hasher_v4.hash_password(password, &salt).unwrap();
        let hash_v5 = hasher_v5.hash_password(password, &salt).unwrap();

        // Different versions should produce different hashes
        assert_ne!(hash_v4, hash_v5);

        // But each should verify correctly with its own hasher
        assert!(hasher_v4.verify_password(password, &salt, &hash_v4).unwrap());
        assert!(hasher_v5.verify_password(password, &salt, &hash_v5).unwrap());
    }

    #[test]
    fn test_empty_password_error() {
        let salt = [0u8; SALT_LEN];
        let result = hash_password(&[], &salt);
        assert!(matches!(result, Err(Blake3BalloonError::EmptyPassword)));
    }

    #[cfg(feature = "salt-generation")]
    #[test]
    fn test_salt_generation_integration() {
        let password = b"test-password";
        let salt = generate_salt();

        let hash = hash_password(password, &salt).unwrap();
        assert!(verify_password(password, &salt, &hash).unwrap());
    }

    #[test]
    fn test_salt_hex_conversion() {
        let original_salt = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        
        let hex = salt_to_hex(&original_salt);
        let recovered_salt = salt_from_hex(&hex).unwrap();
        
        assert_eq!(original_salt, recovered_salt);
    }

    #[test]
    fn test_parameter_version_conversion() {
        assert_eq!(ParameterVersion::from_u32(4).unwrap(), ParameterVersion::V4);
        assert_eq!(ParameterVersion::from_u32(5).unwrap(), ParameterVersion::V5);
        assert!(ParameterVersion::from_u32(999).is_err());

        assert_eq!(ParameterVersion::V4.to_u32(), 4);
        assert_eq!(ParameterVersion::V5.to_u32(), 5);
    }

    #[test]
    fn test_protected_memory() {
        let secret = Protected::new("sensitive data".to_string());
        
        // Should be hidden in debug output
        let debug_output = format!("{:?}", secret);
        assert_eq!(debug_output, "[REDACTED]");
        
        // Should be accessible via expose
        assert_eq!(secret.expose(), "sensitive data");
    }
}