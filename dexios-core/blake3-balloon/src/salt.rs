//! Salt generation utilities for BLAKE3-Balloon hashing
//!
//! This module provides utilities for generating cryptographically secure
//! random salts for use with BLAKE3-Balloon password hashing.

#[cfg(feature = "salt-generation")]
use crate::params::SALT_LEN;

/// Generates a cryptographically secure random salt
///
/// This function generates a 16-byte salt using a cryptographically secure
/// random number generator. The salt should be unique for each password
/// and stored alongside the hash for verification.
///
/// # Availability
///
/// This function is only available when the `salt-generation` feature is enabled.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "salt-generation")]
/// # {
/// use blake3_balloon::generate_salt;
///
/// let salt = generate_salt();
/// assert_eq!(salt.len(), 16);
/// # }
/// ```
///
/// # Security Note
///
/// The generated salt should be stored securely alongside the password hash.
/// Never reuse salts for different passwords, as this reduces security.
#[cfg(feature = "salt-generation")]
#[must_use]
pub fn generate_salt() -> [u8; SALT_LEN] {
    use rand::RngCore;
    
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Generates multiple cryptographically secure random salts
///
/// This function generates multiple unique salts in one call, which can be
/// useful for batch operations or when multiple salts are needed.
///
/// # Arguments
///
/// * `count` - The number of salts to generate
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "salt-generation")]
/// # {
/// use blake3_balloon::generate_salts;
///
/// let salts = generate_salts(3);
/// assert_eq!(salts.len(), 3);
/// assert_ne!(salts[0], salts[1]); // Salts should be different
/// # }
/// ```
#[cfg(feature = "salt-generation")]
#[must_use]
pub fn generate_salts(count: usize) -> Vec<[u8; SALT_LEN]> {
    (0..count).map(|_| generate_salt()).collect()
}

/// Creates a salt from a hexadecimal string
///
/// This function converts a hexadecimal string representation back into
/// a salt array. This is useful for loading salts from storage.
///
/// # Arguments
///
/// * `hex_str` - A hexadecimal string representation of the salt
///
/// # Errors
///
/// Returns an error if:
/// - The hex string is not exactly 32 characters (16 bytes)
/// - The hex string contains invalid hexadecimal characters
///
/// # Examples
///
/// ```rust
/// use blake3_balloon::salt_from_hex;
///
/// let hex = "0123456789abcdef0123456789abcdef";
/// let salt = salt_from_hex(hex).unwrap();
/// assert_eq!(salt.len(), 16);
/// ```
pub fn salt_from_hex(hex_str: &str) -> Result<[u8; SALT_LEN], String> {
    if hex_str.len() != SALT_LEN * 2 {
        return Err(format!(
            "Invalid hex string length: expected {} characters, got {}",
            SALT_LEN * 2,
            hex_str.len()
        ));
    }

    let mut salt = [0u8; SALT_LEN];
    for (i, chunk) in hex_str.as_bytes().chunks(2).enumerate() {
        let hex_byte = std::str::from_utf8(chunk)
            .map_err(|_| "Invalid UTF-8 in hex string")?;
        salt[i] = u8::from_str_radix(hex_byte, 16)
            .map_err(|_| format!("Invalid hexadecimal character in: {}", hex_byte))?;
    }

    Ok(salt)
}

/// Converts a salt to a hexadecimal string
///
/// This function converts a salt array into its hexadecimal string
/// representation for storage or display purposes.
///
/// # Arguments
///
/// * `salt` - The salt to convert
///
/// # Examples
///
/// ```rust
/// use blake3_balloon::salt_to_hex;
///
/// let salt = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
///            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
/// let hex = salt_to_hex(&salt);
/// assert_eq!(hex, "0123456789abcdef0123456789abcdef");
/// ```
#[must_use]
pub fn salt_to_hex(salt: &[u8; SALT_LEN]) -> String {
    salt.iter()
        .map(|byte| format!("{:02x}", byte))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_salt_hex_roundtrip() {
        let original_salt = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        ];
        
        let hex = salt_to_hex(&original_salt);
        let recovered_salt = salt_from_hex(&hex).unwrap();
        
        assert_eq!(original_salt, recovered_salt);
    }

    #[test]
    fn test_salt_from_hex_invalid_length() {
        let result = salt_from_hex("too_short");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid hex string length"));
    }

    #[test]
    fn test_salt_from_hex_invalid_characters() {
        let invalid_hex = "0123456789abcdefgggggggggggggggg";
        let result = salt_from_hex(invalid_hex);
        assert!(result.is_err());
    }

    #[cfg(feature = "salt-generation")]
    #[test]
    fn test_generate_salt_uniqueness() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        
        // While theoretically possible, the probability of generating
        // the same salt twice is astronomically low
        assert_ne!(salt1, salt2);
    }

    #[cfg(feature = "salt-generation")]
    #[test]
    fn test_generate_salts() {
        let salts = generate_salts(5);
        assert_eq!(salts.len(), 5);
        
        // Check that all salts are different
        for i in 0..salts.len() {
            for j in (i + 1)..salts.len() {
                assert_ne!(salts[i], salts[j]);
            }
        }
    }
}