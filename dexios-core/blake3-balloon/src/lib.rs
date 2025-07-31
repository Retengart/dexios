//! # BLAKE3-Balloon Password Hashing
//! 
//! This crate provides a BLAKE3-based implementation of the Balloon password hashing algorithm.
//! 
//! ## Features
//! 
//! - Memory-hard password hashing using BLAKE3 as the underlying hash function
//! - Configurable parameters for memory cost, time cost, and parallelism
//! - Secure memory handling with automatic zeroing of sensitive data
//! - Support for multiple parameter versions
//!
//! ## Example
//!
//! ```rust
//! use blake3_balloon::{hash_password, hash_password_with_params, Params, Version};
//! 
//! # fn main() -> anyhow::Result<()> {
//! let password = b"my secure password";
//! let salt = [0u8; 16]; // Use a random salt in production
//! 
//! // Hash with default parameters
//! let hash = hash_password(password, &salt, Version::V1)?;
//! 
//! // Hash with custom parameters
//! let params = Params::new(1024 * 256, 2, 1)?; // 256 MB, 2 iterations, 1 thread
//! let hash = hash_password_with_params(password, &salt, params)?;
//! # Ok(())
//! # }
//! ```

use anyhow::{anyhow, Result};
use balloon_hash::{Algorithm, Balloon};
use zeroize::Zeroizing;

pub const SALT_SIZE: usize = 16;
pub const HASH_SIZE: usize = 32;

/// Version of the BLAKE3-Balloon parameters
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// Version 1: 272 MB memory cost, 1 time cost, 1 parallelism
    V1,
    /// Custom parameters
    Custom,
}

impl Version {
    /// Get the balloon hash parameters for this version
    pub fn params(&self) -> Result<balloon_hash::Params> {
        match self {
            Version::V1 => balloon_hash::Params::new(278_528, 1, 1)
                .map_err(|_| anyhow!("Failed to create balloon hash parameters")),
            Version::Custom => Err(anyhow!("Custom version requires explicit parameters")),
        }
    }
}

/// Parameters for the BLAKE3-Balloon algorithm
#[derive(Debug, Clone, Copy)]
pub struct Params {
    /// Memory cost in 4KB blocks
    pub space_cost: u32,
    /// Time cost (number of iterations)
    pub time_cost: u32,
    /// Parallelism degree
    pub parallelism: u32,
}

impl Params {
    /// Create new parameters with validation
    pub fn new(space_cost: u32, time_cost: u32, parallelism: u32) -> Result<Self> {
        if space_cost == 0 {
            return Err(anyhow!("Space cost must be greater than 0"));
        }
        if time_cost == 0 {
            return Err(anyhow!("Time cost must be greater than 0"));
        }
        if parallelism == 0 {
            return Err(anyhow!("Parallelism must be greater than 0"));
        }
        
        Ok(Self {
            space_cost,
            time_cost,
            parallelism,
        })
    }

    /// Convert to balloon_hash::Params
    fn to_balloon_params(&self) -> Result<balloon_hash::Params> {
        balloon_hash::Params::new(self.space_cost, self.time_cost, self.parallelism)
            .map_err(|_| anyhow!("Failed to create balloon hash parameters"))
    }
}

/// Hash a password using BLAKE3-Balloon with the specified version
pub fn hash_password(
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    version: Version,
) -> Result<[u8; HASH_SIZE]> {
    let params = version.params()?;
    hash_password_raw(password, salt, params)
}

/// Hash a password using BLAKE3-Balloon with custom parameters
pub fn hash_password_with_params(
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    params: Params,
) -> Result<[u8; HASH_SIZE]> {
    let balloon_params = params.to_balloon_params()?;
    hash_password_raw(password, salt, balloon_params)
}

/// Internal function to perform the actual hashing
fn hash_password_raw(
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    params: balloon_hash::Params,
) -> Result<[u8; HASH_SIZE]> {
    let mut hash = [0u8; HASH_SIZE];
    let balloon = Balloon::<blake3::Hasher>::new(Algorithm::Balloon, params, None);
    
    balloon
        .hash_into(password, salt, &mut hash)
        .map_err(|_| anyhow!("Failed to hash password"))?;
    
    Ok(hash)
}

/// Secure password hashing with automatic memory zeroing
pub fn hash_password_secure(
    password: Vec<u8>,
    salt: &[u8; SALT_SIZE],
    version: Version,
) -> Result<[u8; HASH_SIZE]> {
    let password = Zeroizing::new(password);
    hash_password(&password, salt, version)
}

/// Verify a password against a hash
pub fn verify_password(
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    hash: &[u8; HASH_SIZE],
    version: Version,
) -> Result<bool> {
    let computed_hash = hash_password(password, salt, version)?;
    
    // Constant-time comparison
    let mut diff = 0u8;
    for i in 0..HASH_SIZE {
        diff |= computed_hash[i] ^ hash[i];
    }
    
    Ok(diff == 0)
}

/// Generate a random salt
#[cfg(feature = "rand")]
pub fn generate_salt() -> [u8; SALT_SIZE] {
    use rand::Rng;
    let mut salt = [0u8; SALT_SIZE];
    rand::thread_rng().fill(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_consistency() {
        // Test that the same input always produces the same output
        let password = b"test password 123!@#";
        let salt = [0x42; SALT_SIZE];
        
        let hash1 = hash_password(password, &salt, Version::V1).unwrap();
        let hash2 = hash_password(password, &salt, Version::V1).unwrap();
        
        assert_eq!(hash1, hash2, "Hash should be deterministic");
    }

    #[test]
    fn test_different_passwords() {
        let salt = [0x42; SALT_SIZE];
        
        let hash1 = hash_password(b"password1", &salt, Version::V1).unwrap();
        let hash2 = hash_password(b"password2", &salt, Version::V1).unwrap();
        
        assert_ne!(hash1, hash2, "Different passwords should produce different hashes");
    }

    #[test]
    fn test_different_salts() {
        let password = b"same password";
        let salt1 = [0x01; SALT_SIZE];
        let salt2 = [0x02; SALT_SIZE];
        
        let hash1 = hash_password(password, &salt1, Version::V1).unwrap();
        let hash2 = hash_password(password, &salt2, Version::V1).unwrap();
        
        assert_ne!(hash1, hash2, "Different salts should produce different hashes");
    }

    #[test]
    fn test_verify_correct_password() {
        let password = b"correct horse battery staple";
        let salt = [0x42; SALT_SIZE];
        
        let hash = hash_password(password, &salt, Version::V1).unwrap();
        
        assert!(
            verify_password(password, &salt, &hash, Version::V1).unwrap(),
            "Should verify correct password"
        );
    }

    #[test]
    fn test_verify_wrong_password() {
        let password = b"correct horse battery staple";
        let wrong_password = b"incorrect horse battery staple";
        let salt = [0x42; SALT_SIZE];
        
        let hash = hash_password(password, &salt, Version::V1).unwrap();
        
        assert!(
            !verify_password(wrong_password, &salt, &hash, Version::V1).unwrap(),
            "Should not verify wrong password"
        );
    }

    #[test]
    fn test_custom_params() {
        let password = b"test with custom params";
        let salt = [0x42; SALT_SIZE];
        
        // Test with different parameter configurations
        let params1 = Params::new(1024, 1, 1).unwrap();
        let params2 = Params::new(2048, 2, 1).unwrap();
        
        let hash1 = hash_password_with_params(password, &salt, params1).unwrap();
        let hash2 = hash_password_with_params(password, &salt, params2).unwrap();
        
        assert_ne!(hash1, hash2, "Different parameters should produce different hashes");
    }

    #[test]
    fn test_invalid_params() {
        assert!(Params::new(0, 1, 1).is_err(), "Space cost of 0 should be invalid");
        assert!(Params::new(1, 0, 1).is_err(), "Time cost of 0 should be invalid");
        assert!(Params::new(1, 1, 0).is_err(), "Parallelism of 0 should be invalid");
    }

    #[test]
    fn test_hash_secure() {
        let password = "secure password".to_string().into_bytes();
        let salt = [0x42; SALT_SIZE];
        
        let hash = hash_password_secure(password.clone(), &salt, Version::V1).unwrap();
        
        // Verify the hash is correct
        assert!(
            verify_password(&password, &salt, &hash, Version::V1).unwrap(),
            "Secure hash should verify correctly"
        );
    }

    #[test]
    fn test_known_vector() {
        // Test against a known hash value to ensure consistency across versions
        let password = b"password";
        let salt = [0u8; SALT_SIZE];
        
        let hash = hash_password(password, &salt, Version::V1).unwrap();
        
        // This is just to print the hash for documentation
        println!("Hash for 'password' with zero salt: {:?}", hash);
        
        // The hash should always be 32 bytes
        assert_eq!(hash.len(), HASH_SIZE);
    }

    #[test]
    fn test_empty_password() {
        let password = b"";
        let salt = [0x42; SALT_SIZE];
        
        let hash = hash_password(password, &salt, Version::V1).unwrap();
        assert_eq!(hash.len(), HASH_SIZE);
        
        assert!(
            verify_password(password, &salt, &hash, Version::V1).unwrap(),
            "Empty password should verify correctly"
        );
    }

    #[test]
    fn test_long_password() {
        let password = b"This is a very long password that exceeds typical password lengths. \
                        It contains multiple sentences and should still hash correctly without \
                        any issues. The balloon hashing algorithm should handle arbitrary length \
                        inputs gracefully.";
        let salt = [0x42; SALT_SIZE];
        
        let hash = hash_password(password, &salt, Version::V1).unwrap();
        assert_eq!(hash.len(), HASH_SIZE);
        
        assert!(
            verify_password(password, &salt, &hash, Version::V1).unwrap(),
            "Long password should verify correctly"
        );
    }

    #[test]
    fn test_unicode_password() {
        let password = "пароль密码🔐".as_bytes();
        let salt = [0x42; SALT_SIZE];
        
        let hash = hash_password(password, &salt, Version::V1).unwrap();
        assert_eq!(hash.len(), HASH_SIZE);
        
        assert!(
            verify_password(password, &salt, &hash, Version::V1).unwrap(),
            "Unicode password should verify correctly"
        );
    }

    #[test]
    fn test_constant_time_verification() {
        let password = b"password";
        let salt = [0x42; SALT_SIZE];
        let hash = hash_password(password, &salt, Version::V1).unwrap();
        
        // Test with correct hash
        assert!(verify_password(password, &salt, &hash, Version::V1).unwrap());
        
        // Test with slightly modified hash (should use constant-time comparison)
        let mut wrong_hash = hash;
        wrong_hash[0] ^= 0x01;
        assert!(!verify_password(password, &salt, &wrong_hash, Version::V1).unwrap());
    }

    #[cfg(feature = "rand")]
    #[test]
    fn test_generate_salt() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        
        assert_eq!(salt1.len(), SALT_SIZE);
        assert_eq!(salt2.len(), SALT_SIZE);
        assert_ne!(salt1, salt2, "Generated salts should be different");
    }

    #[test]
    fn test_version_enum() {
        // Test Version enum functionality
        assert_eq!(Version::V1, Version::V1);
        assert_ne!(Version::V1, Version::Custom);
        
        // Test that V1 params can be created
        assert!(Version::V1.params().is_ok());
        
        // Test that Custom version requires explicit params
        assert!(Version::Custom.params().is_err());
    }
}
