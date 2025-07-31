//! Core BLAKE3-Balloon hashing implementation
//!
//! This module provides the main functionality for BLAKE3-Balloon password hashing,
//! combining the BLAKE3 cryptographic hash function with the Balloon hashing algorithm.

use crate::error::{Blake3BalloonError, Result};
use crate::params::{Blake3BalloonConfig, ParameterVersion, OUTPUT_LEN, SALT_LEN};
use crate::protected::Protected;
use balloon_hash::{Algorithm, Balloon};

/// A BLAKE3-Balloon password hasher
///
/// This struct provides a high-level interface for BLAKE3-Balloon password hashing
/// operations. It handles parameter management, memory security, and provides
/// both simple and advanced hashing interfaces.
///
/// # Examples
///
/// ```rust
/// use blake3_balloon::{Blake3BalloonHasher, ParameterVersion};
///
/// let hasher = Blake3BalloonHasher::new(ParameterVersion::V5);
/// let salt = [0u8; 16]; // In practice, use a random salt
/// let password = b"my-secure-password";
/// 
/// let hash = hasher.hash_password(password, &salt).unwrap();
/// ```
pub struct Blake3BalloonHasher {
    config: Blake3BalloonConfig,
}

impl Blake3BalloonHasher {
    /// Creates a new BLAKE3-Balloon hasher with the specified parameter version
    ///
    /// # Arguments
    ///
    /// * `version` - The parameter version to use for hashing
    ///
    /// # Examples
    ///
    /// ```rust
    /// use blake3_balloon::{Blake3BalloonHasher, ParameterVersion};
    ///
    /// let hasher = Blake3BalloonHasher::new(ParameterVersion::V5);
    /// ```
    #[must_use]
    pub fn new(version: ParameterVersion) -> Self {
        Self {
            config: Blake3BalloonConfig::new(version),
        }
    }

    /// Creates a new hasher with the recommended (latest) parameters
    ///
    /// # Examples
    ///
    /// ```rust
    /// use blake3_balloon::Blake3BalloonHasher;
    ///
    /// let hasher = Blake3BalloonHasher::recommended();
    /// ```
    #[must_use]
    pub fn recommended() -> Self {
        Self {
            config: Blake3BalloonConfig::recommended(),
        }
    }

    /// Creates a new hasher with legacy V4 parameters
    ///
    /// This is primarily for compatibility with older hashes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use blake3_balloon::Blake3BalloonHasher;
    ///
    /// let hasher = Blake3BalloonHasher::legacy_v4();
    /// ```
    #[must_use]
    pub fn legacy_v4() -> Self {
        Self {
            config: Blake3BalloonConfig::legacy_v4(),
        }
    }

    /// Gets the parameter version used by this hasher
    ///
    /// # Examples
    ///
    /// ```rust
    /// use blake3_balloon::{Blake3BalloonHasher, ParameterVersion};
    ///
    /// let hasher = Blake3BalloonHasher::new(ParameterVersion::V5);
    /// assert_eq!(hasher.version(), ParameterVersion::V5);
    /// ```
    #[must_use]
    pub fn version(&self) -> ParameterVersion {
        self.config.version
    }

    /// Hashes a password with the given salt
    ///
    /// This is the main hashing function that takes a password and salt,
    /// and returns a securely generated hash using BLAKE3-Balloon.
    ///
    /// # Arguments
    ///
    /// * `password` - The password to hash
    /// * `salt` - A 16-byte salt (must be cryptographically random)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The password is empty
    /// - The salt length is incorrect
    /// - The hashing process fails
    ///
    /// # Examples
    ///
    /// ```rust
    /// use blake3_balloon::Blake3BalloonHasher;
    ///
    /// let hasher = Blake3BalloonHasher::recommended();
    /// let salt = [0u8; 16]; // Use random salt in practice
    /// let password = b"my-secure-password";
    ///
    /// let hash = hasher.hash_password(password, &salt).unwrap();
    /// assert_eq!(hash.len(), 32);
    /// ```
    pub fn hash_password(&self, password: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; OUTPUT_LEN]> {
        if password.is_empty() {
            return Err(Blake3BalloonError::EmptyPassword);
        }

        let params = self.config.version.balloon_params()?;
        let balloon = Balloon::<blake3::Hasher>::new(Algorithm::Balloon, params, None);
        
        let mut output = [0u8; OUTPUT_LEN];
        balloon
            .hash_into(password, salt, &mut output)
            .map_err(|e| Blake3BalloonError::HashingFailed(e.to_string()))?;

        Ok(output)
    }

    /// Hashes a protected password with the given salt
    ///
    /// This method accepts a `Protected` password, which ensures the password
    /// is securely handled in memory and automatically zeroized after use.
    ///
    /// # Arguments
    ///
    /// * `password` - The protected password to hash
    /// * `salt` - A 16-byte salt (must be cryptographically random)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The password is empty
    /// - The salt length is incorrect
    /// - The hashing process fails
    ///
    /// # Examples
    ///
    /// ```rust
    /// use blake3_balloon::{Blake3BalloonHasher, Protected};
    ///
    /// let hasher = Blake3BalloonHasher::recommended();
    /// let salt = [0u8; 16]; // Use random salt in practice
    /// let password = Protected::new(b"my-secure-password".to_vec());
    ///
    /// let hash = hasher.hash_protected_password(password, &salt).unwrap();
    /// ```
    pub fn hash_protected_password(
        &self,
        password: Protected<Vec<u8>>,
        salt: &[u8; SALT_LEN],
    ) -> Result<Protected<[u8; OUTPUT_LEN]>> {
        if password.expose().is_empty() {
            return Err(Blake3BalloonError::EmptyPassword);
        }

        let params = self.config.version.balloon_params()?;
        let balloon = Balloon::<blake3::Hasher>::new(Algorithm::Balloon, params, None);
        
        let mut output = [0u8; OUTPUT_LEN];
        balloon
            .hash_into(password.expose(), salt, &mut output)
            .map_err(|e| Blake3BalloonError::HashingFailed(e.to_string()))?;

        // Password is automatically zeroized when dropped
        drop(password);

        Ok(Protected::new(output))
    }

    /// Verifies a password against a hash
    ///
    /// This is a constant-time comparison that checks if the provided password
    /// produces the same hash when using the same salt.
    ///
    /// # Arguments
    ///
    /// * `password` - The password to verify
    /// * `salt` - The salt used for the original hash
    /// * `expected_hash` - The expected hash to compare against
    ///
    /// # Errors
    ///
    /// Returns an error if the hashing process fails
    ///
    /// # Examples
    ///
    /// ```rust
    /// use blake3_balloon::Blake3BalloonHasher;
    ///
    /// let hasher = Blake3BalloonHasher::recommended();
    /// let salt = [0u8; 16];
    /// let password = b"my-secure-password";
    ///
    /// let hash = hasher.hash_password(password, &salt).unwrap();
    /// let is_valid = hasher.verify_password(password, &salt, &hash).unwrap();
    /// assert!(is_valid);
    /// ```
    pub fn verify_password(
        &self,
        password: &[u8],
        salt: &[u8; SALT_LEN],
        expected_hash: &[u8; OUTPUT_LEN],
    ) -> Result<bool> {
        let computed_hash = self.hash_password(password, salt)?;
        
        // Constant-time comparison to prevent timing attacks
        Ok(constant_time_eq(&computed_hash, expected_hash))
    }
}

impl Default for Blake3BalloonHasher {
    fn default() -> Self {
        Self::recommended()
    }
}

/// Convenience function for hashing a password with BLAKE3-Balloon
///
/// This function provides a simple interface for one-off password hashing
/// operations using the recommended parameters.
///
/// # Arguments
///
/// * `password` - The password to hash
/// * `salt` - A 16-byte salt (must be cryptographically random)
///
/// # Errors
///
/// Returns an error if the hashing process fails
///
/// # Examples
///
/// ```rust
/// use blake3_balloon::hash_password;
///
/// let salt = [0u8; 16]; // Use random salt in practice
/// let password = b"my-secure-password";
///
/// let hash = hash_password(password, &salt).unwrap();
/// assert_eq!(hash.len(), 32);
/// ```
pub fn hash_password(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; OUTPUT_LEN]> {
    let hasher = Blake3BalloonHasher::recommended();
    hasher.hash_password(password, salt)
}

/// Convenience function for hashing a protected password with BLAKE3-Balloon
///
/// This function provides a simple interface for one-off password hashing
/// operations using protected memory and the recommended parameters.
///
/// # Arguments
///
/// * `password` - The protected password to hash
/// * `salt` - A 16-byte salt (must be cryptographically random)
///
/// # Errors
///
/// Returns an error if the hashing process fails
///
/// # Examples
///
/// ```rust
/// use blake3_balloon::{hash_protected_password, Protected};
///
/// let salt = [0u8; 16]; // Use random salt in practice
/// let password = Protected::new(b"my-secure-password".to_vec());
///
/// let hash = hash_protected_password(password, &salt).unwrap();
/// ```
pub fn hash_protected_password(
    password: Protected<Vec<u8>>,
    salt: &[u8; SALT_LEN],
) -> Result<Protected<[u8; OUTPUT_LEN]>> {
    let hasher = Blake3BalloonHasher::recommended();
    hasher.hash_protected_password(password, salt)
}

/// Convenience function for verifying a password against a hash
///
/// # Arguments
///
/// * `password` - The password to verify
/// * `salt` - The salt used for the original hash
/// * `expected_hash` - The expected hash to compare against
///
/// # Errors
///
/// Returns an error if the hashing process fails
///
/// # Examples
///
/// ```rust
/// use blake3_balloon::{hash_password, verify_password};
///
/// let salt = [0u8; 16];
/// let password = b"my-secure-password";
///
/// let hash = hash_password(password, &salt).unwrap();
/// let is_valid = verify_password(password, &salt, &hash).unwrap();
/// assert!(is_valid);
/// ```
pub fn verify_password(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    expected_hash: &[u8; OUTPUT_LEN],
) -> Result<bool> {
    let hasher = Blake3BalloonHasher::recommended();
    hasher.verify_password(password, salt, expected_hash)
}

/// Constant-time equality comparison
///
/// This function compares two byte arrays in constant time to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}