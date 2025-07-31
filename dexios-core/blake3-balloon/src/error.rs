//! Error types for BLAKE3-Balloon operations
//!
//! This module defines the error types that can occur during BLAKE3-Balloon
//! password hashing operations.

use thiserror::Error;

/// Errors that can occur during BLAKE3-Balloon operations
#[derive(Error, Debug)]
pub enum Blake3BalloonError {
    /// Error occurred while initializing balloon hashing parameters
    #[error("Failed to initialize balloon hashing parameters: {0}")]
    ParameterInit(String),

    /// Error occurred during the hashing process
    #[error("Failed to hash password with BLAKE3-Balloon: {0}")]
    HashingFailed(String),

    /// Invalid parameter version provided
    #[error("Unsupported parameter version: {version}. Supported versions: {supported:?}")]
    UnsupportedVersion {
        version: u32,
        supported: Vec<u32>,
    },

    /// Invalid salt length
    #[error("Invalid salt length: expected {expected} bytes, got {actual} bytes")]
    InvalidSaltLength { expected: usize, actual: usize },

    /// Invalid password length (empty password)
    #[error("Password cannot be empty")]
    EmptyPassword,

    /// Internal balloon hash crate error
    #[error("Balloon hash internal error: {0}")]
    BalloonHashError(#[from] balloon_hash::Error),
}

/// Result type alias for BLAKE3-Balloon operations
pub type Result<T> = std::result::Result<T, Blake3BalloonError>;