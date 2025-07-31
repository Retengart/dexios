//! Parameter definitions for BLAKE3-Balloon hashing
//!
//! This module defines the parameter sets used for different versions
//! of BLAKE3-Balloon hashing, providing both security and compatibility.

use crate::error::{Blake3BalloonError, Result};
use balloon_hash::Params as BalloonParams;

/// Standard salt length for BLAKE3-Balloon hashing (16 bytes)
pub const SALT_LEN: usize = 16;

/// Output length for BLAKE3-Balloon hashing (32 bytes)
pub const OUTPUT_LEN: usize = 32;

/// Parameter versions supported by BLAKE3-Balloon
///
/// Each version represents a specific set of parameters that have been
/// tested and validated for security. Different versions may have different
/// memory and time costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParameterVersion {
    /// Version 4 parameters - Legacy support
    V4,
    /// Version 5 parameters - Current recommended parameters
    V5,
}

impl ParameterVersion {
    /// Returns all supported parameter versions
    ///
    /// # Examples
    ///
    /// ```rust
    /// use blake3_balloon::ParameterVersion;
    ///
    /// let versions = ParameterVersion::supported_versions();
    /// assert!(versions.contains(&ParameterVersion::V5));
    /// ```
    #[must_use]
    pub fn supported_versions() -> Vec<Self> {
        vec![Self::V4, Self::V5]
    }

    /// Returns the latest/recommended parameter version
    ///
    /// # Examples
    ///
    /// ```rust
    /// use blake3_balloon::ParameterVersion;
    ///
    /// let latest = ParameterVersion::latest();
    /// assert_eq!(latest, ParameterVersion::V5);
    /// ```
    #[must_use]
    pub fn latest() -> Self {
        Self::V5
    }

    /// Converts a numeric version to a ParameterVersion
    ///
    /// # Arguments
    ///
    /// * `version` - The numeric version to convert
    ///
    /// # Errors
    ///
    /// Returns an error if the version is not supported
    ///
    /// # Examples
    ///
    /// ```rust
    /// use blake3_balloon::ParameterVersion;
    ///
    /// let version = ParameterVersion::from_u32(5).unwrap();
    /// assert_eq!(version, ParameterVersion::V5);
    /// ```
    pub fn from_u32(version: u32) -> Result<Self> {
        match version {
            4 => Ok(Self::V4),
            5 => Ok(Self::V5),
            _ => Err(Blake3BalloonError::UnsupportedVersion {
                version,
                supported: Self::supported_versions()
                    .into_iter()
                    .map(|v| v.to_u32())
                    .collect(),
            }),
        }
    }

    /// Converts the ParameterVersion to a numeric value
    ///
    /// # Examples
    ///
    /// ```rust
    /// use blake3_balloon::ParameterVersion;
    ///
    /// assert_eq!(ParameterVersion::V5.to_u32(), 5);
    /// ```
    #[must_use]
    pub fn to_u32(self) -> u32 {
        match self {
            Self::V4 => 4,
            Self::V5 => 5,
        }
    }

    /// Gets the balloon hash parameters for this version
    ///
    /// # Errors
    ///
    /// Returns an error if the parameters cannot be initialized
    ///
    /// # Examples
    ///
    /// ```rust
    /// use blake3_balloon::ParameterVersion;
    ///
    /// let params = ParameterVersion::V5.balloon_params().unwrap();
    /// ```
    pub fn balloon_params(self) -> Result<BalloonParams> {
        let params = match self {
            Self::V4 => {
                // V4 parameters - these are legacy parameters
                // Memory cost: ~256KB, Time cost: 1, Parallelism: 1
                BalloonParams::new(262_144, 1, 1)
                    .map_err(|e| Blake3BalloonError::ParameterInit(e.to_string()))?
            }
            Self::V5 => {
                // V5 parameters - current recommended parameters
                // Memory cost: ~272KB, Time cost: 1, Parallelism: 1
                // These parameters are designed to provide good security
                // while maintaining reasonable performance
                BalloonParams::new(278_528, 1, 1)
                    .map_err(|e| Blake3BalloonError::ParameterInit(e.to_string()))?
            }
        };

        Ok(params)
    }

    /// Gets a human-readable description of the parameter set
    ///
    /// # Examples
    ///
    /// ```rust
    /// use blake3_balloon::ParameterVersion;
    ///
    /// let description = ParameterVersion::V5.description();
    /// assert!(description.contains("Current recommended"));
    /// ```
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::V4 => "Legacy parameters (256KB memory cost)",
            Self::V5 => "Current recommended parameters (272KB memory cost)",
        }
    }
}

impl std::fmt::Display for ParameterVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BLAKE3-Balloon v{}", self.to_u32())
    }
}

impl Default for ParameterVersion {
    fn default() -> Self {
        Self::latest()
    }
}

/// Configuration for BLAKE3-Balloon hashing operations
///
/// This struct encapsulates all the parameters needed for a BLAKE3-Balloon
/// hashing operation, including the parameter version and any optional settings.
#[derive(Debug, Clone)]
pub struct Blake3BalloonConfig {
    /// The parameter version to use
    pub version: ParameterVersion,
}

impl Blake3BalloonConfig {
    /// Creates a new configuration with the specified version
    ///
    /// # Arguments
    ///
    /// * `version` - The parameter version to use
    ///
    /// # Examples
    ///
    /// ```rust
    /// use blake3_balloon::{Blake3BalloonConfig, ParameterVersion};
    ///
    /// let config = Blake3BalloonConfig::new(ParameterVersion::V5);
    /// ```
    #[must_use]
    pub fn new(version: ParameterVersion) -> Self {
        Self { version }
    }

    /// Creates a configuration with the latest recommended parameters
    ///
    /// # Examples
    ///
    /// ```rust
    /// use blake3_balloon::Blake3BalloonConfig;
    ///
    /// let config = Blake3BalloonConfig::recommended();
    /// ```
    #[must_use]
    pub fn recommended() -> Self {
        Self::new(ParameterVersion::latest())
    }

    /// Creates a configuration with legacy V4 parameters
    ///
    /// This is primarily for compatibility with older hashes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use blake3_balloon::Blake3BalloonConfig;
    ///
    /// let config = Blake3BalloonConfig::legacy_v4();
    /// ```
    #[must_use]
    pub fn legacy_v4() -> Self {
        Self::new(ParameterVersion::V4)
    }
}

impl Default for Blake3BalloonConfig {
    fn default() -> Self {
        Self::recommended()
    }
}