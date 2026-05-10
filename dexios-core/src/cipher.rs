//! This module provides direct AEAD helpers for memory-mode style encryption and
//! decryption.
//!
//! The data is processed in one shot rather than through the LE31 stream layer.
//! In the current Dexios CLI, this path is mainly relevant for compatibility
//! and wrapped-master-key handling rather than new file encryption.
//!
//! # Examples
//! ```rust,ignore
//! // obviously the key should contain data, not be an empty vec
//! let raw_key = Protected::new(vec![0u8; 128]);
//! let salt = dexios_core::kdf::Salt::new([9u8; 16]);
//! let key = dexios_core::primitives::WrappingKey::from(
//!     dexios_core::kdf::Kdf::Blake3Balloon.derive(raw_key, &salt).unwrap(),
//! );
//!
//! let master_key = dexios_core::primitives::MasterKey::new([7u8; 32]);
//!
//! let nonce = gen_keyslot_nonce();
//! let encrypted = dexios_core::cipher::wrap_v1_master_key(key, &master_key, &nonce).unwrap();
//!
//! let key = dexios_core::primitives::WrappingKey::new([9u8; 32]);
//! let _ = dexios_core::cipher::unwrap_v1_master_key(key, &encrypted, &nonce);
//! ```

use std::fmt::{Display, Formatter};

use aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use zeroize::Zeroize;

use crate::header::common::KeyslotNonce;
use crate::header::v1::EncryptedMasterKey;
use crate::primitives::{MasterKey, WrappingKey};

#[derive(Debug)]
pub enum CipherError {
    CipherInit,
    Authentication,
    InvalidMasterKeyLength(usize),
    InvalidEncryptedMasterKeyLength(usize),
}

impl Display for CipherError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CipherInit => f.write_str("unable to initialize V1 cipher"),
            Self::Authentication => f.write_str("V1 cipher authentication failed"),
            Self::InvalidMasterKeyLength(len) => {
                write!(f, "invalid decrypted V1 master key length: {len}")
            }
            Self::InvalidEncryptedMasterKeyLength(len) => {
                write!(f, "invalid encrypted V1 master key length: {len}")
            }
        }
    }
}

impl std::error::Error for CipherError {}

pub fn wrap_v1_master_key(
    wrapping_key: WrappingKey,
    master_key: &MasterKey,
    nonce: &KeyslotNonce,
) -> Result<EncryptedMasterKey, CipherError> {
    let cipher = Ciphers::initialize(wrapping_key)?;
    let encrypted =
        master_key.with_exposed(|master_key| cipher.encrypt(nonce, master_key.as_slice()))?;
    EncryptedMasterKey::try_from_slice(&encrypted)
        .map_err(|_| CipherError::InvalidEncryptedMasterKeyLength(encrypted.len()))
}

pub fn unwrap_v1_master_key(
    wrapping_key: WrappingKey,
    encrypted_master_key: &EncryptedMasterKey,
    nonce: &KeyslotNonce,
) -> Result<MasterKey, CipherError> {
    let cipher = Ciphers::initialize(wrapping_key)?;
    let mut decrypted = cipher.decrypt(nonce, encrypted_master_key.as_bytes().as_slice())?;
    if decrypted.len() != crate::primitives::MASTER_KEY_LEN {
        let len = decrypted.len();
        decrypted.zeroize();
        return Err(CipherError::InvalidMasterKeyLength(len));
    }

    let mut master_key = [0u8; crate::primitives::MASTER_KEY_LEN];
    master_key.copy_from_slice(&decrypted);
    decrypted.zeroize();
    Ok(MasterKey::new(master_key))
}

/// Direct AEAD helper for the single supported Dexios suite.
pub(crate) struct Ciphers(Box<XChaCha20Poly1305>);

impl Ciphers {
    /// This can be used to quickly initialise a `Cipher`
    ///
    /// The returned `Cipher` can be used for both encryption and decryption
    ///
    /// You just need to provide a derived 32-byte key.
    ///
    /// # Examples
    /// ```rust,ignore
    /// // obviously the key should contain data, not be an empty vec
    /// let raw_key = Protected::new(vec![0u8; 128]);
    /// let salt = dexios_core::kdf::Salt::new([9u8; 16]);
    /// let key = dexios_core::primitives::WrappingKey::from(
    ///     dexios_core::kdf::Kdf::Blake3Balloon.derive(raw_key, &salt).unwrap(),
    /// );
    /// let cipher = Ciphers::initialize(key).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the hashed key cannot initialize the fixed cipher.
    pub(crate) fn initialize(key: WrappingKey) -> Result<Self, CipherError> {
        let cipher = key.with_exposed(|key| {
            XChaCha20Poly1305::new_from_slice(key).map_err(|_| CipherError::CipherInit)
        })?;

        Ok(Self(Box::new(cipher)))
    }

    /// This can be used to encrypt data with a given `Ciphers` object
    ///
    /// It requires the nonce, and either some plaintext, or an `aead::Payload` (that contains the plaintext and the AAD)
    ///
    /// # Errors
    ///
    /// Returns an error if the AEAD rejects the supplied nonce, plaintext, or AAD.
    pub(crate) fn encrypt<'msg, 'aad>(
        &self,
        nonce: &KeyslotNonce,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, CipherError> {
        self.0
            .encrypt(nonce.as_bytes().as_ref().into(), plaintext)
            .map_err(|_| CipherError::Authentication)
    }

    /// This can be used to decrypt data with a given `Ciphers` object
    ///
    /// It requires the nonce used for encryption, and either some plaintext, or an `aead::Payload` (that contains the plaintext and the AAD)
    ///
    /// NOTE: The data will not decrypt successfully if an AAD was provided for encryption, but is not present/has been modified while decrypting
    ///
    /// # Errors
    ///
    /// Returns an error if the AEAD rejects the supplied nonce, ciphertext, or AAD.
    pub(crate) fn decrypt<'msg, 'aad>(
        &self,
        nonce: &KeyslotNonce,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, CipherError> {
        self.0
            .decrypt(nonce.as_bytes().as_ref().into(), ciphertext)
            .map_err(|_| CipherError::Authentication)
    }
}
