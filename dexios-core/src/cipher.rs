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
//! let key = dexios_core::kdf::Kdf::Blake3Balloon.derive(raw_key, &salt).unwrap();
//! let cipher = Ciphers::initialize(key).unwrap();
//!
//! let secret = "super secret information";
//!
//! let nonce = gen_keyslot_nonce();
//! let encrypted_data = cipher.encrypt(nonce.as_bytes(), secret.as_bytes()).unwrap();
//!
//! let decrypted_data = cipher.decrypt(nonce.as_bytes(), encrypted_data.as_slice()).unwrap();
//!
//! assert_eq!(secret, decrypted_data);
//! ```

use aead::{Aead, AeadInPlace, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;

use crate::protected::Protected;

/// Direct AEAD helper for the single supported Dexios suite.
pub struct Ciphers(Box<XChaCha20Poly1305>);

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
    /// let key = dexios_core::kdf::Kdf::Blake3Balloon.derive(raw_key, &salt).unwrap();
    /// let cipher = Ciphers::initialize(key).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the hashed key cannot initialize the fixed cipher.
    pub fn initialize(key: Protected<[u8; 32]>) -> anyhow::Result<Self> {
        let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
            .map_err(|_| anyhow::anyhow!("Unable to create cipher with hashed key."))?;

        drop(key);
        Ok(Self(Box::new(cipher)))
    }

    /// This can be used to encrypt data with a given `Ciphers` object
    ///
    /// It requires the nonce, and either some plaintext, or an `aead::Payload` (that contains the plaintext and the AAD)
    ///
    /// # Errors
    ///
    /// Returns an error if the AEAD rejects the supplied nonce, plaintext, or AAD.
    pub fn encrypt<'msg, 'aad>(
        &self,
        nonce: &[u8],
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        self.0.encrypt(nonce.as_ref().into(), plaintext)
    }

    /// This encrypts the provided buffer in place with the supplied nonce and AAD.
    ///
    /// # Errors
    ///
    /// Returns an error if the AEAD rejects the supplied nonce, buffer contents, or AAD.
    pub fn encrypt_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut dyn aead::Buffer,
    ) -> Result<(), aead::Error> {
        self.0.encrypt_in_place(nonce.as_ref().into(), aad, buffer)
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
    pub fn decrypt<'msg, 'aad>(
        &self,
        nonce: &[u8],
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        self.0.decrypt(nonce.as_ref().into(), ciphertext)
    }
}
