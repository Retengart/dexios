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
//!     dexios_core::kdf::Kdf::Argon2id.derive(&raw_key, &salt).unwrap(),
//! );
//!
//! let master_key = dexios_core::primitives::MasterKey::new([7u8; 32]);
//!
//! let nonce = gen_keyslot_nonce();
//! let aad = b"slot-scoped metadata";
//! let encrypted = dexios_core::cipher::wrap_v1_master_key(key, &master_key, &nonce, aad).unwrap();
//!
//! let key = dexios_core::primitives::WrappingKey::new([9u8; 32]);
//! let _ = dexios_core::cipher::unwrap_v1_master_key(key, &encrypted, &nonce, aad);
//! ```

use std::fmt::{Display, Formatter};

use aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;

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

/// Wraps `master_key` under `wrapping_key` with XChaCha20-Poly1305 and the
/// slot-scoped `aad`.
///
/// # Nonce uniqueness (safety contract)
///
/// `nonce` MUST be unique for every `(wrapping_key, master_key)` pairing. Reusing a
/// nonce under the same derived wrapping key while wrapping different master keys
/// leaks the XOR of the two key streams and breaks Poly1305 integrity. Callers MUST
/// source `nonce` from [`crate::primitives::gen_keyslot_nonce`] (a fresh 24-byte
/// CSPRNG value) for every keyslot. Dexios's own workflows pair a fresh
/// `gen_keyslot_nonce()` with a fresh salt for every slot mutation.
pub fn wrap_v1_master_key(
    wrapping_key: WrappingKey,
    master_key: &MasterKey,
    nonce: &KeyslotNonce,
    aad: &[u8],
) -> Result<EncryptedMasterKey, CipherError> {
    let cipher = Ciphers::initialize(wrapping_key)?;
    let encrypted = master_key.with_exposed(|master_key| {
        cipher.encrypt(
            nonce,
            Payload {
                msg: master_key.as_slice(),
                aad,
            },
        )
    })?;
    EncryptedMasterKey::try_from_slice(&encrypted)
        .map_err(|_| CipherError::InvalidEncryptedMasterKeyLength(encrypted.len()))
}

/// Unwraps a master key produced by [`wrap_v1_master_key`].
///
/// # Nonce uniqueness
///
/// `nonce` MUST be the exact unique nonce used at wrap time; it is bound into the
/// XChaCha20-Poly1305 authentication and any mismatch fails with
/// [`CipherError::Authentication`].
pub fn unwrap_v1_master_key(
    wrapping_key: WrappingKey,
    encrypted_master_key: &EncryptedMasterKey,
    nonce: &KeyslotNonce,
    aad: &[u8],
) -> Result<MasterKey, CipherError> {
    use aead::AeadInPlace;
    use zeroize::Zeroizing;

    let cipher = Ciphers::initialize(wrapping_key)?;

    // ENCRYPTED_MASTER_KEY_LEN = 48 = 32-byte key + 16-byte tag. Decrypt the 32-byte
    // buffer in place so the AEAD does not allocate and hand back a separate plaintext
    // Vec that would then need best-effort zeroizing (mem-3).
    let bytes = encrypted_master_key.as_bytes();
    let mut buffer: Zeroizing<[u8; crate::primitives::MASTER_KEY_LEN]> =
        Zeroizing::new([0u8; crate::primitives::MASTER_KEY_LEN]);
    buffer.copy_from_slice(&bytes[..crate::primitives::MASTER_KEY_LEN]);
    let tag = aead::Tag::<XChaCha20Poly1305>::from_slice(&bytes[crate::primitives::MASTER_KEY_LEN..]);

    cipher
        .0
        .decrypt_in_place_detached(
            nonce.as_bytes().as_ref().into(),
            aad,
            buffer.as_mut_slice(),
            tag,
        )
        .map_err(|_| CipherError::Authentication)?;

    Ok(MasterKey::new(*buffer))
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
    ///     dexios_core::kdf::Kdf::Argon2id.derive(&raw_key, &salt).unwrap(),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::{Kdf, Salt};
    use crate::protected::Protected;

    fn wrapping_key() -> WrappingKey {
        let raw = Protected::new(vec![7u8; 32]);
        WrappingKey::from(Kdf::Argon2id.derive(&raw, &Salt::new([9u8; 16])).unwrap())
    }

    #[test]
    fn wrap_then_unwrap_round_trips_and_tamper_fails() {
        let nonce = KeyslotNonce::new([3u8; 24]);
        let mk = MasterKey::new([42u8; 32]);
        let aad = b"slot-aad";

        let wrapped = wrap_v1_master_key(wrapping_key(), &mk, &nonce, aad).unwrap();
        let unwrapped = unwrap_v1_master_key(wrapping_key(), &wrapped, &nonce, aad).unwrap();
        assert!(mk.same_secret_as(&unwrapped));

        let mut tampered = *wrapped.as_bytes();
        tampered[0] ^= 0x01;
        let tampered = EncryptedMasterKey::new(tampered);
        assert!(matches!(
            unwrap_v1_master_key(wrapping_key(), &tampered, &nonce, aad),
            Err(CipherError::Authentication)
        ));
    }
}
