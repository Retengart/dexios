//! This module contains all cryptographic primitives used by `dexios-core`
use crate::header::common::{KeyslotNonce, PayloadNonce};
use crate::kdf::DERIVED_KEY_LEN;
use crate::protected::Protected;
use rand::Rng;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// This is the streaming block size
///
/// NOTE: Stream mode can be used to encrypt files less than this size, provided the implementation
/// is correct
pub const BLOCK_SIZE: usize = 1_048_576; // 1024*1024 bytes

/// This is the length of the salt used for password hashing
pub const SALT_LEN: usize = 16; // bytes

pub const MASTER_KEY_LEN: usize = 32;
pub const ENCRYPTED_MASTER_KEY_LEN: usize = 48;
pub const PAYLOAD_NONCE_LEN: usize = 20;
pub const KEYSLOT_NONCE_LEN: usize = 24;

pub struct MasterKey(Protected<[u8; MASTER_KEY_LEN]>);

impl MasterKey {
    #[must_use]
    pub fn new(mut bytes: [u8; MASTER_KEY_LEN]) -> Self {
        let protected = Protected::new(bytes);
        bytes.zeroize();
        Self(protected)
    }

    #[must_use]
    pub fn from_protected(key: Protected<[u8; MASTER_KEY_LEN]>) -> Self {
        Self(key)
    }

    #[must_use]
    pub(crate) fn with_exposed<R>(&self, f: impl FnOnce(&[u8; MASTER_KEY_LEN]) -> R) -> R {
        self.0.with_exposed(f)
    }

    #[must_use]
    pub fn same_secret_as(&self, other: &Self) -> bool {
        self.with_exposed(|left| other.with_exposed(|right| bool::from(left.ct_eq(right))))
    }
}

impl From<Protected<[u8; MASTER_KEY_LEN]>> for MasterKey {
    fn from(value: Protected<[u8; MASTER_KEY_LEN]>) -> Self {
        Self::from_protected(value)
    }
}

pub struct WrappingKey(Protected<[u8; DERIVED_KEY_LEN]>);

impl WrappingKey {
    #[must_use]
    pub fn new(mut bytes: [u8; DERIVED_KEY_LEN]) -> Self {
        let protected = Protected::new(bytes);
        bytes.zeroize();
        Self(protected)
    }

    #[must_use]
    pub fn from_protected(key: Protected<[u8; DERIVED_KEY_LEN]>) -> Self {
        Self(key)
    }

    #[must_use]
    pub(crate) fn with_exposed<R>(&self, f: impl FnOnce(&[u8; DERIVED_KEY_LEN]) -> R) -> R {
        self.0.with_exposed(f)
    }
}

impl From<Protected<[u8; DERIVED_KEY_LEN]>> for WrappingKey {
    fn from(value: Protected<[u8; DERIVED_KEY_LEN]>) -> Self {
        Self::from_protected(value)
    }
}

#[must_use]
pub fn gen_payload_nonce() -> PayloadNonce {
    let mut nonce = [0u8; PAYLOAD_NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    PayloadNonce::new(nonce)
}

#[must_use]
pub fn gen_keyslot_nonce() -> KeyslotNonce {
    let mut nonce = [0u8; KEYSLOT_NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    KeyslotNonce::new(nonce)
}

/// Generates a new protected master key of the specified `MASTER_KEY_LEN`.
///
/// This can be used to generate a master key for encryption.
/// It uses `ThreadRng` to securely generate completely random bytes, with extra protection
/// from some side-channel attacks
///
/// # Examples
///
/// ```rust
/// # use dexios_core::primitives::*;
/// let master_key = gen_master_key();
/// ```
///
#[must_use]
pub fn gen_master_key() -> MasterKey {
    let mut master_key = [0u8; MASTER_KEY_LEN];
    rand::rng().fill_bytes(&mut master_key);
    let protected = MasterKey::new(master_key);
    master_key.zeroize();
    protected
}

/// Generates a salt, of the specified `SALT_LEN`
///
/// This salt can be used at the current Argon2id KDF boundary.
///
/// # Examples
///
/// ```rust
/// # use dexios_core::primitives::*;
/// let salt = gen_salt();
/// ```
///
#[must_use]
pub fn gen_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    salt
}
