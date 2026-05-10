//! This module contains all cryptographic primitives used by `dexios-core`
use crate::header::common::{KeyslotNonce, PayloadNonce};
use crate::protected::Protected;
use rand::Rng;

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
pub fn gen_master_key() -> Protected<[u8; MASTER_KEY_LEN]> {
    let mut master_key = [0u8; MASTER_KEY_LEN];
    rand::rng().fill_bytes(&mut master_key);
    Protected::new(master_key)
}

/// Generates a salt, of the specified `SALT_LEN`
///
/// This salt can be directly passed to `argon2id_hash()` or `balloon_hash()`
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
