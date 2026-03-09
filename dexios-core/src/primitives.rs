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

/// This is an `enum` containing all AEADs supported by `dexios-core`
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Algorithm {
    Aes256Gcm,
    XChaCha20Poly1305,
    DeoxysII256,
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Algorithm::Aes256Gcm => write!(f, "AES-256-GCM"),
            Algorithm::XChaCha20Poly1305 => write!(f, "XChaCha20-Poly1305"),
            Algorithm::DeoxysII256 => write!(f, "Deoxys-II-256"),
        }
    }
}

/// This defines the possible modes used for encrypting/decrypting
#[derive(Debug, PartialEq, Eq)]
pub enum Mode {
    MemoryMode,
    StreamMode,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Mode::MemoryMode => write!(f, "Memory Mode"),
            Mode::StreamMode => write!(f, "Stream Mode"),
        }
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

/// Legacy compatibility nonce generator.
///
/// New V1 code should use [`gen_payload_nonce`] or [`gen_keyslot_nonce`].
#[must_use]
pub fn gen_nonce(algorithm: &Algorithm, mode: &Mode) -> Vec<u8> {
    let nonce_len = get_nonce_len(algorithm, mode);
    let mut nonce = vec![0u8; nonce_len];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

/// Legacy compatibility nonce-length helper.
///
/// New V1 code should use [`PAYLOAD_NONCE_LEN`] and [`KEYSLOT_NONCE_LEN`]
/// directly.
#[must_use]
pub fn get_nonce_len(algorithm: &Algorithm, mode: &Mode) -> usize {
    match (algorithm, mode) {
        (Algorithm::XChaCha20Poly1305, Mode::StreamMode) => PAYLOAD_NONCE_LEN,
        (Algorithm::XChaCha20Poly1305, Mode::MemoryMode) => KEYSLOT_NONCE_LEN,
        (Algorithm::Aes256Gcm, _) | (Algorithm::DeoxysII256, _) => {
            panic!("AES and Deoxys-II are no longer supported")
        }
    }
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
