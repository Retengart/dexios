//! This module handles key-related functionality within `dexios-core`
//!
//! It contains methods for `balloon` hashing, and securely generating a salt
//!
//! # Examples
//!
//! ```rust,ignore
//! let salt = gen_salt();
//! let secret_data = "secure key".as_bytes().to_vec();
//! let raw_key = Protected::new(secret_data);
//! let key = balloon_hash(raw_key, &salt, &HeaderVersion::V5).unwrap();
//! ```
use anyhow::Result;
use rand::{prelude::StdRng, Rng, SeedableRng};
use zeroize::Zeroize;

use crate::cipher::Ciphers;
use crate::header::{Header, HeaderVersion};
use crate::primitives::{MASTER_KEY_LEN, SALT_LEN};
use crate::protected::Protected;

/// This handles BLAKE3-Balloon hashing of a raw key
///
/// It requires a user to generate the salt
///
/// `HeaderVersion` is required as the parameters are linked to specific header versions
///
/// It's only supported on header version V5.
///
/// It returns a `Protected<[u8; 32]>` - `Protected` wrappers are used for all sensitive information within `dexios-core`
///
/// This function ensures that `raw_key` is securely erased from memory once hashed
///
/// # Examples
///
/// ```rust,ignore
/// let salt = gen_salt();
/// let secret_data = "secure key".as_bytes().to_vec();
/// let raw_key = Protected::new(secret_data);
/// let key = balloon_hash(raw_key, &salt, &HeaderVersion::V5).unwrap();
/// ```
///
pub fn balloon_hash(
    raw_key: Protected<Vec<u8>>,
    salt: &[u8; SALT_LEN],
    version: &HeaderVersion,
) -> Result<Protected<[u8; 32]>> {
    use balloon_hash::Balloon;

    let params = match version {
        HeaderVersion::V5 => balloon_hash::Params::new(278_528, 1, 1)
            .map_err(|_| anyhow::anyhow!("Error initialising balloon hashing parameters"))?,
    };

    let mut key = [0u8; 32];
    let balloon = Balloon::<blake3::Hasher>::new(balloon_hash::Algorithm::Balloon, params, None);
    let result = balloon.hash_into(raw_key.expose(), salt, &mut key);
    drop(raw_key);

    if result.is_err() {
        return Err(anyhow::anyhow!("Error while hashing your key"));
    }

    Ok(Protected::new(key))
}

/// This is a helper function for retrieving the key used for encrypting the data
///
/// In header version V5, this is a cryptographically-secure random value
///
/// In header version V5, this function will iterate through all available keyslots, looking for a match. If it finds a match, it will return the decrypted master key.
#[allow(clippy::module_name_repetitions)]
pub fn decrypt_master_key(
    raw_key: &Protected<Vec<u8>>,
    header: &Header,
    // TODO: use custom error instead of anyhow
) -> Result<Protected<[u8; MASTER_KEY_LEN]>> {
    match header.header_type.version {
        HeaderVersion::V5 => {
            header
                .keyslots
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Unable to find a keyslot!"))?
                .iter()
                .find_map(|keyslot| {
                    let key = keyslot.hash_algorithm.hash(raw_key.clone(), &keyslot.salt).ok()?;

                    let cipher = Ciphers::initialize(key, &header.header_type.algorithm).ok()?;
                    cipher
                        .decrypt(&keyslot.nonce, keyslot.encrypted_key.as_slice())
                        .map(vec_to_arr)
                        .map(Protected::new)
                        .ok()
                })
                .ok_or_else(|| anyhow::anyhow!("Unable to find a match with the key you provided (maybe you supplied the wrong key?)"))
        }
    }
}

// TODO: choose better place for this util
/// This is a simple helper function, used for converting the 32-byte master key `Vec<u8>`s to `[u8; 32]`
#[must_use]
pub fn vec_to_arr<const N: usize>(mut master_key_vec: Vec<u8>) -> [u8; N] {
    let mut master_key = [0u8; N];
    let len = N.min(master_key_vec.len());
    master_key[..len].copy_from_slice(&master_key_vec[..len]);
    master_key_vec.zeroize();
    master_key
}

/// This function is used for autogenerating a passphrase, from a wordlist
///
/// It consists of n words, from the EFF large wordlist. The default amount of words is 7.
///
/// Each word is separated with `-`.
///
/// This provides adequate protection, while also remaining somewhat memorable.
#[must_use]
pub fn generate_passphrase(total_words: &i32) -> Protected<String> {
    let collection = include_str!("wordlist.lst");
    let words = collection.lines().collect::<Vec<_>>();

    let mut passphrase = String::new();

    for i in 0..*total_words {
        let index = StdRng::from_entropy().gen_range(0..=words.len());
        let word = words[index];
        passphrase.push_str(word);
        if i < total_words - 1 {
            passphrase.push('-');
        }
    }

    Protected::new(passphrase)
}
