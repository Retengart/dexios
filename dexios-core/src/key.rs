//! This module handles key-related functionality within `dexios-core`.
//!
//! The canonical password-derivation surface now lives in [`crate::kdf`]. This
//! module keeps master-key recovery, passphrase generation, and temporary
//! compatibility wrappers needed by the legacy header implementation until later
//! tasks remove it.
use anyhow::Result;
use rand::RngExt;
use zeroize::Zeroize;

use crate::cipher::Ciphers;
use crate::header::{Header, HeaderVersion};
use crate::kdf::{Salt, derive_argon2id_with_params, derive_balloon_with_params};
use crate::primitives::{MASTER_KEY_LEN, SALT_LEN};
use crate::protected::Protected;

/// Temporary compatibility wrapper for the legacy header implementation.
///
/// New code should call [`crate::kdf::Kdf::derive`] directly.
pub(crate) fn argon2id_hash(
    raw_key: Protected<Vec<u8>>,
    salt: &[u8; SALT_LEN],
    version: &HeaderVersion,
) -> Result<Protected<[u8; 32]>> {
    let salt = Salt::new(*salt);
    match version {
        HeaderVersion::V1 => derive_argon2id_with_params(raw_key, &salt, 8192, 8, 4),
        HeaderVersion::V2 => derive_argon2id_with_params(raw_key, &salt, 262_144, 8, 4),
        HeaderVersion::V3 => derive_argon2id_with_params(raw_key, &salt, 262_144, 10, 4),
        HeaderVersion::V4 | HeaderVersion::V5 => Err(crate::kdf::KdfError::InvalidParams(
            "argon2id is not supported on header versions above V3.",
        )),
    }
    .map_err(Into::into)
}

/// Temporary compatibility wrapper for the legacy header implementation.
///
/// New code should call [`crate::kdf::Kdf::derive`] directly.
pub(crate) fn balloon_hash(
    raw_key: Protected<Vec<u8>>,
    salt: &[u8; SALT_LEN],
    version: &HeaderVersion,
) -> Result<Protected<[u8; 32]>> {
    let salt = Salt::new(*salt);
    match version {
        HeaderVersion::V1 | HeaderVersion::V2 | HeaderVersion::V3 => {
            Err(crate::kdf::KdfError::InvalidParams(
                "Balloon hashing is not supported in header versions below V4.",
            ))
        }
        HeaderVersion::V4 => derive_balloon_with_params(raw_key, &salt, 262_144, 1, 1),
        HeaderVersion::V5 => derive_balloon_with_params(raw_key, &salt, 278_528, 1, 1),
    }
    .map_err(Into::into)
}

/// This is a helper function for retrieving the effective data-encryption key.
///
/// In header versions below V4, this is the derived password/key hash itself.
///
/// In header versions V4 and above, this function recovers the random wrapped
/// master key stored in the header metadata.
///
/// # Errors
///
/// Returns an error if the header is missing required salt or keyslot data, if the
/// selected KDF fails, if the cipher cannot be initialized, or if none of the
/// available keyslots can be decrypted with the supplied key.
#[allow(clippy::module_name_repetitions)]
pub fn decrypt_master_key(
    raw_key: Protected<Vec<u8>>,
    header: &Header,
) -> Result<Protected<[u8; MASTER_KEY_LEN]>> {
    match header.header_type.version {
        HeaderVersion::V1 | HeaderVersion::V2 | HeaderVersion::V3 => argon2id_hash(
            raw_key,
            &header
                .salt
                .ok_or_else(|| anyhow::anyhow!("Missing salt within the header!"))?,
            &header.header_type.version,
        ),
        HeaderVersion::V4 => {
            let keyslots = header
                .keyslots
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Unable to find a keyslot!"))?;
            let keyslot = keyslots.first().ok_or_else(|| {
                anyhow::anyhow!(
                    "Unable to find a match with the key you provided (maybe you supplied the wrong key?)"
                )
            })?;
            let key = keyslot.hash_algorithm.hash(raw_key, &keyslot.salt)?;

            let cipher = Ciphers::initialize(key, &header.header_type.algorithm)?;
            cipher
                .decrypt(&keyslot.nonce, keyslot.encrypted_key.as_slice())
                .map(vec_to_arr)
                .map(Protected::new)
                .map_err(|_| anyhow::anyhow!("Cannot decrypt master key"))
        }
        HeaderVersion::V5 => header
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
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Unable to find a match with the key you provided (maybe you supplied the wrong key?)"
                )
            }),
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

/// This function is used for autogenerating a passphrase from the bundled
/// wordlist.
///
/// It consists of `n` words joined with `-`. The current CLI default is `7`
/// words.
///
/// This provides adequate protection, while also remaining somewhat memorable.
#[must_use]
pub fn generate_passphrase(total_words: &i32) -> Protected<String> {
    let collection = include_str!("wordlist.lst");
    let words = collection.lines().collect::<Vec<_>>();

    let mut passphrase = String::new();

    for i in 0..*total_words {
        let index = rand::rng().random_range(0..words.len());
        let word = words[index];
        passphrase.push_str(word);
        if i < total_words - 1 {
            passphrase.push('-');
        }
    }

    Protected::new(passphrase)
}
