//! This module handles key-related functionality within `dexios-core`.
//!
//! The canonical password-derivation surface now lives in [`crate::kdf`]. This
//! module keeps passphrase generation and shared key-shape utilities.
use rand::RngExt;
use zeroize::Zeroize;

use crate::protected::Protected;

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
