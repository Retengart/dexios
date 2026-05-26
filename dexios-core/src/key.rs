//! This module handles key-related functionality within `dexios-core`.
//!
//! The canonical password-derivation surface now lives in [`crate::kdf`]. This
//! module keeps passphrase generation and shared key-shape utilities.
use rand::RngExt;
use std::num::NonZeroU16;
use zeroize::Zeroize;

use crate::protected::Protected;

// TODO: choose better place for this util
/// This is a simple helper function, used for converting the 32-byte master key `Vec<u8>`s to `[u8; 32]`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VecToArrayLengthError {
    pub expected: usize,
    pub actual: usize,
}

impl std::fmt::Display for VecToArrayLengthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid key material length: expected {}, got {}",
            self.expected, self.actual
        )
    }
}

impl std::error::Error for VecToArrayLengthError {}

pub fn vec_to_arr<const N: usize>(
    mut master_key_vec: Vec<u8>,
) -> Result<[u8; N], VecToArrayLengthError> {
    let actual = master_key_vec.len();
    if actual != N {
        master_key_vec.zeroize();
        return Err(VecToArrayLengthError {
            expected: N,
            actual,
        });
    }

    let mut master_key = [0u8; N];
    master_key.copy_from_slice(&master_key_vec);
    master_key_vec.zeroize();
    Ok(master_key)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassphraseWordCount(NonZeroU16);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassphraseWordCountError;

impl std::fmt::Display for PassphraseWordCountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("generated passphrase word count must be positive")
    }
}

impl std::error::Error for PassphraseWordCountError {}

impl PassphraseWordCount {
    pub const DEFAULT: Self = Self(match NonZeroU16::new(7) {
        Some(words) => words,
        None => unreachable!(),
    });

    pub fn try_new(words: u16) -> Result<Self, PassphraseWordCountError> {
        NonZeroU16::new(words)
            .map(Self)
            .ok_or(PassphraseWordCountError)
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }

    #[must_use]
    pub const fn as_usize(self) -> usize {
        self.get() as usize
    }
}

/// This function is used for autogenerating a passphrase from the bundled
/// wordlist.
///
/// It consists of `n` words joined with `-`. The current CLI default is `7`
/// words.
///
/// This provides adequate protection, while also remaining somewhat memorable.
#[must_use]
pub fn generate_passphrase(total_words: PassphraseWordCount) -> Protected<String> {
    let collection = include_str!("wordlist.lst");
    let words = collection.lines().collect::<Vec<_>>();

    let mut passphrase = String::new();

    for i in 0..total_words.as_usize() {
        let index = rand::rng().random_range(0..words.len());
        let word = words[index];
        passphrase.push_str(word);
        if i < total_words.as_usize() - 1 {
            passphrase.push('-');
        }
    }

    Protected::new(passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_word_count_rejects_zero() {
        assert!(PassphraseWordCount::try_new(0).is_err());
    }

    #[test]
    fn passphrase_word_count_default_is_seven_words() {
        assert_eq!(PassphraseWordCount::DEFAULT.get(), 7);
    }

    #[test]
    fn generate_passphrase_with_one_word_has_no_separator() {
        let passphrase = generate_passphrase(PassphraseWordCount::try_new(1).unwrap());

        passphrase.with_exposed(|passphrase| {
            assert!(!passphrase.is_empty());
            assert!(!passphrase.contains('-'));
            assert_eq!(passphrase.split('-').count(), 1);
        });
    }
}
