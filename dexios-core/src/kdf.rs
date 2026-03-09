use std::fmt::{Display, Formatter};

use crate::protected::Protected;

pub const DERIVED_KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;

const ARGON2ID_MEMORY_KIB: u32 = 262_144;
const ARGON2ID_TIME_COST: u32 = 10;
const ARGON2ID_PARALLELISM: u32 = 4;

const BLAKE3_BALLOON_SPACE_COST: u32 = 278_528;
const BLAKE3_BALLOON_TIME_COST: u32 = 1;
const BLAKE3_BALLOON_PARALLELISM: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Salt([u8; SALT_LEN]);

impl Salt {
    #[must_use]
    pub const fn new(bytes: [u8; SALT_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SALT_LEN] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kdf {
    Blake3Balloon,
    Argon2id,
}

impl Kdf {
    pub fn derive(
        self,
        raw_key: Protected<Vec<u8>>,
        salt: &Salt,
    ) -> Result<Protected<[u8; DERIVED_KEY_LEN]>, KdfError> {
        match self {
            Self::Blake3Balloon => derive_balloon_with_params(
                raw_key,
                salt,
                BLAKE3_BALLOON_SPACE_COST,
                BLAKE3_BALLOON_TIME_COST,
                BLAKE3_BALLOON_PARALLELISM,
            ),
            Self::Argon2id => derive_argon2id_with_params(
                raw_key,
                salt,
                ARGON2ID_MEMORY_KIB,
                ARGON2ID_TIME_COST,
                ARGON2ID_PARALLELISM,
            ),
        }
    }
}

#[derive(Debug)]
pub enum KdfError {
    InvalidParams(&'static str),
    DeriveFailed(&'static str),
}

impl Display for KdfError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidParams(message) => f.write_str(message),
            Self::DeriveFailed(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for KdfError {}

pub(crate) fn derive_argon2id_with_params(
    raw_key: Protected<Vec<u8>>,
    salt: &Salt,
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
) -> Result<Protected<[u8; DERIVED_KEY_LEN]>, KdfError> {
    use argon2::{Argon2, Params};

    let params = Params::new(
        memory_kib,
        time_cost,
        parallelism,
        Some(Params::DEFAULT_OUTPUT_LEN),
    )
    .map_err(|_| KdfError::InvalidParams("Error initialising argon2id parameters"))?;

    let mut key = [0u8; DERIVED_KEY_LEN];
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let result = argon2.hash_password_into(raw_key.expose(), salt.as_bytes(), &mut key);
    drop(raw_key);

    if result.is_err() {
        return Err(KdfError::DeriveFailed("Error while hashing your key"));
    }

    Ok(Protected::new(key))
}

pub(crate) fn derive_balloon_with_params(
    raw_key: Protected<Vec<u8>>,
    salt: &Salt,
    space_cost: u32,
    time_cost: u32,
    parallelism: u32,
) -> Result<Protected<[u8; DERIVED_KEY_LEN]>, KdfError> {
    use balloon_hash::Balloon;

    let params = balloon_hash::Params::new(space_cost, time_cost, parallelism)
        .map_err(|_| KdfError::InvalidParams("Error initialising balloon hashing parameters"))?;

    let mut key = [0u8; DERIVED_KEY_LEN];
    let balloon = Balloon::<blake3::Hasher>::new(balloon_hash::Algorithm::Balloon, params, None);
    let result = balloon.hash_into(raw_key.expose(), salt.as_bytes(), &mut key);
    drop(raw_key);

    if result.is_err() {
        return Err(KdfError::DeriveFailed("Error while hashing your key"));
    }

    Ok(Protected::new(key))
}
