use std::fmt::{Display, Formatter};

use crate::protected::Protected;

pub const DERIVED_KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;

pub const BLAKE3_BALLOON_SPACE_COST: u32 = 278_528;
pub const BLAKE3_BALLOON_TIME_COST: u32 = 1;
pub const BLAKE3_BALLOON_P_COST: u32 = 1;
pub const BLAKE3_BALLOON_ALGORITHM_DELTA: u32 = 3;
pub const BLAKE3_BALLOON_KDF_PROFILE_ID: u8 = 0x01;
pub const BLAKE3_BALLOON_KDF_PARAM_PROFILE_ID: u8 = 0x01;
pub const BLAKE3_BALLOON_OUTPUT_LEN: usize = DERIVED_KEY_LEN;
pub const BLAKE3_BALLOON_SALT_LEN: usize = SALT_LEN;

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
}

impl Kdf {
    pub fn derive(
        self,
        raw_key: &Protected<Vec<u8>>,
        salt: &Salt,
    ) -> Result<Protected<[u8; DERIVED_KEY_LEN]>, KdfError> {
        match self {
            Self::Blake3Balloon => derive_balloon_with_params(
                raw_key,
                salt,
                BLAKE3_BALLOON_SPACE_COST,
                BLAKE3_BALLOON_TIME_COST,
                BLAKE3_BALLOON_P_COST,
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

pub(crate) fn derive_balloon_with_params(
    raw_key: &Protected<Vec<u8>>,
    salt: &Salt,
    space_cost: u32,
    time_cost: u32,
    p_cost: u32,
) -> Result<Protected<[u8; DERIVED_KEY_LEN]>, KdfError> {
    use balloon_hash::Balloon;

    let params = balloon_hash::Params::new(space_cost, time_cost, p_cost)
        .map_err(|_| KdfError::InvalidParams("Error initialising balloon hashing parameters"))?;

    let mut key = [0u8; DERIVED_KEY_LEN];
    let balloon = Balloon::<blake3::Hasher>::new(balloon_hash::Algorithm::Balloon, params, None);
    let result =
        raw_key.with_exposed(|raw_key| balloon.hash_into(raw_key, salt.as_bytes(), &mut key));

    if result.is_err() {
        return Err(KdfError::DeriveFailed("Error while hashing your key"));
    }

    Ok(Protected::new(key))
}
