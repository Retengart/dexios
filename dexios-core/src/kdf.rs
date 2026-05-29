use std::fmt::{Display, Formatter};

use crate::protected::Protected;
use zeroize::Zeroize;

pub const DERIVED_KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;

// Argon2id KDF parameters. Argon2id is the OWASP-recommended, RFC 9106 memory-hard
// password KDF and the only normal KDF for new V1 keyslots. Parameters are fixed (not
// user-tunable) and versioned by the canonical KDF param-profile id; changing them
// later introduces a new param-profile id.
//
// `m_cost` is expressed in KiB: 262_144 KiB == 256 MiB of working memory. `t_cost` = 4
// passes, `p_cost` = 4 lanes. The RustCrypto `argon2` crate computes lanes sequentially
// in pure Rust (no threads), but still emits the spec-correct Argon2id p=4 digest; only
// wall-clock differs. These comfortably exceed the OWASP Argon2id memory floors. See
// book/src/dexios-core/Password-Hashing.md.
pub const ARGON2ID_M_COST: u32 = 262_144;
pub const ARGON2ID_T_COST: u32 = 4;
pub const ARGON2ID_P_COST: u32 = 4;
pub const ARGON2ID_KDF_PROFILE_ID: u8 = 0x01;
pub const ARGON2ID_KDF_PARAM_PROFILE_ID: u8 = 0x01;
pub const ARGON2ID_OUTPUT_LEN: usize = DERIVED_KEY_LEN;
pub const ARGON2ID_SALT_LEN: usize = SALT_LEN;

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
    Argon2id,
}

impl Kdf {
    /// Derives a 32-byte wrapping key from `raw_key` and `salt` using the frozen
    /// production Argon2id parameters ([`ARGON2ID_M_COST`] = 256 MiB, t=4, p=4,
    /// version 0x13). See `book/src/dexios-core/Password-Hashing.md`.
    #[must_use = "a derived wrapping key must be used; dropping it wastes an expensive KDF call"]
    pub fn derive(
        self,
        raw_key: &Protected<Vec<u8>>,
        salt: &Salt,
    ) -> Result<Protected<[u8; DERIVED_KEY_LEN]>, KdfError> {
        match self {
            Self::Argon2id => derive_argon2id_with_params(
                raw_key,
                salt,
                ARGON2ID_M_COST,
                ARGON2ID_T_COST,
                ARGON2ID_P_COST,
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
            Self::InvalidParams(message) | Self::DeriveFailed(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for KdfError {}

/// Derives a 32-byte key with explicit Argon2id parameters. The public
/// [`Kdf::derive`] always calls this with the frozen production constants; the
/// parameterized form exists so cost parameters live in exactly one place.
pub(crate) fn derive_argon2id_with_params(
    raw_key: &Protected<Vec<u8>>,
    salt: &Salt,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Protected<[u8; DERIVED_KEY_LEN]>, KdfError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(m_cost, t_cost, p_cost, Some(DERIVED_KEY_LEN))
        .map_err(|_| KdfError::InvalidParams("Error initialising Argon2id parameters"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; DERIVED_KEY_LEN];
    // `salt` is 16 bytes, comfortably above argon2's 8-byte minimum salt length.
    let result = raw_key
        .with_exposed(|raw_key| argon2.hash_password_into(raw_key, salt.as_bytes(), &mut key));

    if result == Ok(()) {
        let protected = Protected::new(key);
        key.zeroize();
        Ok(protected)
    } else {
        key.zeroize();
        Err(KdfError::DeriveFailed("Error while hashing your key"))
    }
}
