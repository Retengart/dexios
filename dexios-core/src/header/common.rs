use std::fmt::{Display, Formatter};

pub const CANONICAL_HEADER_LEN: usize = 512;
pub const CANONICAL_HEADER_STATIC_LEN: usize = 64;
pub const CANONICAL_KEYSLOT_LEN: usize = 112;
pub const MAX_KEYSLOTS: usize = 4;
pub const RETIRED_CURRENT_V1_HEADER_LEN: usize = 416;

pub const HEADER_LEN: usize = CANONICAL_HEADER_LEN;
pub const HEADER_STATIC_LEN: usize = CANONICAL_HEADER_STATIC_LEN;
pub const KEYSLOT_LEN: usize = CANONICAL_KEYSLOT_LEN;

const _: () = {
    assert!(
        HEADER_STATIC_LEN + MAX_KEYSLOTS * KEYSLOT_LEN == HEADER_LEN,
        "header geometry: static + slots must equal HEADER_LEN"
    );
    // V1Keyslot::deserialize slices slot_bytes[..92]; padding is KEYSLOT_LEN - 92.
    assert!(
        KEYSLOT_LEN >= 92,
        "keyslot record must hold at least 92 bytes"
    );
};

pub const MAGIC: [u8; 4] = *b"DXIO";
pub const VERSION_V1: [u8; 2] = [0x00, 0x01];
pub const CANONICAL_V1_DISCRIMINATOR: [u8; 4] = *b"CV1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayloadNonce([u8; 20]);

impl PayloadNonce {
    #[must_use]
    pub const fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, HeaderReadError> {
        if bytes.len() != 20 {
            return Err(HeaderReadError::InvalidPayloadNonceLength(bytes.len()));
        }

        let mut nonce = [0u8; 20];
        nonce.copy_from_slice(bytes);
        Ok(Self(nonce))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyslotNonce([u8; 24]);

impl KeyslotNonce {
    #[must_use]
    pub const fn new(bytes: [u8; 24]) -> Self {
        Self(bytes)
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, HeaderReadError> {
        if bytes.len() != 24 {
            return Err(HeaderReadError::InvalidKeyslotNonceLength(bytes.len()));
        }

        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(bytes);
        Ok(Self(nonce))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 24] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Salt([u8; 16]);

impl Salt {
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, HeaderReadError> {
        if bytes.len() != 16 {
            return Err(HeaderReadError::InvalidSaltLength(bytes.len()));
        }

        let mut salt = [0u8; 16];
        salt.copy_from_slice(bytes);
        Ok(Self(salt))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    #[must_use]
    pub const fn to_kdf_salt(&self) -> crate::kdf::Salt {
        crate::kdf::Salt::new(self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V1HeaderAad([u8; CANONICAL_HEADER_STATIC_LEN]);

impl V1HeaderAad {
    pub(crate) const fn from_static_header_bytes(bytes: [u8; CANONICAL_HEADER_STATIC_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CANONICAL_HEADER_STATIC_LEN] {
        &self.0
    }
}

#[derive(Debug)]
pub enum HeaderReadError {
    Io(std::io::Error),
    InvalidMagic([u8; 4]),
    UnsupportedFormat([u8; 2]),
    UnsupportedVersion([u8; 2]),
    RetiredV1Layout,
    InvalidCanonicalDiscriminator([u8; 4]),
    InvalidPayloadKind(u8),
    InvalidPayloadFraming(u8),
    InvalidKdfProfile(u8),
    InvalidKdfParamProfile(u8),
    InvalidSlotState { index: usize, state: u8 },
    InvalidPhysicalSlotIndex { expected: usize, actual: u8 },
    TruncatedHeader,
    InvalidKeyslotCount(u8),
    InvalidKeyslotTag([u8; 2]),
    InvalidPayloadNonceLength(usize),
    InvalidKeyslotNonceLength(usize),
    InvalidSaltLength(usize),
    InvalidEncryptedMasterKeyLength(usize),
    NonZeroReservedBytes,
    NonZeroActiveKeyslotPadding(usize),
    NonZeroInactiveKeyslotPadding(usize),
}

impl Display for HeaderReadError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "unable to read v1 header: {error}"),
            Self::InvalidMagic(magic) => write!(f, "invalid V1 header magic: {magic:02X?}"),
            Self::UnsupportedFormat(prefix) => {
                write!(f, "unsupported Dexios header format: {prefix:02X?}")
            }
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported V1 header version bytes: {version:02X?}")
            }
            Self::RetiredV1Layout => f.write_str("retired current V1 header layout"),
            Self::InvalidCanonicalDiscriminator(discriminator) => {
                write!(
                    f,
                    "invalid canonical V1 discriminator: {discriminator:02X?}"
                )
            }
            Self::InvalidPayloadKind(kind) => {
                write!(f, "invalid canonical V1 payload kind: {kind}")
            }
            Self::InvalidPayloadFraming(framing) => {
                write!(f, "invalid canonical V1 payload framing: {framing}")
            }
            Self::InvalidKdfProfile(profile) => {
                write!(f, "invalid canonical V1 KDF profile: {profile}")
            }
            Self::InvalidKdfParamProfile(profile) => {
                write!(f, "invalid canonical V1 KDF parameter profile: {profile}")
            }
            Self::InvalidSlotState { index, state } => {
                write!(f, "invalid canonical V1 slot {index} state: {state}")
            }
            Self::InvalidPhysicalSlotIndex { expected, actual } => {
                write!(
                    f,
                    "invalid canonical V1 physical slot index: expected {expected}, got {actual}"
                )
            }
            Self::TruncatedHeader => f.write_str("truncated V1 header"),
            Self::InvalidKeyslotCount(count) => write!(f, "invalid V1 keyslot count: {count}"),
            Self::InvalidKeyslotTag(tag) => write!(f, "invalid V1 keyslot tag: {tag:02X?}"),
            Self::InvalidPayloadNonceLength(len) => {
                write!(f, "invalid V1 payload nonce length: {len}")
            }
            Self::InvalidKeyslotNonceLength(len) => {
                write!(f, "invalid V1 keyslot nonce length: {len}")
            }
            Self::InvalidSaltLength(len) => write!(f, "invalid V1 salt length: {len}"),
            Self::InvalidEncryptedMasterKeyLength(len) => {
                write!(f, "invalid V1 encrypted master key length: {len}")
            }
            Self::NonZeroReservedBytes => write!(f, "non-zero reserved bytes in V1 header"),
            Self::NonZeroActiveKeyslotPadding(index) => {
                write!(
                    f,
                    "non-zero active keyslot padding in V1 header slot {index}"
                )
            }
            Self::NonZeroInactiveKeyslotPadding(index) => {
                write!(
                    f,
                    "non-zero inactive keyslot bytes in V1 header slot {index}"
                )
            }
        }
    }
}

impl std::error::Error for HeaderReadError {}

impl From<std::io::Error> for HeaderReadError {
    fn from(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            return Self::TruncatedHeader;
        }

        Self::Io(error)
    }
}

#[derive(Debug)]
pub enum HeaderWriteError {
    NoKeyslots,
    TooManyKeyslots(usize),
    InvalidKeyslotIndex(usize),
    Io(std::io::Error),
}

impl Display for HeaderWriteError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoKeyslots => f.write_str("v1 header must contain at least one keyslot"),
            Self::TooManyKeyslots(count) => {
                write!(f, "v1 header cannot encode {count} keyslots")
            }
            Self::InvalidKeyslotIndex(index) => {
                write!(f, "invalid V1 keyslot index: {index}")
            }
            Self::Io(error) => write!(f, "unable to write v1 header: {error}"),
        }
    }
}

impl std::error::Error for HeaderWriteError {}
