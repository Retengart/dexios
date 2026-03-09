use std::fmt::{Display, Formatter};

pub const HEADER_LEN: usize = 416;
pub const HEADER_STATIC_LEN: usize = 32;
pub const KEYSLOT_LEN: usize = 96;
pub const MAX_KEYSLOTS: usize = 4;

pub const MAGIC: [u8; 4] = *b"DXIO";
pub const VERSION_V1: [u8; 2] = [0x00, 0x01];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayloadNonce([u8; 20]);

impl PayloadNonce {
    #[must_use]
    pub const fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
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

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aad([u8; HEADER_STATIC_LEN]);

impl Aad {
    #[must_use]
    pub const fn new(bytes: [u8; HEADER_STATIC_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HEADER_STATIC_LEN] {
        &self.0
    }
}

#[derive(Debug)]
pub enum HeaderReadError {
    Io(std::io::Error),
    InvalidMagic([u8; 4]),
    UnsupportedVersion([u8; 2]),
    InvalidKeyslotCount(u8),
    InvalidKeyslotTag([u8; 2]),
    NonZeroReservedBytes,
    NonZeroActiveKeyslotPadding(usize),
    NonZeroInactiveKeyslotPadding(usize),
}

impl Display for HeaderReadError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "unable to read v1 header: {error}"),
            Self::InvalidMagic(magic) => write!(f, "invalid V1 header magic: {magic:02X?}"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported V1 header version bytes: {version:02X?}")
            }
            Self::InvalidKeyslotCount(count) => write!(f, "invalid V1 keyslot count: {count}"),
            Self::InvalidKeyslotTag(tag) => write!(f, "invalid V1 keyslot tag: {tag:02X?}"),
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
        Self::Io(error)
    }
}

#[derive(Debug)]
pub enum HeaderWriteError {
    TooManyKeyslots(usize),
    Io(std::io::Error),
}

impl Display for HeaderWriteError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyKeyslots(count) => {
                write!(f, "v1 header cannot encode {count} keyslots")
            }
            Self::Io(error) => write!(f, "unable to write v1 header: {error}"),
        }
    }
}

impl std::error::Error for HeaderWriteError {}
