pub mod common;
pub mod v1;

pub use common::{HeaderReadError, HeaderWriteError};

use common::Aad;
use common::{HEADER_LEN, MAGIC, VERSION_V1};

pub mod legacy {
    pub use crate::header_legacy::{
        ARGON2ID_LATEST, BLAKE3BALLOON_LATEST, HEADER_VERSION, HashingAlgorithm, Header,
        HeaderType, HeaderVersion, Keyslot,
    };
}

pub(crate) use crate::header_legacy::{Header, HeaderVersion};

#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub enum ParsedHeader {
    V1(v1::V1Header),
}

pub fn read_header(
    reader: &mut impl std::io::Read,
) -> Result<(ParsedHeader, Aad), HeaderReadError> {
    let mut prefix = [0u8; 6];
    reader.read_exact(&mut prefix)?;

    let mut magic = [0u8; 4];
    magic.copy_from_slice(&prefix[..4]);
    if magic != MAGIC {
        return Err(HeaderReadError::InvalidMagic(magic));
    }

    let mut version = [0u8; 2];
    version.copy_from_slice(&prefix[4..6]);
    if version != VERSION_V1 {
        return Err(HeaderReadError::UnsupportedVersion(version));
    }

    let mut bytes = [0u8; HEADER_LEN];
    bytes[..6].copy_from_slice(&prefix);
    reader.read_exact(&mut bytes[6..])?;

    let header = v1::V1Header::deserialize_bytes(bytes)?;
    let aad = header.create_aad();
    Ok((ParsedHeader::V1(header), aad))
}
