pub mod common;
pub mod v1;

pub use crate::header_legacy::{
    ARGON2ID_LATEST, BLAKE3BALLOON_LATEST, HEADER_VERSION, HashingAlgorithm, Header, HeaderType,
    HeaderVersion, Keyslot,
};
pub use common::{HeaderReadError, HeaderWriteError};

use common::Aad;

#[allow(clippy::module_name_repetitions)]
pub enum ParsedHeader {
    V1(v1::V1Header),
}

pub fn read_header(
    reader: &mut impl std::io::Read,
) -> Result<(ParsedHeader, Aad), HeaderReadError> {
    let header = v1::V1Header::deserialize(reader)?;
    let aad = header.create_aad();
    Ok((ParsedHeader::V1(header), aad))
}
