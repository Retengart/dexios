pub mod common;
pub mod v1;

pub use common::{HeaderReadError, HeaderWriteError, PayloadNonce, V1HeaderAad};

use common::{HEADER_LEN, MAGIC, VERSION_V1};

#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub enum ParsedHeader {
    V1(ParsedV1Payload),
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct ParsedV1Payload {
    header: v1::V1Header,
    aad: V1HeaderAad,
}

impl ParsedV1Payload {
    #[must_use]
    pub const fn header(&self) -> &v1::V1Header {
        &self.header
    }

    #[must_use]
    pub const fn aad(&self) -> &V1HeaderAad {
        &self.aad
    }

    #[must_use]
    pub const fn payload_nonce(&self) -> &PayloadNonce {
        self.header.payload_nonce()
    }

    #[must_use]
    pub fn into_header(self) -> v1::V1Header {
        self.header
    }
}

pub fn read_header(reader: &mut impl std::io::Read) -> Result<ParsedHeader, HeaderReadError> {
    let mut prefix = [0u8; 6];
    reader.read_exact(&mut prefix)?;

    let format_prefix = [prefix[0], prefix[1]];
    if matches!(
        format_prefix,
        [0xDE, 0x01] | [0xDE, 0x02] | [0xDE, 0x03] | [0xDE, 0x04] | [0xDE, 0x05]
    ) {
        return Err(HeaderReadError::UnsupportedFormat(format_prefix));
    }

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
    let aad = header.aad();
    Ok(ParsedHeader::V1(ParsedV1Payload { header, aad }))
}
