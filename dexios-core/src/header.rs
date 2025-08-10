//! The Dexios header is an encrypted file/data header that stores specific information needed for decryption.
//!
//! This includes:
//! * header version
//! * salt
//! * nonce
//! * encryption algorithm
//! * whether the file was encrypted in "memory" or stream mode
//!
//! It allows for serialization, deserialization, and has a convenience function for quickly writing the header to a file.
//!
//! # Examples
//!
//! ```rust,ignore
//! let header_bytes: [u8; 64] = [
//!     222, 2, 14, 1, 12, 1, 142, 88, 243, 144, 119, 187, 189, 190, 121, 90, 211, 56, 185, 14, 76,
//!     45, 16, 5, 237, 72, 7, 203, 13, 145, 13, 155, 210, 29, 128, 142, 241, 233, 42, 168, 243,
//!     129, 0, 0, 0, 0, 0, 0, 214, 45, 3, 4, 11, 212, 129, 123, 192, 157, 185, 109, 151, 225, 233,
//!     161,
//! ];
//! let mut cursor = Cursor::new(header_bytes);
//!
//! // the cursor may be a file, this is just an example
//!
//! let (header, aad) = Header::deserialize(&mut cursor).unwrap();
//! ```
//!
//! ```rust,ignore
//! let mut output_file = File::create("test").unwrap();
//!
//! header.write(&mut output_file).unwrap();
//! ```
//!

use crate::{
    key::balloon_hash,
    protected::Protected,
};

use super::primitives::{get_nonce_len, Algorithm, Mode, ENCRYPTED_MASTER_KEY_LEN, SALT_LEN};
use anyhow::{Context, Result};
use std::io::{Cursor, Read, Seek, Write};

/// This defines the latest header version, so program's using this can easily stay up to date.
///
/// It's also here to just help users keep track
pub const HEADER_VERSION: HeaderVersion = HeaderVersion::V5;

/// This stores all possible versions of the header
#[allow(clippy::module_name_repetitions)]
#[derive(PartialEq, Eq, Clone, Copy, PartialOrd)]
pub enum HeaderVersion {
    V5,
}

impl std::fmt::Display for HeaderVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::V5 => write!(f, "V5"),
        }
    }
}

/// This is the Header's type - it contains the specific details that are needed to decrypt the data
///
/// It contains the header's version, the "mode" that was used to encrypt the data, and the algorithm used.
///
/// This needs to be manually created for encrypting data
#[allow(clippy::module_name_repetitions)]
pub struct HeaderType {
    pub version: HeaderVersion,
    pub algorithm: Algorithm,
    pub mode: Mode,
}

/// This is the `HeaderType` struct, but in the format of raw bytes
///
/// This does not need to be used outside of this core library
struct HeaderTag {
    pub version: [u8; 2],
    pub algorithm: [u8; 2],
    pub mode: [u8; 2],
}

/// This is the main `Header` struct, and it contains all of the information about the encrypted data
///
/// It contains the `HeaderType`, the nonce, and the salt
///
/// This needs to be manually created for encrypting data
pub struct Header {
    pub header_type: HeaderType,
    pub nonce: Vec<u8>,
    pub salt: Option<[u8; SALT_LEN]>, // option as v4+ use the keyslots
    pub keyslots: Option<Vec<Keyslot>>,
}

pub const BLAKE3BALLOON_LATEST: u8 = 5;

/// This is in place to make `Keyslot` handling a **lot** easier
/// You may use the constants `BLAKE3BALLOON_LATEST` for defining versions
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HashingAlgorithm {
    Blake3Balloon(u8),
}

impl std::fmt::Display for HashingAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Blake3Balloon(i) => write!(f, "BLAKE3-Balloon (param v{})", i),
        }
    }
}

impl HashingAlgorithm {
    /// A simple helper function that will hash a value with the appropriate algorithm and version
    pub fn hash(
        &self,
        raw_key: Protected<Vec<u8>>,
        salt: &[u8; SALT_LEN],
    ) -> Result<Protected<[u8; 32]>, anyhow::Error> {
        match self {
            HashingAlgorithm::Blake3Balloon(i) => match i {
                5 => balloon_hash(raw_key, salt, &HeaderVersion::V5),
                _ => Err(anyhow::anyhow!(
                    "Balloon hashing is not supported with the parameters provided."
                )),
            },
        }
    }
}

/// This defines a keyslot that is used with header V4 and above.
/// A keyslot contains information about the key, and the encrypted key itself
#[derive(Clone)]
pub struct Keyslot {
    pub hash_algorithm: HashingAlgorithm,
    pub encrypted_key: [u8; ENCRYPTED_MASTER_KEY_LEN],
    pub nonce: Vec<u8>,
    pub salt: [u8; SALT_LEN],
}

impl Keyslot {
    /// This is used to convert a keyslot into bytes - ideal for writing headers
    #[must_use]
    pub fn serialize(&self) -> [u8; 2] {
        match self.hash_algorithm {
            HashingAlgorithm::Blake3Balloon(i) => match i {
                5 => [0xDF, 0xB5],
                _ => [0x00, 0x00],
            },
        }
    }
}

impl Header {
    /// This is a private function (used by other header functions) for returning the `HeaderType`'s raw bytes
    ///
    /// It's used for serialization, and has it's own dedicated function as it will be used often
    fn get_tag(&self) -> HeaderTag {
        let version = self.serialize_version();
        let algorithm = self.serialize_algorithm();
        let mode = self.serialize_mode();
        HeaderTag {
            version,
            algorithm,
            mode,
        }
    }

    /// This is a private function used for serialization
    ///
    /// It converts a `HeaderVersion` into the associated raw bytes
    fn serialize_version(&self) -> [u8; 2] {
        match self.header_type.version {
            HeaderVersion::V5 => {
                let info: [u8; 2] = [0xDE, 0x05];
                info
            }
        }
    }

    /// This is used for deserializing raw bytes from a reader into a `Header` struct
    ///
    /// This also returns the AAD, read from the header. AAD is only generated in `HeaderVersion::V3` and above - it will be blank in older versions.
    ///
    /// The AAD needs to be passed to decryption functions in order to validate the header, and decrypt the data.
    ///
    /// The AAD for older versions is empty as no AAD is the default for AEADs, and the header validation was not in place prior to V3.
    ///
    /// NOTE: This leaves the cursor at 64 bytes into the buffer, as that is the size of the header
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let header_bytes: [u8; 64] = [
    ///     222, 2, 14, 1, 12, 1, 142, 88, 243, 144, 119, 187, 189, 190, 121, 90, 211, 56, 185, 14, 76,
    ///     45, 16, 5, 237, 72, 7, 203, 13, 145, 13, 155, 210, 29, 128, 142, 241, 233, 42, 168, 243,
    ///     129, 0, 0, 0, 0, 0, 0, 214, 45, 3, 4, 11, 212, 129, 123, 192, 157, 185, 109, 151, 225, 233,
    ///     161,
    /// ];
    /// let mut cursor = Cursor::new(header_bytes);
    ///
    /// // the cursor may be a file, this is just an example
    ///
    /// let (header, aad) = Header::deserialize(&mut cursor).unwrap();
    /// ```
    ///
    #[allow(clippy::too_many_lines)]
    pub fn deserialize(reader: &mut (impl Read + Seek)) -> Result<(Self, Vec<u8>)> {
        let mut version_bytes = [0u8; 2];
        reader
            .read_exact(&mut version_bytes)
            .context("Unable to read version from the header")?;
        reader
            .seek(std::io::SeekFrom::Current(-2))
            .context("Unable to seek back to start of header")?;

        let version = match version_bytes {
            [0xDE, 0x05] => HeaderVersion::V5,
            _ => return Err(anyhow::anyhow!("Error getting version from header")),
        };

        let header_length: usize = match version {
            HeaderVersion::V5 => 416,
        };

        let mut full_header_bytes = vec![0u8; header_length];
        reader
            .read_exact(&mut full_header_bytes)
            .context("Unable to read full bytes of the header")?;

        let mut cursor = Cursor::new(full_header_bytes.clone());
        cursor
            .seek(std::io::SeekFrom::Start(2))
            .context("Unable to seek past version bytes")?; // seek past the version bytes as we already have those

        let mut algorithm_bytes = [0u8; 2];
        cursor
            .read_exact(&mut algorithm_bytes)
            .context("Unable to read algorithm's bytes from header")?;

        let algorithm = match algorithm_bytes {
            [0x0E, 0x01] => Algorithm::XChaCha20Poly1305,
            [0x0E, 0x02] => Algorithm::Aes256GcmSiv,
            _ => return Err(anyhow::anyhow!("Error getting encryption mode from header")),
        };

        let mut mode_bytes = [0u8; 2];
        cursor
            .read_exact(&mut mode_bytes)
            .context("Unable to read encryption mode's bytes from header")?;

        let mode = match mode_bytes {
            [0x0C, 0x01] => Mode::StreamMode,
            [0x0C, 0x02] => Mode::MemoryMode,
            _ => return Err(anyhow::anyhow!("Error getting cipher mode from header")),
        };

        let header_type = HeaderType {
            version,
            algorithm,
            mode,
        };

        let nonce_len = get_nonce_len(&header_type.algorithm, &header_type.mode);
        let salt = [0u8; 16];
        let mut nonce = vec![0u8; nonce_len];

        let keyslots: Option<Vec<Keyslot>> = match header_type.version {
            HeaderVersion::V5 => {
                cursor
                    .read_exact(&mut nonce)
                    .context("Unable to read nonce from header")?;
                cursor
                    .read_exact(&mut vec![0u8; 26 - nonce_len])
                    .context("Unable to read padding from header")?; // here we reach the 32 bytes

                let keyslot_nonce_len = get_nonce_len(&algorithm, &Mode::MemoryMode);

                let mut keyslots: Vec<Keyslot> = Vec::new();
                for _ in 0..4 {
                    let mut identifier = [0u8; 2];
                    cursor
                        .read_exact(&mut identifier)
                        .context("Unable to read keyslot identifier from header")?;

                    if identifier[..1] != [0xDF] {
                        continue;
                    }

                    let mut encrypted_key = [0u8; 48];
                    let mut nonce = vec![0u8; keyslot_nonce_len];
                    let mut padding = vec![0u8; 24 - keyslot_nonce_len];
                    let mut salt = [0u8; SALT_LEN];

                    cursor
                        .read_exact(&mut encrypted_key)
                        .context("Unable to read keyslot encrypted bytes from header")?;

                    cursor
                        .read_exact(&mut nonce)
                        .context("Unable to read keyslot nonce from header")?;

                    cursor
                        .read_exact(&mut padding)
                        .context("Unable to read keyslot padding from header")?;

                    cursor
                        .read_exact(&mut salt)
                        .context("Unable to read keyslot salt from header")?;

                    cursor
                        .read_exact(&mut [0u8; 6])
                        .context("Unable to read keyslot padding from header")?;

                    let hash_algorithm = match identifier {
                        [0xDF, 0xB5] => HashingAlgorithm::Blake3Balloon(5),
                        _ => return Err(anyhow::anyhow!("Key hashing algorithm not identified")),
                    };

                    let keyslot = Keyslot {
                        hash_algorithm,
                        encrypted_key,
                        nonce,
                        salt,
                    };

                    keyslots.push(keyslot);
                }

                Some(keyslots)
            }
        };

        let aad = match header_type.version {
            HeaderVersion::V5 => {
                let mut aad = Vec::new();
                aad.extend_from_slice(&full_header_bytes[..32]);
                aad
            }
        };

        Ok((
            Self {
                header_type,
                nonce,
                salt: Some(salt),
                keyslots,
            },
            aad,
        ))
    }

    /// This is a private function used for serialization
    ///
    /// It converts an `Algorithm` into the associated raw bytes
    fn serialize_algorithm(&self) -> [u8; 2] {
        match self.header_type.algorithm {
            Algorithm::XChaCha20Poly1305 => {
                let info: [u8; 2] = [0x0E, 0x01];
                info
            }
            Algorithm::Aes256GcmSiv => {
                let info: [u8; 2] = [0x0E, 0x02];
                info
            }
        }
    }

    /// This is a private function used for serialization
    ///
    /// It converts a `Mode` into the associated raw bytes
    fn serialize_mode(&self) -> [u8; 2] {
        match self.header_type.mode {
            Mode::StreamMode => {
                let info: [u8; 2] = [0x0C, 0x01];
                info
            }
            Mode::MemoryMode => {
                let info: [u8; 2] = [0x0C, 0x02];
                info
            }
        }
    }

    /// This is a private function (called by `serialize()`)
    ///
    /// It serializes V5 headers
    fn serialize_v5(&self, tag: &HeaderTag) -> Vec<u8> {
        let padding =
            vec![0u8; 26 - get_nonce_len(&self.header_type.algorithm, &self.header_type.mode)];

        let keyslots = self.keyslots.clone().unwrap();

        let mut header_bytes = Vec::<u8>::new();

        // start of header static info
        header_bytes.extend_from_slice(&tag.version);
        header_bytes.extend_from_slice(&tag.algorithm);
        header_bytes.extend_from_slice(&tag.mode);
        header_bytes.extend_from_slice(&self.nonce);
        header_bytes.extend_from_slice(&padding);
        // end of header static info

        for keyslot in &keyslots {
            let keyslot_nonce_len = get_nonce_len(&self.header_type.algorithm, &Mode::MemoryMode);

            header_bytes.extend_from_slice(&keyslot.serialize());
            header_bytes.extend_from_slice(&keyslot.encrypted_key);
            header_bytes.extend_from_slice(&keyslot.nonce);
            header_bytes.extend_from_slice(&vec![0u8; 24 - keyslot_nonce_len]);
            header_bytes.extend_from_slice(&keyslot.salt);
            header_bytes.extend_from_slice(&[0u8; 6]);
        }

        for _ in 0..(4 - keyslots.len()) {
            header_bytes.extend_from_slice(&[0u8; 96]);
        }

        header_bytes
    }

    /// This serializes a `Header` struct, and returns the raw bytes
    ///
    /// The returned bytes may be used as AAD, or written to a file
    ///
    /// NOTE: This should **NOT** be used for validating or creating AAD.
    ///
    /// It only has support for V3 headers and above
    ///
    /// Create AAD with `create_aad()`.
    ///
    /// Use the AAD returned from `deserialize()` for validation.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let header_bytes = header.serialize().unwrap();
    /// ```
    ///
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let tag = self.get_tag();
        match self.header_type.version {
            HeaderVersion::V5 => Ok(self.serialize_v5(&tag)),
        }
    }

    #[must_use]
    pub fn get_size(&self) -> u64 {
        match self.header_type.version {
            HeaderVersion::V5 => 416,
        }
    }

    /// This is for creating AAD
    ///
    /// It only has support for V3 headers and above
    ///
    /// It will return the bytes used for AAD
    ///
    /// You may view more about what is used as AAD [here](https://brxken128.github.io/dexios/dexios-core/Headers.html#authenticating-the-header-with-aad-v840).
    pub fn create_aad(&self) -> Result<Vec<u8>> {
        let tag = self.get_tag();
        match self.header_type.version {
            HeaderVersion::V5 => {
                let mut header_bytes = Vec::<u8>::new();
                header_bytes.extend_from_slice(&tag.version);
                header_bytes.extend_from_slice(&tag.algorithm);
                header_bytes.extend_from_slice(&tag.mode);
                header_bytes.extend_from_slice(&self.nonce);
                header_bytes.extend_from_slice(&vec![
                    0u8;
                    26 - get_nonce_len(
                        &self.header_type.algorithm,
                        &self.header_type.mode
                    )
                ]);
                Ok(header_bytes)
            }
        }
    }

    /// This is a convenience function for writing a header to a writer
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut output_file = File::create("test").unwrap();
    ///
    /// header.write(&mut output_file).unwrap();
    /// ```
    ///
    pub fn write(&self, writer: &mut impl Write) -> Result<()> {
        let header_bytes = self.serialize()?;
        writer
            .write(&header_bytes)
            .context("Unable to write header")?;

        Ok(())
    }
}
