//! This module contains the typed LE31 stream-mode helpers used by Dexios for
//! V1 file payload encryption and decryption.
//!
//! Normal V1 callers provide a typed master key and a V1 header or parsed V1
//! payload bundle. The stream layer derives AAD from those typed inputs; it does
//! not accept arbitrary caller-supplied AAD for the normal V1 API.

use std::fmt::{Display, Formatter};
use std::io::{ErrorKind, Read, Write};

use aead::{
    KeyInit, Payload,
    stream::{DecryptorLE31, EncryptorLE31},
};
use chacha20poly1305::XChaCha20Poly1305;
use zeroize::Zeroize;

use crate::header::ParsedV1Payload;
use crate::header::common::{PayloadNonce, V1HeaderAad};
use crate::header::v1::V1Header;
use crate::primitives::{BLOCK_SIZE, MasterKey};

#[derive(Debug)]
pub enum StreamError {
    InvalidNonceLength(usize),
    CipherInit,
    Read(std::io::Error),
    Write(std::io::Error),
    Flush(std::io::Error),
    Authentication,
    TruncatedCiphertext,
    MissingFinalBlock,
    FinalBlockAuthentication,
}

impl Display for StreamError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidNonceLength(len) => write!(f, "invalid V1 stream nonce length: {len}"),
            Self::CipherInit => f.write_str("unable to initialize V1 stream cipher"),
            Self::Read(error) => write!(f, "unable to read V1 stream data: {error}"),
            Self::Write(error) => write!(f, "unable to write V1 stream data: {error}"),
            Self::Flush(error) => write!(f, "unable to flush V1 stream output: {error}"),
            Self::Authentication => f.write_str("V1 stream authentication failed"),
            Self::TruncatedCiphertext => f.write_str("truncated V1 stream ciphertext"),
            Self::MissingFinalBlock => f.write_str("missing V1 stream final block"),
            Self::FinalBlockAuthentication => {
                f.write_str("V1 stream final block authentication failed")
            }
        }
    }
}

impl std::error::Error for StreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(error) | Self::Write(error) | Self::Flush(error) => Some(error),
            _ => None,
        }
    }
}

fn read_up_to_full(reader: &mut impl Read, buffer: &mut [u8]) -> Result<usize, StreamError> {
    let mut filled = 0;

    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read_count) => filled += read_count,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(StreamError::Read(error)),
        }
    }

    Ok(filled)
}

pub struct V1PayloadStream;

impl V1PayloadStream {
    pub fn encrypt_file(
        master_key: MasterKey,
        header: &V1Header,
        reader: &mut impl Read,
        writer: &mut impl Write,
    ) -> Result<(), StreamError> {
        V1PayloadEncryptor::new(master_key, header)?.encrypt_file(reader, writer)
    }

    /// Decrypts into `writer` as uncommitted scratch; callers must only commit
    /// the plaintext after this function returns `Ok(())`.
    pub fn decrypt_file(
        master_key: MasterKey,
        payload: &ParsedV1Payload,
        reader: &mut impl Read,
        writer: &mut impl Write,
    ) -> Result<(), StreamError> {
        V1PayloadDecryptor::new(master_key, payload)?.decrypt_file(reader, writer)
    }
}

pub struct V1PayloadEncryptor {
    stream: EncryptionStreams,
    aad: V1HeaderAad,
}

impl V1PayloadEncryptor {
    pub fn new(master_key: MasterKey, header: &V1Header) -> Result<Self, StreamError> {
        Ok(Self {
            stream: EncryptionStreams::initialize(master_key, header.payload_nonce())?,
            aad: header.aad(),
        })
    }

    pub fn encrypt_next(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, StreamError> {
        let payload = Payload {
            aad: self.aad.as_bytes(),
            msg: plaintext,
        };
        self.stream.encrypt_next(payload)
    }

    pub fn encrypt_last(self, plaintext: &[u8]) -> Result<Vec<u8>, StreamError> {
        let payload = Payload {
            aad: self.aad.as_bytes(),
            msg: plaintext,
        };
        self.stream.encrypt_last(payload)
    }

    pub fn encrypt_file(
        mut self,
        reader: &mut impl Read,
        writer: &mut impl Write,
    ) -> Result<(), StreamError> {
        #[cfg(feature = "visual")]
        let pb = crate::visual::create_spinner();

        let mut read_buffer = vec![0u8; BLOCK_SIZE].into_boxed_slice();
        loop {
            let read_count = match read_up_to_full(reader, &mut read_buffer) {
                Ok(read_count) => read_count,
                Err(error) => {
                    read_buffer.zeroize();
                    return Err(error);
                }
            };

            let encrypted_data = if read_count == BLOCK_SIZE {
                match self.encrypt_next(read_buffer.as_ref()) {
                    Ok(encrypted_data) => encrypted_data,
                    Err(error) => {
                        read_buffer.zeroize();
                        return Err(error);
                    }
                }
            } else {
                let encrypted_data = match self.encrypt_last(&read_buffer[..read_count]) {
                    Ok(encrypted_data) => encrypted_data,
                    Err(error) => {
                        read_buffer.zeroize();
                        return Err(error);
                    }
                };
                if let Err(error) = writer.write_all(&encrypted_data) {
                    read_buffer.zeroize();
                    return Err(StreamError::Write(error));
                }
                break;
            };

            if let Err(error) = writer.write_all(&encrypted_data) {
                read_buffer.zeroize();
                return Err(StreamError::Write(error));
            }
        }

        read_buffer.zeroize();
        writer.flush().map_err(StreamError::Flush)?;

        #[cfg(feature = "visual")]
        pb.finish_and_clear();

        Ok(())
    }
}

pub struct V1PayloadDecryptor {
    stream: DecryptionStreams,
    aad: V1HeaderAad,
}

impl V1PayloadDecryptor {
    pub fn new(master_key: MasterKey, payload: &ParsedV1Payload) -> Result<Self, StreamError> {
        Ok(Self {
            stream: DecryptionStreams::initialize(master_key, payload.payload_nonce())?,
            aad: *payload.aad(),
        })
    }

    pub fn decrypt_next(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, StreamError> {
        if ciphertext.len() < 16 {
            return Err(StreamError::TruncatedCiphertext);
        }
        let payload = Payload {
            aad: self.aad.as_bytes(),
            msg: ciphertext,
        };
        self.stream.decrypt_next(payload)
    }

    pub fn decrypt_last(self, ciphertext: &[u8]) -> Result<Vec<u8>, StreamError> {
        if ciphertext.is_empty() {
            return Err(StreamError::MissingFinalBlock);
        }
        if ciphertext.len() < 16 {
            return Err(StreamError::TruncatedCiphertext);
        }
        let payload = Payload {
            aad: self.aad.as_bytes(),
            msg: ciphertext,
        };
        self.stream.decrypt_last(payload)
    }

    pub fn decrypt_file(
        mut self,
        reader: &mut impl Read,
        writer: &mut impl Write,
    ) -> Result<(), StreamError> {
        #[cfg(feature = "visual")]
        let pb = crate::visual::create_spinner();

        let mut buffer = vec![0u8; BLOCK_SIZE + 16].into_boxed_slice();
        loop {
            let read_count = match read_up_to_full(reader, &mut buffer) {
                Ok(read_count) => read_count,
                Err(error) => {
                    buffer.zeroize();
                    return Err(error);
                }
            };

            if read_count == 0 {
                buffer.zeroize();
                return Err(StreamError::MissingFinalBlock);
            }

            if read_count == BLOCK_SIZE + 16 {
                let mut decrypted_data = match self.decrypt_next(buffer.as_ref()) {
                    Ok(decrypted_data) => decrypted_data,
                    Err(error) => {
                        buffer.zeroize();
                        return Err(error);
                    }
                };
                if let Err(error) = writer.write_all(&decrypted_data) {
                    decrypted_data.zeroize();
                    buffer.zeroize();
                    return Err(StreamError::Write(error));
                }
                decrypted_data.zeroize();
            } else {
                let mut decrypted_data = match self.decrypt_last(&buffer[..read_count]) {
                    Ok(decrypted_data) => decrypted_data,
                    Err(error) => {
                        buffer.zeroize();
                        return Err(error);
                    }
                };
                if let Err(error) = writer.write_all(&decrypted_data) {
                    decrypted_data.zeroize();
                    buffer.zeroize();
                    return Err(StreamError::Write(error));
                }
                decrypted_data.zeroize();
                break;
            }
        }

        buffer.zeroize();
        writer.flush().map_err(StreamError::Flush)?;

        #[cfg(feature = "visual")]
        pb.finish_and_clear();

        Ok(())
    }
}

enum EncryptionStreams {
    XChaCha20Poly1305(Box<EncryptorLE31<XChaCha20Poly1305>>),
}

impl EncryptionStreams {
    fn initialize(key: MasterKey, nonce: &PayloadNonce) -> Result<Self, StreamError> {
        if nonce.as_bytes().len() != crate::primitives::PAYLOAD_NONCE_LEN {
            return Err(StreamError::InvalidNonceLength(nonce.as_bytes().len()));
        }

        let cipher = key.with_exposed(|key| {
            XChaCha20Poly1305::new_from_slice(key).map_err(|_| StreamError::CipherInit)
        })?;
        let stream = EncryptorLE31::from_aead(cipher, nonce.as_bytes().as_ref().into());

        Ok(Self::XChaCha20Poly1305(Box::new(stream)))
    }

    fn encrypt_next<'msg, 'aad>(
        &mut self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, StreamError> {
        match self {
            Self::XChaCha20Poly1305(stream) => stream
                .encrypt_next(payload)
                .map_err(|_| StreamError::Authentication),
        }
    }

    fn encrypt_last<'msg, 'aad>(
        self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, StreamError> {
        match self {
            Self::XChaCha20Poly1305(stream) => stream
                .encrypt_last(payload)
                .map_err(|_| StreamError::Authentication),
        }
    }
}

enum DecryptionStreams {
    XChaCha20Poly1305(Box<DecryptorLE31<XChaCha20Poly1305>>),
}

impl DecryptionStreams {
    fn initialize(key: MasterKey, nonce: &PayloadNonce) -> Result<Self, StreamError> {
        if nonce.as_bytes().len() != crate::primitives::PAYLOAD_NONCE_LEN {
            return Err(StreamError::InvalidNonceLength(nonce.as_bytes().len()));
        }

        let cipher = key.with_exposed(|key| {
            XChaCha20Poly1305::new_from_slice(key).map_err(|_| StreamError::CipherInit)
        })?;
        let stream = DecryptorLE31::from_aead(cipher, nonce.as_bytes().as_ref().into());

        Ok(Self::XChaCha20Poly1305(Box::new(stream)))
    }

    fn decrypt_next<'msg, 'aad>(
        &mut self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, StreamError> {
        match self {
            Self::XChaCha20Poly1305(stream) => stream
                .decrypt_next(payload)
                .map_err(|_| StreamError::Authentication),
        }
    }

    fn decrypt_last<'msg, 'aad>(
        self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, StreamError> {
        match self {
            Self::XChaCha20Poly1305(stream) => stream
                .decrypt_last(payload)
                .map_err(|_| StreamError::FinalBlockAuthentication),
        }
    }
}
