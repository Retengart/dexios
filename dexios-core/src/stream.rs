//! This module contains the typed LE31 stream-mode helpers used by Dexios for
//! V1 file payload encryption and decryption.
//!
//! Normal V1 callers provide a typed master key and a V1 header or parsed V1
//! payload bundle. The stream layer derives AAD from those typed inputs; it does
//! not accept arbitrary caller-supplied AAD for the normal V1 API.

use std::fmt::{Display, Formatter};
use std::io::{self, ErrorKind, Read, Write};

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
    InvalidChunkSize(usize),
    CipherInit,
    Read(io::Error),
    Write(io::Error),
    Flush(io::Error),
    Authentication,
    TruncatedCiphertext,
    MissingFinalBlock,
    FinalBlockAuthentication,
}

impl Display for StreamError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidNonceLength(len) => write!(f, "invalid V1 stream nonce length: {len}"),
            Self::InvalidChunkSize(len) => write!(f, "invalid V1 stream chunk size: {len}"),
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

#[expect(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::needless_continue,
    reason = "the `filled < buffer.len()` loop guard keeps `buffer[filled..]` in bounds and `filled += read_count` <= buffer.len(); the explicit `continue` documents the EINTR retry"
)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct V1FinalAuth {
    _private: (),
}

impl V1PayloadStream {
    pub fn encrypt_file(
        master_key: MasterKey,
        header: &V1Header,
        reader: &mut impl Read,
        writer: &mut impl Write,
    ) -> Result<(), StreamError> {
        V1PayloadEncryptor::new(master_key, header)?.encrypt_file(reader, writer)
    }

    /// Decrypts into `writer` as uncommitted scratch.
    ///
    /// Callers must commit or publish final plaintext only after this function
    /// returns `Ok(V1FinalAuth)`, proving the final authentication receipt was
    /// produced for the complete V1 payload.
    pub fn decrypt_file_uncommitted(
        master_key: MasterKey,
        payload: &ParsedV1Payload,
        reader: &mut impl Read,
        writer: &mut impl Write,
    ) -> Result<V1FinalAuth, StreamError> {
        V1PayloadDecryptor::new(master_key, payload)?.decrypt_file_uncommitted(reader, writer)
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
        if plaintext.len() != BLOCK_SIZE {
            return Err(StreamError::InvalidChunkSize(plaintext.len()));
        }
        let payload = Payload {
            aad: self.aad.as_bytes(),
            msg: plaintext,
        };
        self.stream.encrypt_next(payload)
    }

    pub fn encrypt_last(self, plaintext: &[u8]) -> Result<Vec<u8>, StreamError> {
        if plaintext.len() >= BLOCK_SIZE {
            return Err(StreamError::InvalidChunkSize(plaintext.len()));
        }
        let payload = Payload {
            aad: self.aad.as_bytes(),
            msg: plaintext,
        };
        self.stream.encrypt_last(payload)
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "read_count is the count returned by read_up_to_full into a BLOCK_SIZE buffer, so read_buffer[..read_count] is always in bounds"
    )]
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

/// Streaming V1 payload encryptor.
///
/// Dropping the writer without calling `finish` zeroizes the internal plaintext
/// buffer but intentionally does not write the final authenticated block. The
/// resulting ciphertext is incomplete and must not be published.
#[must_use = "call finish() to write the final authenticated block"]
pub struct V1PayloadEncryptingWriter<W: Write> {
    encryptor: Option<V1PayloadEncryptor>,
    writer: Option<W>,
    buffer: Box<[u8]>,
    buffered: usize,
    finished: bool,
}

impl<W: Write> V1PayloadEncryptingWriter<W> {
    pub fn new(master_key: MasterKey, header: &V1Header, writer: W) -> Result<Self, StreamError> {
        Ok(Self {
            encryptor: Some(V1PayloadEncryptor::new(master_key, header)?),
            writer: Some(writer),
            buffer: vec![0u8; BLOCK_SIZE].into_boxed_slice(),
            buffered: 0,
            finished: false,
        })
    }

    #[expect(
        clippy::expect_used,
        reason = "writer is only taken once in finish(); the Option is always Some until the writer is consumed exactly here"
    )]
    pub fn finish(mut self) -> Result<W, StreamError> {
        self.finish_payload()?;
        Ok(self.writer.take().expect("finished writer is present"))
    }

    #[expect(
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "buffered <= BLOCK_SIZE invariant keeps available = BLOCK_SIZE - buffered and the buffer[buffered..buffered+take] / input[..take] ranges in bounds (take = min(available, input.len()))"
    )]
    fn write_plaintext(&mut self, mut input: &[u8]) -> Result<(), StreamError> {
        if self.finished {
            return Err(StreamError::Write(io::Error::new(
                ErrorKind::BrokenPipe,
                "V1 payload writer is already finished",
            )));
        }

        while !input.is_empty() {
            let available = BLOCK_SIZE - self.buffered;
            let take = available.min(input.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&input[..take]);
            self.buffered += take;
            input = &input[take..];

            if self.buffered == BLOCK_SIZE {
                self.write_full_buffer()?;
            }
        }

        Ok(())
    }

    #[expect(
        clippy::expect_used,
        reason = "encryptor and writer stay Some for the entire lifetime of an unfinished writer; both are only consumed in finish_payload()"
    )]
    fn write_full_buffer(&mut self) -> Result<(), StreamError> {
        let encrypted = match self
            .encryptor
            .as_mut()
            .expect("unfinished writer has encryptor")
            .encrypt_next(&self.buffer)
        {
            Ok(encrypted) => encrypted,
            Err(error) => {
                self.buffer.zeroize();
                self.buffered = 0;
                return Err(error);
            }
        };
        self.buffer.zeroize();
        self.buffered = 0;
        self.writer
            .as_mut()
            .expect("unfinished writer is present")
            .write_all(&encrypted)
            .map_err(StreamError::Write)
    }

    #[expect(
        clippy::expect_used,
        clippy::indexing_slicing,
        reason = "encryptor/writer are Some until consumed exactly here, and buffered <= BLOCK_SIZE keeps buffer[..buffered] in bounds"
    )]
    fn finish_payload(&mut self) -> Result<(), StreamError> {
        if self.finished {
            return Ok(());
        }

        let encryptor = self
            .encryptor
            .take()
            .expect("unfinished writer has encryptor");
        let encrypted = match encryptor.encrypt_last(&self.buffer[..self.buffered]) {
            Ok(encrypted) => encrypted,
            Err(error) => {
                self.buffer.zeroize();
                self.buffered = 0;
                return Err(error);
            }
        };
        self.buffer.zeroize();
        self.buffered = 0;
        let writer = self.writer.as_mut().expect("unfinished writer is present");
        writer.write_all(&encrypted).map_err(StreamError::Write)?;
        writer.flush().map_err(StreamError::Flush)?;
        self.finished = true;
        Ok(())
    }
}

impl<W: Write> Write for V1PayloadEncryptingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_plaintext(buf).map_err(stream_error_to_io)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer
            .as_mut()
            .ok_or_else(|| io::Error::new(ErrorKind::BrokenPipe, "V1 payload writer is closed"))?
            .flush()
    }
}

impl<W: Write> Drop for V1PayloadEncryptingWriter<W> {
    fn drop(&mut self) {
        self.buffer.zeroize();
        self.buffered = 0;
    }
}

/// Exposes uncommitted plaintext chunks before final authentication completes.
pub struct V1PayloadDecryptingReader<R: Read> {
    decryptor: Option<V1PayloadDecryptor>,
    reader: R,
    ciphertext_buffer: Box<[u8]>,
    plaintext_buffer: Vec<u8>,
    plaintext_offset: usize,
    final_auth: Option<V1FinalAuth>,
}

impl<R: Read> V1PayloadDecryptingReader<R> {
    pub fn new(
        master_key: MasterKey,
        payload: &ParsedV1Payload,
        reader: R,
    ) -> Result<Self, StreamError> {
        Ok(Self {
            decryptor: Some(V1PayloadDecryptor::new(master_key, payload)?),
            reader,
            ciphertext_buffer: vec![0u8; BLOCK_SIZE + 16].into_boxed_slice(),
            plaintext_buffer: Vec::new(),
            plaintext_offset: 0,
            final_auth: None,
        })
    }

    pub fn finish(self) -> Result<V1FinalAuth, StreamError> {
        if self.plaintext_offset != self.plaintext_buffer.len() {
            return Err(StreamError::MissingFinalBlock);
        }
        self.final_auth.ok_or(StreamError::MissingFinalBlock)
    }

    /// Reads plaintext into `buf` before final authentication has completed.
    ///
    /// Bytes returned from this method are uncommitted scratch until `finish`
    /// returns `Ok(V1FinalAuth)`.
    #[expect(
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "plaintext_offset <= plaintext_buffer.len() invariant keeps available = len - offset and the buf[..take] / plaintext_buffer[offset..offset+take] ranges in bounds (take = min(available, buf.len()))"
    )]
    pub fn read_uncommitted(&mut self, buf: &mut [u8]) -> Result<usize, StreamError> {
        if buf.is_empty() {
            return Ok(0);
        }

        if self.plaintext_offset == self.plaintext_buffer.len() {
            self.plaintext_buffer.zeroize();
            self.plaintext_buffer.clear();
            self.plaintext_offset = 0;
            self.fill_plaintext()?;
        }

        if self.plaintext_offset == self.plaintext_buffer.len() && self.final_auth.is_some() {
            return Ok(0);
        }

        let available = self.plaintext_buffer.len() - self.plaintext_offset;
        let take = available.min(buf.len());
        buf[..take].copy_from_slice(
            &self.plaintext_buffer[self.plaintext_offset..self.plaintext_offset + take],
        );
        self.plaintext_offset += take;
        Ok(take)
    }

    #[expect(
        clippy::expect_used,
        clippy::indexing_slicing,
        reason = "decryptor is Some until the final block is consumed exactly here, and read_count <= ciphertext_buffer.len() keeps the final-block slice in bounds"
    )]
    fn fill_plaintext(&mut self) -> Result<(), StreamError> {
        if self.final_auth.is_some() {
            return Ok(());
        }

        let read_count = read_up_to_full(&mut self.reader, &mut self.ciphertext_buffer)?;
        if read_count == 0 {
            return Err(StreamError::MissingFinalBlock);
        }

        let plaintext = if read_count == BLOCK_SIZE + 16 {
            self.decryptor
                .as_mut()
                .expect("unfinished decrypting reader has decryptor")
                .decrypt_next(&self.ciphertext_buffer)?
        } else {
            let decryptor = self
                .decryptor
                .take()
                .expect("unfinished decrypting reader has decryptor");
            let plaintext = decryptor.decrypt_last(&self.ciphertext_buffer[..read_count])?;
            self.final_auth = Some(V1FinalAuth { _private: () });
            plaintext
        };

        self.plaintext_buffer = plaintext;
        self.plaintext_offset = 0;
        Ok(())
    }
}

impl<R: Read> Drop for V1PayloadDecryptingReader<R> {
    fn drop(&mut self) {
        self.ciphertext_buffer.zeroize();
        self.plaintext_buffer.zeroize();
        self.plaintext_offset = 0;
    }
}

fn stream_error_to_io(error: StreamError) -> io::Error {
    match error {
        StreamError::Write(error) | StreamError::Flush(error) => error,
        error => io::Error::other(error),
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
        if ciphertext.len() != BLOCK_SIZE + 16 {
            return Err(StreamError::InvalidChunkSize(ciphertext.len()));
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
        if ciphertext.len() >= BLOCK_SIZE + 16 {
            return Err(StreamError::InvalidChunkSize(ciphertext.len()));
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

    #[expect(
        clippy::indexing_slicing,
        reason = "read_count is the count returned by read_up_to_full into a BLOCK_SIZE + 16 buffer, so buffer[..read_count] is always in bounds"
    )]
    pub fn decrypt_file_uncommitted(
        mut self,
        reader: &mut impl Read,
        writer: &mut impl Write,
    ) -> Result<V1FinalAuth, StreamError> {
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

        Ok(V1FinalAuth { _private: () })
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
