//! This module contains the LE31 stream-mode helpers used by Dexios for file
//! payload encryption and decryption.
//!
//! Current Dexios write paths use this module for new encrypted files.
//!
//! # Examples
//!
//! ```rust,ignore
//! // obviously the key should contain data, not be an empty vec
//! let raw_key = Protected::new(vec![0u8; 128]);
//! let salt = dexios_core::kdf::Salt::new([9u8; 16]);
//! let key = dexios_core::kdf::Kdf::Blake3Balloon.derive(raw_key, &salt).unwrap();
//!
//! // this nonce should be read from somewhere, not generated
//! let nonce = gen_payload_nonce();
//!
//! let decrypt_stream = DecryptionStreams::initialize(key, nonce.as_bytes()).unwrap();
//!
//! let mut input_file = File::open("input.encrypted").unwrap();
//! let mut output_file = File::create("output").unwrap();
//!
//! // aad should be retrieved from the `Header` (with `Header::deserialize()`)
//! let aad = Vec::new();
//!
//! decrypt_stream.decrypt_file(&mut input_file, &mut output_file, &aad);
//! ```

use std::io::{Read, Write};

use aead::{
    KeyInit, Payload,
    stream::{DecryptorLE31, EncryptorLE31},
};
use anyhow::Context;
use chacha20poly1305::XChaCha20Poly1305;
// use rand::{prelude::StdRng, Rng, SeedableRng, RngCore};
use zeroize::Zeroize;

use crate::primitives::{BLOCK_SIZE, PAYLOAD_NONCE_LEN};
use crate::protected::Protected;

/// This `enum` contains streams for that are used solely for encryption
///
pub enum EncryptionStreams {
    XChaCha20Poly1305(Box<EncryptorLE31<XChaCha20Poly1305>>),
}

/// This `enum` contains streams for that are used solely for decryption
///
pub enum DecryptionStreams {
    XChaCha20Poly1305(Box<DecryptorLE31<XChaCha20Poly1305>>),
}

impl EncryptionStreams {
    /// This method can be used to quickly create an `EncryptionStreams` object
    ///
    /// It requies a 32-byte hashed key, which will be dropped once the stream has been initialized
    ///
    /// It requires a pre-generated payload nonce.
    ///
    /// If the nonce length is not exact, you will receive an error.
    ///
    /// It will create the stream with the specified algorithm, and it will also generate the appropriate nonce
    ///
    /// The `EncryptionStreams` object is returned
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // obviously the key should contain data, not be an empty vec
    /// let raw_key = Protected::new(vec![0u8; 128]);
    /// let salt = dexios_core::kdf::Salt::new([9u8; 16]);
    /// let key = dexios_core::kdf::Kdf::Blake3Balloon.derive(raw_key, &salt).unwrap();
    ///
    /// let nonce = dexios_core::primitives::gen_payload_nonce();
    /// let encrypt_stream = EncryptionStreams::initialize(key, nonce.as_bytes()).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the nonce length is invalid for V1 or if the hashed
    /// key cannot initialize the stream cipher.
    pub fn initialize(key: Protected<[u8; 32]>, nonce: &[u8]) -> anyhow::Result<Self> {
        if nonce.len() != PAYLOAD_NONCE_LEN {
            return Err(anyhow::anyhow!("Nonce is not the correct length"));
        }

        let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
            .map_err(|_| anyhow::anyhow!("Unable to create cipher with hashed key."))?;
        let stream = EncryptorLE31::from_aead(cipher, nonce.into());

        drop(key);
        Ok(EncryptionStreams::XChaCha20Poly1305(Box::new(stream)))
    }

    /// This is used for encrypting the *next* block of data in streaming mode
    ///
    /// It requires either some plaintext, or an `aead::Payload` (that contains the plaintext and the AAD)
    ///
    /// # Errors
    ///
    /// Returns an error if the AEAD rejects the supplied payload or AAD.
    pub fn encrypt_next<'msg, 'aad>(
        &mut self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            EncryptionStreams::XChaCha20Poly1305(s) => s.encrypt_next(payload),
        }
    }

    /// This is used for encrypting the *last* block of data in streaming mode. It consumes the stream object to prevent further usage.
    ///
    /// It requires either some plaintext, or an `aead::Payload` (that contains the plaintext and the AAD)
    ///
    /// # Errors
    ///
    /// Returns an error if the AEAD rejects the supplied payload or AAD.
    pub fn encrypt_last<'msg, 'aad>(
        self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            EncryptionStreams::XChaCha20Poly1305(s) => s.encrypt_last(payload),
        }
    }

    /// This is a convenience function for reading from a reader, encrypting, and writing to the writer.
    ///
    /// Every single block is provided with the AAD
    ///
    /// Valid AAD must be provided if you are using `HeaderVersion::V3` and
    /// above. It must be empty if the header version is lower.
    ///
    /// You are free to use a custom AAD, just ensure that it is present for decryption, or else you will receive an error.
    ///
    /// This does not handle writing the header.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut input_file = File::open("input").unwrap();
    /// let mut output_file = File::create("output.encrypted").unwrap();
    ///
    /// // aad should be generated from the header with `create_aad()`
    /// let aad = header.create_aad().unwrap();
    ///
    /// let encrypt_stream = EncryptionStreams::initialize(key, nonce.as_bytes()).unwrap();
    /// encrypt_stream.encrypt_file(&mut input_file, &mut output_file, &aad);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if reading from the input fails, writing to the output
    /// fails, flushing the writer fails, or the stream cipher rejects a block.
    pub fn encrypt_file(
        mut self,
        reader: &mut impl Read,
        writer: &mut impl Write,
        aad: &[u8],
    ) -> anyhow::Result<()> {
        #[cfg(feature = "visual")]
        let pb = crate::visual::create_spinner();

        let mut read_buffer = vec![0u8; BLOCK_SIZE].into_boxed_slice();
        loop {
            let read_count = reader
                .read(&mut read_buffer)
                .context("Unable to read from the reader")?;
            if read_count == BLOCK_SIZE {
                // aad is just empty bytes normally
                // create_aad returns empty bytes if the header isn't V3+
                // this means we don't need to do anything special in regards to older versions
                let payload = Payload {
                    aad,
                    msg: read_buffer.as_ref(),
                };

                let encrypted_data = self
                    .encrypt_next(payload)
                    .map_err(|_| anyhow::anyhow!("Unable to encrypt the data"))?;

                writer
                    .write_all(&encrypted_data)
                    .context("Unable to write to the output")?;
            } else {
                // if we read something less than BLOCK_SIZE, and have hit the end of the file
                let payload = Payload {
                    aad,
                    msg: &read_buffer[..read_count],
                };

                let encrypted_data = self
                    .encrypt_last(payload)
                    .map_err(|_| anyhow::anyhow!("Unable to encrypt the data"))?;

                writer
                    .write_all(&encrypted_data)
                    .context("Unable to write to the output")?;
                break;
            }
        }
        read_buffer.zeroize();
        writer.flush().context("Unable to flush the output")?;

        #[cfg(feature = "visual")]
        pb.finish_and_clear();

        Ok(())
    }
}

impl DecryptionStreams {
    /// This method can be used to quickly create an `DecryptionStreams` object
    ///
    /// It requies a 32-byte hashed key, which will be dropped once the stream has been initialized
    ///
    /// It requires the same nonce that was returned upon initializing `EncryptionStreams`
    ///
    /// It will create the stream with the specified algorithm
    ///
    /// The `DecryptionStreams` object will be returned
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // obviously the key should contain data, not be an empty vec
    /// let raw_key = Protected::new(vec![0u8; 128]);
    /// let salt = dexios_core::kdf::Salt::new([9u8; 16]);
    /// let key = dexios_core::kdf::Kdf::Blake3Balloon.derive(raw_key, &salt).unwrap();
    ///
    /// // this nonce should be read from somewhere, not generated
    /// let nonce = dexios_core::primitives::gen_payload_nonce();
    ///
    /// let decrypt_stream = DecryptionStreams::initialize(key, nonce.as_bytes()).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the nonce length is invalid for V1 or if the hashed
    /// key cannot initialize the stream cipher.
    pub fn initialize(key: Protected<[u8; 32]>, nonce: &[u8]) -> anyhow::Result<Self> {
        if nonce.len() != PAYLOAD_NONCE_LEN {
            return Err(anyhow::anyhow!("Nonce is not the correct length"));
        }

        let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
            .map_err(|_| anyhow::anyhow!("Unable to create cipher with hashed key."))?;
        let stream = DecryptorLE31::from_aead(cipher, nonce.into());

        drop(key);
        Ok(DecryptionStreams::XChaCha20Poly1305(Box::new(stream)))
    }

    /// This is used for decrypting the *next* block of data in streaming mode
    ///
    /// It requires either some plaintext, or an `aead::Payload` (that contains the plaintext and the AAD)
    ///
    /// Whatever you provided as AAD while encrypting must be present during decryption, or else you will receive an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the AEAD rejects the supplied payload or AAD.
    pub fn decrypt_next<'msg, 'aad>(
        &mut self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            DecryptionStreams::XChaCha20Poly1305(s) => s.decrypt_next(payload),
        }
    }

    /// This is used for decrypting the *last* block of data in streaming mode. It consumes the stream object to prevent further usage.
    ///
    /// It requires either some plaintext, or an `aead::Payload` (that contains the plaintext and the AAD)
    ///
    /// Whatever you provided as AAD while encrypting must be present during decryption, or else you will receive an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the AEAD rejects the supplied payload or AAD.
    pub fn decrypt_last<'msg, 'aad>(
        self,
        payload: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        match self {
            DecryptionStreams::XChaCha20Poly1305(s) => s.decrypt_last(payload),
        }
    }

    /// This is a convenience function for reading from a reader, decrypting, and writing to the writer.
    ///
    /// Every single block is provided with the AAD
    ///
    /// Valid AAD must be provided if you are using `HeaderVersion::V3` and above. It must be empty if the `HeaderVersion` is lower. Whatever you provided as AAD while encrypting must be present during decryption, or else you will receive an error.
    ///
    /// This does not handle writing the header.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut input_file = File::open("input.encrypted").unwrap();
    /// let mut output_file = File::create("output").unwrap();
    ///
    /// // aad should be retrieved from the `Header` (with `Header::deserialize()`)
    /// let aad = Vec::new();
    ///
    /// let decrypt_stream = DecryptionStreams::initialize(key, nonce.as_bytes()).unwrap();
    /// decrypt_stream.decrypt_file(&mut input_file, &mut output_file, &aad);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if reading from the input fails, writing to the output
    /// fails, or the stream cipher rejects a block during decryption.
    pub fn decrypt_file(
        mut self,
        reader: &mut impl Read,
        writer: &mut impl Write,
        aad: &[u8],
    ) -> anyhow::Result<()> {
        #[cfg(feature = "visual")]
        let pb = crate::visual::create_spinner();

        let mut buffer = vec![0u8; BLOCK_SIZE + 16].into_boxed_slice();
        loop {
            let read_count = reader.read(&mut buffer)?;
            if read_count == (BLOCK_SIZE + 16) {
                let payload = Payload {
                    aad,
                    msg: buffer.as_ref(),
                };

                let mut decrypted_data = self.decrypt_next(payload).map_err(|_| {
                    anyhow::anyhow!("Unable to decrypt the data. This means either: you're using the wrong key, this isn't an encrypted file, or the header has been tampered with.")
                })?;

                writer
                    .write_all(&decrypted_data)
                    .context("Unable to write to the output")?;

                decrypted_data.zeroize();
            } else {
                // if we read something less than BLOCK_SIZE+16, and have hit the end of the file
                let payload = Payload {
                    aad,
                    msg: &buffer[..read_count],
                };

                let mut decrypted_data = self.decrypt_last(payload).map_err(|_| {
                    anyhow::anyhow!("Unable to decrypt the final block of data. This means either: you're using the wrong key, this isn't an encrypted file, or the header has been tampered with.")
                })?;

                writer
                    .write_all(&decrypted_data)
                    .context("Unable to write to the output file")?;

                decrypted_data.zeroize();
                break;
            }
        }

        writer.flush().context("Unable to flush the output")?;

        #[cfg(feature = "visual")]
        pb.finish_and_clear();

        Ok(())
    }
}

pub mod legacy {
    use crate::primitives::legacy::Algorithm;
    use crate::protected::Protected;

    use super::{DecryptionStreams, EncryptionStreams};

    pub fn initialize_encryption(
        key: Protected<[u8; 32]>,
        nonce: &[u8],
        algorithm: &Algorithm,
    ) -> anyhow::Result<EncryptionStreams> {
        if algorithm != &Algorithm::XChaCha20Poly1305 {
            return Err(anyhow::anyhow!("Unsupported cipher suite"));
        }

        EncryptionStreams::initialize(key, nonce)
    }

    pub fn initialize_decryption(
        key: Protected<[u8; 32]>,
        nonce: &[u8],
        algorithm: &Algorithm,
    ) -> anyhow::Result<DecryptionStreams> {
        if algorithm != &Algorithm::XChaCha20Poly1305 {
            return Err(anyhow::anyhow!("Unsupported cipher suite"));
        }

        DecryptionStreams::initialize(key, nonce)
    }
}
