//! This provides functionality for V1 encryption that adheres to the Dexios format.

use std::cell::RefCell;
use std::io::{Read, Seek, Write};

use core::cipher::Ciphers;
use core::header::common::Salt;
use core::header::v1::{V1Header, V1Keyslot, V1Keyslots};
use core::kdf::Kdf;
use core::primitives::{ENCRYPTED_MASTER_KEY_LEN, gen_keyslot_nonce, gen_payload_nonce};
use core::protected::Protected;
use core::stream::V1PayloadStream;

use crate::utils::{gen_master_key, gen_salt};

#[derive(Debug)]
pub enum Error {
    ResetCursorPosition,
    HashKey,
    EncryptMasterKey,
    EncryptFile,
    WriteHeader,
    InitializeStreams,
    InitializeChiphers,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ResetCursorPosition => f.write_str("Unable to reset cursor position"),
            Error::HashKey => f.write_str("Cannot hash raw key"),
            Error::EncryptMasterKey => f.write_str("Cannot encrypt master key"),
            Error::EncryptFile => f.write_str("Cannot encrypt file"),
            Error::WriteHeader => f.write_str("Cannot write header"),
            Error::InitializeStreams => f.write_str("Cannot initialize streams"),
            Error::InitializeChiphers => f.write_str("Cannot initialize chiphers"),
        }
    }
}

impl std::error::Error for Error {}

pub struct Request<'a, R, W>
where
    R: Read + Seek,
    W: Write + Seek,
{
    pub reader: &'a RefCell<R>,
    pub writer: &'a RefCell<W>,
    pub header_writer: Option<&'a RefCell<W>>,
    pub raw_key: Protected<Vec<u8>>,
    pub kdf: Kdf,
}

pub fn execute<R, W>(req: Request<'_, R, W>) -> Result<(), Error>
where
    R: Read + Seek,
    W: Write + Seek,
{
    let salt_bytes = gen_salt();
    let header_salt = Salt::new(salt_bytes);
    let kdf_salt = core::kdf::Salt::new(salt_bytes);

    let key = req
        .kdf
        .derive(req.raw_key, &kdf_salt)
        .map_err(|_| Error::HashKey)?;
    let cipher = Ciphers::initialize(key).map_err(|_| Error::InitializeChiphers)?;

    let master_key = gen_master_key();
    let master_key_nonce = gen_keyslot_nonce();
    let master_key_encrypted = {
        let encrypted_key = cipher
            .encrypt(master_key_nonce.as_bytes(), master_key.as_slice())
            .map_err(|_| Error::EncryptMasterKey)?;

        let mut encrypted_key_arr = [0u8; ENCRYPTED_MASTER_KEY_LEN];
        let len = ENCRYPTED_MASTER_KEY_LEN.min(encrypted_key.len());
        encrypted_key_arr[..len].copy_from_slice(&encrypted_key[..len]);
        encrypted_key_arr
    };

    let keyslot = V1Keyslot::new(req.kdf, master_key_encrypted, master_key_nonce, header_salt);
    let payload_nonce = gen_payload_nonce();
    let header = V1Header::new(payload_nonce, V1Keyslots::single(keyslot))
        .map_err(|_| Error::WriteHeader)?;

    req.writer
        .borrow_mut()
        .rewind()
        .map_err(|_| Error::ResetCursorPosition)?;

    match req.header_writer {
        None => {
            req.writer
                .borrow_mut()
                .write_all(&header.serialize().map_err(|_| Error::WriteHeader)?)
                .map_err(|_| Error::WriteHeader)?;
        }
        Some(header_writer) => {
            header_writer
                .borrow_mut()
                .rewind()
                .map_err(|_| Error::ResetCursorPosition)?;
            header_writer
                .borrow_mut()
                .write_all(&header.serialize().map_err(|_| Error::WriteHeader)?)
                .map_err(|_| Error::WriteHeader)?;
        }
    }

    let mut reader = req.reader.borrow_mut();
    reader.rewind().map_err(|_| Error::ResetCursorPosition)?;

    let mut writer = req.writer.borrow_mut();
    V1PayloadStream::encrypt_file(master_key, &header, &mut *reader, &mut *writer)
        .map_err(|_| Error::EncryptFile)?;

    Ok(())
}

#[cfg(test)]
pub mod tests {
    use std::io::Cursor;

    use core::header::common::HEADER_LEN;
    use core::header::{ParsedHeader, read_header};
    use core::kdf::Kdf;

    use super::*;

    pub const PASSWORD: &[u8; 8] = b"12345678";

    #[test]
    fn should_encrypt_content_with_v1_header() {
        let input_cur = RefCell::new(Cursor::new(b"Hello world".to_vec()));
        let output_cur = RefCell::new(Cursor::new(Vec::new()));

        execute(Request {
            reader: &input_cur,
            writer: &output_cur,
            header_writer: None,
            raw_key: Protected::new(PASSWORD.to_vec()),
            kdf: Kdf::Blake3Balloon,
        })
        .expect("encrypt");

        let mut encrypted = output_cur.into_inner().into_inner();
        let (parsed, _) = read_header(&mut Cursor::new(&encrypted)).expect("read header");
        let ParsedHeader::V1(header) = parsed;

        assert_eq!(header.keyslots().len(), 1);
        assert_eq!(encrypted.len(), HEADER_LEN + b"Hello world".len() + 16);

        encrypted.drain(..HEADER_LEN);
        assert_eq!(encrypted.len(), b"Hello world".len() + 16);
    }

    #[test]
    fn should_save_v1_header_separately() {
        let input_cur = RefCell::new(Cursor::new(b"Hello world".to_vec()));
        let output_cur = RefCell::new(Cursor::new(Vec::new()));
        let output_header_cur = RefCell::new(Cursor::new(Vec::new()));

        execute(Request {
            reader: &input_cur,
            writer: &output_cur,
            header_writer: Some(&output_header_cur),
            raw_key: Protected::new(PASSWORD.to_vec()),
            kdf: Kdf::Blake3Balloon,
        })
        .expect("encrypt detached");

        let output_content = output_cur.into_inner().into_inner();
        let output_header = output_header_cur.into_inner().into_inner();
        let (parsed, _) =
            read_header(&mut Cursor::new(&output_header)).expect("read detached header");
        let ParsedHeader::V1(header) = parsed;

        assert_eq!(header.keyslots().len(), 1);
        assert_eq!(output_header.len(), HEADER_LEN);
        assert_eq!(output_content.len(), b"Hello world".len() + 16);
    }
}
