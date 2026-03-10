//! This provides functionality for decryption that adheres to the Dexios format.

use std::cell::RefCell;
use std::io::{Read, Seek, Write};

use core::header::common::HEADER_LEN;
use core::header::v1::V1Header;
use core::header::{ParsedHeader, read_header};
use core::protected::Protected;
use core::stream::DecryptionStreams;

use crate::key::decrypt_v1_master_key_with_index;

#[derive(Debug)]
pub enum Error {
    InitializeChiphers,
    InitializeStreams,
    DeserializeHeader,
    ReadEncryptedData,
    DecryptMasterKey,
    DecryptData,
    WriteData,
    RewindDataReader,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InitializeChiphers => f.write_str("Cannot initialize chiphers"),
            Error::InitializeStreams => f.write_str("Cannot initialize streams"),
            Error::DeserializeHeader => f.write_str("Cannot deserialize header"),
            Error::ReadEncryptedData => f.write_str("Unable to read encrypted data"),
            Error::DecryptMasterKey => f.write_str("Cannot decrypt master key"),
            Error::DecryptData => f.write_str("Unable to decrypt data"),
            Error::WriteData => f.write_str("Unable to write data"),
            Error::RewindDataReader => f.write_str("Unable to rewind the reader"),
        }
    }
}

impl std::error::Error for Error {}

pub type OnDecryptedHeaderFn = Box<dyn FnOnce(&V1Header)>;

pub struct Request<'a, R, W>
where
    R: Read + Seek,
    W: Write + Seek,
{
    pub header_reader: Option<&'a RefCell<R>>,
    pub reader: &'a RefCell<R>,
    pub writer: &'a RefCell<W>,
    pub raw_key: Protected<Vec<u8>>,
    pub on_decrypted_header: Option<OnDecryptedHeaderFn>,
}

pub fn execute<R, W>(req: Request<'_, R, W>) -> Result<(), Error>
where
    R: Read + Seek,
    W: Write + Seek,
{
    let (header, aad) = match req.header_reader {
        Some(header_reader) => {
            let (parsed, aad) = read_header(&mut *header_reader.borrow_mut())
                .map_err(|_| Error::DeserializeHeader)?;
            let ParsedHeader::V1(header) = parsed;

            // Try reading an empty header from the content.
            let mut header_bytes = vec![0u8; HEADER_LEN];

            let needs_rewind = match req.reader.borrow_mut().read_exact(&mut header_bytes) {
                Ok(()) => !header_bytes.into_iter().all(|b| b == 0),
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => true,
                Err(_) => return Err(Error::ReadEncryptedData),
            };

            if needs_rewind {
                // Return the cursor position to the start if no detached zero header was found.
                req.reader
                    .borrow_mut()
                    .rewind()
                    .map_err(|_| Error::RewindDataReader)?;
            }

            (header, aad)
        }
        None => {
            let (parsed, aad) =
                read_header(&mut *req.reader.borrow_mut()).map_err(|_| Error::DeserializeHeader)?;
            let ParsedHeader::V1(header) = parsed;
            (header, aad)
        }
    };

    if let Some(cb) = req.on_decrypted_header {
        cb(&header);
    }

    let (master_key, _) = decrypt_v1_master_key_with_index(header.keyslots(), req.raw_key)
        .map_err(|_| Error::DecryptMasterKey)?;

    let streams = DecryptionStreams::initialize(master_key, header.payload_nonce().as_bytes())
        .map_err(|_| Error::InitializeStreams)?;

    streams
        .decrypt_file(
            &mut *req.reader.borrow_mut(),
            &mut *req.writer.borrow_mut(),
            aad.as_bytes(),
        )
        .map_err(|_| Error::DecryptData)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use crate::encrypt;
    use crate::encrypt::tests::PASSWORD;
    use core::kdf::Kdf;

    #[test]
    fn should_decrypt_embedded_v1_content() {
        let input_cur = RefCell::new(Cursor::new(b"Hello world".to_vec()));
        let encrypted_cur = RefCell::new(Cursor::new(Vec::new()));

        encrypt::execute(encrypt::Request {
            reader: &input_cur,
            writer: &encrypted_cur,
            header_writer: None,
            raw_key: Protected::new(PASSWORD.to_vec()),
            kdf: Kdf::Blake3Balloon,
        })
        .expect("encrypt fixture");

        encrypted_cur
            .borrow_mut()
            .rewind()
            .expect("rewind encrypted");

        let mut output_content = vec![];
        let output_cur = RefCell::new(Cursor::new(&mut output_content));

        let req = Request {
            header_reader: None,
            reader: &encrypted_cur,
            writer: &output_cur,
            raw_key: Protected::new(PASSWORD.to_vec()),
            on_decrypted_header: None,
        };

        match execute(req) {
            Ok(()) => {
                assert_eq!(output_content, "Hello world".as_bytes().to_vec());
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_decrypt_detached_v1_content() {
        let input_cur = RefCell::new(Cursor::new(b"Hello world".to_vec()));
        let encrypted_cur = RefCell::new(Cursor::new(Vec::new()));
        let header_cur = RefCell::new(Cursor::new(Vec::new()));

        encrypt::execute(encrypt::Request {
            reader: &input_cur,
            writer: &encrypted_cur,
            header_writer: Some(&header_cur),
            raw_key: Protected::new(PASSWORD.to_vec()),
            kdf: Kdf::Blake3Balloon,
        })
        .expect("encrypt detached fixture");

        encrypted_cur
            .borrow_mut()
            .rewind()
            .expect("rewind encrypted");
        header_cur.borrow_mut().rewind().expect("rewind header");

        let mut output_content = vec![];
        let output_cur = RefCell::new(Cursor::new(&mut output_content));

        let req = Request {
            header_reader: Some(&header_cur),
            reader: &encrypted_cur,
            writer: &output_cur,
            raw_key: Protected::new(PASSWORD.to_vec()),
            on_decrypted_header: None,
        };

        match execute(req) {
            Ok(()) => {
                assert_eq!(output_content, "Hello world".as_bytes().to_vec());
            }
            _ => unreachable!(),
        }
    }
}
