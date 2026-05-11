//! This provides functionality for decryption that adheres to the Dexios format.

use std::cell::RefCell;
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::path::Path;

use core::header::common::HEADER_LEN;
use core::header::v1::V1Header;
use core::header::{HeaderReadError, ParsedHeader, ParsedV1Payload, read_header};
use core::primitives::MasterKey;
use core::protected::Protected;
use core::stream::{StreamError, V1PayloadStream};

use crate::key::decrypt_v1_master_key_with_index;
use crate::storage::identity::{
    IdentityError, OverwritePolicy, PathIdentityGraph, PathRole, ResolvedTarget,
};
use crate::storage::transaction::{CommitReceipt, StagedOutputTransaction, TransactionError};
use crate::workflow_error::{
    WorkflowErrorClass, classify_identity_error, classify_transaction_error,
};

#[derive(Debug)]
pub enum Error {
    InitializeChiphers,
    InitializeStreams,
    DeserializeHeader,
    InvalidMagic([u8; 4]),
    UnsupportedFormat([u8; 2]),
    UnsupportedVersion([u8; 2]),
    ReadEncryptedData,
    DecryptMasterKey,
    UnsupportedKdf([u8; 2]),
    DecryptData,
    WriteData,
    RewindDataReader,
    PathIdentity(IdentityError),
    Transaction(TransactionError),
}

impl Error {
    #[must_use]
    pub fn workflow_class(&self) -> WorkflowErrorClass {
        match self {
            Self::DeserializeHeader => WorkflowErrorClass::MalformedFormat,
            Self::InvalidMagic(_) | Self::UnsupportedFormat(_) | Self::UnsupportedVersion(_) => {
                WorkflowErrorClass::UnsupportedFormat
            }
            Self::ReadEncryptedData | Self::WriteData | Self::RewindDataReader => {
                WorkflowErrorClass::IoFailure
            }
            Self::DecryptMasterKey => WorkflowErrorClass::IncorrectKey,
            Self::UnsupportedKdf(_) => WorkflowErrorClass::KdfFailure,
            Self::DecryptData => WorkflowErrorClass::AuthenticationFailure,
            Self::PathIdentity(error) => classify_identity_error(error),
            Self::Transaction(error) => classify_transaction_error(error),
            Self::InitializeChiphers | Self::InitializeStreams => WorkflowErrorClass::Other,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InitializeChiphers => f.write_str("Cannot initialize chiphers"),
            Error::InitializeStreams => f.write_str("Cannot initialize streams"),
            Error::DeserializeHeader => f.write_str("Cannot deserialize header"),
            Error::InvalidMagic(magic) => write!(f, "Invalid Dexios header magic: {magic:02X?}"),
            Error::UnsupportedFormat(prefix) => {
                write!(f, "Unsupported Dexios header format: {prefix:02X?}")
            }
            Error::UnsupportedVersion(version) => {
                write!(f, "Unsupported Dexios header version: {version:02X?}")
            }
            Error::ReadEncryptedData => f.write_str("Unable to read encrypted data"),
            Error::DecryptMasterKey => f.write_str("Cannot decrypt master key"),
            Error::UnsupportedKdf(tag) => write!(f, "Unsupported keyslot KDF tag: {tag:02X?}"),
            Error::DecryptData => f.write_str("Unable to decrypt data"),
            Error::WriteData => f.write_str("Unable to write data"),
            Error::RewindDataReader => f.write_str("Unable to rewind the reader"),
            Error::PathIdentity(error) => write!(f, "{error}"),
            Error::Transaction(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for Error {}

pub type OnDecryptedHeaderFn = Box<dyn FnOnce(&V1Header)>;

pub struct DecryptIntent {
    input_target: ResolvedTarget,
    detached_header_target: Option<ResolvedTarget>,
    output_target: ResolvedTarget,
    raw_key: Protected<Vec<u8>>,
    on_decrypted_header: Option<OnDecryptedHeaderFn>,
}

impl std::fmt::Debug for DecryptIntent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptIntent")
            .field("input_target", &self.input_target)
            .field("detached_header_target", &self.detached_header_target)
            .field("output_target", &self.output_target)
            .field("raw_key", &self.raw_key)
            .field(
                "on_decrypted_header",
                &self.on_decrypted_header.as_ref().map(|_| "<callback>"),
            )
            .finish()
    }
}

impl DecryptIntent {
    pub fn new<P, O, H>(
        input_path: P,
        output_path: O,
        output_overwrite: OverwritePolicy,
        detached_header_path: Option<H>,
        raw_key: Protected<Vec<u8>>,
        on_decrypted_header: Option<OnDecryptedHeaderFn>,
    ) -> Result<Self, Error>
    where
        P: AsRef<Path>,
        O: AsRef<Path>,
        H: AsRef<Path>,
    {
        let input_path = input_path.as_ref().to_path_buf();
        let mut graph = PathIdentityGraph::new();
        let input_target = graph
            .add_existing(&input_path, PathRole::Input)
            .map_err(Error::PathIdentity)?;
        let detached_header_target = detached_header_path
            .map(|path| graph.add_existing(path, PathRole::DetachedHeader))
            .transpose()
            .map_err(Error::PathIdentity)?;
        let output_target = graph
            .add_output(output_path, PathRole::Output, output_overwrite)
            .map_err(Error::PathIdentity)?;
        graph.validate().map_err(Error::PathIdentity)?;

        Ok(Self {
            input_target,
            detached_header_target,
            output_target,
            raw_key,
            on_decrypted_header,
        })
    }
}

pub(crate) struct HandleRequest<'a, R, W>
where
    R: Read + Seek,
    W: Write + Seek,
{
    pub(crate) header_reader: Option<&'a RefCell<R>>,
    pub(crate) reader: &'a RefCell<R>,
    pub(crate) writer: &'a RefCell<W>,
    pub(crate) raw_key: Protected<Vec<u8>>,
    pub(crate) on_decrypted_header: Option<OnDecryptedHeaderFn>,
}

pub(crate) fn execute_handles<R, W>(req: HandleRequest<'_, R, W>) -> Result<(), Error>
where
    R: Read + Seek,
    W: Write + Seek,
{
    let payload = read_v1_payload(req.header_reader, req.reader)?;

    if let Some(cb) = req.on_decrypted_header {
        cb(payload.header());
    }

    let master_key = decrypt_master_key(&payload, req.raw_key)?;
    decrypt_payload_with_master_key(
        &payload,
        req.reader,
        &mut *req.writer.borrow_mut(),
        master_key,
    )
}

pub fn execute(intent: DecryptIntent) -> Result<CommitReceipt, Error> {
    let DecryptIntent {
        input_target,
        detached_header_target,
        output_target,
        raw_key,
        on_decrypted_header,
    } = intent;

    let reader =
        RefCell::new(File::open(input_target.target_path()).map_err(|_| Error::ReadEncryptedData)?);
    let header_reader = detached_header_target
        .map(|target| File::open(target.target_path()).map(RefCell::new))
        .transpose()
        .map_err(|_| Error::ReadEncryptedData)?;

    execute_transactional_target(
        header_reader.as_ref(),
        &reader,
        output_target,
        raw_key,
        on_decrypted_header,
    )
}

pub fn execute_transactional(intent: DecryptIntent) -> Result<CommitReceipt, Error> {
    execute(intent)
}

fn execute_transactional_target<R>(
    header_reader: Option<&RefCell<R>>,
    reader: &RefCell<R>,
    output_target: ResolvedTarget,
    raw_key: Protected<Vec<u8>>,
    on_decrypted_header: Option<OnDecryptedHeaderFn>,
) -> Result<CommitReceipt, Error>
where
    R: Read + Seek,
{
    let payload = read_v1_payload(header_reader, reader)?;

    if let Some(cb) = on_decrypted_header {
        cb(payload.header());
    }

    let master_key = decrypt_master_key(&payload, raw_key)?;
    let mut transaction =
        StagedOutputTransaction::new(output_target).map_err(Error::Transaction)?;
    transaction
        .with_writer(|writer| {
            decrypt_payload_with_master_key(&payload, reader, writer, master_key)
                .map_err(|_| io::Error::other("decrypt payload"))
        })
        .map_err(map_decrypt_transaction_error)?;
    transaction.commit().map_err(Error::Transaction)
}

fn read_v1_payload<R>(
    header_reader: Option<&RefCell<R>>,
    reader: &RefCell<R>,
) -> Result<ParsedV1Payload, Error>
where
    R: Read + Seek,
{
    if let Some(header_reader) = header_reader {
        let parsed =
            read_header(&mut *header_reader.borrow_mut()).map_err(map_header_read_error)?;
        let ParsedHeader::V1(payload) = parsed;
        // Try reading an empty header from the content.
        let mut header_bytes = vec![0u8; HEADER_LEN];

        let needs_rewind = match reader.borrow_mut().read_exact(&mut header_bytes) {
            Ok(()) => !header_bytes.into_iter().all(|b| b == 0),
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => true,
            Err(_) => return Err(Error::ReadEncryptedData),
        };

        if needs_rewind {
            // Return the cursor position to the start if no detached zero header was found.
            reader
                .borrow_mut()
                .rewind()
                .map_err(|_| Error::RewindDataReader)?;
        }

        Ok(payload)
    } else {
        let parsed = read_header(&mut *reader.borrow_mut()).map_err(map_header_read_error)?;
        let ParsedHeader::V1(payload) = parsed;
        Ok(payload)
    }
}

fn decrypt_master_key(
    payload: &ParsedV1Payload,
    raw_key: Protected<Vec<u8>>,
) -> Result<MasterKey, Error> {
    let (master_key, _) =
        decrypt_v1_master_key_with_index(payload.header().keyslots_collection(), raw_key).map_err(
            |err| match err {
                crate::key::Error::UnsupportedKdf(tag) => Error::UnsupportedKdf(tag),
                _ => Error::DecryptMasterKey,
            },
        )?;

    Ok(master_key)
}

fn decrypt_payload_with_master_key<R, W>(
    payload: &ParsedV1Payload,
    reader: &RefCell<R>,
    writer: &mut W,
    master_key: MasterKey,
) -> Result<(), Error>
where
    R: Read + Seek,
    W: Write + Seek,
{
    V1PayloadStream::decrypt_file(master_key, payload, &mut *reader.borrow_mut(), &mut *writer)
        .map_err(map_stream_error)?;

    Ok(())
}

fn map_header_read_error(error: HeaderReadError) -> Error {
    match error {
        HeaderReadError::Io(_) => Error::ReadEncryptedData,
        HeaderReadError::InvalidMagic(magic) => Error::InvalidMagic(magic),
        HeaderReadError::UnsupportedFormat(prefix) => Error::UnsupportedFormat(prefix),
        HeaderReadError::UnsupportedVersion(version) => Error::UnsupportedVersion(version),
        HeaderReadError::TruncatedHeader
        | HeaderReadError::InvalidKeyslotCount(_)
        | HeaderReadError::InvalidKeyslotTag(_)
        | HeaderReadError::InvalidPayloadNonceLength(_)
        | HeaderReadError::InvalidKeyslotNonceLength(_)
        | HeaderReadError::InvalidSaltLength(_)
        | HeaderReadError::InvalidEncryptedMasterKeyLength(_)
        | HeaderReadError::NonZeroReservedBytes
        | HeaderReadError::NonZeroActiveKeyslotPadding(_)
        | HeaderReadError::NonZeroInactiveKeyslotPadding(_) => Error::DeserializeHeader,
    }
}

fn map_decrypt_transaction_error(error: TransactionError) -> Error {
    match error {
        TransactionError::Write { .. } => Error::DecryptData,
        error => Error::Transaction(error),
    }
}

fn map_stream_error(error: StreamError) -> Error {
    match error {
        StreamError::InvalidNonceLength(_)
        | StreamError::CipherInit
        | StreamError::Read(_)
        | StreamError::Write(_)
        | StreamError::Flush(_)
        | StreamError::Authentication
        | StreamError::TruncatedCiphertext
        | StreamError::MissingFinalBlock
        | StreamError::FinalBlockAuthentication => Error::DecryptData,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};

    use crate::encrypt;
    use crate::encrypt::tests::PASSWORD;
    use core::kdf::Kdf;
    use core::stream::StreamError;

    #[test]
    fn should_decrypt_embedded_v1_content() {
        let input_cur = RefCell::new(Cursor::new(b"Hello world".to_vec()));
        let encrypted_cur = RefCell::new(Cursor::new(Vec::new()));

        encrypt::execute_handles(encrypt::HandleRequest {
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

        let req = HandleRequest {
            header_reader: None,
            reader: &encrypted_cur,
            writer: &output_cur,
            raw_key: Protected::new(PASSWORD.to_vec()),
            on_decrypted_header: None,
        };

        match execute_handles(req) {
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

        encrypt::execute_handles(encrypt::HandleRequest {
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

        let req = HandleRequest {
            header_reader: Some(&header_cur),
            reader: &encrypted_cur,
            writer: &output_cur,
            raw_key: Protected::new(PASSWORD.to_vec()),
            on_decrypted_header: None,
        };

        match execute_handles(req) {
            Ok(()) => {
                assert_eq!(output_content, "Hello world".as_bytes().to_vec());
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_decrypt_detached_v1_content_after_zero_header_placeholder() {
        let input_cur = RefCell::new(Cursor::new(b"Hello world".to_vec()));
        let encrypted_cur = RefCell::new(Cursor::new(Vec::new()));
        let header_cur = RefCell::new(Cursor::new(Vec::new()));

        encrypt::execute_handles(encrypt::HandleRequest {
            reader: &input_cur,
            writer: &encrypted_cur,
            header_writer: Some(&header_cur),
            raw_key: Protected::new(PASSWORD.to_vec()),
            kdf: Kdf::Blake3Balloon,
        })
        .expect("encrypt detached fixture");

        let ciphertext = encrypted_cur.into_inner().into_inner();
        let mut content_with_placeholder = vec![0u8; HEADER_LEN];
        content_with_placeholder.extend_from_slice(&ciphertext);

        let encrypted_with_placeholder = RefCell::new(Cursor::new(content_with_placeholder));
        header_cur.borrow_mut().rewind().expect("rewind header");

        let mut output_content = vec![];
        let output_cur = RefCell::new(Cursor::new(&mut output_content));

        let req = HandleRequest {
            header_reader: Some(&header_cur),
            reader: &encrypted_with_placeholder,
            writer: &output_cur,
            raw_key: Protected::new(PASSWORD.to_vec()),
            on_decrypted_header: None,
        };

        execute_handles(req).expect("decrypt detached fixture with zero placeholder");

        assert_eq!(output_content, b"Hello world");
        assert_eq!(
            encrypted_with_placeholder.borrow().position(),
            u64::try_from(HEADER_LEN + ciphertext.len()).expect("reader position")
        );
    }

    #[test]
    fn stream_error_variants_map_to_decrypt_data_without_message_matching() {
        let variants = [
            StreamError::InvalidNonceLength(19),
            StreamError::CipherInit,
            StreamError::Read(io::Error::other("read")),
            StreamError::Write(io::Error::other("write")),
            StreamError::Flush(io::Error::other("flush")),
            StreamError::Authentication,
            StreamError::TruncatedCiphertext,
            StreamError::MissingFinalBlock,
            StreamError::FinalBlockAuthentication,
        ];

        for error in variants {
            assert!(matches!(map_stream_error(error), Error::DecryptData));
        }
    }
}
