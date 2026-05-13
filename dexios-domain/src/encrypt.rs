//! This provides functionality for V1 encryption that adheres to the Dexios format.

use std::cell::RefCell;
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};

use core::cipher::wrap_v1_master_key;
use core::header::common::Salt;
use core::header::v1::{V1Header, V1Keyslot, V1Keyslots};
use core::kdf::Kdf;
use core::primitives::{MasterKey, WrappingKey, gen_keyslot_nonce, gen_payload_nonce};
use core::protected::Protected;
use core::stream::V1PayloadStream;

use crate::storage::identity::{
    IdentityError, OverwritePolicy, PathIdentityGraph, PathRole, ResolvedTarget,
};
use crate::storage::transaction::{
    CommitReceipt, LinkedOutputTransaction, StagedOutputTransaction, TransactionError,
};
use crate::utils::{gen_master_key, gen_salt};
use crate::workflow_error::{
    WorkflowErrorClass, classify_identity_error, classify_transaction_error,
};

#[derive(Debug)]
pub enum Error {
    OpenInput,
    ResetCursorPosition,
    HashKey,
    EncryptMasterKey,
    EncryptFile,
    WriteHeader,
    InitializeStreams,
    InitializeChiphers,
    PathIdentity(IdentityError),
    Transaction(TransactionError),
}

impl Error {
    #[must_use]
    pub fn workflow_class(&self) -> WorkflowErrorClass {
        match self {
            Self::OpenInput | Self::ResetCursorPosition | Self::EncryptFile | Self::WriteHeader => {
                WorkflowErrorClass::IoFailure
            }
            Self::HashKey => WorkflowErrorClass::KdfFailure,
            Self::PathIdentity(error) => classify_identity_error(error),
            Self::Transaction(error) => classify_transaction_error(error),
            Self::EncryptMasterKey | Self::InitializeStreams | Self::InitializeChiphers => {
                WorkflowErrorClass::Other
            }
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::OpenInput => f.write_str("Cannot open input file"),
            Error::ResetCursorPosition => f.write_str("Unable to reset cursor position"),
            Error::HashKey => f.write_str("Cannot hash raw key"),
            Error::EncryptMasterKey => f.write_str("Cannot encrypt master key"),
            Error::EncryptFile => f.write_str("Cannot encrypt file"),
            Error::WriteHeader => f.write_str("Cannot write header"),
            Error::InitializeStreams => f.write_str("Cannot initialize streams"),
            Error::InitializeChiphers => f.write_str("Cannot initialize chiphers"),
            Error::PathIdentity(error) => write!(f, "{error}"),
            Error::Transaction(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PathIdentity(error) => Some(error),
            Self::Transaction(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct DetachedHeaderTarget {
    path: PathBuf,
    overwrite: OverwritePolicy,
}

impl DetachedHeaderTarget {
    pub fn new<P: AsRef<Path>>(path: P, overwrite: OverwritePolicy) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            overwrite,
        }
    }
}

#[derive(Debug)]
pub struct EncryptIntent {
    input_target: ResolvedTarget,
    output_target: ResolvedTarget,
    header_target: Option<ResolvedTarget>,
    raw_key: Protected<Vec<u8>>,
    kdf: Kdf,
}

impl EncryptIntent {
    pub fn new<P, O>(
        input_path: P,
        output_path: O,
        output_overwrite: OverwritePolicy,
        header: Option<DetachedHeaderTarget>,
        raw_key: Protected<Vec<u8>>,
        kdf: Kdf,
    ) -> Result<Self, Error>
    where
        P: AsRef<Path>,
        O: AsRef<Path>,
    {
        let input_path = input_path.as_ref().to_path_buf();
        let mut graph = PathIdentityGraph::new();
        let input_target = graph
            .add_existing(&input_path, PathRole::Input)
            .map_err(Error::PathIdentity)?;
        let output_target = graph
            .add_output(output_path, PathRole::Output, output_overwrite)
            .map_err(Error::PathIdentity)?;
        let header_target = header
            .map(|target| graph.add_output(target.path, PathRole::DetachedHeader, target.overwrite))
            .transpose()
            .map_err(Error::PathIdentity)?;
        graph.validate().map_err(Error::PathIdentity)?;

        Ok(Self {
            input_target,
            output_target,
            header_target,
            raw_key,
            kdf,
        })
    }
}

// Private crate adapter for legacy in-memory callers. Public encrypt workflows
// must use `EncryptIntent` so path identity and transaction checks cannot be
// bypassed by caller-owned final writers.
pub(crate) struct HandleRequest<'a, R, W>
where
    R: Read + Seek,
    W: Write + Seek,
{
    pub(crate) reader: &'a RefCell<R>,
    pub(crate) writer: &'a RefCell<W>,
    pub(crate) header_writer: Option<&'a RefCell<W>>,
    pub(crate) raw_key: Protected<Vec<u8>>,
    pub(crate) kdf: Kdf,
}

pub(crate) fn execute_handles<R, W>(req: HandleRequest<'_, R, W>) -> Result<(), Error>
where
    R: Read + Seek,
    W: Write + Seek,
{
    let HandleRequest {
        reader,
        writer,
        header_writer,
        raw_key,
        kdf,
    } = req;

    let (header, master_key) = build_v1_encryption_state(raw_key, kdf)?;
    let header_bytes = header.serialize().map_err(|_| Error::WriteHeader)?;

    writer
        .borrow_mut()
        .rewind()
        .map_err(|_| Error::ResetCursorPosition)?;

    match header_writer {
        None => {
            writer
                .borrow_mut()
                .write_all(&header_bytes)
                .map_err(|_| Error::WriteHeader)?;
        }
        Some(header_writer) => {
            header_writer
                .borrow_mut()
                .rewind()
                .map_err(|_| Error::ResetCursorPosition)?;
            header_writer
                .borrow_mut()
                .write_all(&header_bytes)
                .map_err(|_| Error::WriteHeader)?;
        }
    }

    encrypt_payload(reader, &mut *writer.borrow_mut(), master_key, &header)
}

pub fn execute(intent: EncryptIntent) -> Result<CommitReceipt, Error> {
    let EncryptIntent {
        input_target,
        output_target,
        header_target,
        raw_key,
        kdf,
    } = intent;
    let reader =
        RefCell::new(File::open(input_target.target_path()).map_err(|_| Error::OpenInput)?);

    execute_transactional_targets(&reader, output_target, header_target, raw_key, kdf)
}

pub fn execute_transactional(intent: EncryptIntent) -> Result<CommitReceipt, Error> {
    execute(intent)
}

fn execute_transactional_targets<R>(
    reader: &RefCell<R>,
    output_target: ResolvedTarget,
    header_target: Option<ResolvedTarget>,
    raw_key: Protected<Vec<u8>>,
    kdf: Kdf,
) -> Result<CommitReceipt, Error>
where
    R: Read + Seek,
{
    let (header, master_key) = build_v1_encryption_state(raw_key, kdf)?;
    let header_bytes = header.serialize().map_err(|_| Error::WriteHeader)?;

    if let Some(header_target) = header_target {
        let mut transaction = LinkedOutputTransaction::new();
        let output_index = transaction
            .stage(output_target)
            .map_err(Error::Transaction)?;
        let header_index = transaction
            .stage(header_target)
            .map_err(Error::Transaction)?;

        transaction
            .staged_output_mut(header_index)
            .ok_or(Error::WriteHeader)?
            .write_all(&header_bytes)
            .map_err(map_header_transaction_error)?;

        transaction
            .staged_output_mut(output_index)
            .ok_or(Error::EncryptFile)?
            .with_writer(|writer| {
                encrypt_payload(reader, writer, master_key, &header)
                    .map_err(|_| io::Error::other("encrypt payload"))
            })
            .map_err(map_encrypt_transaction_error)?;

        transaction.commit_all().map_err(Error::Transaction)
    } else {
        let mut transaction =
            StagedOutputTransaction::new(output_target).map_err(Error::Transaction)?;
        transaction
            .write_all(&header_bytes)
            .map_err(map_header_transaction_error)?;
        transaction
            .with_writer(|writer| {
                encrypt_payload(reader, writer, master_key, &header)
                    .map_err(|_| io::Error::other("encrypt payload"))
            })
            .map_err(map_encrypt_transaction_error)?;
        transaction.commit().map_err(Error::Transaction)
    }
}

fn build_v1_encryption_state(
    raw_key: Protected<Vec<u8>>,
    kdf: Kdf,
) -> Result<(V1Header, MasterKey), Error> {
    let salt_bytes = gen_salt();
    let header_salt = Salt::new(salt_bytes);
    let kdf_salt = header_salt.to_kdf_salt();

    let key = kdf
        .derive(&raw_key, &kdf_salt)
        .map_err(|_| Error::HashKey)?;
    drop(raw_key);

    let master_key: MasterKey = gen_master_key();
    let master_key_nonce = gen_keyslot_nonce();
    let master_key_encrypted =
        wrap_v1_master_key(WrappingKey::from(key), &master_key, &master_key_nonce)
            .map_err(|_| Error::EncryptMasterKey)?;

    let keyslot = V1Keyslot::new(
        kdf,
        *master_key_encrypted.as_bytes(),
        master_key_nonce,
        header_salt,
    );
    let payload_nonce = gen_payload_nonce();
    let header = V1Header::new(payload_nonce, V1Keyslots::single(keyslot))
        .map_err(|_| Error::WriteHeader)?;

    Ok((header, master_key))
}

fn encrypt_payload<R, W>(
    reader: &RefCell<R>,
    writer: &mut W,
    master_key: MasterKey,
    header: &V1Header,
) -> Result<(), Error>
where
    R: Read + Seek,
    W: Write + Seek,
{
    let mut reader = reader.borrow_mut();
    reader.rewind().map_err(|_| Error::ResetCursorPosition)?;

    V1PayloadStream::encrypt_file(master_key, header, &mut *reader, &mut *writer)
        .map_err(|_| Error::EncryptFile)?;

    Ok(())
}

fn map_header_transaction_error(error: TransactionError) -> Error {
    match error {
        TransactionError::Write { .. } => Error::WriteHeader,
        error => Error::Transaction(error),
    }
}

fn map_encrypt_transaction_error(error: TransactionError) -> Error {
    match error {
        TransactionError::Write { .. } => Error::EncryptFile,
        error => Error::Transaction(error),
    }
}

#[cfg(test)]
pub mod tests {
    use std::io::{Cursor, SeekFrom, Write};

    use core::header::common::HEADER_LEN;
    use core::header::{ParsedHeader, read_header};
    use core::kdf::Kdf;

    use super::*;

    pub const PASSWORD: &[u8; 8] = b"12345678";

    #[derive(Default)]
    struct ShortWriteCursor {
        inner: Cursor<Vec<u8>>,
    }

    impl ShortWriteCursor {
        fn len(&self) -> usize {
            self.inner.get_ref().len()
        }
    }

    impl Write for ShortWriteCursor {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let n = buf.len().min(1);
            self.inner.write(&buf[..n])
        }

        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }

    impl Seek for ShortWriteCursor {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    #[test]
    fn should_encrypt_content_with_v1_header() {
        let input_cur = RefCell::new(Cursor::new(b"Hello world".to_vec()));
        let output_cur = RefCell::new(Cursor::new(Vec::new()));

        execute_handles(HandleRequest {
            reader: &input_cur,
            writer: &output_cur,
            header_writer: None,
            raw_key: Protected::new(PASSWORD.to_vec()),
            kdf: Kdf::Blake3Balloon,
        })
        .expect("encrypt");

        let mut encrypted = output_cur.into_inner().into_inner();
        let parsed = read_header(&mut Cursor::new(&encrypted)).expect("read header");
        let ParsedHeader::V1(payload) = parsed;
        let header = payload.header();

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

        execute_handles(HandleRequest {
            reader: &input_cur,
            writer: &output_cur,
            header_writer: Some(&output_header_cur),
            raw_key: Protected::new(PASSWORD.to_vec()),
            kdf: Kdf::Blake3Balloon,
        })
        .expect("encrypt detached");

        let output_content = output_cur.into_inner().into_inner();
        let output_header = output_header_cur.into_inner().into_inner();
        let parsed = read_header(&mut Cursor::new(&output_header)).expect("read detached header");
        let ParsedHeader::V1(payload) = parsed;
        let header = payload.header();

        assert_eq!(header.keyslots().len(), 1);
        assert_eq!(output_header.len(), HEADER_LEN);
        assert_eq!(output_content.len(), b"Hello world".len() + 16);
    }

    #[test]
    fn encrypt_must_write_the_full_embedded_header() {
        let input = RefCell::new(Cursor::new(b"Hello world".to_vec()));
        let output = RefCell::new(ShortWriteCursor::default());

        execute_handles(HandleRequest {
            reader: &input,
            writer: &output,
            header_writer: None,
            raw_key: Protected::new(PASSWORD.to_vec()),
            kdf: Kdf::Blake3Balloon,
        })
        .expect("encrypt");

        let expected_len = HEADER_LEN + b"Hello world".len() + 16;

        assert_eq!(output.borrow().len(), expected_len);
    }
}
