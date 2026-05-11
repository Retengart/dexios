//! This provides functionality for V1 encryption that adheres to the Dexios format.

use std::cell::RefCell;
use std::io::{self, Read, Seek, Write};
use std::path::Path;

use core::cipher::wrap_v1_master_key;
use core::header::common::Salt;
use core::header::v1::{V1Header, V1Keyslot, V1Keyslots};
use core::kdf::Kdf;
use core::primitives::{gen_keyslot_nonce, gen_payload_nonce, MasterKey, WrappingKey};
use core::protected::Protected;
use core::stream::V1PayloadStream;

use crate::storage::identity::{IdentityError, OverwritePolicy, PathIdentityGraph, PathRole};
use crate::storage::transaction::{
    CommitReceipt, LinkedOutputTransaction, StagedOutputTransaction, TransactionError,
};
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
    PathIdentity(IdentityError),
    Transaction(TransactionError),
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
            Error::PathIdentity(error) => write!(f, "{error}"),
            Error::Transaction(error) => write!(f, "{error}"),
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

pub struct OutputTarget<'a> {
    pub path: &'a Path,
    pub overwrite: OverwritePolicy,
}

pub struct HeaderTarget<'a> {
    pub path: &'a Path,
    pub overwrite: OverwritePolicy,
}

pub struct TransactionalRequest<'a, R>
where
    R: Read + Seek,
{
    pub input_path: &'a Path,
    pub reader: &'a RefCell<R>,
    pub output: OutputTarget<'a>,
    pub header: Option<HeaderTarget<'a>>,
    pub raw_key: Protected<Vec<u8>>,
    pub kdf: Kdf,
}

pub fn execute<R, W>(req: Request<'_, R, W>) -> Result<(), Error>
where
    R: Read + Seek,
    W: Write + Seek,
{
    let Request {
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

pub fn execute_transactional<R>(req: TransactionalRequest<'_, R>) -> Result<CommitReceipt, Error>
where
    R: Read + Seek,
{
    let mut graph = PathIdentityGraph::new();
    graph
        .add_existing(req.input_path, PathRole::Input)
        .map_err(Error::PathIdentity)?;
    let output_target = graph
        .add_output(req.output.path, PathRole::Output, req.output.overwrite)
        .map_err(Error::PathIdentity)?;
    let header_target = req
        .header
        .map(|target| graph.add_output(target.path, PathRole::DetachedHeader, target.overwrite))
        .transpose()
        .map_err(Error::PathIdentity)?;
    graph.validate().map_err(Error::PathIdentity)?;

    let (header, master_key) = build_v1_encryption_state(req.raw_key, req.kdf)?;
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
                encrypt_payload(req.reader, writer, master_key, &header)
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
                encrypt_payload(req.reader, writer, master_key, &header)
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
    use std::io::Cursor;

    use core::header::common::HEADER_LEN;
    use core::header::{read_header, ParsedHeader};
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
        let parsed = read_header(&mut Cursor::new(&output_header)).expect("read detached header");
        let ParsedHeader::V1(payload) = parsed;
        let header = payload.header();

        assert_eq!(header.keyslots().len(), 1);
        assert_eq!(output_header.len(), HEADER_LEN);
        assert_eq!(output_content.len(), b"Hello world".len() + 16);
    }
}
