//! This provides functionality for restoring a dumped header that adheres to the Dexios format, provided the target file contains enough empty bytes at the start to do so.

use super::Error;
use std::cell::RefCell;
use std::fs;
use std::io::{Cursor, ErrorKind, Read, Seek, Write};
use std::path::Path;

use core::header::common::HEADER_LEN;
use core::header::{ParsedHeader, read_header};

use crate::storage::identity::{OverwritePolicy, PathIdentityGraph, PathRole};
use crate::storage::transaction::{CommitReceipt, StagedOutputTransaction};

pub struct Request<'a, R, RW>
where
    R: Read + Seek,
    RW: Read + Write + Seek,
{
    pub reader: &'a RefCell<R>,
    pub writer: &'a RefCell<RW>,
}

pub struct TransactionalRequest<'a> {
    pub header_path: &'a Path,
    pub target_path: &'a Path,
}

pub fn execute<R, RW>(req: Request<'_, R, RW>) -> Result<(), Error>
where
    R: Read + Seek,
    RW: Read + Write + Seek,
{
    let parsed = read_header(&mut *req.reader.borrow_mut()).map_err(Error::from)?;
    let ParsedHeader::V1(payload) = parsed;

    let mut header_bytes = [0u8; HEADER_LEN];
    req.writer
        .borrow_mut()
        .read_exact(&mut header_bytes)
        .map_err(|err| {
            if err.kind() == ErrorKind::UnexpectedEof {
                Error::UnsupportedRestore
            } else {
                Error::Read
            }
        })?;

    if !header_bytes.into_iter().all(|b| b == 0) {
        return Err(Error::UnsupportedRestore);
    }

    req.writer
        .borrow_mut()
        .rewind()
        .map_err(|_| Error::Rewind)?;

    payload
        .header()
        .write(&mut *req.writer.borrow_mut())
        .map_err(|_| Error::Write)?;

    Ok(())
}

pub fn execute_transactional(req: TransactionalRequest<'_>) -> Result<CommitReceipt, Error> {
    let mut graph = PathIdentityGraph::new();
    graph
        .add_existing(req.header_path, PathRole::DetachedHeader)
        .map_err(|_| Error::InvalidFile)?;
    let target = graph
        .add_output(
            req.target_path,
            PathRole::MutationTarget,
            OverwritePolicy::ReplaceAtCommit,
        )
        .map_err(|_| Error::InvalidFile)?;
    graph.validate().map_err(|_| Error::InvalidFile)?;

    let header = fs::read(req.header_path).map_err(|_| Error::Read)?;
    let target_bytes = fs::read(req.target_path).map_err(|_| Error::Read)?;
    let replacement = restored_header_bytes(&header, target_bytes)?;

    let mut transaction = StagedOutputTransaction::new(target).map_err(|_| Error::Write)?;
    transaction
        .write_all(&replacement)
        .map_err(|_| Error::Write)?;
    transaction.commit().map_err(|_| Error::Write)
}

fn restored_header_bytes(header: &[u8], mut target: Vec<u8>) -> Result<Vec<u8>, Error> {
    let mut reader = Cursor::new(header);
    let parsed = read_header(&mut reader).map_err(Error::from)?;
    let ParsedHeader::V1(payload) = parsed;
    let serialized = payload.header().serialize().map_err(|_| Error::Write)?;

    let target_header = target
        .get_mut(..HEADER_LEN)
        .ok_or(Error::UnsupportedRestore)?;
    if !target_header.iter().all(|b| *b == 0) {
        return Err(Error::UnsupportedRestore);
    }

    target_header.copy_from_slice(&serialized);

    Ok(target)
}
