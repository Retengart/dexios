//! This provides functionality for stripping a header that adheres to the Dexios format.

use super::Error;
use std::cell::RefCell;
use std::fs;
use std::io::{Cursor, Read, Seek, Write};
use std::path::Path;

use core::header::common::HEADER_LEN;
use core::header::{ParsedHeader, read_header};

use crate::storage::identity::{OverwritePolicy, PathIdentityGraph, PathRole};
use crate::storage::transaction::{CommitReceipt, StagedOutputTransaction};

pub struct Request<'a, RW>
where
    RW: Read + Write + Seek,
{
    pub handle: &'a RefCell<RW>,
}

pub struct TransactionalRequest<'a> {
    pub target_path: &'a Path,
}

pub fn execute<RW>(req: Request<'_, RW>) -> Result<(), Error>
where
    RW: Read + Write + Seek,
{
    let parsed = read_header(&mut *req.handle.borrow_mut()).map_err(Error::from)?;
    match parsed {
        ParsedHeader::V1(_) => {}
    }

    req.handle
        .borrow_mut()
        .rewind()
        .map_err(|_| Error::Rewind)?;

    req.handle
        .borrow_mut()
        .write_all(&[0u8; HEADER_LEN])
        .map_err(|_| Error::Write)?;

    Ok(())
}

pub fn execute_transactional(req: TransactionalRequest<'_>) -> Result<CommitReceipt, Error> {
    let mut graph = PathIdentityGraph::new();
    let target = graph
        .add_output(
            req.target_path,
            PathRole::MutationTarget,
            OverwritePolicy::ReplaceAtCommit,
        )
        .map_err(|_| Error::InvalidFile)?;
    graph.validate().map_err(|_| Error::InvalidFile)?;

    let original = fs::read(req.target_path).map_err(|_| Error::Read)?;
    let replacement = stripped_header_bytes(original)?;

    let mut transaction = StagedOutputTransaction::new(target).map_err(|_| Error::Write)?;
    transaction
        .write_all(&replacement)
        .map_err(|_| Error::Write)?;
    transaction.commit().map_err(|_| Error::Write)
}

fn stripped_header_bytes(mut original: Vec<u8>) -> Result<Vec<u8>, Error> {
    let mut reader = Cursor::new(original.as_slice());
    let parsed = read_header(&mut reader).map_err(Error::from)?;
    match parsed {
        ParsedHeader::V1(_) => {}
    }

    let header = original.get_mut(..HEADER_LEN).ok_or(Error::InvalidFile)?;
    header.fill(0);

    Ok(original)
}
