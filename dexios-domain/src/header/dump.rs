//! This provides functionality for dumping a header that adheres to the Dexios format.

use super::Error;
use std::cell::RefCell;
use std::io::{Read, Seek, Write};
use std::path::Path;

use core::header::{ParsedHeader, read_header};

use crate::storage::identity::{OverwritePolicy, PathIdentityGraph, PathRole};
use crate::storage::transaction::{CommitReceipt, StagedOutputTransaction};

pub struct Request<'a, R, W>
where
    R: Read + Seek,
    W: Write + Seek,
{
    pub reader: &'a RefCell<R>,
    pub writer: &'a RefCell<W>,
}

pub struct OutputTarget<'a> {
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
}

pub fn execute<R, W>(req: Request<'_, R, W>) -> Result<(), Error>
where
    R: Read + Seek,
    W: Write + Seek,
{
    let header_bytes = dump_header_bytes(req.reader)?;

    req.writer
        .borrow_mut()
        .write_all(&header_bytes)
        .map_err(|_| Error::Write)?;

    Ok(())
}

pub fn execute_transactional<R>(req: TransactionalRequest<'_, R>) -> Result<CommitReceipt, Error>
where
    R: Read + Seek,
{
    let mut graph = PathIdentityGraph::new();
    graph
        .add_existing(req.input_path, PathRole::Input)
        .map_err(|_| Error::InvalidFile)?;
    let output_target = graph
        .add_output(req.output.path, PathRole::Output, req.output.overwrite)
        .map_err(|_| Error::InvalidFile)?;
    graph.validate().map_err(|_| Error::InvalidFile)?;

    let header_bytes = dump_header_bytes(req.reader)?;
    let mut transaction = StagedOutputTransaction::new(output_target).map_err(|_| Error::Write)?;
    transaction
        .write_all(&header_bytes)
        .map_err(|_| Error::Write)?;
    transaction.commit().map_err(|_| Error::Write)
}

fn dump_header_bytes<R>(reader: &RefCell<R>) -> Result<Vec<u8>, Error>
where
    R: Read + Seek,
{
    let parsed = read_header(&mut *reader.borrow_mut()).map_err(Error::from)?;
    let ParsedHeader::V1(payload) = parsed;

    payload.header().serialize().map_err(|_| Error::Write)
}
