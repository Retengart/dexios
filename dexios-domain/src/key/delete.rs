//! This provides functionality for deleting a key from a Dexios V1 header.

use super::Error;
use core::header::common::HEADER_LEN;
use core::header::v1::V1Header;
use core::header::{ParsedHeader, read_header};
use core::protected::Protected;
use std::cell::RefCell;
use std::fs;
use std::io::{Cursor, Read, Seek, Write};
use std::path::Path;

use crate::storage::identity::{OverwritePolicy, PathIdentityGraph, PathRole};
use crate::storage::transaction::{CommitReceipt, StagedOutputTransaction};

pub struct Request<'a, RW>
where
    RW: Read + Write + Seek,
{
    pub handle: &'a RefCell<RW>, // header read+write+seek
    pub raw_key_old: Protected<Vec<u8>>,
}

pub struct TransactionalRequest<'a> {
    pub target_path: &'a Path,
    pub raw_key_old: Protected<Vec<u8>>,
}

pub fn execute<RW>(req: Request<'_, RW>) -> Result<(), Error>
where
    RW: Read + Write + Seek,
{
    let parsed =
        read_header(&mut *req.handle.borrow_mut()).map_err(|_| Error::HeaderDeserialize)?;
    let ParsedHeader::V1(payload) = parsed;
    let header = payload.header();
    let header_new = deleted_header(header, req.raw_key_old)?;

    // write the header to the handle
    req.handle
        .borrow_mut()
        .seek(std::io::SeekFrom::Current(
            -i64::try_from(HEADER_LEN).map_err(|_| Error::HeaderSizeParse)?,
        ))
        .map_err(|_| Error::Seek)?;
    header_new
        .write(&mut *req.handle.borrow_mut())
        .map_err(|_| Error::HeaderWrite)?;

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
        .map_err(|_| Error::HeaderDeserialize)?;
    graph.validate().map_err(|_| Error::HeaderDeserialize)?;

    let original = fs::read(req.target_path).map_err(|_| Error::HeaderDeserialize)?;
    let replacement = replacement_bytes(original, req.raw_key_old)?;

    let mut transaction = StagedOutputTransaction::new(target).map_err(|_| Error::HeaderWrite)?;
    transaction
        .write_all(&replacement)
        .map_err(|_| Error::HeaderWrite)?;
    transaction.commit().map_err(|_| Error::HeaderWrite)
}

fn replacement_bytes(
    mut original: Vec<u8>,
    raw_key_old: Protected<Vec<u8>>,
) -> Result<Vec<u8>, Error> {
    let mut reader = Cursor::new(original.as_slice());
    let parsed = read_header(&mut reader).map_err(|_| Error::HeaderDeserialize)?;
    let ParsedHeader::V1(payload) = parsed;
    let header_new = deleted_header(payload.header(), raw_key_old)?;
    let header_bytes = header_new.serialize().map_err(|_| Error::HeaderWrite)?;

    let target_header = original
        .get_mut(..HEADER_LEN)
        .ok_or(Error::HeaderDeserialize)?;
    target_header.copy_from_slice(&header_bytes);

    Ok(original)
}

fn deleted_header(header: &V1Header, raw_key_old: Protected<Vec<u8>>) -> Result<V1Header, Error> {
    let mut keyslots = header.keyslots_collection().clone();

    // all of these functions need either the master key, or the index
    let (_, index) = super::decrypt_v1_master_key_with_index(&keyslots, raw_key_old)?;

    if keyslots.len() == 1 {
        return Err(Error::CannotRemoveFinalV1Keyslot);
    }

    keyslots.remove(index).map_err(|_| Error::HeaderWrite)?;

    V1Header::new(*header.payload_nonce(), keyslots).map_err(|_| Error::HeaderWrite)
}
