//! This provides functionality for changing an existing key in a header that
//! adheres to the Dexios V1 format.

use super::Error;
use core::header::common::{HEADER_LEN, Salt};
use core::header::v1::{V1Header, V1Keyslot};
use core::header::{ParsedHeader, read_header};
use core::kdf::Kdf;
use core::primitives::{gen_keyslot_nonce, gen_salt};
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
    pub raw_key_new: Protected<Vec<u8>>,
    pub kdf: Kdf,
}

pub struct TransactionalRequest<'a> {
    pub target_path: &'a Path,
    pub raw_key_old: Protected<Vec<u8>>,
    pub raw_key_new: Protected<Vec<u8>>,
    pub kdf: Kdf,
}

pub fn execute<RW>(req: Request<'_, RW>) -> Result<(), Error>
where
    RW: Read + Write + Seek,
{
    let Request {
        handle,
        raw_key_old,
        raw_key_new,
        kdf,
    } = req;

    let parsed = read_header(&mut *handle.borrow_mut()).map_err(|_| Error::HeaderDeserialize)?;
    let ParsedHeader::V1(payload) = parsed;
    let header = payload.header();
    let header_new = changed_header(header, raw_key_old, raw_key_new, kdf)?;

    // write the header to the handle
    handle
        .borrow_mut()
        .seek(std::io::SeekFrom::Current(
            -i64::try_from(HEADER_LEN).map_err(|_| Error::HeaderSizeParse)?,
        ))
        .map_err(|_| Error::Seek)?;
    header_new
        .write(&mut *handle.borrow_mut())
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
    let replacement = replacement_bytes(original, req.raw_key_old, req.raw_key_new, req.kdf)?;

    let mut transaction = StagedOutputTransaction::new(target).map_err(|_| Error::HeaderWrite)?;
    transaction
        .write_all(&replacement)
        .map_err(|_| Error::HeaderWrite)?;
    transaction.commit().map_err(|_| Error::HeaderWrite)
}

fn replacement_bytes(
    mut original: Vec<u8>,
    raw_key_old: Protected<Vec<u8>>,
    raw_key_new: Protected<Vec<u8>>,
    kdf: Kdf,
) -> Result<Vec<u8>, Error> {
    let mut reader = Cursor::new(original.as_slice());
    let parsed = read_header(&mut reader).map_err(|_| Error::HeaderDeserialize)?;
    let ParsedHeader::V1(payload) = parsed;
    let header_new = changed_header(payload.header(), raw_key_old, raw_key_new, kdf)?;
    let header_bytes = header_new.serialize().map_err(|_| Error::HeaderWrite)?;

    let target_header = original
        .get_mut(..HEADER_LEN)
        .ok_or(Error::HeaderDeserialize)?;
    target_header.copy_from_slice(&header_bytes);

    Ok(original)
}

fn changed_header(
    header: &V1Header,
    raw_key_old: Protected<Vec<u8>>,
    raw_key_new: Protected<Vec<u8>>,
    kdf: Kdf,
) -> Result<V1Header, Error> {
    let mut keyslots = header.keyslots_collection().clone();

    // all of these functions need either the master key, or the index
    let (master_key, index) = super::decrypt_v1_master_key_with_index(&keyslots, raw_key_old)?;

    let salt_bytes = gen_salt();
    let salt = Salt::new(salt_bytes);
    let key_new = kdf
        .derive(&raw_key_new, &salt.to_kdf_salt())
        .map_err(|_| Error::KeyHash)?;
    drop(raw_key_new);

    let master_key_nonce = gen_keyslot_nonce();

    let encrypted_master_key = super::encrypt_master_key(master_key, key_new, &master_key_nonce)?;

    keyslots
        .replace(
            index,
            V1Keyslot::new(kdf, encrypted_master_key, master_key_nonce, salt),
        )
        .map_err(|_| Error::HeaderWrite)?;

    V1Header::new(*header.payload_nonce(), keyslots).map_err(|_| Error::HeaderWrite)
}
