//! This provides functionality for deleting a key from a Dexios V1 header.

use super::Error;
use core::header::common::HEADER_LEN;
use core::header::v1::V1Header;
use core::header::{ParsedHeader, read_header};
use core::protected::Protected;
use std::fs;
use std::io::Cursor;
use std::path::Path;

use crate::storage::identity::ResolvedTarget;
use crate::storage::identity::{OverwritePolicy, PathIdentityGraph, PathRole};
use crate::storage::transaction::{CommitReceipt, StagedOutputTransaction};

pub struct DeleteIntent {
    target: ResolvedTarget,
    original: Vec<u8>,
    header: V1Header,
}

impl DeleteIntent {
    pub fn new<P>(target_path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let mut graph = PathIdentityGraph::new();
        let target = graph
            .add_output(
                target_path,
                PathRole::MutationTarget,
                OverwritePolicy::ReplaceAtCommit,
            )
            .map_err(Error::PathIdentity)?;
        graph.validate().map_err(Error::PathIdentity)?;

        let original = fs::read(target.target_path()).map_err(|_| Error::ReadIo)?;
        let header = parse_v1_header(&original)?;

        if let Some(tag) = super::unsupported_keyslot_kdf_tag(header.keyslots_collection()) {
            return Err(Error::UnsupportedKdf(tag));
        }

        Ok(Self {
            target,
            original,
            header,
        })
    }
}

pub fn execute(
    intent: DeleteIntent,
    raw_key_old: Protected<Vec<u8>>,
) -> Result<CommitReceipt, Error> {
    let DeleteIntent {
        target,
        mut original,
        header,
    } = intent;

    let replacement_header = deleted_header(&header, raw_key_old)?;
    let header_bytes = validated_header_bytes(&replacement_header)?;
    let target_header = original
        .get_mut(..HEADER_LEN)
        .ok_or(Error::HeaderDeserialize)?;
    target_header.copy_from_slice(&header_bytes);

    let mut transaction = StagedOutputTransaction::new(target).map_err(Error::Transaction)?;
    transaction
        .write_all(&original)
        .map_err(Error::Transaction)?;
    transaction.commit().map_err(Error::Transaction)
}

fn deleted_header(header: &V1Header, raw_key_old: Protected<Vec<u8>>) -> Result<V1Header, Error> {
    let mut keyslots = header.keyslots_collection().clone();

    // all of these functions need either the master key, or the index
    let (master_key, index) = super::decrypt_v1_master_key_with_index(header, raw_key_old)?;
    drop(master_key);

    if keyslots.len() == 1 {
        return Err(Error::CannotRemoveFinalV1Keyslot);
    }

    keyslots.remove(index).map_err(|_| Error::HeaderWrite)?;

    V1Header::new(*header.payload_nonce(), keyslots).map_err(|_| Error::HeaderWrite)
}

fn parse_v1_header(bytes: &[u8]) -> Result<V1Header, Error> {
    let mut reader = Cursor::new(bytes);
    let parsed = read_header(&mut reader).map_err(super::map_header_read_error)?;
    let ParsedHeader::V1(payload) = parsed;
    Ok(payload.header().clone())
}

fn validated_header_bytes(header: &V1Header) -> Result<Vec<u8>, Error> {
    let header_bytes = header.serialize().map_err(|_| Error::HeaderWrite)?;
    if header_bytes.len() != HEADER_LEN {
        return Err(Error::HeaderWrite);
    }

    parse_v1_header(&header_bytes)?;
    Ok(header_bytes)
}
