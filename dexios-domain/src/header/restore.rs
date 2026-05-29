//! This provides functionality for restoring a dumped header that adheres to the Dexios format, provided the target file contains enough empty bytes at the start to do so.

use super::Error;
use std::io::Cursor;
use std::path::Path;

use core::header::common::HEADER_LEN;
use core::header::{ParsedHeader, read_header};

use crate::storage::identity::{OverwritePolicy, PathIdentityGraph, PathRole};
use crate::storage::mutation::{MutationFreshnessError, MutationSnapshot};
use crate::storage::transaction::{CommitReceipt, StagedOutputTransaction, TransactionError};

#[derive(Debug)]
pub struct RestoreIntent {
    header_target: MutationSnapshot,
    target: MutationSnapshot,
}

impl RestoreIntent {
    pub fn new<H, T>(header_path: H, target_path: T) -> Result<Self, Error>
    where
        H: AsRef<Path>,
        T: AsRef<Path>,
    {
        let header_path = header_path.as_ref().to_path_buf();
        let target_path = target_path.as_ref().to_path_buf();
        let mut graph = PathIdentityGraph::new();
        let header_target = graph
            .add_existing(&header_path, PathRole::DetachedHeader)
            .map_err(Error::PathIdentity)?;
        let target = graph
            .add_output(
                &target_path,
                PathRole::MutationTarget,
                OverwritePolicy::ReplaceAtCommit,
            )
            .map_err(Error::PathIdentity)?;
        graph.validate().map_err(Error::PathIdentity)?;
        let header_target = read_snapshot(header_target)?;
        let target = read_snapshot(target)?;

        Ok(Self {
            header_target,
            target,
        })
    }
}

/// Restores a detached header into a stripped embedded artifact.
///
/// # Not payload-bound
///
/// This validates only that the detached header is a structurally well-formed canonical
/// V1 header and that the target is a stripped artifact; it performs **no** cryptographic
/// binding between the header and the payload. V1 stores no payload MAC in the header, so
/// binding would require a trial decrypt with the key. Restoring the wrong header for a
/// file therefore succeeds structurally but leaves the payload undecryptable — callers
/// should warn the user (the CLI does).
pub fn execute(intent: RestoreIntent) -> Result<CommitReceipt, Error> {
    let RestoreIntent {
        header_target,
        target,
    } = intent;
    let replacement = restored_header_bytes(
        header_target.original_bytes(),
        target.original_bytes().to_vec(),
    )?;
    header_target
        .ensure_fresh()
        .map_err(super::map_mutation_freshness_error)?;
    target
        .ensure_fresh()
        .map_err(super::map_mutation_freshness_error)?;
    let (target, _) = target.into_parts();

    let mut transaction = StagedOutputTransaction::new(target).map_err(Error::Transaction)?;
    transaction
        .write_all(&replacement)
        .map_err(map_write_transaction_error)?;
    transaction.commit().map_err(Error::Transaction)
}

pub fn execute_transactional(intent: RestoreIntent) -> Result<CommitReceipt, Error> {
    execute(intent)
}

fn restored_header_bytes(header: &[u8], mut target: Vec<u8>) -> Result<Vec<u8>, Error> {
    match header.len() {
        len if len < HEADER_LEN => return Err(Error::ShortDetachedHeader { actual_len: len }),
        len if len > HEADER_LEN => return Err(Error::TrailingDetachedHeader { actual_len: len }),
        _ => {}
    }

    let mut reader = Cursor::new(header);
    let parsed = read_header(&mut reader).map_err(Error::from)?;
    let ParsedHeader::V1(payload) = parsed;
    let serialized = payload.header().serialize().map_err(|_| Error::WriteIo)?;
    debug_assert_eq!(serialized.len(), HEADER_LEN);

    let target_len = target.len();
    if target_len <= HEADER_LEN {
        return Err(Error::TargetTooShort {
            actual_len: target_len,
        });
    }

    let target_header = target.get_mut(..HEADER_LEN).ok_or(Error::TargetTooShort {
        actual_len: target_len,
    })?;
    if !target_header.iter().all(|b| *b == 0) {
        return Err(Error::TargetNotStripped);
    }

    target_header.copy_from_slice(&serialized);

    Ok(target)
}

fn map_write_transaction_error(error: TransactionError) -> Error {
    match error {
        TransactionError::Write { .. } => Error::WriteIo,
        error => Error::Transaction(error),
    }
}

fn read_snapshot(
    target: crate::storage::identity::ResolvedTarget,
) -> Result<MutationSnapshot, Error> {
    MutationSnapshot::read(target).map_err(map_snapshot_read_error)
}

fn map_snapshot_read_error(error: MutationFreshnessError) -> Error {
    match error {
        MutationFreshnessError::Read { .. } => Error::ReadIo,
        error => super::map_mutation_freshness_error(error),
    }
}
