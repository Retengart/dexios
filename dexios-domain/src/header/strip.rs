//! This provides functionality for stripping a header that adheres to the Dexios format.

use super::Error;
use std::io::Cursor;
use std::path::Path;

use core::header::common::HEADER_LEN;
use core::header::{ParsedHeader, read_header};

use crate::storage::identity::{OverwritePolicy, PathIdentityGraph, PathRole};
use crate::storage::mutation::{MutationFreshnessError, MutationSnapshot};
use crate::storage::transaction::{CommitReceipt, StagedOutputTransaction, TransactionError};

#[derive(Debug)]
pub struct StripIntent {
    target: MutationSnapshot,
}

impl StripIntent {
    pub fn new<P: AsRef<Path>>(target_path: P) -> Result<Self, Error> {
        let target_path = target_path.as_ref().to_path_buf();
        let mut graph = PathIdentityGraph::new();
        let target = graph
            .add_output(
                &target_path,
                PathRole::MutationTarget,
                OverwritePolicy::ReplaceAtCommit,
            )
            .map_err(Error::PathIdentity)?;
        graph.validate().map_err(Error::PathIdentity)?;
        let target = read_snapshot(target)?;

        Ok(Self { target })
    }
}

pub fn execute(intent: StripIntent) -> Result<CommitReceipt, Error> {
    let StripIntent { target } = intent;
    let replacement = stripped_header_bytes(target.original_bytes().to_vec())?;
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

pub fn execute_transactional(intent: StripIntent) -> Result<CommitReceipt, Error> {
    execute(intent)
}

fn stripped_header_bytes(mut original: Vec<u8>) -> Result<Vec<u8>, Error> {
    if original.len() <= HEADER_LEN {
        return Err(Error::MissingPayload {
            actual_len: original.len(),
        });
    }

    let mut reader = Cursor::new(original.as_slice());
    let parsed = read_header(&mut reader).map_err(Error::from)?;
    match parsed {
        ParsedHeader::V1(_) => {}
    }

    let header = original.get_mut(..HEADER_LEN).ok_or(Error::InvalidFile)?;
    header.fill(0);

    Ok(original)
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
