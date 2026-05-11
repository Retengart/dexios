//! This provides functionality for dumping a header that adheres to the Dexios format.

use super::Error;
use std::fs;
use std::io::Cursor;
use std::path::Path;

use core::header::common::HEADER_LEN;
use core::header::{ParsedHeader, read_header};

use crate::storage::identity::{OverwritePolicy, PathIdentityGraph, PathRole, ResolvedTarget};
use crate::storage::transaction::{CommitReceipt, StagedOutputTransaction, TransactionError};

#[derive(Debug)]
pub struct DumpIntent {
    input_target: ResolvedTarget,
    output_target: ResolvedTarget,
}

impl DumpIntent {
    pub fn new<I, O>(
        input_path: I,
        output_path: O,
        overwrite: OverwritePolicy,
    ) -> Result<Self, Error>
    where
        I: AsRef<Path>,
        O: AsRef<Path>,
    {
        let input_path = input_path.as_ref().to_path_buf();
        let mut graph = PathIdentityGraph::new();
        let input_target = graph
            .add_existing(&input_path, PathRole::Input)
            .map_err(Error::PathIdentity)?;
        let output_target = graph
            .add_output(output_path, PathRole::Output, overwrite)
            .map_err(Error::PathIdentity)?;
        graph.validate().map_err(Error::PathIdentity)?;

        Ok(Self {
            input_target,
            output_target,
        })
    }
}

pub fn execute(intent: DumpIntent) -> Result<CommitReceipt, Error> {
    let DumpIntent {
        input_target,
        output_target,
    } = intent;

    let input = fs::read(input_target.target_path()).map_err(|_| Error::ReadIo)?;
    let header_bytes = dump_header_bytes(&input)?;
    let mut transaction =
        StagedOutputTransaction::new(output_target).map_err(Error::Transaction)?;
    transaction
        .write_all(&header_bytes)
        .map_err(map_write_transaction_error)?;
    transaction.commit().map_err(Error::Transaction)
}

pub fn execute_transactional(intent: DumpIntent) -> Result<CommitReceipt, Error> {
    execute(intent)
}

fn dump_header_bytes(input: &[u8]) -> Result<Vec<u8>, Error> {
    if input.len() <= HEADER_LEN {
        return Err(Error::MissingPayload {
            actual_len: input.len(),
        });
    }

    let mut reader = Cursor::new(input);
    let parsed = read_header(&mut reader).map_err(Error::from)?;
    let ParsedHeader::V1(payload) = parsed;
    let serialized = payload.header().serialize().map_err(|_| Error::WriteIo)?;
    debug_assert_eq!(serialized.len(), HEADER_LEN);

    Ok(serialized)
}

fn map_write_transaction_error(error: TransactionError) -> Error {
    match error {
        TransactionError::Write { .. } => Error::WriteIo,
        error => Error::Transaction(error),
    }
}
