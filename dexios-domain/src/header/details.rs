//! Identity-bound header detail reads for the CLI-facing details workflow.

use std::path::Path;

use core::header::{ParsedHeader, read_header};

use super::Error;
use crate::storage::FileStorage;
use crate::storage::identity::{IdentityError, PathIdentityGraph, PathRole, ResolvedTarget};

#[derive(Debug)]
pub struct DetailsIntent {
    input_target: ResolvedTarget,
}

impl DetailsIntent {
    pub fn new<I>(input_path: I) -> Result<Self, Error>
    where
        I: AsRef<Path>,
    {
        let input_path = input_path.as_ref().to_path_buf();
        let mut graph = PathIdentityGraph::new();
        let input_target = graph
            .add_existing(&input_path, PathRole::Input)
            .map_err(Error::PathIdentity)?;
        graph.validate().map_err(Error::PathIdentity)?;

        Ok(Self { input_target })
    }
}

pub fn execute(intent: DetailsIntent) -> Result<ParsedHeader, Error> {
    let DetailsIntent { input_target } = intent;
    let entry = FileStorage
        .read_resolved_existing_no_follow(&input_target)
        .map_err(map_read_storage_error)?;
    let reader = entry.try_reader().map_err(map_read_storage_error)?;
    let mut reader = reader.borrow_mut();

    read_header(&mut *reader).map_err(Error::from)
}

fn map_read_storage_error(error: crate::storage::Error) -> Error {
    match error {
        crate::storage::Error::UnsafePath(path) => {
            Error::PathIdentity(IdentityError::UnsafePath(path))
        }
        crate::storage::Error::OpenFileWithSource { source, .. }
        | crate::storage::Error::FileAccessWithSource(source)
        | crate::storage::Error::FileLenWithSource(source) => Error::ReadIoWithSource(source),
        _ => Error::ReadIo,
    }
}
