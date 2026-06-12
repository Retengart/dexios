//! This provides functionality for verifying that a decryption key is correct
//! for Dexios V1.

use std::io;
use std::path::Path;

use super::Error;
use core::header::v1::V1Header;
use core::header::{ParsedHeader, read_header};
use core::protected::Protected;

use crate::storage;
use crate::storage::identity::{IdentityError, PathIdentityGraph, PathRole};

pub struct VerifyIntent {
    header: V1Header,
}

impl VerifyIntent {
    pub fn new<P>(target_path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        // Resolve the target through the path-identity layer with a read-only `Input`
        // role: a symlinked target (or symlinked prefix) is rejected here, and the
        // resolved canonical path carries the dev/ino identity used by the no-follow
        // read below to defend against TOCTOU swaps (verify-1).
        let mut graph = PathIdentityGraph::new();
        let target = graph
            .add_existing(target_path, PathRole::Input)
            .map_err(map_identity_error)?;
        graph.validate().map_err(Error::PathIdentity)?;

        // Read the header through the same no-follow resolution the other read-side
        // intents use; this re-opens with `O_NOFOLLOW` and re-verifies the dev/ino
        // identity, so the header cannot be read through a symlink. Verify is strictly
        // read-only: nothing is mutated and no output is staged.
        let entry = storage::FileStorage
            .read_resolved_existing_no_follow(&target)
            .map_err(map_storage_error)?;
        let reader = entry.try_reader().map_err(map_storage_error)?;
        let parsed = {
            let mut stream = reader.borrow_mut();
            read_header(&mut *stream)?
        };
        let ParsedHeader::V1(payload) = parsed;
        let header = payload.header().clone();

        if let Some(tag) = super::all_keyslots_have_unsupported_kdf(header.keyslots_collection()) {
            return Err(Error::UnsupportedKdf(tag));
        }

        Ok(Self { header })
    }
}

pub fn execute(intent: VerifyIntent, raw_key: Protected<Vec<u8>>) -> Result<(), Error> {
    let (master_key, _) = super::decrypt_v1_master_key_with_index(&intent.header, raw_key)?;

    // Ensure the master key is gone from memory in the event that the key is correct.
    drop(master_key);

    Ok(())
}

// Preserve the historical `ReadIo` outcome for a non-existent target while keeping the
// symlink/aliasing rejections as `PathIdentity` errors.
fn map_identity_error(error: IdentityError) -> Error {
    match &error {
        IdentityError::Io(kind) | IdentityError::IoWithSource { kind, .. }
            if *kind == io::ErrorKind::NotFound =>
        {
            Error::ReadIo
        }
        _ => Error::PathIdentity(error),
    }
}

// `read_resolved_existing_no_follow` rejects a symlinked / swapped target as an unsafe
// path; surface that as a path-identity rejection and any other read failure as IO.
fn map_storage_error(error: storage::Error) -> Error {
    match error {
        storage::Error::UnsafePath(path) => Error::PathIdentity(IdentityError::UnsafePath(path)),
        _ => Error::ReadIo,
    }
}
