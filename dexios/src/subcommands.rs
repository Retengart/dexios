use anyhow::Result;
use clap::ArgMatches;
use std::fmt;

// this is called from main.rs
// it gets params and sends them to the appropriate functions

use crate::global::{
    parameters::{
        forcemode, get_param, get_params, key_manipulation_params, pack_params, parameter_handler,
    },
    states::{HashMode, Key, KeyParams},
};
use domain::storage::cleanup::{
    CleanupFailure, CleanupGateError, CleanupReceipt, CleanupResult, HashVerification,
    PostCommitSuccess,
};
use domain::storage::transaction::CommitReceipt;

pub(crate) mod decrypt;
pub(crate) mod encrypt;
pub(crate) mod errors;
pub(crate) mod hashing;
pub(crate) mod header;
pub(crate) mod key;
pub(crate) mod pack;
pub(crate) mod unpack;

pub(crate) fn hash_after_commit(files: &[String], hash_mode: HashMode) -> Result<HashVerification> {
    if hash_mode == HashMode::CalculateHash {
        hashing::hash_stream(files)?;
        Ok(HashVerification::Succeeded)
    } else {
        Ok(HashVerification::NotRequested)
    }
}

pub(crate) fn cleanup_after_commit(
    cleanup_receipt: &CleanupReceipt,
    commit_receipt: &CommitReceipt,
    hash_verification: HashVerification,
) -> std::result::Result<(), CleanupAfterCommitError> {
    // Central ordinary delete-after-success cleanup gate.
    // Source gate: cleanup is blocked after partial commit.
    // TransactionError::PartialCommit only carries PartialCommitReceipt evidence,
    // which cannot satisfy the CommitReceipt argument required here.
    // Source gate: HashVerification::Failed means requested hash did not succeed.
    // Source gate: changed cleanup identity blocks cleanup.
    // Domain-returned processed-source cleanup evidence records cleanup target identity before deletion.
    let proof = PostCommitSuccess::from_commit_and_hash(commit_receipt, hash_verification)
        .map_err(CleanupAfterCommitError::Gate)?;
    let result = cleanup_receipt.run(&proof);
    ensure_cleanup_succeeded(result)
}

fn ensure_cleanup_succeeded(
    result: CleanupResult,
) -> std::result::Result<(), CleanupAfterCommitError> {
    if result.is_success() {
        return Ok(());
    }

    // Source gate: typed cleanup evidence stays attached for maintainer diagnostics.
    if !result.failures.is_empty() {
        return Err(CleanupAfterCommitError::CleanupFailed(result));
    }

    Ok(())
}

#[derive(Debug)]
pub(crate) enum CleanupAfterCommitError {
    Gate(CleanupGateError),
    CleanupFailed(CleanupResult),
}

impl fmt::Display for CleanupAfterCommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gate(CleanupGateError::CommitNotAuthorized) => {
                f.write_str("Output commit was not cleanup-authorized; source was not deleted")
            }
            Self::Gate(CleanupGateError::HashNotVerified) => {
                f.write_str("Requested hash did not succeed; source was not deleted")
            }
            Self::CleanupFailed(_) => {
                f.write_str("Cleanup failed after output commit; committed outputs remain in place")
            }
        }
    }
}

impl std::error::Error for CleanupAfterCommitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Gate(error) => Some(error),
            Self::CleanupFailed(result) => result
                .failures
                .first()
                .map(|failure: &CleanupFailure| failure as &(dyn std::error::Error + 'static)),
        }
    }
}

pub(crate) fn encrypt(sub_matches: &ArgMatches) -> Result<()> {
    let params = parameter_handler(sub_matches)?;

    encrypt::stream_mode(
        &get_param("input", sub_matches)?,
        &get_param("output", sub_matches)?,
        &params,
    )
}

pub(crate) fn decrypt(sub_matches: &ArgMatches) -> Result<()> {
    let params = parameter_handler(sub_matches)?;

    // stream decrypt is the default as it will redirect to memory mode if the header says so (for backwards-compat)
    decrypt::stream_mode(
        &get_param("input", sub_matches)?,
        &get_param("output", sub_matches)?,
        &params,
    )
}

pub(crate) fn pack(sub_matches: &ArgMatches) -> Result<()> {
    let (crypto_params, pack_params) = pack_params(sub_matches)?;

    pack::execute(&pack::Request {
        input_file: &get_params("input", sub_matches)?,
        output_file: &get_param("output", sub_matches)?,
        pack_params,
        crypto_params,
    })
}

pub(crate) fn unpack(sub_matches: &ArgMatches) -> Result<()> {
    use super::global::states::PrintMode;

    let crypto_params = parameter_handler(sub_matches)?;

    let print_mode = if sub_matches.get_flag("verbose") {
        PrintMode::Verbose
    } else {
        PrintMode::Quiet
    };

    unpack::unpack(
        &get_param("input", sub_matches)?,
        &get_param("output", sub_matches)?,
        print_mode,
        crypto_params,
    )
}

pub(crate) fn hash_stream(sub_matches: &ArgMatches) -> Result<()> {
    let files = get_params("input", sub_matches)?;

    hashing::hash_stream(&files)
}

pub(crate) fn header_dump(sub_matches: &ArgMatches) -> Result<()> {
    let force = forcemode(sub_matches);

    header::dump(
        &get_param("input", sub_matches)?,
        &get_param("output", sub_matches)?,
        force,
    )
}

pub(crate) fn header_restore(sub_matches: &ArgMatches) -> Result<()> {
    let force = forcemode(sub_matches);

    header::restore(
        &get_param("input", sub_matches)?,
        &get_param("output", sub_matches)?,
        force,
    )
}

pub(crate) fn header_strip(sub_matches: &ArgMatches) -> Result<()> {
    let force = forcemode(sub_matches);

    header::strip(
        &get_param("input", sub_matches)?,
        &get_param("header", sub_matches)?,
        force,
    )
}

pub(crate) fn header_details(sub_matches: &ArgMatches) -> Result<()> {
    header::details(&get_param("input", sub_matches)?, sub_matches.get_flag("raw"))
}

pub(crate) fn key_change(sub_matches: &ArgMatches) -> Result<()> {
    let mut params = key_manipulation_params(sub_matches)?;
    params.force = forcemode(sub_matches);

    key::change(&get_param("input", sub_matches)?, &params)
}

pub(crate) fn key_add(sub_matches: &ArgMatches) -> Result<()> {
    let params = key_manipulation_params(sub_matches)?;

    key::add(&get_param("input", sub_matches)?, &params)
}

pub(crate) fn key_del(sub_matches: &ArgMatches) -> Result<()> {
    let key = Key::init(sub_matches, &KeyParams::default(), "keyfile")?;
    let force = forcemode(sub_matches);

    key::delete(&get_param("input", sub_matches)?, &key, force)
}

pub(crate) fn key_verify(sub_matches: &ArgMatches) -> Result<()> {
    let key = Key::init(sub_matches, &KeyParams::default(), "keyfile")?;

    key::verify(&get_param("input", sub_matches)?, &key)
}
