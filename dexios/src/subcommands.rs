use anyhow::Result;
use clap::ArgMatches;
use std::path::Path;

// this is called from main.rs
// it gets params and sends them to the appropriate functions

use crate::global::{
    parameters::{
        forcemode, get_param, get_params, key_manipulation_params, pack_params, parameter_handler,
    },
    states::{HashMode, Key, KeyParams},
};
use domain::storage::cleanup::{
    CleanupReceipt, CleanupResult, HashVerification, PostCommitSuccess,
};
use domain::storage::transaction::CommitReceipt;

pub mod decrypt;
pub mod encrypt;
pub mod errors;
pub mod hashing;
pub mod header;
pub mod key;
pub mod pack;
pub mod unpack;

pub fn hash_after_commit(files: &[String], hash_mode: HashMode) -> Result<HashVerification> {
    if hash_mode == HashMode::CalculateHash {
        hashing::hash_stream(files)?;
        Ok(HashVerification::Succeeded)
    } else {
        Ok(HashVerification::NotRequested)
    }
}

pub fn cleanup_after_commit(
    paths: &[String],
    commit_receipt: &CommitReceipt,
    hash_verification: HashVerification,
) -> Result<()> {
    // Central ordinary delete-after-success cleanup gate.
    // Source gate: cleanup is blocked after partial commit.
    // Source gate: HashVerification::Failed means requested hash did not succeed.
    // Source gate: changed cleanup identity blocks cleanup.
    // CleanupReceipt::from_paths records cleanup target identity before deletion.
    let cleanup_receipt =
        CleanupReceipt::from_paths(paths.iter().map(|path| Path::new(path.as_str())))?;
    let proof = PostCommitSuccess::from_commit_and_hash(commit_receipt, hash_verification)?;
    let result = cleanup_receipt.run(&proof);
    ensure_cleanup_succeeded(result)
}

fn ensure_cleanup_succeeded(result: CleanupResult) -> Result<()> {
    if result.is_success() {
        return Ok(());
    }

    let failures = result
        .failures
        .iter()
        .map(|failure| format!("{} ({:?})", failure.target.path.display(), failure.error))
        .collect::<Vec<_>>()
        .join(", ");

    Err(anyhow::anyhow!(
        "cleanup failed after output commit; committed outputs were not rolled back; deleted {} target(s), failed to delete: {}",
        result.deleted.len(),
        failures
    ))
}

pub fn encrypt(sub_matches: &ArgMatches) -> Result<()> {
    let params = parameter_handler(sub_matches)?;

    encrypt::stream_mode(
        &get_param("input", sub_matches)?,
        &get_param("output", sub_matches)?,
        &params,
    )
}

pub fn decrypt(sub_matches: &ArgMatches) -> Result<()> {
    let params = parameter_handler(sub_matches)?;

    // stream decrypt is the default as it will redirect to memory mode if the header says so (for backwards-compat)
    decrypt::stream_mode(
        &get_param("input", sub_matches)?,
        &get_param("output", sub_matches)?,
        &params,
    )
}

pub fn pack(sub_matches: &ArgMatches) -> Result<()> {
    let (crypto_params, pack_params) = pack_params(sub_matches)?;

    pack::execute(&pack::Request {
        input_file: &get_params("input", sub_matches)?,
        output_file: &get_param("output", sub_matches)?,
        pack_params,
        crypto_params,
    })
}

pub fn unpack(sub_matches: &ArgMatches) -> Result<()> {
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

pub fn hash_stream(sub_matches: &ArgMatches) -> Result<()> {
    let files = get_params("input", sub_matches)?;

    hashing::hash_stream(&files)
}

pub fn header_dump(sub_matches: &ArgMatches) -> Result<()> {
    let sub_matches_dump = sub_matches.subcommand_matches("dump").unwrap();
    let force = forcemode(sub_matches_dump);

    header::dump(
        &get_param("input", sub_matches_dump)?,
        &get_param("output", sub_matches_dump)?,
        force,
    )
}

pub fn header_restore(sub_matches: &ArgMatches) -> Result<()> {
    let sub_matches_restore = sub_matches.subcommand_matches("restore").unwrap();

    header::restore(
        &get_param("input", sub_matches_restore)?,
        &get_param("output", sub_matches_restore)?,
    )
}

pub fn header_strip(sub_matches: &ArgMatches) -> Result<()> {
    let sub_matches_strip = sub_matches.subcommand_matches("strip").unwrap();

    header::strip(&get_param("input", sub_matches_strip)?)
}

pub fn header_details(sub_matches: &ArgMatches) -> Result<()> {
    let sub_matches_details = sub_matches.subcommand_matches("details").unwrap();

    header::details(&get_param("input", sub_matches_details)?)
}

pub fn key_change(sub_matches: &ArgMatches) -> Result<()> {
    let sub_matches_change_key = sub_matches.subcommand_matches("change").unwrap();

    let params = key_manipulation_params(sub_matches_change_key)?;

    key::change(&get_param("input", sub_matches_change_key)?, &params)
}

pub fn key_add(sub_matches: &ArgMatches) -> Result<()> {
    let sub_matches_add_key = sub_matches.subcommand_matches("add").unwrap();

    let params = key_manipulation_params(sub_matches_add_key)?;

    key::add(&get_param("input", sub_matches_add_key)?, &params)
}

pub fn key_del(sub_matches: &ArgMatches) -> Result<()> {
    let sub_matches_del_key = sub_matches.subcommand_matches("del").unwrap();
    let key = Key::init(sub_matches_del_key, &KeyParams::default(), "keyfile")?;

    key::delete(&get_param("input", sub_matches_del_key)?, &key)
}

pub fn key_verify(sub_matches: &ArgMatches) -> Result<()> {
    let sub_matches_verify_key = sub_matches.subcommand_matches("verify").unwrap();
    let key = Key::init(sub_matches_verify_key, &KeyParams::default(), "keyfile")?;

    key::verify(&get_param("input", sub_matches_verify_key)?, &key)
}
