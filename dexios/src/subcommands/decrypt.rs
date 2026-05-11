use std::process::exit;

use crate::cli::prompt::overwrite_check;
use crate::global::states::{DeleteInput, ForceMode, HeaderLocation, PasswordState};
use crate::global::structs::CryptoParams;

use anyhow::Result;

use domain::storage::identity::OverwritePolicy;

use super::errors::map_decrypt_error;

fn overwrite_policy(path_exists: bool) -> OverwritePolicy {
    if path_exists {
        OverwritePolicy::ReplaceAtCommit
    } else {
        OverwritePolicy::CreateNew
    }
}

fn existing_path(path: &str) -> bool {
    std::fs::metadata(path).is_ok()
}

fn overwrite_check_if_needed(path: &str, path_exists: bool, force: ForceMode) -> Result<bool> {
    if path_exists {
        overwrite_check(path, force)
    } else {
        Ok(true)
    }
}

// this function is for decrypting a file in stream mode
// it handles user-facing prompts and delegates path validation/opening to domain
pub fn stream_mode(input: &str, output: &str, params: &CryptoParams) -> Result<()> {
    // 1. validate and prepare options
    let output_exists = existing_path(output);
    if !overwrite_check_if_needed(output, output_exists, params.force)? {
        exit(0);
    }

    let raw_key = params.key.get_secret(&PasswordState::Direct)?;

    // 2. decrypt file
    let detached_header_path = match &params.header_location {
        HeaderLocation::Embedded => None,
        HeaderLocation::Detached(path) => Some(path.as_str()),
    };
    let intent = domain::decrypt::DecryptIntent::new(
        input,
        output,
        overwrite_policy(output_exists),
        detached_header_path,
        raw_key,
        None,
    )
    .map_err(map_decrypt_error)?;
    let commit_receipt =
        domain::decrypt::execute_transactional(intent).map_err(map_decrypt_error)?;

    let hash_verification = super::hash_after_commit(&[input.to_string()], params.hash_mode)?;

    if params.delete_input == DeleteInput::Delete {
        super::cleanup_after_commit(&[input.to_string()], &commit_receipt, hash_verification)?;
    }

    Ok(())
}
