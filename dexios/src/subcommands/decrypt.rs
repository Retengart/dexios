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

fn reject_stdin_keyfile_prompt_conflict(params: &CryptoParams, prompt_needed: bool) -> Result<()> {
    if prompt_needed && params.force == ForceMode::Prompt && params.key.reads_stdin() {
        return Err(anyhow::anyhow!(
            "--keyfile - cannot be combined with interactive overwrite prompts; pass --force to avoid reading confirmation from stdin"
        ));
    }
    Ok(())
}

// this function is for decrypting a file in stream mode
// it handles user-facing prompts and delegates path validation/opening to domain
pub(crate) fn stream_mode(input: &str, output: &str, params: &CryptoParams) -> Result<()> {
    // 1. validate and prepare options
    let output_exists = existing_path(output);
    reject_stdin_keyfile_prompt_conflict(params, output_exists)?;
    if !overwrite_check_if_needed(output, output_exists, params.force)? {
        return Ok(());
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
    let result =
        domain::decrypt::execute_transactional_with_cleanup(intent).map_err(map_decrypt_error)?;

    let hash_verification = super::hash_after_commit(&[input.to_string()], params.hash_mode)?;

    if params.delete_input == DeleteInput::Delete {
        super::cleanup_after_commit(
            result.cleanup_receipt(),
            result.commit_receipt(),
            hash_verification,
        )?;
    }

    Ok(())
}
