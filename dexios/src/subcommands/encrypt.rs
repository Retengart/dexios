use crate::cli::prompt::overwrite_check;
use crate::global::states::{DeleteInput, ForceMode, HeaderLocation, PasswordState};
use crate::global::structs::CryptoParams;
use anyhow::Result;

use domain::storage::identity::OverwritePolicy;

use super::errors::map_encrypt_error;

fn should_continue_after_overwrite_checks<F>(output_ok: bool, header_check: F) -> Result<bool>
where
    F: FnOnce() -> Result<Option<bool>>,
{
    if !output_ok {
        return Ok(false);
    }

    Ok(header_check()?.unwrap_or(true))
}

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

// this function is for encrypting a file in stream mode
// it handles user-facing prompts and delegates path validation/opening to domain
pub(crate) fn stream_mode(input: &str, output: &str, params: &CryptoParams) -> Result<()> {
    // 1. validate and prepare options
    let output_exists = existing_path(output);
    let header_exists = match &params.header_location {
        HeaderLocation::Embedded => None,
        HeaderLocation::Detached(path) => Some(existing_path(path)),
    };
    reject_stdin_keyfile_prompt_conflict(params, output_exists || header_exists.unwrap_or(false))?;

    let output_ok = overwrite_check_if_needed(output, output_exists, params.force)?;

    if !should_continue_after_overwrite_checks(output_ok, || match &params.header_location {
        HeaderLocation::Embedded => Ok(None),
        HeaderLocation::Detached(path) => {
            overwrite_check_if_needed(path, header_exists.unwrap_or(false), params.force).map(Some)
        }
    })? {
        return Ok(());
    }

    let raw_key = params.key.get_secret(&PasswordState::Validate)?;

    let header = match &params.header_location {
        HeaderLocation::Embedded => None,
        HeaderLocation::Detached(path) => Some(domain::encrypt::DetachedHeaderTarget::new(
            path,
            overwrite_policy(header_exists.unwrap_or(false)),
        )),
    };

    // 2. encrypt file
    let intent = domain::encrypt::EncryptIntent::new(
        input,
        output,
        overwrite_policy(output_exists),
        header,
        raw_key,
        params.kdf,
    )
    .map_err(map_encrypt_error)?;
    let result =
        domain::encrypt::execute_transactional_with_cleanup(intent).map_err(map_encrypt_error)?;

    let hash_verification = super::hash_after_commit(&[output.to_string()], params.hash_mode)?;

    if params.delete_input == DeleteInput::Delete {
        super::cleanup_after_commit(
            result.cleanup_receipt(),
            result.commit_receipt(),
            hash_verification,
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn detached_header_decline_returns_false_before_work_starts() {
        assert!(!super::should_continue_after_overwrite_checks(true, || Ok(Some(false))).unwrap());
    }

    #[test]
    fn approve_all_overwrite_checks_returns_true() {
        assert!(super::should_continue_after_overwrite_checks(true, || Ok(Some(true))).unwrap());
        assert!(super::should_continue_after_overwrite_checks(true, || Ok(None)).unwrap());
    }

    #[test]
    fn main_output_decline_short_circuits_header_check() {
        let mut called = false;

        let result = super::should_continue_after_overwrite_checks(false, || {
            called = true;
            Ok(Some(true))
        })
        .unwrap();

        assert!(!result);
        assert!(!called);
    }
}
