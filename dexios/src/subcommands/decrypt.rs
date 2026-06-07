use crate::cli::overwrite::{
    ExistingPathProbe, PlannedOverwrite, confirm_overwrites, reject_stdin_keyfile_prompt_conflict,
};
use crate::global::states::{DeleteInput, HeaderLocation, PasswordState};
use crate::global::structs::CryptoParams;

use anyhow::Result;

use super::errors::map_decrypt_error;

// Handles user-facing prompts and delegates path validation/opening to the domain layer.
pub(crate) fn stream_mode(input: &str, output: &str, params: &CryptoParams) -> Result<()> {
    let output_plan = PlannedOverwrite::new(output, ExistingPathProbe::Metadata);
    reject_stdin_keyfile_prompt_conflict(params, output_plan.exists())?;
    if !confirm_overwrites([&output_plan], params.force)? {
        return Ok(());
    }

    let raw_key = params.key.get_secret(&PasswordState::Direct)?;

    let detached_header_path = match &params.header_location {
        HeaderLocation::Embedded => None,
        HeaderLocation::Detached(path) => Some(path.as_str()),
    };
    let intent = domain::decrypt::DecryptIntent::new(
        input,
        output,
        output_plan.policy(),
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
