use crate::cli::overwrite::{
    ExistingPathProbe, PlannedOverwrite, confirm_overwrites, reject_stdin_keyfile_prompt_conflict,
};
use crate::global::states::{DeleteInput, HeaderLocation, PasswordState};
use crate::global::structs::CryptoParams;
use anyhow::Result;

use super::errors::map_encrypt_error;

// Handles user-facing prompts and delegates path validation/opening to the domain layer.
pub(crate) fn stream_mode(input: &str, output: &str, params: &CryptoParams) -> Result<()> {
    let output_plan = PlannedOverwrite::new(output, ExistingPathProbe::Metadata);
    let header_plan = match &params.header_location {
        HeaderLocation::Embedded => None,
        HeaderLocation::Detached(path) => {
            Some(PlannedOverwrite::new(path, ExistingPathProbe::Metadata))
        }
    };
    reject_stdin_keyfile_prompt_conflict(
        params,
        output_plan.exists() || header_plan.as_ref().is_some_and(PlannedOverwrite::exists),
    )?;
    let mut prompt_targets = vec![&output_plan];
    if let Some(header_plan) = &header_plan {
        prompt_targets.push(header_plan);
    }
    if !confirm_overwrites(prompt_targets, params.force)? {
        return Ok(());
    }

    let raw_key = params.key.get_secret(&PasswordState::Validate)?;

    let header = header_plan
        .as_ref()
        .map(|plan| domain::encrypt::DetachedHeaderTarget::new(plan.path(), plan.policy()));

    // 2. encrypt file
    let intent = domain::encrypt::EncryptIntent::new(
        input,
        output,
        output_plan.policy(),
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
