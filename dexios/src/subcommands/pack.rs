use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::cli::overwrite::{
    ExistingPathProbe, PlannedOverwrite, confirm_overwrites, reject_stdin_keyfile_prompt_conflict,
};
use crate::global::states::{
    DeleteSource, DirectoryMode, HeaderLocation, PasswordState, PrintMode,
};
use crate::global::structs::{CryptoParams, PackParams};
use crate::info;
use crate::subcommands::errors::map_pack_error;
use domain::archive::ArchivePolicy;
use domain::pack::{DetachedHeaderTarget, PackIntent};

pub(crate) struct Request<'a> {
    pub input_file: &'a Vec<String>,
    pub output_file: &'a str,
    pub pack_params: PackParams,
    pub crypto_params: CryptoParams,
}

// Packing is delegated to the domain layer, which writes a canonical
// manifest-first archive payload through staged transaction semantics.
pub(crate) fn execute(req: &Request<'_>) -> Result<()> {
    // 1. validate and prepare options
    if req.input_file.iter().any(|f| f == req.output_file) {
        return Err(anyhow::anyhow!(
            "Input and output files cannot have the same name."
        ));
    }

    if req.input_file.iter().any(|f| PathBuf::from(f).is_file()) {
        return Err(anyhow::anyhow!("Input path cannot be a file."));
    }

    let output_path = PathBuf::from(req.output_file);
    let output_plan = PlannedOverwrite::new(&output_path, ExistingPathProbe::SymlinkMetadata);
    let detached_header_path = match &req.crypto_params.header_location {
        HeaderLocation::Embedded => None,
        HeaderLocation::Detached(path) => Some(PathBuf::from(path)),
    };
    let detached_header_plan = detached_header_path
        .as_ref()
        .map(|path| PlannedOverwrite::new(path, ExistingPathProbe::SymlinkMetadata));
    reject_stdin_keyfile_prompt_conflict(
        &req.crypto_params,
        output_plan.exists()
            || detached_header_plan
                .as_ref()
                .is_some_and(PlannedOverwrite::exists),
    )?;
    let mut prompt_targets = vec![&output_plan];
    if let Some(detached_header_plan) = &detached_header_plan {
        prompt_targets.push(detached_header_plan);
    }
    if !confirm_overwrites(prompt_targets, req.crypto_params.force)? {
        return Ok(());
    }

    let input_files = req.input_file.iter().map(PathBuf::from).collect::<Vec<_>>();
    let raw_key = req.crypto_params.key.get_secret(&PasswordState::Validate)?;

    let on_archive_entry = (req.pack_params.print_mode == PrintMode::Verbose).then(|| {
        Box::new(|archive_path: &Path| {
            info!("Packing {}", archive_path.display());
        }) as domain::pack::OnArchiveEntryFn
    });

    let detached_header_target = detached_header_plan
        .as_ref()
        .map(|plan| DetachedHeaderTarget::new(plan.path(), plan.policy()));

    // 2. compress and encrypt files
    let intent = PackIntent::new(
        input_files,
        output_path,
        output_plan.policy(),
        detached_header_target,
        raw_key,
        req.crypto_params.kdf,
        ArchivePolicy::default(),
        req.pack_params.dir_mode == DirectoryMode::Recursive,
        on_archive_entry,
    )
    .map_err(map_pack_error)?;
    let result =
        domain::pack::execute_transactional_with_cleanup(intent).map_err(map_pack_error)?;

    let hash_verification = super::hash_after_commit(
        &[String::from(req.output_file)],
        req.crypto_params.hash_mode,
    )?;

    if req.pack_params.delete_source == DeleteSource::Delete {
        super::cleanup_after_commit(
            result.cleanup_receipt(),
            result.commit_receipt(),
            hash_verification,
        )?;
    }

    Ok(())
}
