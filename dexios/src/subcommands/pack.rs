use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::global::states::{
    DeleteSource, DirectoryMode, HeaderLocation, PasswordState, PrintMode,
};
use crate::global::structs::{CryptoParams, PackParams};
use crate::info;
use crate::subcommands::errors::map_pack_error;
use domain::archive::ArchivePolicy;
use domain::pack::{DetachedHeaderTarget, PackIntent};
use domain::storage::identity::OverwritePolicy;

use crate::cli::prompt::overwrite_check;

fn should_continue_after_overwrite_checks<F>(output_ok: bool, header_check: F) -> Result<bool>
where
    F: FnOnce() -> Result<Option<bool>>,
{
    if !output_ok {
        return Ok(false);
    }

    Ok(header_check()?.unwrap_or(true))
}

pub struct Request<'a> {
    pub input_file: &'a Vec<String>,
    pub output_file: &'a str,
    pub pack_params: PackParams,
    pub crypto_params: CryptoParams,
}

fn overwrite_policy_for(path: &Path) -> OverwritePolicy {
    if fs::symlink_metadata(path).is_ok() {
        OverwritePolicy::ReplaceAtCommit
    } else {
        OverwritePolicy::CreateNew
    }
}

// this first indexes the input directory
// once it has the total number of files/folders, it creates a temporary zip file
// it compresses all of the files into the temporary archive
// once compressed, it encrypts the zip file
// it drops/deletes the temporary archive afterwards; this is cleanup only, not a secure-erase guarantee
pub fn execute(req: &Request) -> Result<()> {
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
    let output_overwrite_policy = overwrite_policy_for(&output_path);
    let detached_header_path = match &req.crypto_params.header_location {
        HeaderLocation::Embedded => None,
        HeaderLocation::Detached(path) => Some(PathBuf::from(path)),
    };
    let detached_header_overwrite_policy = detached_header_path
        .as_ref()
        .map_or(OverwritePolicy::CreateNew, |path| {
            overwrite_policy_for(path)
        });

    let output_ok = overwrite_check(req.output_file, req.crypto_params.force)?;

    if !should_continue_after_overwrite_checks(output_ok, || {
        match &req.crypto_params.header_location {
            HeaderLocation::Embedded => Ok(None),
            HeaderLocation::Detached(path) => {
                overwrite_check(path, req.crypto_params.force).map(Some)
            }
        }
    })? {
        return Ok(());
    }

    let input_files = req.input_file.iter().map(PathBuf::from).collect::<Vec<_>>();
    let raw_key = req.crypto_params.key.get_secret(&PasswordState::Validate)?;

    let on_archive_entry = (req.pack_params.print_mode == PrintMode::Verbose).then(|| {
        Box::new(|archive_path: &Path| {
            info!("Packing {}", archive_path.display());
        }) as domain::pack::OnArchiveEntryFn
    });

    // 2. compress and encrypt files
    let intent = PackIntent::new(
        input_files,
        output_path,
        output_overwrite_policy,
        detached_header_path
            .map(|path| DetachedHeaderTarget::new(path, detached_header_overwrite_policy)),
        raw_key,
        req.crypto_params.kdf,
        ArchivePolicy::default(),
        req.pack_params.dir_mode == DirectoryMode::Recursive,
        on_archive_entry,
    )
    .map_err(map_pack_error)?;
    let commit_receipt = domain::pack::execute_transactional(intent).map_err(map_pack_error)?;

    let hash_verification = super::hash_after_commit(
        &[String::from(req.output_file)],
        req.crypto_params.hash_mode,
    )?;

    if req.pack_params.delete_source == DeleteSource::Delete {
        super::cleanup_after_commit(req.input_file, &commit_receipt, hash_verification)?;
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
