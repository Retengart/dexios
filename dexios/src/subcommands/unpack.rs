use crate::{cli::prompt::get_answer, global::states::DeleteInput};

use anyhow::Result;

use super::errors::map_unpack_error;
use crate::global::{
    states::{ForceMode, HeaderLocation, PasswordState, PrintMode},
    structs::CryptoParams,
};
use crate::{info, warn};
use std::path::Path;

fn should_unpack_entry<F>(file_path: &Path, force: ForceMode, verbose: bool, ask: F) -> Result<bool>
where
    F: FnOnce(&str, bool, ForceMode) -> Result<bool>,
{
    let file_name = file_path
        .file_name()
        .unwrap_or(file_path.as_os_str())
        .to_string_lossy()
        .into_owned();

    if std::fs::metadata(file_path).is_ok() {
        let answer = ask(
            &format!("{file_name} already exists, would you like to overwrite?"),
            true,
            force,
        )?;
        if !answer {
            warn!("Skipping {}", file_name);
            return Ok(false);
        }
    }

    if verbose {
        info!("Extracting {}", file_name);
    }

    Ok(true)
}

fn reject_stdin_keyfile_prompt_conflict(params: &CryptoParams) -> Result<()> {
    if params.force == ForceMode::Prompt && params.key.reads_stdin() {
        return Err(anyhow::anyhow!(
            "--keyfile - cannot be combined with interactive overwrite prompts; pass --force to avoid reading confirmation from stdin"
        ));
    }
    Ok(())
}

// Unpacking is delegated to the domain layer, which validates the manifest,
// stages selected file bodies, and commits only after final authentication.
#[allow(clippy::module_name_repetitions)]
#[allow(clippy::needless_pass_by_value)]
pub fn unpack(
    input: &str,  // encrypted archive file
    output: &str, // directory
    print_mode: PrintMode,
    params: CryptoParams, // params for decrypt function
) -> Result<()> {
    let header_path = match &params.header_location {
        HeaderLocation::Embedded => None,
        HeaderLocation::Detached(path) => Some(Path::new(path)),
    };

    reject_stdin_keyfile_prompt_conflict(&params)?;
    let raw_key = params.key.get_secret(&PasswordState::Direct)?;
    let verbose = print_mode == PrintMode::Verbose;

    let intent = domain::unpack::UnpackIntent::new(
        input,
        header_path,
        output,
        raw_key,
        None,
        None,
        Some(Box::new(move |file_path| {
            should_unpack_entry(&file_path, params.force, verbose, get_answer)
                .map_err(|_| String::from("prompt failed"))
        })),
    )
    .map_err(map_unpack_error)?;
    let extraction_result =
        domain::unpack::execute_with_cleanup(intent).map_err(map_unpack_error)?;

    let hash_verification = super::hash_after_commit(&[String::from(input)], params.hash_mode)?;

    if params.delete_input == DeleteInput::Delete {
        super::cleanup_after_commit(
            extraction_result.cleanup_receipt(),
            extraction_result.commit_receipt(),
            hash_verification,
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn prompt_errors_are_returned_not_panicked() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("dexios-unpack-{unique}.txt"));
        std::fs::write(&path, b"existing").unwrap();

        let result = should_unpack_entry(
            &path,
            crate::global::states::ForceMode::Prompt,
            false,
            |_p, _d, _f| Err(anyhow::anyhow!("tty failure")),
        );

        std::fs::remove_file(path).ok();

        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn non_utf_paths_do_not_panic() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let path = PathBuf::from(OsString::from_vec(vec![0x66, 0x6f, 0x80, 0x6f]));
        let result = should_unpack_entry(
            &path,
            crate::global::states::ForceMode::Prompt,
            false,
            |_p, _d, _f| Ok(true),
        );

        assert!(result.is_ok());
    }
}
