use crate::{cli::prompt::get_answer, global::states::HashMode};
use std::sync::Arc;

use anyhow::Result;

use domain::storage::Storage;

use crate::global::{
    states::{ForceMode, HeaderLocation, PasswordState, PrintMode},
    structs::CryptoParams,
};
use crate::{info, warn};
use std::path::{Path, PathBuf};

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

// this first decrypts the input file to a temporary zip file
// it then unpacks that temporary zip file to the target directory
// once finished, it erases the temporary file to avoid any residual data
#[allow(clippy::module_name_repetitions)]
#[allow(clippy::needless_pass_by_value)]
pub fn unpack(
    input: &str,  // encrypted zip file
    output: &str, // directory
    print_mode: PrintMode,
    params: CryptoParams, // params for decrypt function
) -> Result<()> {
    // TODO: It is necessary to raise it to a higher level
    let stor = Arc::new(domain::storage::FileStorage);

    let input_file = stor.read_file(input)?;
    let header_file = match &params.header_location {
        HeaderLocation::Embedded => None,
        HeaderLocation::Detached(path) => Some(stor.read_file(path)?),
    };

    let raw_key = params.key.get_secret(&PasswordState::Direct)?;
    let verbose = print_mode == PrintMode::Verbose;

    domain::unpack::execute(
        stor,
        domain::unpack::Request {
            header_reader: header_file.as_ref().and_then(|h| h.try_reader().ok()),
            reader: input_file.try_reader()?,
            output_dir_path: PathBuf::from(output),
            raw_key,
            on_decrypted_header: None,
            on_archive_info: None,
            on_zip_file: Some(Box::new(move |file_path| {
                should_unpack_entry(&file_path, params.force, verbose, get_answer)
                    .map_err(|err| err.to_string())
            })),
        },
    )?;

    if params.hash_mode == HashMode::CalculateHash {
        super::hashing::hash_stream(&[input.to_string()])?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
