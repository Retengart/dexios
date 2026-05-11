use std::path::Path;
use std::process::exit;
use std::sync::Arc;

use crate::cli::prompt::overwrite_check;
use crate::global::states::{DeleteInput, ForceMode, HashMode, HeaderLocation, PasswordState};
use crate::global::structs::CryptoParams;

use anyhow::Result;

use domain::storage::Storage;
use domain::storage::identity::OverwritePolicy;

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

fn output_target<'a>(path: &'a str, path_exists: bool) -> domain::decrypt::OutputTarget<'a> {
    domain::decrypt::OutputTarget {
        path: Path::new(path),
        overwrite: overwrite_policy(path_exists),
    }
}

fn overwrite_check_if_needed(path: &str, path_exists: bool, force: ForceMode) -> Result<bool> {
    if path_exists {
        overwrite_check(path, force)
    } else {
        Ok(true)
    }
}

// this function is for decrypting a file in stream mode
// it handles any user-facing interactiveness, opening files, or redirecting to memory mode if
// the header says so (backwards-compat)
// it also manages using a detached header file if selected
// it creates the stream object and uses the convenience function provided by dexios-core
pub fn stream_mode(input: &str, output: &str, params: &CryptoParams) -> Result<()> {
    // TODO: It is necessary to raise it to a higher level
    let stor = Arc::new(domain::storage::FileStorage);

    // 1. validate and prepare options
    if input == output {
        return Err(anyhow::anyhow!(
            "Input and output files cannot have the same name."
        ));
    }

    let output_exists = existing_path(output);
    if !overwrite_check_if_needed(output, output_exists, params.force)? {
        exit(0);
    }

    let input_file = stor.read_file(input)?;
    let header_file = match &params.header_location {
        HeaderLocation::Embedded => None,
        HeaderLocation::Detached(path) => Some(stor.read_file(path)?),
    };

    let raw_key = params.key.get_secret(&PasswordState::Direct)?;

    // 2. decrypt file
    let detached_header_path = match &params.header_location {
        HeaderLocation::Embedded => None,
        HeaderLocation::Detached(path) => Some(Path::new(path.as_str())),
    };
    let _receipt = domain::decrypt::execute_transactional(domain::decrypt::TransactionalRequest {
        input_path: Path::new(input),
        detached_header_path,
        header_reader: header_file.as_ref().and_then(|h| h.try_reader().ok()),
        reader: input_file.try_reader()?,
        output: output_target(output, output_exists),
        raw_key,
        on_decrypted_header: None,
    })?;

    if params.hash_mode == HashMode::CalculateHash {
        super::hashing::hash_stream(&[input.to_string()])?;
    }

    if params.delete_input == DeleteInput::Delete {
        drop(header_file);
        drop(input_file);
        super::delete_path(input)?;
    }

    Ok(())
}
