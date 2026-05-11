use crate::cli::prompt::overwrite_check;
use crate::global::states::{DeleteInput, ForceMode, HashMode, HeaderLocation, PasswordState};
use crate::global::structs::CryptoParams;
use anyhow::Result;
use std::path::Path;
use std::sync::Arc;

use domain::storage::identity::OverwritePolicy;
use domain::storage::Storage;

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

fn output_target<'a>(path: &'a str, path_exists: bool) -> domain::encrypt::OutputTarget<'a> {
    domain::encrypt::OutputTarget {
        path: Path::new(path),
        overwrite: overwrite_policy(path_exists),
    }
}

fn header_target<'a>(path: &'a str, path_exists: bool) -> domain::encrypt::HeaderTarget<'a> {
    domain::encrypt::HeaderTarget {
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

// this function is for encrypting a file in stream mode
// it handles any user-facing interactiveness, opening files
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
    let header_exists = match &params.header_location {
        HeaderLocation::Embedded => None,
        HeaderLocation::Detached(path) => Some(existing_path(path)),
    };

    let output_ok = overwrite_check_if_needed(output, output_exists, params.force)?;

    if !should_continue_after_overwrite_checks(output_ok, || match &params.header_location {
        HeaderLocation::Embedded => Ok(None),
        HeaderLocation::Detached(path) => {
            overwrite_check_if_needed(path, header_exists.unwrap_or(false), params.force).map(Some)
        }
    })? {
        return Ok(());
    }

    let input_file = stor.read_file(input)?;
    let raw_key = params.key.get_secret(&PasswordState::Validate)?;

    let header = match &params.header_location {
        HeaderLocation::Embedded => None,
        HeaderLocation::Detached(path) => Some(header_target(path, header_exists.unwrap_or(false))),
    };

    // 2. encrypt file
    let req = domain::encrypt::TransactionalRequest {
        input_path: Path::new(input),
        reader: input_file.try_reader()?,
        output: output_target(output, output_exists),
        header,
        raw_key,
        kdf: params.kdf,
    };
    let _receipt = domain::encrypt::execute_transactional(req)?;

    if params.hash_mode == HashMode::CalculateHash {
        super::hashing::hash_stream(&[output.to_string()])?;
    }

    if params.delete_input == DeleteInput::Delete {
        drop(input_file);
        super::delete_path(input)?;
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
