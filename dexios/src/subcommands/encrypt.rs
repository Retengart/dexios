use crate::cli::prompt::overwrite_check;
use crate::global::states::{EraseMode, HashMode, HeaderLocation, PasswordState};
use crate::global::structs::CryptoParams;
use anyhow::Result;
use core::header::{HEADER_VERSION, HeaderType};
use core::primitives::{Algorithm, Mode};
use std::sync::Arc;

use domain::storage::Storage;

fn should_continue_after_overwrite_checks(output_ok: bool, header_ok: Option<bool>) -> bool {
    output_ok && header_ok.unwrap_or(true)
}

// this function is for encrypting a file in stream mode
// it handles any user-facing interactiveness, opening files
// it creates the stream object and uses the convenience function provided by dexios-core
pub fn stream_mode(
    input: &str,
    output: &str,
    params: &CryptoParams,
    algorithm: Algorithm,
) -> Result<()> {
    // TODO: It is necessary to raise it to a higher level
    let stor = Arc::new(domain::storage::FileStorage);

    // 1. validate and prepare options
    if input == output {
        return Err(anyhow::anyhow!(
            "Input and output files cannot have the same name."
        ));
    }

    let output_ok = overwrite_check(output, params.force)?;
    let header_ok = match &params.header_location {
        HeaderLocation::Embedded => None,
        HeaderLocation::Detached(path) => Some(overwrite_check(path, params.force)?),
    };

    if !should_continue_after_overwrite_checks(output_ok, header_ok) {
        return Ok(());
    }

    let input_file = stor.read_file(input)?;
    let raw_key = params.key.get_secret(&PasswordState::Validate)?;
    let output_file = stor
        .create_file(output)
        .or_else(|_| stor.write_file(output))?;

    let header_file = match &params.header_location {
        HeaderLocation::Embedded => None,
        HeaderLocation::Detached(path) => Some(stor.create_file(path).or_else(|_| stor.write_file(path))?),
    };

    // 2. encrypt file
    let req = domain::encrypt::Request {
        reader: input_file.try_reader()?,
        writer: output_file.try_writer()?,
        header_writer: header_file.as_ref().and_then(|f| f.try_writer().ok()),
        raw_key,
        header_type: HeaderType {
            version: HEADER_VERSION,
            mode: Mode::StreamMode,
            algorithm,
        },
        hashing_algorithm: params.hashing_algorithm,
    };
    domain::encrypt::execute(req)?;

    // 3. flush result
    if let Some(header_file) = header_file {
        stor.flush_file(&header_file)?;
    }
    stor.flush_file(&output_file)?;

    if params.hash_mode == HashMode::CalculateHash {
        super::hashing::hash_stream(&[output.to_string()])?;
    }

    if let EraseMode::EraseFile(passes) = params.erase {
        super::erase::secure_erase(input, passes, params.force)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn detached_header_decline_returns_false_before_work_starts() {
        assert!(!super::should_continue_after_overwrite_checks(
            true,
            Some(false)
        ));
    }

    #[test]
    fn approve_all_overwrite_checks_returns_true() {
        assert!(super::should_continue_after_overwrite_checks(true, Some(true)));
        assert!(super::should_continue_after_overwrite_checks(true, None));
    }
}
