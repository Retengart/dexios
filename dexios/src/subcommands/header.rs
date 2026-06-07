use crate::cli::prompt::overwrite_check;
use crate::global::states::ForceMode;
use anyhow::Result;
use core::header::ParsedHeader;
use core::header::v1::KeyslotKdf;
use domain::storage::identity::OverwritePolicy;
use domain::utils::hex_encode;

use super::errors::{map_header_details_error, map_header_error};

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

// Per-keyslot encrypted master keys are sensitive material; they stay hidden behind
// `--raw` so they are not dumped to terminals, scrollback, or logs by default.
const ENCRYPTED_MASTER_KEY_REDACTION: &str = "<hidden — use --raw to show>";

pub(crate) fn details(input: &str, raw: bool) -> Result<()> {
    let intent =
        domain::header::details::DetailsIntent::new(input).map_err(map_header_details_error)?;

    match domain::header::details::execute(intent).map_err(map_header_details_error)? {
        ParsedHeader::V1(payload) => {
            let header = payload.header();
            println!("Header version: V1");
            println!("Cipher suite: XChaCha20-Poly1305 / LE31 stream");
            println!(
                "Payload nonce: {} (hex)",
                hex_encode(header.payload_nonce().as_bytes())
            );
            println!("AAD: {} (hex)", hex_encode(payload.aad().as_bytes()));

            for (i, keyslot) in header.keyslots().iter().enumerate() {
                let kdf = match keyslot.kdf() {
                    KeyslotKdf::Argon2id => "Argon2id",
                    KeyslotKdf::UnsupportedArgon2id => "Argon2id (unsupported historical tag)",
                };
                println!("Keyslot {i}:");
                println!("  KDF: {kdf}");
                println!("  Salt: {} (hex)", hex_encode(keyslot.salt().as_bytes()));
                let encrypted_master_key = if raw {
                    hex_encode(keyslot.encrypted_master_key())
                } else {
                    ENCRYPTED_MASTER_KEY_REDACTION.to_string()
                };
                println!("  Encrypted master key: {encrypted_master_key} (hex)");
                println!(
                    "  Keyslot nonce: {} (hex)",
                    hex_encode(keyslot.nonce().as_bytes())
                );
            }
        }
    }

    Ok(())
}

pub(crate) fn dump(input: &str, output: &str, force: ForceMode) -> Result<()> {
    let output_exists = existing_path(output);
    if !overwrite_check_if_needed(output, output_exists, force)? {
        return Ok(());
    }

    let intent =
        domain::header::dump::DumpIntent::new(input, output, overwrite_policy(output_exists))
            .map_err(map_header_error)?;

    let _receipt = domain::header::dump::execute_transactional(intent).map_err(map_header_error)?;

    Ok(())
}

pub(crate) fn restore(input: &str, output: &str, force: ForceMode) -> Result<()> {
    if !overwrite_check(output, force)? {
        return Ok(());
    }

    let intent =
        domain::header::restore::RestoreIntent::new(input, output).map_err(map_header_error)?;

    let _receipt =
        domain::header::restore::execute_transactional(intent).map_err(map_header_error)?;

    crate::warn!(
        "Restored header was validated for structure only, not against the payload. \
         If this is not the file's original header, decryption will fail authentication."
    );

    Ok(())
}

// The supplied detached header must byte-match the embedded header before the
// embedded header is destroyed.
pub(crate) fn strip(input: &str, header: &str, force: ForceMode) -> Result<()> {
    if !overwrite_check(input, force)? {
        return Ok(());
    }

    let intent =
        domain::header::strip::StripIntent::new(header, input).map_err(map_header_error)?;

    let _receipt =
        domain::header::strip::execute_transactional(intent).map_err(map_header_error)?;

    Ok(())
}
