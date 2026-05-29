use std::fs::File;

use crate::cli::prompt::overwrite_check;
use crate::global::states::ForceMode;
use anyhow::{Context, Result};
use core::header::v1::KeyslotKdf;
use core::header::{ParsedHeader, read_header};
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

pub fn details(input: &str) -> Result<()> {
    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open input file: {input}"))?;

    match read_header(&mut input_file) {
        Ok(ParsedHeader::V1(payload)) => {
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
                println!(
                    "  Encrypted master key: {} (hex)",
                    hex_encode(keyslot.encrypted_master_key())
                );
                println!(
                    "  Keyslot nonce: {} (hex)",
                    hex_encode(keyslot.nonce().as_bytes())
                );
            }

            Ok(())
        }
        Err(error) => Err(map_header_details_error(domain::header::Error::from(error))),
    }
}

// this function reads the header fromthe input file and writes it to the output file
// it's used for extracting an encrypted file's header for backups and such
// it implements a check to ensure the header is valid
pub fn dump(input: &str, output: &str, force: ForceMode) -> Result<()> {
    let output_exists = existing_path(output);
    if !overwrite_check_if_needed(output, output_exists, force)? {
        std::process::exit(0);
    }

    let intent =
        domain::header::dump::DumpIntent::new(input, output, overwrite_policy(output_exists))
            .map_err(map_header_error)?;

    let _receipt = domain::header::dump::execute_transactional(intent).map_err(map_header_error)?;

    Ok(())
}

// this function reads the header from the input file
// it then writes the header to the start of the ouput file
// this can be used for restoring a dumped header to a file that had it's header stripped
// this does not work for files encrypted *with* a detached header
// it implements a check to ensure the header is valid before restoring to a file
pub fn restore(input: &str, output: &str, force: ForceMode) -> Result<()> {
    if !overwrite_check(output, force)? {
        return Ok(());
    }

    let intent =
        domain::header::restore::RestoreIntent::new(input, output).map_err(map_header_error)?;

    let _receipt =
        domain::header::restore::execute_transactional(intent).map_err(map_header_error)?;

    Ok(())
}

// this wipes the length of the header from the provided file
// the header must be intact for this to work, as the length varies between the versions
// it can be useful for storing the header separate from the file, to make an attacker's life that little bit harder
// it implements a check to ensure the header is valid before stripping
pub fn strip(input: &str, force: ForceMode) -> Result<()> {
    if !overwrite_check(input, force)? {
        return Ok(());
    }

    let intent = domain::header::strip::StripIntent::new(input).map_err(map_header_error)?;

    let _receipt =
        domain::header::strip::execute_transactional(intent).map_err(map_header_error)?;

    Ok(())
}
