use std::{
    cell::RefCell,
    fs::{File, OpenOptions},
};

use crate::cli::prompt::overwrite_check;
use crate::global::states::ForceMode;
use anyhow::{Context, Result};
use core::header::common::HeaderReadError;
use core::header::v1::KeyslotKdf;
use core::header::{ParsedHeader, read_header};
use domain::storage::Storage;
use domain::utils::hex_encode;

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
                    KeyslotKdf::Blake3Balloon => "BLAKE3-Balloon",
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
        Err(HeaderReadError::UnsupportedFormat(_))
        | Err(HeaderReadError::UnsupportedVersion(_)) => {
            Err(anyhow::anyhow!("Unsupported Dexios format"))
        }
        Err(HeaderReadError::InvalidMagic(magic)) => {
            Err(anyhow::anyhow!("Invalid Dexios header magic: {magic:02X?}"))
        }
        Err(
            err @ (HeaderReadError::TruncatedHeader
            | HeaderReadError::InvalidKeyslotCount(_)
            | HeaderReadError::InvalidKeyslotTag(_)
            | HeaderReadError::InvalidPayloadNonceLength(_)
            | HeaderReadError::InvalidKeyslotNonceLength(_)
            | HeaderReadError::InvalidSaltLength(_)
            | HeaderReadError::InvalidEncryptedMasterKeyLength(_)
            | HeaderReadError::NonZeroReservedBytes
            | HeaderReadError::NonZeroActiveKeyslotPadding(_)
            | HeaderReadError::NonZeroInactiveKeyslotPadding(_)),
        ) => Err(anyhow::anyhow!("Malformed Dexios V1 header: {err}")),
        Err(err @ HeaderReadError::Io(_)) => Err(anyhow::anyhow!("{err}")),
    }
}

// this function reads the header fromthe input file and writes it to the output file
// it's used for extracting an encrypted file's header for backups and such
// it implements a check to ensure the header is valid
pub fn dump(input: &str, output: &str, force: ForceMode) -> Result<()> {
    let stor = std::sync::Arc::new(domain::storage::FileStorage);
    let input_file = stor.read_file(input)?;

    if !overwrite_check(output, force)? {
        std::process::exit(0);
    }

    let output_file = stor
        .create_file(output)
        .or_else(|_| stor.write_file(output))?;

    let req = domain::header::dump::Request {
        reader: input_file.try_reader()?,
        writer: output_file.try_writer()?,
    };

    domain::header::dump::execute(req)?;

    stor.flush_file(&output_file)?;

    Ok(())
}

// this function reads the header from the input file
// it then writes the header to the start of the ouput file
// this can be used for restoring a dumped header to a file that had it's header stripped
// this does not work for files encrypted *with* a detached header
// it implements a check to ensure the header is valid before restoring to a file
pub fn restore(input: &str, output: &str) -> Result<()> {
    let stor = std::sync::Arc::new(domain::storage::FileStorage);

    let input_file = stor.read_file(input)?;

    let output_file = RefCell::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(output)
            .with_context(|| format!("Unable to open output file: {output}"))?,
    );

    let req = domain::header::restore::Request {
        reader: input_file.try_reader()?,
        writer: &output_file,
    };

    domain::header::restore::execute(req)?;

    Ok(())
}

// this wipes the length of the header from the provided file
// the header must be intact for this to work, as the length varies between the versions
// it can be useful for storing the header separate from the file, to make an attacker's life that little bit harder
// it implements a check to ensure the header is valid before stripping
pub fn strip(input: &str) -> Result<()> {
    let input_file = RefCell::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(input)
            .with_context(|| format!("Unable to open input file: {input}"))?,
    );

    let req = domain::header::strip::Request {
        handle: &input_file,
    };

    domain::header::strip::execute(req)?;

    Ok(())
}
