use std::{
    cell::RefCell,
    fs::{File, OpenOptions},
    io::Seek,
};

use crate::cli::prompt::overwrite_check;
use crate::global::states::ForceMode;
use anyhow::{Context, Result};
use core::header::common::HeaderReadError;
use core::header::legacy::Header as LegacyHeader;
use core::header::legacy::HeaderVersion as LegacyHeaderVersion;
use core::header::v1::KeyslotKdf;
use core::header::{ParsedHeader, read_header};
use domain::storage::Storage;
use domain::utils::hex_encode;

pub fn details(input: &str) -> Result<()> {
    let mut input_file =
        File::open(input).with_context(|| format!("Unable to open input file: {input}"))?;

    match read_header(&mut input_file) {
        Ok((parsed, aad)) => {
            let ParsedHeader::V1(header) = parsed;
            println!("Header version: V1");
            println!("Cipher suite: XChaCha20-Poly1305 / LE31 stream");
            println!(
                "Payload nonce: {} (hex)",
                hex_encode(header.payload_nonce().as_bytes())
            );
            println!("AAD: {} (hex)", hex_encode(aad.as_bytes()));

            for (i, keyslot) in header.keyslots().iter().enumerate() {
                let kdf = match keyslot.kdf() {
                    KeyslotKdf::Blake3Balloon => "BLAKE3-Balloon",
                    KeyslotKdf::Argon2id => "Argon2id",
                };
                println!("Keyslot {i}:");
                println!("  KDF: {kdf}");
                println!("  Salt: {} (hex)", hex_encode(keyslot.salt().as_bytes()));
                println!(
                    "  Master Key: {} (hex, encrypted)",
                    hex_encode(keyslot.encrypted_master_key())
                );
                println!(
                    "  Master Key Nonce: {} (hex)",
                    hex_encode(keyslot.nonce().as_bytes())
                );
            }

            return Ok(());
        }
        Err(HeaderReadError::InvalidMagic(_)) | Err(HeaderReadError::UnsupportedVersion(_)) => {}
        Err(err) => return Err(anyhow::anyhow!(err.to_string())),
    }

    input_file.rewind().with_context(|| {
        format!("Unable to rewind input file while reading legacy header: {input}")
    })?;
    let (header, aad) = LegacyHeader::deserialize(&mut input_file)
        .map_err(|_| anyhow::anyhow!("This does not seem like a valid Dexios header"))?;

    println!("Header version: {} (legacy)", header.header_type.version);
    println!("Cipher suite: legacy / compatibility");
    println!("Payload nonce: {} (hex)", hex_encode(&header.nonce));
    println!("AAD: {} (hex)", hex_encode(&aad));

    match header.header_type.version {
        LegacyHeaderVersion::V1 | LegacyHeaderVersion::V2 | LegacyHeaderVersion::V3 => {
            println!("Salt: {} (hex)", hex_encode(&header.salt.unwrap()));
        }
        LegacyHeaderVersion::V4 | LegacyHeaderVersion::V5 => {
            for (i, keyslot) in header.keyslots.unwrap().iter().enumerate() {
                println!("Keyslot {i}:");
                println!("  KDF: {}", keyslot.hash_algorithm);
                println!("  Salt: {} (hex)", hex_encode(&keyslot.salt));
                println!(
                    "  Master Key: {} (hex, encrypted)",
                    hex_encode(&keyslot.encrypted_key)
                );
                println!("  Master Key Nonce: {} (hex)", hex_encode(&keyslot.nonce));
            }
        }
    }

    Ok(())
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
