//! This provides functionality for verifying that a decryption key is correct
//! for Dexios V1.

use std::fs::File;
use std::path::Path;

use super::Error;
use core::header::v1::V1Keyslots;
use core::header::{ParsedHeader, read_header};
use core::protected::Protected;

pub struct VerifyIntent {
    keyslots: V1Keyslots,
}

impl VerifyIntent {
    pub fn new<P>(target_path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let mut target = File::open(target_path).map_err(|_| Error::ReadIo)?;
        let parsed = read_header(&mut target).map_err(super::map_header_read_error)?;
        let ParsedHeader::V1(payload) = parsed;
        let keyslots = payload.header().keyslots_collection().clone();

        if let Some(tag) = super::all_keyslots_have_unsupported_kdf(&keyslots) {
            return Err(Error::UnsupportedKdf(tag));
        }

        Ok(Self { keyslots })
    }
}

pub fn execute(intent: VerifyIntent, raw_key: Protected<Vec<u8>>) -> Result<(), Error> {
    let (master_key, _) = super::decrypt_v1_master_key_with_index(&intent.keyslots, raw_key)?;

    // Ensure the master key is gone from memory in the event that the key is correct.
    drop(master_key);

    Ok(())
}
