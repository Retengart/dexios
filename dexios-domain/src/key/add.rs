//! This provides functionality for checking whether a key can be added to a
//! header that adheres to the Dexios V1 format.

use std::fs::File;
use std::path::Path;

use super::Error;
use core::header::{ParsedHeader, read_header};

pub struct AddIntent {
    _private: (),
}

impl AddIntent {
    pub fn new<P>(target_path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let mut target = File::open(target_path).map_err(|_| Error::ReadIo)?;
        let parsed = read_header(&mut target).map_err(super::map_header_read_error)?;
        let ParsedHeader::V1(payload) = parsed;
        let keyslots = payload.header().keyslots_collection();

        if let Some(tag) = super::unsupported_keyslot_kdf_tag(keyslots) {
            return Err(Error::UnsupportedKdf(tag));
        }

        if keyslots.is_full() {
            return Err(Error::TooManyKeyslots);
        }

        Ok(Self { _private: () })
    }
}

pub fn execute(_intent: AddIntent) -> Result<(), Error> {
    Err(Error::CannotAddV1KeyslotWithoutReencrypt)
}
