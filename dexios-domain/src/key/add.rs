//! This provides functionality for adding a key to a header that adheres to the
//! Dexios V1 format.

use std::io::Seek;

use super::Error;
use core::header::{ParsedHeader, read_header};
use core::protected::Protected;
use std::cell::RefCell;
use std::io::{Read, Write};

pub struct Request<'a, RW>
where
    RW: Read + Write + Seek,
{
    pub handle: &'a RefCell<RW>, // header read+write+seek
    pub raw_key_old: Protected<Vec<u8>>,
}

pub fn execute<RW>(req: Request<'_, RW>) -> Result<(), Error>
where
    RW: Read + Write + Seek,
{
    let parsed =
        read_header(&mut *req.handle.borrow_mut()).map_err(|_| Error::HeaderDeserialize)?;
    let ParsedHeader::V1(payload) = parsed;
    let keyslots = payload.header().keyslots_collection().clone();

    // all of these functions need either the master key, or the index
    let (_, _) = super::decrypt_v1_master_key_with_index(&keyslots, req.raw_key_old)?;

    if keyslots.is_full() {
        return Err(Error::TooManyKeyslots);
    }

    Err(Error::CannotAddV1KeyslotWithoutReencrypt)
}
