//! This provides functionality for verifying that a decryption key is correct for Dexios V1.

use std::io::Seek;

use super::Error;
use core::header::{ParsedHeader, read_header};
use core::protected::Protected;
use std::cell::RefCell;
use std::io::Read;

pub struct Request<'a, R>
where
    R: Read + Seek,
{
    pub handle: &'a RefCell<R>, // header read+write+seek
    pub raw_key: Protected<Vec<u8>>,
}

pub fn execute<R>(req: Request<'_, R>) -> Result<(), Error>
where
    R: Read + Seek,
{
    let (parsed, _) =
        read_header(&mut *req.handle.borrow_mut()).map_err(|_| Error::HeaderDeserialize)?;
    let ParsedHeader::V1(header) = parsed;

    // all of these functions need either the master key, or the index
    let (master_key, _) =
        super::decrypt_v1_master_key_with_index(header.keyslots_collection(), req.raw_key)?;

    // ensure the master key is gone from memory in the event that the key is correct
    drop(master_key);

    Ok(())
}
