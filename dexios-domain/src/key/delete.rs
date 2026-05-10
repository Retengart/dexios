//! This provides functionality for deleting a key from a Dexios V1 header.

use super::Error;
use core::header::common::HEADER_LEN;
use core::header::{ParsedHeader, read_header};
use core::protected::Protected;
use std::cell::RefCell;
use std::io::Seek;
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
    let (parsed, _) =
        read_header(&mut *req.handle.borrow_mut()).map_err(|_| Error::HeaderDeserialize)?;
    let ParsedHeader::V1(header) = parsed;

    req.handle
        .borrow_mut()
        .seek(std::io::SeekFrom::Current(
            -i64::try_from(HEADER_LEN).map_err(|_| Error::HeaderSizeParse)?,
        ))
        .map_err(|_| Error::Seek)?;

    let mut keyslots = header.keyslots_collection().clone();

    // all of these functions need either the master key, or the index
    let (_, index) = super::decrypt_v1_master_key_with_index(&keyslots, req.raw_key_old)?;

    if keyslots.len() == 1 {
        return Err(Error::CannotRemoveFinalV1Keyslot);
    }

    keyslots.remove(index).map_err(|_| Error::HeaderWrite)?;

    let header_new = core::header::v1::V1Header::new(*header.payload_nonce(), keyslots)
        .map_err(|_| Error::HeaderWrite)?;

    // write the header to the handle
    header_new
        .write(&mut *req.handle.borrow_mut())
        .map_err(|_| Error::HeaderWrite)?;

    Ok(())
}
