//! This provides functionality for stripping a header that adheres to the Dexios format.

use super::Error;
use std::cell::RefCell;
use std::io::{Read, Seek, Write};

use core::header::common::HEADER_LEN;
use core::header::{ParsedHeader, read_header};

pub struct Request<'a, RW>
where
    RW: Read + Write + Seek,
{
    pub handle: &'a RefCell<RW>,
}

pub fn execute<RW>(req: Request<'_, RW>) -> Result<(), Error>
where
    RW: Read + Write + Seek,
{
    let (parsed, _) = read_header(&mut *req.handle.borrow_mut()).map_err(Error::from)?;
    match parsed {
        ParsedHeader::V1(_) => {}
    }

    req.handle
        .borrow_mut()
        .rewind()
        .map_err(|_| Error::Rewind)?;

    req.handle
        .borrow_mut()
        .write_all(&[0u8; HEADER_LEN])
        .map_err(|_| Error::Write)?;

    Ok(())
}
