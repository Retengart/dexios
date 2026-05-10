//! This provides functionality for restoring a dumped header that adheres to the Dexios format, provided the target file contains enough empty bytes at the start to do so.

use super::Error;
use std::cell::RefCell;
use std::io::{ErrorKind, Read, Seek, Write};

use core::header::common::HEADER_LEN;
use core::header::{ParsedHeader, read_header};

pub struct Request<'a, R, RW>
where
    R: Read + Seek,
    RW: Read + Write + Seek,
{
    pub reader: &'a RefCell<R>,
    pub writer: &'a RefCell<RW>,
}

pub fn execute<R, RW>(req: Request<'_, R, RW>) -> Result<(), Error>
where
    R: Read + Seek,
    RW: Read + Write + Seek,
{
    let parsed = read_header(&mut *req.reader.borrow_mut()).map_err(Error::from)?;
    let ParsedHeader::V1(payload) = parsed;

    let mut header_bytes = [0u8; HEADER_LEN];
    req.writer
        .borrow_mut()
        .read_exact(&mut header_bytes)
        .map_err(|err| {
            if err.kind() == ErrorKind::UnexpectedEof {
                Error::UnsupportedRestore
            } else {
                Error::Read
            }
        })?;

    if !header_bytes.into_iter().all(|b| b == 0) {
        return Err(Error::UnsupportedRestore);
    }

    req.writer
        .borrow_mut()
        .rewind()
        .map_err(|_| Error::Rewind)?;

    payload
        .header()
        .write(&mut *req.writer.borrow_mut())
        .map_err(|_| Error::Write)?;

    Ok(())
}
