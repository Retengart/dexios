//! This provides functionality for dumping a header that adheres to the Dexios format.

use super::Error;
use std::cell::RefCell;
use std::io::{Read, Seek, Write};

use core::header::{ParsedHeader, read_header};

pub struct Request<'a, R, W>
where
    R: Read + Seek,
    W: Write + Seek,
{
    pub reader: &'a RefCell<R>,
    pub writer: &'a RefCell<W>,
}

pub fn execute<R, W>(req: Request<'_, R, W>) -> Result<(), Error>
where
    R: Read + Seek,
    W: Write + Seek,
{
    let (parsed, _) = read_header(&mut *req.reader.borrow_mut()).map_err(Error::from)?;
    let ParsedHeader::V1(header) = parsed;

    header
        .write(&mut *req.writer.borrow_mut())
        .map_err(|_| Error::Write)?;

    Ok(())
}
