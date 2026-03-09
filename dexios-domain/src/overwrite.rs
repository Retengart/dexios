//! This contains the actual logic for "shredding" a file.
//!
//! This will not be effective on flash storage, and if you are planning to release a program that uses this function, I'd recommend putting the default number of passes to 1.

use rand::Rng;
use std::cell::RefCell;
use std::fmt;
use std::io::{Seek, Write};

const BLOCK_SIZE: usize = 512;

#[derive(Debug)]
pub enum Error {
    ResetCursorPosition,
    OverwriteWithRandomBytes,
    OverwriteWithZeros,
    FlushFile,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ResetCursorPosition => f.write_str("Unable to reset cursor position"),
            Error::OverwriteWithRandomBytes => f.write_str("Unable to overwrite with random bytes"),
            Error::OverwriteWithZeros => f.write_str("Unable to overwrite with zeros"),
            Error::FlushFile => f.write_str("Unable to flush"),
        }
    }
}

impl std::error::Error for Error {}

pub struct Request<'a, W: Write + Seek> {
    pub writer: &'a RefCell<W>,
    pub buf_capacity: usize,
    pub passes: i32,
}

fn write_random_pass<W: Write, R: Rng>(
    writer: &mut W,
    len: usize,
    rng: &mut R,
) -> Result<(), Error> {
    let mut remaining = len;

    while remaining > 0 {
        let block_size = remaining.min(BLOCK_SIZE);
        let mut block_buf = vec![0u8; block_size];
        rng.fill_bytes(&mut block_buf);
        writer
            .write_all(&block_buf)
            .map_err(|_| Error::OverwriteWithRandomBytes)?;
        remaining -= block_size;
    }

    Ok(())
}

fn write_zero_pass<W: Write>(writer: &mut W, len: usize) -> Result<(), Error> {
    let zero_block = [0u8; BLOCK_SIZE];
    let mut remaining = len;

    while remaining > 0 {
        let block_size = remaining.min(BLOCK_SIZE);
        writer
            .write_all(&zero_block[..block_size])
            .map_err(|_| Error::OverwriteWithZeros)?;
        remaining -= block_size;
    }

    Ok(())
}

pub fn execute<W: Write + Seek>(req: Request<'_, W>) -> Result<(), Error> {
    let mut writer = req.writer.borrow_mut();
    for _ in 0..req.passes {
        writer.rewind().map_err(|_| Error::ResetCursorPosition)?;
        let mut rng = rand::rng();
        write_random_pass(&mut *writer, req.buf_capacity, &mut rng)?;

        writer.flush().map_err(|_| Error::FlushFile)?;
    }

    writer.rewind().map_err(|_| Error::ResetCursorPosition)?;
    write_zero_pass(&mut *writer, req.buf_capacity)?;
    writer.flush().map_err(|_| Error::FlushFile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};
    use std::io::Cursor;

    struct ChunkLimitedWriter {
        cursor: Cursor<Vec<u8>>,
    }

    impl Write for ChunkLimitedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            assert!(buf.len() <= BLOCK_SIZE, "write larger than BLOCK_SIZE");
            self.cursor.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.cursor.flush()
        }
    }

    impl Seek for ChunkLimitedWriter {
        fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
            self.cursor.seek(pos)
        }
    }

    fn make_test(capacity: usize, passes: i32) {
        let mut buf = vec![0u8; capacity];
        rand::rng().fill_bytes(&mut buf);

        let writer = Cursor::new(&mut buf);

        let req = Request {
            writer: &RefCell::new(writer),
            buf_capacity: capacity,
            passes,
        };

        match execute(req) {
            Ok(()) => {
                assert_eq!(buf.len(), capacity);
                assert_eq!(buf, [0].repeat(capacity));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn should_overwrite_empty_content() {
        make_test(0, 1);
    }

    #[test]
    fn should_overwrite_small_content() {
        make_test(100, 1);
    }

    #[test]
    fn should_overwrite_perfectly_divisible_content() {
        make_test(BLOCK_SIZE, 1);
    }

    #[test]
    fn should_overwrite_not_perfectly_divisible_content() {
        make_test(515, 1);
    }

    #[test]
    fn should_overwrite_large_content() {
        make_test(BLOCK_SIZE * 100, 1);
    }

    #[test]
    fn should_erase_fill_random_bytes_one_hundred_times() {
        make_test(515, 100);
    }

    #[test]
    fn should_erase_fill_random_bytes_zero_times() {
        make_test(515, 0);
    }

    #[test]
    fn write_random_pass_writes_non_zero_bytes() {
        let mut cursor = Cursor::new(vec![0u8; 32]);
        let mut rng = StdRng::seed_from_u64(1);

        write_random_pass(&mut cursor, 32, &mut rng).unwrap();

        assert_ne!(cursor.into_inner(), vec![0u8; 32]);
    }

    #[test]
    fn zero_pass_streams_in_fixed_blocks() {
        let writer = RefCell::new(ChunkLimitedWriter {
            cursor: Cursor::new(vec![0xAA; BLOCK_SIZE * 4 + 3]),
        });

        execute(Request {
            writer: &writer,
            buf_capacity: BLOCK_SIZE * 4 + 3,
            passes: 0,
        })
        .unwrap();
    }
}
