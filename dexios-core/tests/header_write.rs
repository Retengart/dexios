use dexios_core::header::common::{HeaderWriteError, KeyslotNonce, PayloadNonce, Salt};
use dexios_core::header::v1::{V1Header, V1Keyslot, V1Keyslots};
use dexios_core::kdf::Kdf;
use std::io::{Cursor, Seek, SeekFrom, Write};

#[derive(Default)]
struct ShortWriteCursor {
    inner: Cursor<Vec<u8>>,
}

impl ShortWriteCursor {
    fn len(&self) -> usize {
        self.inner.get_ref().len()
    }
}

impl Write for ShortWriteCursor {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = buf.len().min(1);
        self.inner.write(&buf[..n])
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl Seek for ShortWriteCursor {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

#[derive(Default)]
struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "forced write failure",
        ))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn v1_header_write_must_write_the_full_serialized_header() {
    let header = V1Header::new(
        PayloadNonce::new([7u8; 20]),
        V1Keyslots::single(V1Keyslot::new(
            Kdf::Blake3Balloon,
            [5u8; 48],
            KeyslotNonce::new([9u8; 24]),
            Salt::new([3u8; 16]),
        )),
    )
    .expect("v1 header");
    let mut sink = ShortWriteCursor::default();

    header.write(&mut sink).expect("v1 header write");

    assert_eq!(sink.len(), header.serialize().unwrap().len());
}

#[test]
fn v1_header_write_preserves_underlying_io_error_details() {
    let header = V1Header::new(
        PayloadNonce::new([7u8; 20]),
        V1Keyslots::single(V1Keyslot::new(
            Kdf::Blake3Balloon,
            [5u8; 48],
            KeyslotNonce::new([9u8; 24]),
            Salt::new([3u8; 16]),
        )),
    )
    .expect("v1 header");
    let mut sink = FailingWriter;

    let error = header
        .write(&mut sink)
        .expect_err("short write should fail");

    assert!(matches!(
        error,
        HeaderWriteError::Io(inner) if inner.kind() == std::io::ErrorKind::WriteZero
    ));
}
