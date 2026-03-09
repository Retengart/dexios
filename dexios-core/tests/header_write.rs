use dexios_core::header::common::{KeyslotNonce, PayloadNonce, Salt};
use dexios_core::header::v1::{KeyslotKdf, V1Header, V1Keyslot};
use dexios_core::header::{Header, HeaderType, HeaderVersion};
use dexios_core::primitives::{Algorithm, Mode};
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

#[test]
fn header_write_must_write_the_full_serialized_header() {
    let header = Header {
        header_type: HeaderType {
            version: HeaderVersion::V5,
            algorithm: Algorithm::XChaCha20Poly1305,
            mode: Mode::StreamMode,
        },
        nonce: vec![7u8; 20],
        salt: None,
        keyslots: Some(vec![]),
    };
    let mut sink = ShortWriteCursor::default();

    header.write(&mut sink).expect("header write");

    assert_eq!(sink.len(), header.serialize().unwrap().len());
}

#[test]
fn v1_header_write_must_write_the_full_serialized_header() {
    let header = V1Header::new(
        PayloadNonce::new([7u8; 20]),
        vec![V1Keyslot::new(
            KeyslotKdf::Blake3Balloon,
            [5u8; 48],
            KeyslotNonce::new([9u8; 24]),
            Salt::new([3u8; 16]),
        )],
    )
    .expect("v1 header");
    let mut sink = ShortWriteCursor::default();

    header.write(&mut sink).expect("v1 header write");

    assert_eq!(sink.len(), header.serialize().unwrap().len());
}
