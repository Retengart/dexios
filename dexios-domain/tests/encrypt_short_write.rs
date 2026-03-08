use core::header::{HashingAlgorithm, Header, HeaderType, HeaderVersion};
use core::primitives::{Algorithm, Mode};
use core::protected::Protected;
use dexios_domain::encrypt;
use std::cell::RefCell;
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
fn encrypt_must_write_the_full_embedded_header() {
    let input = RefCell::new(Cursor::new(b"Hello world".to_vec()));
    let output = RefCell::new(ShortWriteCursor::default());

    encrypt::execute(encrypt::Request {
        reader: &input,
        writer: &output,
        header_writer: None,
        raw_key: Protected::new(b"12345678".to_vec()),
        header_type: HeaderType {
            version: HeaderVersion::V5,
            algorithm: Algorithm::XChaCha20Poly1305,
            mode: Mode::StreamMode,
        },
        hashing_algorithm: HashingAlgorithm::Blake3Balloon(5),
    })
    .expect("encrypt");

    let header = Header {
        header_type: HeaderType {
            version: HeaderVersion::V5,
            algorithm: Algorithm::XChaCha20Poly1305,
            mode: Mode::StreamMode,
        },
        nonce: vec![0u8; 20],
        salt: None,
        keyslots: Some(vec![]),
    };
    let expected_len = header.get_size() as usize + b"Hello world".len() + 16;

    assert_eq!(output.borrow().len(), expected_len);
}
