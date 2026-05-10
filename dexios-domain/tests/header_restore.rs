use core::header::legacy::{Header, HeaderType, HeaderVersion};
use core::primitives::legacy::{Algorithm, Mode};
use dexios_domain::header::{self, restore};
use std::cell::RefCell;
use std::io::Cursor;

fn legacy_v5_header() -> Header {
    Header {
        header_type: HeaderType {
            version: HeaderVersion::V5,
            algorithm: Algorithm::XChaCha20Poly1305,
            mode: Mode::StreamMode,
        },
        nonce: vec![7u8; 20],
        salt: None,
        keyslots: Some(vec![]),
    }
}

#[test]
fn restores_valid_legacy_v5_header_into_full_zero_target() {
    let header = legacy_v5_header();
    let header_bytes = header.serialize().expect("serialize header");
    let target = RefCell::new(Cursor::new(vec![0u8; header_bytes.len()]));

    restore::execute(restore::Request {
        reader: &RefCell::new(Cursor::new(header_bytes.clone())),
        writer: &target,
    })
    .expect("restore into full zero target");

    assert_eq!(target.borrow().get_ref(), &header_bytes);
}

#[test]
#[ignore = "known bug: Phase 1 baseline; unignore in Phase 5"]
fn quarantined_known_bug_header_restore_rejects_short_target() {
    let header = legacy_v5_header();
    let header_size = usize::try_from(header.get_size()).expect("header size");
    let dumped_header = RefCell::new(Cursor::new(header.serialize().expect("serialize header")));
    let target = RefCell::new(Cursor::new(vec![0u8; header_size - 1]));

    let error = restore::execute(restore::Request {
        reader: &dumped_header,
        writer: &target,
    })
    .expect_err("short restore target should be rejected before writing");

    assert!(matches!(error, header::Error::Read));
    assert_eq!(target.borrow().get_ref().len(), header_size - 1);
}
