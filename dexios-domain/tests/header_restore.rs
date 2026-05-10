use core::header::common::{HEADER_LEN, KeyslotNonce, PayloadNonce, Salt};
use core::header::v1::{KeyslotKdf, V1Header, V1Keyslot, V1Keyslots};
use dexios_domain::header::{self, restore};
use std::cell::RefCell;
use std::io::Cursor;

fn v1_header_bytes() -> Vec<u8> {
    let keyslot = V1Keyslot::new(
        KeyslotKdf::Blake3Balloon,
        [1u8; 48],
        KeyslotNonce::new([2u8; 24]),
        Salt::new([3u8; 16]),
    );
    let header = V1Header::new(PayloadNonce::new([4u8; 20]), V1Keyslots::single(keyslot))
        .expect("create V1 header");

    header.serialize().expect("serialize V1 header")
}

#[test]
fn restores_valid_v1_header_into_full_zero_target() {
    let header_bytes = v1_header_bytes();
    let target = RefCell::new(Cursor::new(vec![0u8; HEADER_LEN]));

    restore::execute(restore::Request {
        reader: &RefCell::new(Cursor::new(header_bytes.clone())),
        writer: &target,
    })
    .expect("restore into full zero target");

    assert_eq!(target.borrow().get_ref(), &header_bytes);
}

#[test]
fn header_restore_rejects_short_target_without_writing() {
    let dumped_header = RefCell::new(Cursor::new(v1_header_bytes()));
    let target = RefCell::new(Cursor::new(vec![0u8; HEADER_LEN - 1]));

    let error = restore::execute(restore::Request {
        reader: &dumped_header,
        writer: &target,
    })
    .expect_err("short restore target should be rejected before writing");

    assert!(matches!(error, header::Error::UnsupportedRestore));
    assert_eq!(target.borrow().get_ref(), &vec![0u8; HEADER_LEN - 1]);
}
