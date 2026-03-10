use dexios_core::header::legacy::Header;
use std::io::Cursor;

#[test]
fn legacy_header_deserialize_rejects_unsupported_aes_without_panicking() {
    let mut bytes = [0u8; 128];
    bytes[0..2].copy_from_slice(&[0xDE, 0x04]);
    bytes[2..4].copy_from_slice(&[0x0E, 0x02]);
    bytes[4..6].copy_from_slice(&[0x0C, 0x01]);

    let result = Header::deserialize(&mut Cursor::new(bytes));

    assert!(result.is_err());
}
