use dexios_core::header::common::{KeyslotNonce, PayloadNonce, Salt};
use dexios_core::header::v1::{KeyslotKdf, V1Header, V1Keyslot};

mod support {
    use super::*;

    pub fn sample_v1_header() -> V1Header {
        V1Header::new(
            PayloadNonce::new([7u8; 20]),
            vec![V1Keyslot::new(
                KeyslotKdf::Blake3Balloon,
                [11u8; 48],
                KeyslotNonce::new([13u8; 24]),
                Salt::new([17u8; 16]),
            )],
        )
        .expect("sample v1 header")
    }
}

#[test]
fn serializes_v1_header_to_416_bytes() {
    let header = support::sample_v1_header();
    let bytes = header.serialize().unwrap();

    assert_eq!(bytes.len(), 416);
}

#[test]
fn deserialize_roundtrip_preserves_payload_nonce_and_keyslots() {
    let header = support::sample_v1_header();
    let bytes = header.serialize().unwrap();
    let (parsed, aad) = dexios_core::header::read_header(&mut std::io::Cursor::new(bytes)).unwrap();

    let dexios_core::header::ParsedHeader::V1(parsed) = parsed;
    assert_eq!(
        parsed.payload_nonce().as_bytes(),
        header.payload_nonce().as_bytes()
    );
    assert_eq!(parsed.keyslots().len(), 1);
    assert_eq!(aad.as_bytes().len(), 32);
}

#[test]
fn serializes_sample_v1_header_to_exact_bytes() {
    let header = support::sample_v1_header();
    let bytes = header.serialize().unwrap();

    let mut expected = vec![
        0x44, 0x58, 0x49, 0x4F, 0x00, 0x01, 0x01, 0x00, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 0, 0, 0, 0, 0xDF, 0x01,
    ];
    expected.extend_from_slice(&[11u8; 48]);
    expected.extend_from_slice(&[13u8; 24]);
    expected.extend_from_slice(&[17u8; 16]);
    expected.extend_from_slice(&[0u8; 6]);
    expected.extend_from_slice(&[0u8; 288]);

    assert_eq!(bytes, expected);
}

#[test]
fn creates_exact_aad_bytes_for_sample_v1_header() {
    let header = support::sample_v1_header();

    assert_eq!(
        header.create_aad().as_bytes(),
        &[
            0x44, 0x58, 0x49, 0x4F, 0x00, 0x01, 0x01, 0x00, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
            7, 7, 7, 7, 7, 7, 7, 0, 0, 0, 0,
        ]
    );
}

#[test]
fn read_header_rejects_invalid_magic_before_dispatching() {
    let mut bytes = support::sample_v1_header().serialize().unwrap();
    bytes[..4].copy_from_slice(b"BAD!");

    let error = dexios_core::header::read_header(&mut std::io::Cursor::new(bytes))
        .expect_err("invalid magic should fail");

    assert!(matches!(
        error,
        dexios_core::header::HeaderReadError::InvalidMagic([0x42, 0x41, 0x44, 0x21])
    ));
}

#[test]
fn read_header_rejects_reserved_bytes_and_inactive_keyslot_padding() {
    let mut bytes = support::sample_v1_header().serialize().unwrap();
    bytes[7] = 1;

    let error = dexios_core::header::read_header(&mut std::io::Cursor::new(bytes))
        .expect_err("non-zero reserved byte should fail");

    assert!(matches!(
        error,
        dexios_core::header::HeaderReadError::NonZeroReservedBytes
    ));

    let mut bytes = support::sample_v1_header().serialize().unwrap();
    bytes[128] = 1;

    let error = dexios_core::header::read_header(&mut std::io::Cursor::new(bytes))
        .expect_err("non-zero inactive keyslot bytes should fail");

    assert!(matches!(
        error,
        dexios_core::header::HeaderReadError::NonZeroInactiveKeyslotPadding(1)
    ));
}
