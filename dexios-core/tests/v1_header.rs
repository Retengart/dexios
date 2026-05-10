use dexios_core::cipher::Ciphers;
use dexios_core::header::common::{KeyslotNonce, PayloadNonce, Salt as HeaderSalt};
use dexios_core::header::v1::{KeyslotKdf, V1Header, V1Keyslot};
use dexios_core::header::{HeaderReadError, ParsedHeader};
use dexios_core::kdf::{Kdf, Salt};
use dexios_core::stream::{DecryptionStreams, EncryptionStreams};
use std::path::Path;

mod support {
    use super::*;

    pub fn sample_v1_header() -> V1Header {
        V1Header::new(
            PayloadNonce::new([7u8; 20]),
            vec![V1Keyslot::new(
                KeyslotKdf::Blake3Balloon,
                [11u8; 48],
                KeyslotNonce::new([13u8; 24]),
                HeaderSalt::new([17u8; 16]),
            )],
        )
        .expect("sample v1 header")
    }
}

fn fixture_path(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("testdata")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn decode_hex_fixture(path: &str) -> Vec<u8> {
    let fixture = std::fs::read_to_string(path).expect("read hex fixture");
    let nibbles: Vec<u8> = fixture
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .map(|ch| {
            ch.to_digit(16)
                .unwrap_or_else(|| panic!("invalid hex digit {ch:?} in {path}")) as u8
        })
        .collect();

    assert!(
        nibbles.len().is_multiple_of(2),
        "hex fixture {path} must have an even number of digits"
    );

    nibbles
        .chunks_exact(2)
        .map(|pair| (pair[0] << 4) | pair[1])
        .collect()
}

#[test]
fn serializes_v1_header_to_416_bytes() {
    let header = support::sample_v1_header();
    let bytes = header.serialize().unwrap();

    assert_eq!(bytes.len(), 416);
}

#[test]
fn payload_nonce_length_is_fixed_for_v1() {
    assert_eq!(dexios_core::primitives::PAYLOAD_NONCE_LEN, 20);
}

#[test]
fn keyslot_nonce_length_is_fixed_for_v1() {
    assert_eq!(dexios_core::primitives::KEYSLOT_NONCE_LEN, 24);
}

#[test]
fn cipher_initialization_uses_the_single_suite_signature() {
    let key = Kdf::Blake3Balloon
        .derive(
            dexios_core::protected::Protected::new(b"password".to_vec()),
            &Salt::new([9u8; 16]),
        )
        .unwrap();

    let cipher = Ciphers::initialize(key).unwrap();
    let nonce = dexios_core::primitives::gen_keyslot_nonce();
    let encrypted = cipher
        .encrypt(nonce.as_bytes(), b"hello".as_slice())
        .unwrap();
    let decrypted = cipher
        .decrypt(nonce.as_bytes(), encrypted.as_slice())
        .unwrap();

    assert_eq!(decrypted, b"hello");
}

#[test]
fn stream_initialization_uses_the_single_suite_signature() {
    let key = Kdf::Blake3Balloon
        .derive(
            dexios_core::protected::Protected::new(b"password".to_vec()),
            &Salt::new([9u8; 16]),
        )
        .unwrap();

    let nonce = dexios_core::primitives::gen_payload_nonce();
    let encrypted = EncryptionStreams::initialize(key, nonce.as_bytes())
        .unwrap()
        .encrypt_last(b"hello".as_slice())
        .unwrap();

    let key = Kdf::Blake3Balloon
        .derive(
            dexios_core::protected::Protected::new(b"password".to_vec()),
            &Salt::new([9u8; 16]),
        )
        .unwrap();

    let decrypted = DecryptionStreams::initialize(key, nonce.as_bytes())
        .unwrap()
        .decrypt_last(encrypted.as_slice())
        .unwrap();

    assert_eq!(decrypted, b"hello");
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
fn fixture_v1_valid_single_keyslot_roundtrips() {
    let path = fixture_path("v1_valid_single_keyslot.hex");
    let original_bytes = decode_hex_fixture(&path);
    let (parsed, aad) =
        dexios_core::header::read_header(&mut std::io::Cursor::new(&original_bytes)).unwrap();

    let ParsedHeader::V1(parsed) = parsed;
    assert_eq!(parsed.keyslots().len(), 1);
    assert_eq!(aad.as_bytes().len(), 32);
    assert_eq!(parsed.serialize().unwrap(), original_bytes);
}

#[test]
fn fixture_v1_malformed_reserved_byte_is_rejected() {
    let path = fixture_path("v1_malformed_reserved_byte.hex");
    let bytes = decode_hex_fixture(&path);
    let error = dexios_core::header::read_header(&mut std::io::Cursor::new(&bytes))
        .expect_err("non-zero reserved byte fixture should fail");

    assert!(matches!(error, HeaderReadError::NonZeroReservedBytes));
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
