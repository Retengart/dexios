use dexios_core::cipher::Ciphers;
use dexios_core::header::common::{
    HEADER_LEN, HEADER_STATIC_LEN, KEYSLOT_LEN, KeyslotNonce, PayloadNonce, Salt as HeaderSalt,
};
use dexios_core::header::v1::{KeyslotKdf, V1Header, V1Keyslot, V1Keyslots};
use dexios_core::header::{HeaderReadError, ParsedHeader, ParsedV1Payload};
use dexios_core::kdf::{Kdf, Salt};
use dexios_core::protected::Protected;
use dexios_core::stream::{DecryptionStreams, EncryptionStreams, V1PayloadStream};
use std::path::Path;

mod support {
    use super::*;

    pub fn sample_v1_header() -> V1Header {
        let keyslots = V1Keyslots::single(V1Keyslot::new(
            Kdf::Blake3Balloon,
            [11u8; 48],
            KeyslotNonce::new([13u8; 24]),
            HeaderSalt::new([17u8; 16]),
        ));

        V1Header::new(PayloadNonce::new([7u8; 20]), keyslots).expect("sample v1 header")
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
fn v1_header_rejects_zero_keyslots() {
    let empty = V1Keyslots::try_from_vec(Vec::new()).expect_err("empty keyslots should fail");

    assert!(matches!(
        empty,
        dexios_core::header::HeaderWriteError::NoKeyslots
    ));
}

#[test]
fn v1_keyslot_collection_rejects_more_than_max() {
    let keyslot = V1Keyslot::new(
        Kdf::Blake3Balloon,
        [11u8; 48],
        KeyslotNonce::new([13u8; 24]),
        HeaderSalt::new([17u8; 16]),
    );
    let too_many = vec![keyslot; 5];

    let error = V1Keyslots::try_from_vec(too_many).expect_err("over-capacity keyslots should fail");

    assert!(matches!(
        error,
        dexios_core::header::HeaderWriteError::TooManyKeyslots(5)
    ));
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
fn v1_payload_stream_uses_header_derived_aad() {
    let header = support::sample_v1_header();
    let other_header = V1Header::new(
        PayloadNonce::new([8u8; 20]),
        V1Keyslots::single(V1Keyslot::new(
            Kdf::Blake3Balloon,
            [21u8; 48],
            KeyslotNonce::new([23u8; 24]),
            HeaderSalt::new([29u8; 16]),
        )),
    )
    .expect("other valid v1 header");

    let plaintext = b"v1 aad binds the payload to the serialized header";
    let mut encrypted = Vec::new();
    V1PayloadStream::encrypt_file(
        Protected::new([31u8; 32]),
        &header,
        &mut std::io::Cursor::new(plaintext),
        &mut encrypted,
    )
    .expect("encrypt with header-derived aad");

    let mut decrypted = Vec::new();
    V1PayloadStream::decrypt_file(
        Protected::new([31u8; 32]),
        &header,
        &header.aad(),
        &mut std::io::Cursor::new(&encrypted),
        &mut decrypted,
    )
    .expect("decrypt with matching aad");
    assert_eq!(decrypted, plaintext);

    let wrong_aad = other_header.aad();
    let wrong_aad_result = V1PayloadStream::decrypt_file(
        Protected::new([31u8; 32]),
        &header,
        &wrong_aad,
        &mut std::io::Cursor::new(&encrypted),
        &mut Vec::new(),
    );
    assert!(
        wrong_aad_result.is_err(),
        "decryption should fail when a different valid header's AAD is supplied"
    );
}

#[test]
fn read_header_returns_v1_payload_with_header_and_matching_aad() {
    let header = support::sample_v1_header();
    let bytes = header.serialize().unwrap();

    let parsed = dexios_core::header::read_header(&mut std::io::Cursor::new(bytes)).unwrap();
    let ParsedHeader::V1(payload) = parsed;

    let _: &ParsedV1Payload = &payload;
    assert_eq!(
        payload.header().payload_nonce().as_bytes(),
        header.payload_nonce().as_bytes()
    );
    assert_eq!(payload.header().keyslots().len(), 1);
    assert_eq!(payload.aad(), &payload.header().aad());
    assert_eq!(payload.payload_nonce(), payload.header().payload_nonce());
}

#[test]
fn deserialize_roundtrip_preserves_payload_nonce_and_keyslots() {
    let header = support::sample_v1_header();
    let bytes = header.serialize().unwrap();
    let parsed = dexios_core::header::read_header(&mut std::io::Cursor::new(bytes)).unwrap();

    let dexios_core::header::ParsedHeader::V1(parsed) = parsed;
    assert_eq!(
        parsed.payload_nonce().as_bytes(),
        header.payload_nonce().as_bytes()
    );
    assert_eq!(parsed.header().keyslots().len(), 1);
    assert_eq!(parsed.aad().as_bytes().len(), 32);
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
    let parsed =
        dexios_core::header::read_header(&mut std::io::Cursor::new(&original_bytes)).unwrap();

    let ParsedHeader::V1(parsed) = parsed;
    assert_eq!(parsed.header().keyslots().len(), 1);
    assert_eq!(parsed.aad().as_bytes().len(), 32);
    assert_eq!(parsed.header().serialize().unwrap(), original_bytes);
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
        header.aad().as_bytes(),
        &[
            0x44, 0x58, 0x49, 0x4F, 0x00, 0x01, 0x01, 0x00, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
            7, 7, 7, 7, 7, 7, 7, 0, 0, 0, 0,
        ]
    );
}

#[test]
fn detached_v1_header_bytes_are_exactly_416_bytes() {
    let header = support::sample_v1_header();
    let bytes = header.serialize().unwrap();
    assert_eq!(bytes.len(), HEADER_LEN);

    let parsed = dexios_core::header::read_header(&mut std::io::Cursor::new(&bytes)).unwrap();
    let ParsedHeader::V1(parsed) = parsed;

    assert_eq!(parsed.header().serialize().unwrap(), bytes);
}

#[test]
fn v1_header_serialization_writes_zero_inactive_keyslots() {
    let header = support::sample_v1_header();
    let bytes = header.serialize().unwrap();
    let inactive_start = HEADER_STATIC_LEN + KEYSLOT_LEN;

    assert_eq!(bytes[inactive_start..], [0u8; KEYSLOT_LEN * 3]);
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
fn read_header_rejects_legacy_prefix_as_unsupported_format() {
    let mut bytes = [0u8; HEADER_LEN];
    bytes[0..6].copy_from_slice(&[0xDE, 0x05, 0x0E, 0x01, 0x0C, 0x01]);

    let error = dexios_core::header::read_header(&mut std::io::Cursor::new(bytes))
        .expect_err("legacy header prefix should fail");

    assert!(matches!(
        error,
        dexios_core::header::HeaderReadError::UnsupportedFormat([0xDE, 0x05])
    ));
}

#[test]
fn read_header_rejects_truncated_header() {
    let bytes = support::sample_v1_header().serialize().unwrap();
    let truncated = &bytes[..HEADER_LEN - 1];

    let error = dexios_core::header::read_header(&mut std::io::Cursor::new(truncated))
        .expect_err("truncated V1 header should fail");

    assert!(matches!(
        error,
        dexios_core::header::HeaderReadError::TruncatedHeader
    ));
}

#[test]
fn v1_header_rejects_keyslot_count_above_max() {
    let mut bytes = support::sample_v1_header().serialize().unwrap();
    bytes[6] = 5;

    let error = dexios_core::header::read_header(&mut std::io::Cursor::new(bytes))
        .expect_err("over-capacity keyslot count should fail");

    assert!(matches!(
        error,
        dexios_core::header::HeaderReadError::InvalidKeyslotCount(5)
    ));
}

#[test]
fn v1_header_rejects_invalid_kdf_tag() {
    let mut bytes = support::sample_v1_header().serialize().unwrap();
    bytes[HEADER_STATIC_LEN..HEADER_STATIC_LEN + 2].copy_from_slice(&[0xAA, 0xBB]);

    let error = dexios_core::header::read_header(&mut std::io::Cursor::new(bytes))
        .expect_err("invalid KDF tag should fail");

    assert!(matches!(
        error,
        dexios_core::header::HeaderReadError::InvalidKeyslotTag([0xAA, 0xBB])
    ));
}

#[test]
fn v1_header_preserves_historical_argon2id_tag_as_unsupported() {
    let mut bytes = support::sample_v1_header().serialize().unwrap();
    bytes[HEADER_STATIC_LEN..HEADER_STATIC_LEN + 2].copy_from_slice(&[0xDF, 0x02]);

    let parsed = dexios_core::header::read_header(&mut std::io::Cursor::new(bytes))
        .expect("historical Argon2id tag remains structurally recognized");

    let ParsedHeader::V1(parsed) = parsed;
    assert_eq!(
        parsed.header().keyslots()[0].kdf(),
        KeyslotKdf::UnsupportedArgon2id
    );
}

#[test]
fn new_keyslot_constructor_uses_supported_kdf_selector() {
    let keyslot = V1Keyslot::new(
        Kdf::Blake3Balloon,
        [11u8; 48],
        KeyslotNonce::new([13u8; 24]),
        HeaderSalt::new([17u8; 16]),
    );
    let header = V1Header::new(PayloadNonce::new([7u8; 20]), V1Keyslots::single(keyslot))
        .expect("sample v1 header");
    let bytes = header.serialize().unwrap();

    assert_eq!(
        &bytes[HEADER_STATIC_LEN..HEADER_STATIC_LEN + 2],
        &[0xDF, 0x01]
    );
}

#[test]
fn v1_header_rejects_active_keyslot_padding() {
    let mut bytes = support::sample_v1_header().serialize().unwrap();
    bytes[HEADER_STATIC_LEN + 90] = 1;

    let error = dexios_core::header::read_header(&mut std::io::Cursor::new(bytes))
        .expect_err("active keyslot padding should fail");

    assert!(matches!(
        error,
        dexios_core::header::HeaderReadError::NonZeroActiveKeyslotPadding(0)
    ));
}

#[test]
fn v1_header_rejects_inactive_keyslot_bytes() {
    let mut bytes = support::sample_v1_header().serialize().unwrap();
    bytes[HEADER_STATIC_LEN + KEYSLOT_LEN] = 1;

    let error = dexios_core::header::read_header(&mut std::io::Cursor::new(bytes))
        .expect_err("non-zero inactive keyslot bytes should fail");

    assert!(matches!(
        error,
        dexios_core::header::HeaderReadError::NonZeroInactiveKeyslotPadding(1)
    ));
}

#[test]
fn v1_header_rejects_nonzero_reserved_bytes() {
    let mut bytes = support::sample_v1_header().serialize().unwrap();
    bytes[7] = 1;

    let error = dexios_core::header::read_header(&mut std::io::Cursor::new(bytes))
        .expect_err("non-zero reserved byte should fail");

    assert!(matches!(
        error,
        dexios_core::header::HeaderReadError::NonZeroReservedBytes
    ));
}

#[test]
fn v1_primitives_reject_invalid_lengths() {
    assert!(matches!(
        PayloadNonce::try_from_slice(&[0u8; 19]),
        Err(HeaderReadError::InvalidPayloadNonceLength(19))
    ));
    assert!(matches!(
        KeyslotNonce::try_from_slice(&[0u8; 23]),
        Err(HeaderReadError::InvalidKeyslotNonceLength(23))
    ));
    assert!(matches!(
        HeaderSalt::try_from_slice(&[0u8; 15]),
        Err(HeaderReadError::InvalidSaltLength(15))
    ));
    assert!(matches!(
        dexios_core::header::v1::EncryptedMasterKey::try_from_slice(&[0u8; 47]),
        Err(HeaderReadError::InvalidEncryptedMasterKeyLength(47))
    ));
}
