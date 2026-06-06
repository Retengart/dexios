#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::unreachable, clippy::string_slice, clippy::too_many_lines, clippy::cast_possible_truncation, clippy::cast_possible_wrap, clippy::cast_sign_loss, clippy::cast_precision_loss, clippy::match_same_arms, clippy::items_after_statements, clippy::redundant_closure_for_method_calls, clippy::needless_collect, clippy::manual_let_else, clippy::format_collect, clippy::case_sensitive_file_extension_comparisons, clippy::struct_excessive_bools, reason = "integration tests assert exact behavior and may panic on failure"))]
use dexios_core::header::common::{
    CANONICAL_HEADER_LEN, CANONICAL_HEADER_STATIC_LEN, CANONICAL_V1_DISCRIMINATOR, HEADER_LEN,
    HEADER_STATIC_LEN, KEYSLOT_LEN, KeyslotNonce, PayloadNonce, Salt as HeaderSalt,
};
use dexios_core::header::v1::{
    EncryptedMasterKey, KeyslotKdf, V1Header, V1Keyslot, V1KeyslotIndex, V1Keyslots,
};
use dexios_core::header::{HeaderReadError, ParsedHeader, ParsedV1Payload};
use dexios_core::kdf::{
    ARGON2ID_KDF_PARAM_PROFILE_ID, ARGON2ID_KDF_PROFILE_ID, Kdf, Salt,
};
use dexios_core::payload::{PayloadFramingProfile, PayloadKind};
use dexios_core::primitives::{MasterKey, WrappingKey};
use dexios_core::stream::{StreamError, V1PayloadDecryptor, V1PayloadEncryptor, V1PayloadStream};
use std::path::Path;

mod support {
    use super::*;

    pub(crate) fn sample_v1_header() -> V1Header {
        let keyslots = V1Keyslots::single(V1Keyslot::new(
            Kdf::Argon2id,
            [11u8; 48],
            KeyslotNonce::new([13u8; 24]),
            HeaderSalt::new([17u8; 16]),
        ));

        V1Header::new(PayloadNonce::new([7u8; 20]), keyslots).expect("sample v1 header")
    }

    pub(crate) fn parsed_payload_for(header: &V1Header) -> ParsedV1Payload {
        let bytes = header.serialize().unwrap();
        let ParsedHeader::V1(payload) =
            dexios_core::header::read_header(&mut std::io::Cursor::new(bytes)).unwrap();
        payload
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

fn assert_retired_layout_public_entry_points(case: &str, bytes: &[u8]) {
    let top_level_error = dexios_core::header::read_header(&mut std::io::Cursor::new(bytes))
        .expect_err("retired V1 fixture should be rejected by top-level parser");
    assert!(
        matches!(top_level_error, HeaderReadError::RetiredV1Layout),
        "{case}: read_header returned {top_level_error:?}"
    );

    let direct_v1_error = V1Header::deserialize(&mut std::io::Cursor::new(bytes))
        .expect_err("retired V1 fixture should be rejected by direct public V1 parser");
    assert!(
        matches!(direct_v1_error, HeaderReadError::RetiredV1Layout),
        "{case}: V1Header::deserialize returned {direct_v1_error:?}"
    );
}

#[test]
fn serializes_canonical_v1_header_to_canonical_length() {
    let header = support::sample_v1_header();
    let bytes = header.serialize().unwrap();

    assert_eq!(bytes.len(), CANONICAL_HEADER_LEN);
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
        Kdf::Argon2id,
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
fn keyslot_wrap_unwrap_uses_typed_nonce_and_key_inputs() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let nonce = KeyslotNonce::new([13u8; 24]);
    let wrapping_aad = header
        .slot_wrapping_aad_for_physical_slot(
            V1KeyslotIndex::try_from_physical_index(0).expect("slot zero index"),
        )
        .expect("slot wrapping aad");
    let encrypted_master_key: EncryptedMasterKey = dexios_core::cipher::wrap_v1_master_key(
        WrappingKey::new([41u8; 32]),
        &MasterKey::new([31u8; 32]),
        &nonce,
        &wrapping_aad,
    )
    .expect("wrap typed master key");

    let unwrapped = dexios_core::cipher::unwrap_v1_master_key(
        WrappingKey::new([41u8; 32]),
        &encrypted_master_key,
        &nonce,
        &wrapping_aad,
    )
    .expect("unwrap typed master key");

    let encrypted = V1PayloadEncryptor::new(MasterKey::new([31u8; 32]), &header)
        .unwrap()
        .encrypt_last(b"hello".as_slice())
        .unwrap();
    let decrypted = V1PayloadDecryptor::new(unwrapped, &payload)
        .unwrap()
        .decrypt_last(encrypted.as_slice())
        .unwrap();

    assert_eq!(decrypted, b"hello");

    let wrong_key = dexios_core::cipher::unwrap_v1_master_key(
        WrappingKey::new([42u8; 32]),
        &encrypted_master_key,
        &nonce,
        &wrapping_aad,
    );
    assert!(matches!(
        wrong_key,
        Err(dexios_core::cipher::CipherError::Authentication)
    ));
}

#[test]
fn keyslot_wrap_unwrap_authenticates_slot_scoped_metadata() {
    let header = support::sample_v1_header();
    let keyslot = &header.keyslots()[0];
    let wrapping_aad = header
        .slot_wrapping_aad_for_physical_slot(
            V1KeyslotIndex::try_from_physical_index(keyslot.physical_index())
                .expect("fixture slot index"),
        )
        .expect("slot wrapping aad");
    let encrypted_master_key = dexios_core::cipher::wrap_v1_master_key(
        WrappingKey::new([41u8; 32]),
        &MasterKey::new([31u8; 32]),
        keyslot.nonce(),
        &wrapping_aad,
    )
    .expect("wrap typed master key");

    let mut wrong_slot_index = wrapping_aad.clone();
    wrong_slot_index[CANONICAL_HEADER_STATIC_LEN] = 1;
    let mut wrong_kdf_profile = wrapping_aad.clone();
    wrong_kdf_profile[CANONICAL_HEADER_STATIC_LEN + 1] = 0xDF;
    let mut wrong_kdf_param_profile = wrapping_aad.clone();
    wrong_kdf_param_profile[CANONICAL_HEADER_STATIC_LEN + 2] = 0x02;
    let mut wrong_salt = wrapping_aad.clone();
    wrong_salt[CANONICAL_HEADER_STATIC_LEN + 3] ^= 0x01;
    let mut wrong_keyslot_nonce = wrapping_aad.clone();
    wrong_keyslot_nonce[CANONICAL_HEADER_STATIC_LEN + 3 + 16] ^= 0x01;
    let mut wrong_static_header = wrapping_aad;
    wrong_static_header[16] ^= 0x01;

    for (case, aad) in [
        ("slot_index", wrong_slot_index),
        ("kdf_profile", wrong_kdf_profile),
        ("kdf_param_profile", wrong_kdf_param_profile),
        ("salt", wrong_salt),
        ("keyslot_nonce", wrong_keyslot_nonce),
        ("static_header_aad", wrong_static_header),
    ] {
        let result = dexios_core::cipher::unwrap_v1_master_key(
            WrappingKey::new([41u8; 32]),
            &encrypted_master_key,
            keyslot.nonce(),
            &aad,
        );
        assert!(
            matches!(
                result,
                Err(dexios_core::cipher::CipherError::Authentication)
            ),
            "{case} must be authenticated by keyslot wrapping AAD"
        );
    }
}

#[test]
fn stream_initialization_uses_typed_master_key_and_payload_nonce() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);

    let encrypted = V1PayloadEncryptor::new(MasterKey::new([31u8; 32]), &header)
        .expect("typed encryptor")
        .encrypt_last(b"hello".as_slice())
        .expect("encrypt final chunk");

    let decrypted = V1PayloadDecryptor::new(MasterKey::new([31u8; 32]), &payload)
        .expect("typed decryptor")
        .decrypt_last(encrypted.as_slice())
        .expect("decrypt final chunk");

    assert_eq!(decrypted, b"hello");
}

#[test]
fn keyslot_salt_has_named_kdf_salt_boundary() {
    let header_salt = HeaderSalt::new([17u8; 16]);
    let kdf_salt: Salt = header_salt.to_kdf_salt();

    assert_eq!(kdf_salt.as_bytes(), header_salt.as_bytes());
}

#[test]
fn v1_payload_stream_uses_header_derived_aad() {
    let header = support::sample_v1_header();
    let other_header = V1Header::new(
        PayloadNonce::new([8u8; 20]),
        V1Keyslots::single(V1Keyslot::new(
            Kdf::Argon2id,
            [21u8; 48],
            KeyslotNonce::new([23u8; 24]),
            HeaderSalt::new([29u8; 16]),
        )),
    )
    .expect("other valid v1 header");

    let plaintext = b"v1 aad binds the payload to the serialized header";
    let mut encrypted = Vec::new();
    V1PayloadStream::encrypt_file(
        MasterKey::new([31u8; 32]),
        &header,
        &mut std::io::Cursor::new(plaintext),
        &mut encrypted,
    )
    .expect("encrypt with header-derived aad");

    let payload = support::parsed_payload_for(&header);
    let mut decrypted = Vec::new();
    V1PayloadStream::decrypt_file_uncommitted(
        MasterKey::new([31u8; 32]),
        &payload,
        &mut std::io::Cursor::new(&encrypted),
        &mut decrypted,
    )
    .expect("decrypt with matching aad");
    assert_eq!(decrypted, plaintext);

    let wrong_payload = support::parsed_payload_for(&other_header);
    let wrong_bundle_result = V1PayloadStream::decrypt_file_uncommitted(
        MasterKey::new([31u8; 32]),
        &wrong_payload,
        &mut std::io::Cursor::new(&encrypted),
        &mut Vec::new(),
    );
    assert!(
        wrong_bundle_result.is_err(),
        "decryption should fail when a different parsed V1 payload bundle is supplied"
    );
}

#[test]
fn v1_stream_file_api_returns_typed_stream_errors() {
    let header = support::sample_v1_header();
    let payload = support::parsed_payload_for(&header);
    let result = V1PayloadStream::decrypt_file_uncommitted(
        MasterKey::new([31u8; 32]),
        &payload,
        &mut std::io::Cursor::new(Vec::<u8>::new()),
        &mut Vec::new(),
    );

    assert!(matches!(result, Err(StreamError::MissingFinalBlock)));
}

#[test]
fn shared_payload_kind_and_framing_roundtrip_through_header_bytes() {
    let header = support::sample_v1_header();
    let raw_bytes = header.serialize().unwrap();

    assert_eq!(header.payload_kind(), PayloadKind::RawFile);
    assert_eq!(header.payload_framing(), PayloadFramingProfile::RawLe31);
    assert_eq!(
        &raw_bytes[11..13],
        &[
            PayloadKind::RawFile.to_byte(),
            PayloadFramingProfile::RawLe31.to_byte(),
        ],
        "raw-file payload kind/framing bytes must be exact"
    );

    let mut archive_bytes = raw_bytes;
    archive_bytes[11] = PayloadKind::ManifestArchive.to_byte();
    archive_bytes[12] = PayloadFramingProfile::ManifestFirst.to_byte();

    let ParsedHeader::V1(archive_payload) =
        dexios_core::header::read_header(&mut std::io::Cursor::new(archive_bytes.clone()))
            .expect("manifest archive payload metadata must parse");

    assert_eq!(
        archive_payload.header().payload_kind(),
        PayloadKind::ManifestArchive
    );
    assert_eq!(
        archive_payload.header().payload_framing(),
        PayloadFramingProfile::ManifestFirst
    );
    assert_eq!(
        &archive_payload.header().serialize().unwrap()[11..13],
        &[0x02, 0x02],
        "manifest-archive payload kind/framing roundtrip must keep exact bytes"
    );

    assert!(matches!(
        PayloadKind::try_from_byte(0x7F),
        Err(dexios_core::payload::PayloadError::UnsupportedPayloadKind(
            0x7F
        ))
    ));
    assert!(matches!(
        PayloadFramingProfile::try_from_byte(0x7F),
        Err(dexios_core::payload::PayloadError::UnsupportedPayloadFramingProfile(0x7F))
    ));
}

#[test]
fn new_manifest_archive_constructor_sets_canonical_payload_metadata() {
    let raw_header = support::sample_v1_header();
    let header = V1Header::new_manifest_archive(
        PayloadNonce::new([9u8; 20]),
        raw_header.keyslots_collection().clone(),
    )
    .expect("manifest archive header");
    let bytes = header.serialize().expect("serialize manifest header");

    assert_eq!(header.payload_kind(), PayloadKind::ManifestArchive);
    assert_eq!(
        header.payload_framing(),
        PayloadFramingProfile::ManifestFirst
    );
    assert_eq!(bytes[11], PayloadKind::ManifestArchive.to_byte());
    assert_eq!(bytes[12], PayloadFramingProfile::ManifestFirst.to_byte());

    let ParsedHeader::V1(parsed) =
        dexios_core::header::read_header(&mut std::io::Cursor::new(bytes))
            .expect("manifest archive header parses");

    assert_eq!(parsed.header().payload_kind(), PayloadKind::ManifestArchive);
    assert_eq!(
        parsed.header().payload_framing(),
        PayloadFramingProfile::ManifestFirst
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

    let ParsedHeader::V1(parsed) = parsed;
    assert_eq!(
        parsed.payload_nonce().as_bytes(),
        header.payload_nonce().as_bytes()
    );
    assert_eq!(parsed.header().keyslots().len(), 1);
    assert_eq!(parsed.aad().as_bytes().len(), CANONICAL_HEADER_STATIC_LEN);
}

#[test]
fn serializes_sample_v1_header_to_exact_bytes() {
    let header = support::sample_v1_header();
    let bytes = header.serialize().unwrap();

    let mut expected = Vec::with_capacity(CANONICAL_HEADER_LEN);
    expected.extend_from_slice(b"DXIO");
    expected.extend_from_slice(&[0x00, 0x01]);
    expected.extend_from_slice(&CANONICAL_V1_DISCRIMINATOR);
    expected.extend_from_slice(&[0x01, 0x01, 0x01, 0x01, 0x04, 0x00]);
    expected.extend_from_slice(&[7u8; 20]);
    expected.extend_from_slice(&[0u8; 28]);
    expected.extend_from_slice(&[0x01, 0x00, 0x01, 0x01]);
    expected.extend_from_slice(&[17u8; 16]);
    expected.extend_from_slice(&[13u8; 24]);
    expected.extend_from_slice(&[11u8; 48]);
    expected.extend_from_slice(&[0u8; 20]);
    expected.extend_from_slice(&[0u8; KEYSLOT_LEN * 3]);

    assert_eq!(bytes, expected);
}

#[test]
fn obsolete_current_v1_valid_single_keyslot_is_rejection_evidence() {
    let path = fixture_path("v1_valid_single_keyslot.hex");
    let original_bytes = decode_hex_fixture(&path);

    assert_retired_layout_public_entry_points(
        "retired valid single-keyslot fixture",
        &original_bytes,
    );
}

#[test]
fn retired_current_v1_malformed_reserved_byte_is_rejection_evidence() {
    let path = fixture_path("v1_malformed_reserved_byte.hex");
    let bytes = decode_hex_fixture(&path);

    assert_retired_layout_public_entry_points("retired malformed reserved-byte fixture", &bytes);
}

#[test]
fn creates_exact_aad_bytes_for_sample_v1_header() {
    let header = support::sample_v1_header();

    let mut expected = [0u8; CANONICAL_HEADER_STATIC_LEN];
    expected[0..4].copy_from_slice(b"DXIO");
    expected[4..6].copy_from_slice(&[0x00, 0x01]);
    expected[6..10].copy_from_slice(&CANONICAL_V1_DISCRIMINATOR);
    expected[10] = 0x01;
    expected[11] = 0x01;
    expected[12] = 0x01;
    expected[13] = 0x01;
    expected[14] = 0x04;
    expected[16..36].copy_from_slice(&[7u8; 20]);

    assert_eq!(header.aad().as_bytes(), &expected);
}

#[test]
fn payload_aad_excludes_mutable_keyslot_table_state() {
    let first_header = support::sample_v1_header();
    let second_keyslot = V1Keyslot::new(
        Kdf::Argon2id,
        [29u8; 48],
        KeyslotNonce::new([31u8; 24]),
        HeaderSalt::new([37u8; 16]),
    );
    let two_slot_header = V1Header::new(
        PayloadNonce::new([7u8; 20]),
        V1Keyslots::try_from_vec(vec![first_header.keyslots()[0], second_keyslot])
            .expect("two physical keyslots"),
    )
    .expect("two-slot header");
    let changed_slot_header = V1Header::new(
        PayloadNonce::new([7u8; 20]),
        V1Keyslots::single(V1Keyslot::new(
            Kdf::Argon2id,
            [41u8; 48],
            KeyslotNonce::new([43u8; 24]),
            HeaderSalt::new([47u8; 16]),
        )),
    )
    .expect("changed slot header");

    assert_eq!(first_header.aad(), two_slot_header.aad());
    assert_eq!(first_header.aad(), changed_slot_header.aad());
}

#[test]
fn slot_wrapping_aad_binds_static_header_and_physical_slot_metadata() {
    let header = support::sample_v1_header();
    let aad = header
        .slot_wrapping_aad_for_physical_slot(
            V1KeyslotIndex::try_from_physical_index(0).expect("slot zero index"),
        )
        .expect("slot wrapping aad");

    let mut expected = Vec::new();
    expected.extend_from_slice(header.aad().as_bytes());
    expected.push(0);
    expected.push(0x01);
    expected.push(0x01);
    expected.extend_from_slice(&[17u8; 16]);
    expected.extend_from_slice(&[13u8; 24]);

    assert_eq!(aad, expected);

    let two_slot_header = V1Header::new(
        PayloadNonce::new([7u8; 20]),
        V1Keyslots::try_from_vec(vec![
            V1Keyslot::new(
                Kdf::Argon2id,
                [11u8; 48],
                KeyslotNonce::new([13u8; 24]),
                HeaderSalt::new([17u8; 16]),
            ),
            V1Keyslot::new(
                Kdf::Argon2id,
                [19u8; 48],
                KeyslotNonce::new([23u8; 24]),
                HeaderSalt::new([29u8; 16]),
            ),
        ])
        .expect("two slot keyslots"),
    )
    .expect("two slot header");
    let slot_one_aad = two_slot_header
        .slot_wrapping_aad_for_physical_slot(
            V1KeyslotIndex::try_from_physical_index(1).expect("slot one index"),
        )
        .expect("slot one wrapping aad");
    assert_ne!(aad, slot_one_aad);
}

#[test]
fn detached_canonical_v1_header_bytes_are_exactly_canonical_length() {
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
        HeaderReadError::InvalidMagic([0x42, 0x41, 0x44, 0x21])
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
        HeaderReadError::UnsupportedFormat([0xDE, 0x05])
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
        HeaderReadError::TruncatedHeader
    ));
}

#[test]
fn parser_table_rejects_canonical_v1_malformed_metadata_by_variant() {
    fn read_header_error(bytes: &[u8]) -> HeaderReadError {
        dexios_core::header::read_header(&mut std::io::Cursor::new(bytes))
            .expect_err("parser table case should reject malformed input")
    }

    fn retired_current_v1() -> Vec<u8> {
        let path = fixture_path("v1_valid_single_keyslot.hex");
        decode_hex_fixture(&path)
    }

    let canonical = support::sample_v1_header().serialize().unwrap();
    let mut malformed_discriminator = canonical.clone();
    malformed_discriminator[7] = b'X';
    let mut malformed_schema = canonical.clone();
    malformed_schema[10] = 0x02;
    let mut malformed_reserved = canonical.clone();
    malformed_reserved[36] = 0x01;
    let mut unsupported_payload_kind = canonical.clone();
    unsupported_payload_kind[11] = 0x7F;
    let mut unsupported_payload_framing = canonical.clone();
    unsupported_payload_framing[12] = 0x7F;
    let mut raw_kind_manifest_framing = canonical.clone();
    raw_kind_manifest_framing[11] = PayloadKind::RawFile.to_byte();
    raw_kind_manifest_framing[12] = PayloadFramingProfile::ManifestFirst.to_byte();
    let mut manifest_kind_raw_framing = canonical.clone();
    manifest_kind_raw_framing[11] = PayloadKind::ManifestArchive.to_byte();
    manifest_kind_raw_framing[12] = PayloadFramingProfile::RawLe31.to_byte();
    let mut unsupported_kdf_profile = canonical.clone();
    unsupported_kdf_profile[HEADER_STATIC_LEN + 2] = 0x7F;
    let mut unsupported_kdf_param_profile = canonical.clone();
    unsupported_kdf_param_profile[HEADER_STATIC_LEN + 3] = 0x7F;
    let mut invalid_keyslot_state = canonical.clone();
    invalid_keyslot_state[HEADER_STATIC_LEN] = 0x03;
    let mut invalid_physical_slot_index = canonical.clone();
    invalid_physical_slot_index[HEADER_STATIC_LEN + 1] = 0x03;
    let truncated_canonical_header = canonical[..HEADER_LEN - 1].to_vec();
    let truncated_canonical_keyslot_input = canonical[..HEADER_STATIC_LEN + 8].to_vec();

    type HeaderErrorPredicate = fn(&HeaderReadError) -> bool;
    type ParserCase = (&'static str, Vec<u8>, HeaderErrorPredicate);

    let parser_table: Vec<ParserCase> = vec![
        ("retired_current_v1", retired_current_v1(), |error| {
            matches!(error, HeaderReadError::RetiredV1Layout)
        }),
        (
            "malformed_discriminator",
            malformed_discriminator,
            |error| {
                matches!(
                    error,
                    HeaderReadError::InvalidCanonicalDiscriminator(discriminator)
                        if *discriminator == [b'C', b'X', b'1', 0]
                )
            },
        ),
        ("malformed_schema", malformed_schema, |error| {
            matches!(error, HeaderReadError::UnsupportedVersion([0x00, 0x02]))
        }),
        ("malformed_reserved", malformed_reserved, |error| {
            matches!(error, HeaderReadError::NonZeroReservedBytes)
        }),
        (
            "unsupported_payload_kind",
            unsupported_payload_kind,
            |error| matches!(error, HeaderReadError::InvalidPayloadKind(0x7F)),
        ),
        (
            "unsupported_payload_framing",
            unsupported_payload_framing,
            |error| matches!(error, HeaderReadError::InvalidPayloadFraming(0x7F)),
        ),
        (
            "raw_kind_manifest_framing",
            raw_kind_manifest_framing,
            |error| matches!(error, HeaderReadError::InvalidPayloadFraming(0x02)),
        ),
        (
            "manifest_kind_raw_framing",
            manifest_kind_raw_framing,
            |error| matches!(error, HeaderReadError::InvalidPayloadFraming(0x01)),
        ),
        (
            "unsupported_kdf_profile",
            unsupported_kdf_profile,
            |error| matches!(error, HeaderReadError::InvalidKdfProfile(0x7F)),
        ),
        (
            "unsupported_kdf_param_profile",
            unsupported_kdf_param_profile,
            |error| matches!(error, HeaderReadError::InvalidKdfParamProfile(0x7F)),
        ),
        ("invalid_keyslot_state", invalid_keyslot_state, |error| {
            matches!(
                error,
                HeaderReadError::InvalidSlotState {
                    index: 0,
                    state: 0x03
                }
            )
        }),
        (
            "invalid_physical_slot_index",
            invalid_physical_slot_index,
            |error| {
                matches!(
                    error,
                    HeaderReadError::InvalidPhysicalSlotIndex {
                        expected: 0,
                        actual: 0x03
                    }
                )
            },
        ),
        (
            "truncated_canonical_header",
            truncated_canonical_header,
            |error| matches!(error, HeaderReadError::TruncatedHeader),
        ),
        (
            "truncated_canonical_keyslot_input",
            truncated_canonical_keyslot_input,
            |error| matches!(error, HeaderReadError::TruncatedHeader),
        ),
    ];

    for (case, bytes, matches_expected_variant) in parser_table {
        let error = read_header_error(&bytes);
        assert!(
            matches_expected_variant(&error),
            "{case}: unexpected parser error variant: {error:?}"
        );
    }
}

#[test]
fn v1_header_rejects_keyslot_count_above_max() {
    let mut bytes = support::sample_v1_header().serialize().unwrap();
    bytes[14] = 5;

    let error = dexios_core::header::read_header(&mut std::io::Cursor::new(bytes))
        .expect_err("invalid canonical slot capacity should fail");

    assert!(matches!(
        error,
        HeaderReadError::InvalidKeyslotCount(5)
    ));
}

#[test]
fn v1_header_rejects_invalid_kdf_tag() {
    let mut bytes = support::sample_v1_header().serialize().unwrap();
    bytes[HEADER_STATIC_LEN + 2] = 0xAA;

    let error = dexios_core::header::read_header(&mut std::io::Cursor::new(bytes))
        .expect_err("invalid KDF profile should fail");

    assert!(matches!(
        error,
        HeaderReadError::InvalidKdfProfile(0xAA)
    ));
}

#[test]
fn v1_header_rejects_historical_argon2id_profile_as_unsupported_metadata() {
    let mut bytes = support::sample_v1_header().serialize().unwrap();
    bytes[HEADER_STATIC_LEN + 2] = 0x02;

    let error = dexios_core::header::read_header(&mut std::io::Cursor::new(bytes))
        .expect_err("historical Argon2id profile is unsupported canonical metadata");

    assert!(matches!(error, HeaderReadError::InvalidKdfProfile(0x02)));
}

#[test]
fn v1_header_parses_historical_argon2id_tag_as_unsupported_keyslot_metadata() {
    let mut bytes = support::sample_v1_header().serialize().unwrap();
    bytes[HEADER_STATIC_LEN + 2..HEADER_STATIC_LEN + 4].copy_from_slice(&[0xDF, 0x02]);

    let ParsedHeader::V1(payload) =
        dexios_core::header::read_header(&mut std::io::Cursor::new(bytes))
            .expect("historical Argon2id keyslot tag should remain parseable");

    assert_eq!(
        payload.header().keyslots()[0].kdf(),
        KeyslotKdf::UnsupportedArgon2id
    );
}

#[test]
fn new_keyslot_constructor_uses_supported_kdf_selector() {
    let keyslot = V1Keyslot::new(
        Kdf::Argon2id,
        [11u8; 48],
        KeyslotNonce::new([13u8; 24]),
        HeaderSalt::new([17u8; 16]),
    );
    let header = V1Header::new(PayloadNonce::new([7u8; 20]), V1Keyslots::single(keyslot))
        .expect("sample v1 header");
    let bytes = header.serialize().unwrap();

    assert_eq!(
        &bytes[HEADER_STATIC_LEN..HEADER_STATIC_LEN + 4],
        &[0x01, 0x00, 0x01, 0x01]
    );
}

#[test]
fn canonical_header_serializes_kdf_profile_ids_not_parameter_values() {
    let header = support::sample_v1_header();
    let bytes = header.serialize().unwrap();

    assert_eq!(bytes[13], ARGON2ID_KDF_PARAM_PROFILE_ID);
    assert_eq!(bytes[HEADER_STATIC_LEN + 2], ARGON2ID_KDF_PROFILE_ID);
    assert_eq!(
        bytes[HEADER_STATIC_LEN + 3],
        ARGON2ID_KDF_PARAM_PROFILE_ID
    );

    let header_source = include_str!("../src/header/v1.rs");
    assert!(
        !header_source.contains("ARGON2ID_M_COST"),
        "canonical V1 header must serialize the KDF parameter profile id, not raw parameter knobs"
    );
}

#[test]
fn v1_header_rejects_unsupported_static_kdf_param_profile_before_derivation() {
    let mut bytes = support::sample_v1_header().serialize().unwrap();
    bytes[13] = 0x02;

    let error = dexios_core::header::read_header(&mut std::io::Cursor::new(bytes))
        .expect_err("unsupported static KDF parameter profile should fail during parsing");

    assert!(matches!(
        error,
        HeaderReadError::InvalidKdfParamProfile(0x02)
    ));
}

#[test]
fn v1_header_rejects_active_keyslot_padding() {
    let mut bytes = support::sample_v1_header().serialize().unwrap();
    bytes[HEADER_STATIC_LEN + 92] = 1;

    let error = dexios_core::header::read_header(&mut std::io::Cursor::new(bytes))
        .expect_err("active keyslot padding should fail");

    assert!(matches!(
        error,
        HeaderReadError::NonZeroActiveKeyslotPadding(0)
    ));
}

#[test]
fn v1_header_rejects_inactive_keyslot_bytes() {
    let mut bytes = support::sample_v1_header().serialize().unwrap();
    bytes[HEADER_STATIC_LEN + KEYSLOT_LEN + 2] = 1;

    let error = dexios_core::header::read_header(&mut std::io::Cursor::new(bytes))
        .expect_err("non-zero inactive keyslot bytes should fail");

    assert!(matches!(
        error,
        HeaderReadError::NonZeroInactiveKeyslotPadding(1)
    ));
}

#[test]
fn v1_header_rejects_nonzero_reserved_bytes() {
    let mut bytes = support::sample_v1_header().serialize().unwrap();
    bytes[15] = 1;

    let error = dexios_core::header::read_header(&mut std::io::Cursor::new(bytes))
        .expect_err("non-zero reserved byte should fail");

    assert!(matches!(
        error,
        HeaderReadError::NonZeroReservedBytes
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
        EncryptedMasterKey::try_from_slice(&[0u8; 47]),
        Err(HeaderReadError::InvalidEncryptedMasterKeyLength(47))
    ));
}

#[test]
fn with_keyslots_preserves_manifest_archive_payload_metadata() {
    let source = V1Header::new_manifest_archive(
        PayloadNonce::new([9u8; 20]),
        V1Keyslots::single(V1Keyslot::new(
            Kdf::Argon2id,
            [11u8; 48],
            KeyslotNonce::new([13u8; 24]),
            HeaderSalt::new([17u8; 16]),
        )),
    )
    .expect("manifest archive source header");

    let new_keyslots = V1Keyslots::single(V1Keyslot::new(
        Kdf::Argon2id,
        [22u8; 48],
        KeyslotNonce::new([23u8; 24]),
        HeaderSalt::new([27u8; 16]),
    ));
    let rebuilt = source
        .with_keyslots(new_keyslots)
        .expect("with_keyslots must succeed");

    assert_eq!(rebuilt.payload_kind(), PayloadKind::ManifestArchive);
    assert_eq!(
        rebuilt.payload_framing(),
        PayloadFramingProfile::ManifestFirst
    );
    assert_eq!(
        rebuilt.payload_nonce().as_bytes(),
        source.payload_nonce().as_bytes()
    );
    assert_eq!(rebuilt.keyslots()[0].encrypted_master_key(), &[22u8; 48]);
    // AINT-01: the static header AAD is a pure function of payload_kind /
    // payload_framing / payload_nonce, so a key rotation MUST leave it byte
    // identical even though the keyslot table changed. Assert the guarantee
    // directly rather than relying on the individual-field assertions above to
    // imply it (closes the regression surface if aad() ever grows a new input).
    assert_eq!(
        rebuilt.aad().as_bytes(),
        source.aad().as_bytes(),
        "AINT-01: with_keyslots must preserve the archive AAD across key rotation"
    );
}

#[test]
fn with_keyslots_preserves_raw_file_payload_metadata() {
    let source = support::sample_v1_header(); // RawFile / RawLe31
    let rebuilt = source
        .with_keyslots(source.keyslots_collection().clone())
        .expect("with_keyslots round-trip");

    assert_eq!(rebuilt.payload_kind(), PayloadKind::RawFile);
    assert_eq!(rebuilt.payload_framing(), PayloadFramingProfile::RawLe31);
    assert_eq!(rebuilt, source); // PartialEq round-trip
}
