#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::unreachable, clippy::string_slice, clippy::too_many_lines, clippy::cast_possible_truncation, clippy::cast_possible_wrap, clippy::cast_sign_loss, clippy::cast_precision_loss, clippy::match_same_arms, clippy::items_after_statements, clippy::redundant_closure_for_method_calls, clippy::needless_collect, clippy::manual_let_else, clippy::format_collect, clippy::case_sensitive_file_extension_comparisons, clippy::struct_excessive_bools, reason = "integration tests assert exact behavior and may panic on failure"))]
use dexios_core::header::common::{KeyslotNonce, PayloadNonce, Salt};
use dexios_core::header::v1::{V1Header, V1Keyslot, V1KeyslotIndex, V1Keyslots};
use dexios_core::kdf::Kdf;
use dexios_core::key::{VecToArrayLengthError, vec_to_arr};
use dexios_core::primitives::MasterKey;
use dexios_core::stream::V1PayloadDecryptingReader;
use std::io::Cursor;

const KEY_RS: &str = include_str!("../src/key.rs");
const PRIMITIVES_RS: &str = include_str!("../src/primitives.rs");
const STREAM_RS: &str = include_str!("../src/stream.rs");
const V1_RS: &str = include_str!("../src/header/v1.rs");
const CARGO_TOML: &str = include_str!("../Cargo.toml");

fn sample_keyslot(seed: u8) -> V1Keyslot {
    V1Keyslot::new(
        Kdf::Argon2id,
        [seed; 48],
        KeyslotNonce::new([seed.wrapping_add(1); 24]),
        Salt::new([seed.wrapping_add(2); 16]),
    )
}

fn sample_two_slot_header() -> V1Header {
    V1Header::new(
        PayloadNonce::new([7u8; 20]),
        V1Keyslots::try_from_vec(vec![sample_keyslot(11), sample_keyslot(21)])
            .expect("sample two-slot keyslot table"),
    )
    .expect("sample two-slot header")
}

#[test]
fn slot_wrapping_aad_uses_only_keyslots_owned_by_the_header() {
    let header = sample_two_slot_header();

    let slot_zero_aad = header
        .slot_wrapping_aad_for_physical_slot(
            V1KeyslotIndex::try_from_physical_index(0).expect("slot zero index"),
        )
        .expect("slot zero wrapping aad");
    let slot_one_aad = header
        .slot_wrapping_aad_for_physical_slot(
            V1KeyslotIndex::try_from_physical_index(1).expect("slot one index"),
        )
        .expect("slot one wrapping aad");

    assert_ne!(slot_zero_aad, slot_one_aad);
    let public_slot_wrapping_signatures_accepting_keyslots = V1_RS
        .match_indices("pub fn ")
        .filter_map(|(index, _)| {
            let tail = &V1_RS[index..];
            tail.find('{')
                .map(|signature_end| tail[..signature_end].split_whitespace().collect::<String>())
        })
        .filter(|signature| {
            signature.contains("slot_wrapping_aad") && signature.contains("&V1Keyslot")
        })
        .collect::<Vec<_>>();
    assert!(
        public_slot_wrapping_signatures_accepting_keyslots.is_empty(),
        "slot wrapping AAD must not accept a detached caller-supplied keyslot: {public_slot_wrapping_signatures_accepting_keyslots:?}"
    );
    assert!(
        V1_RS.contains("pub fn slot_wrapping_aad_for_physical_slot"),
        "slot wrapping AAD must be derived from this header's own keyslot table"
    );
    assert!(
        !V1_RS.contains("pub fn for_physical_index"),
        "public keyslot API must not let callers forge detached physical indices"
    );
}

#[test]
fn vec_to_arr_rejects_key_material_with_the_wrong_length() {
    let short = vec_to_arr::<4>(vec![1, 2, 3]).expect_err("short input must not be zero-padded");
    assert_eq!(
        short,
        VecToArrayLengthError {
            expected: 4,
            actual: 3
        }
    );

    let long = vec_to_arr::<4>(vec![1, 2, 3, 4, 5]).expect_err("long input must not be truncated");
    assert_eq!(
        long,
        VecToArrayLengthError {
            expected: 4,
            actual: 5
        }
    );
}

#[test]
fn vec_to_arr_preserves_exact_length_key_material() {
    let key = vec_to_arr::<4>(vec![1, 2, 3, 4]).expect("exact-length input is accepted");

    assert_eq!(key, [1, 2, 3, 4]);
    assert!(
        KEY_RS.contains("Result<[u8; N], VecToArrayLengthError>"),
        "vec_to_arr must expose a checked Result boundary"
    );
    assert!(
        !KEY_RS.contains("N.min(master_key_vec.len())"),
        "vec_to_arr must not silently truncate or zero-pad input"
    );
}

#[test]
fn master_key_same_secret_as_preserves_equality_semantics_without_direct_array_equality() {
    let first = MasterKey::new([31u8; 32]);
    let same = MasterKey::new([31u8; 32]);
    let different = MasterKey::new([32u8; 32]);

    assert!(first.same_secret_as(&same));
    assert!(!first.same_secret_as(&different));
    assert!(
        !PRIMITIVES_RS.contains("left == right"),
        "same_secret_as must not use direct array equality for secret material"
    );
    assert!(
        PRIMITIVES_RS.contains("use subtle::ConstantTimeEq;"),
        "same_secret_as must use the crypto constant-time equality primitive directly"
    );
    assert!(
        CARGO_TOML.contains("subtle"),
        "dexios-core must declare subtle as a direct dependency for secret equality"
    );
}

#[test]
fn stream_reader_public_api_does_not_implement_standard_read() {
    static_assertions::assert_not_impl_any!(
        V1PayloadDecryptingReader<Cursor<Vec<u8>>>: std::io::Read
    );
    assert!(
        !STREAM_RS.contains("impl<R: Read> Read for V1PayloadDecryptingReader<R>"),
        "public decrypting reader must not implement standard Read for pre-auth plaintext"
    );
    assert!(
        STREAM_RS.contains("read_uncommitted"),
        "pre-auth plaintext reads must be exposed only through an explicit uncommitted API"
    );
    assert!(
        !STREAM_RS.contains("pub fn decrypt_file("),
        "public file-level decrypt helper must not hide pre-auth plaintext publication behind a generic name"
    );
    assert!(
        STREAM_RS.contains("decrypt_file_uncommitted"),
        "file-level decrypt helper must label pre-auth plaintext as uncommitted"
    );
}
