#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::unreachable,
        clippy::string_slice,
        clippy::too_many_lines,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        clippy::match_same_arms,
        clippy::items_after_statements,
        clippy::redundant_closure_for_method_calls,
        clippy::needless_collect,
        clippy::manual_let_else,
        clippy::format_collect,
        clippy::case_sensitive_file_extension_comparisons,
        clippy::struct_excessive_bools,
        reason = "integration tests assert exact behavior and may panic on failure"
    )
)]
use dexios_core::kdf::{Kdf, Salt};
use dexios_core::protected::Protected;
use serde::Deserialize;

#[derive(Deserialize)]
struct VectorFile {
    vector: Vec<KdfVector>,
}

#[derive(Deserialize)]
struct KdfVector {
    algorithm: String,
    case: String,
    password: String,
    salt_hex: String,
    expected_hex: String,
}

fn load_vectors() -> Vec<KdfVector> {
    toml::from_str::<VectorFile>(include_str!("testdata/kdf_vectors.toml"))
        .expect("valid KDF vector file")
        .vector
}

fn find_vector<'a>(vectors: &'a [KdfVector], algorithm: &str, case: &str) -> &'a KdfVector {
    vectors
        .iter()
        .find(|vector| vector.algorithm == algorithm && vector.case == case)
        .expect("known KDF vector")
}

fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
    let bytes = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let chunk = std::str::from_utf8(chunk).expect("valid utf-8 hex");
            u8::from_str_radix(chunk, 16).expect("valid hex byte")
        })
        .collect::<Vec<_>>();
    bytes.try_into().expect("hex value with expected length")
}

fn assert_vector(algorithm: Kdf, algorithm_name: &str, case: &str) {
    let vectors = load_vectors();
    let vector = find_vector(&vectors, algorithm_name, case);
    let salt = Salt::new(decode_hex::<16>(&vector.salt_hex));
    let expected = decode_hex::<32>(&vector.expected_hex);
    let key = algorithm
        .derive(&Protected::new(vector.password.as_bytes().to_vec()), &salt)
        .expect("KDF hash");

    key.with_exposed(|key_bytes| assert_eq!(key_bytes, &expected));
}

#[test]
fn argon2id_derives_a_32_byte_key() {
    let derived = Kdf::Argon2id
        .derive(&Protected::new(b"password".to_vec()), &Salt::new([9; 16]))
        .unwrap();
    derived.with_exposed(|key_bytes| assert_eq!(key_bytes.len(), 32));
}

#[test]
fn argon2id_matches_stable_known_vector() {
    assert_vector(Kdf::Argon2id, "argon2id", "stable");
}

#[test]
fn argon2id_distinct_inputs_yield_distinct_keys() {
    let password = Protected::new(b"test-password".to_vec());
    let base = Kdf::Argon2id
        .derive(&password, &Salt::new([5u8; 16]))
        .unwrap();
    let other_salt = Kdf::Argon2id
        .derive(&password, &Salt::new([6u8; 16]))
        .unwrap();
    let other_password = Kdf::Argon2id
        .derive(
            &Protected::new(b"test-password!".to_vec()),
            &Salt::new([5u8; 16]),
        )
        .unwrap();

    base.with_exposed(|base| {
        assert_ne!(base, &[0u8; 32], "derived key must not be all zeros");
        other_salt.with_exposed(|other| assert_ne!(base, other, "salt must change the key"));
        other_password
            .with_exposed(|other| assert_ne!(base, other, "password must change the key"));
    });
}
