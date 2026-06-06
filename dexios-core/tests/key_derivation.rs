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
use dexios_core::kdf::{
    ARGON2ID_KDF_PARAM_PROFILE_ID, ARGON2ID_KDF_PROFILE_ID, ARGON2ID_M_COST, ARGON2ID_OUTPUT_LEN,
    ARGON2ID_P_COST, ARGON2ID_SALT_LEN, ARGON2ID_T_COST, Kdf, Salt,
};
use dexios_core::protected::Protected;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

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
    provenance: String,
    #[serde(flatten)]
    metadata: BTreeMap<String, toml::Value>,
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
fn kdf_vector_file_contains_expected_cases() {
    let vectors = load_vectors();
    let mut seen_pairs = BTreeSet::new();

    for vector in &vectors {
        assert!(seen_pairs.insert((vector.algorithm.as_str(), vector.case.as_str())));
        assert!(!vector.provenance.is_empty());
        assert!(vector.metadata.contains_key("source_kind"));
        assert!(vector.metadata.contains_key("source_name"));

        match vector.algorithm.as_str() {
            "argon2id" => {
                assert!(vector.metadata.contains_key("params_m_cost"));
                assert!(vector.metadata.contains_key("params_t_cost"));
                assert!(vector.metadata.contains_key("params_p_cost"));
            }
            other => panic!("unexpected KDF algorithm in testdata: {other}"),
        }
    }

    assert!(
        vectors.iter().all(|vector| vector.algorithm != "balloon"),
        "BLAKE3-Balloon was retired in the crypto-1 Argon2id migration; no balloon vectors remain"
    );
    assert!(
        vectors
            .iter()
            .any(|vector| vector.algorithm == "argon2id" && vector.case == "stable")
    );
}

#[test]
fn normal_kdf_selector_is_argon2id_only() {
    let supported = [Kdf::Argon2id];

    for selector in supported {
        match selector {
            Kdf::Argon2id => {}
        }
    }
}

#[test]
fn argon2id_derives_a_32_byte_key() {
    let derived = Kdf::Argon2id
        .derive(&Protected::new(b"password".to_vec()), &Salt::new([9; 16]))
        .unwrap();
    derived.with_exposed(|key_bytes| assert_eq!(key_bytes.len(), 32));
}

#[test]
fn argon2id_vector_metadata_matches_frozen_contract() {
    let vectors = load_vectors();
    let vector = find_vector(&vectors, "argon2id", "stable");

    assert_eq!(
        vector.metadata["params_m_cost"].as_integer(),
        Some(i64::from(ARGON2ID_M_COST))
    );
    assert_eq!(
        vector.metadata["params_t_cost"].as_integer(),
        Some(i64::from(ARGON2ID_T_COST))
    );
    assert_eq!(
        vector.metadata["params_p_cost"].as_integer(),
        Some(i64::from(ARGON2ID_P_COST))
    );
}

#[test]
fn canonical_argon2id_profile_ids_match_frozen_params() {
    assert_eq!(ARGON2ID_KDF_PROFILE_ID, 0x01);
    assert_eq!(ARGON2ID_KDF_PARAM_PROFILE_ID, 0x01);
    assert_eq!(ARGON2ID_M_COST, 262_144); // 256 MiB at 1 KiB blocks
    assert_eq!(ARGON2ID_T_COST, 4);
    assert_eq!(ARGON2ID_P_COST, 4);
    assert_eq!(ARGON2ID_OUTPUT_LEN, 32);
    assert_eq!(ARGON2ID_SALT_LEN, 16);
}

#[test]
fn workspace_manifest_source_gates_kdf_dependency_policy() {
    let workspace_manifest: toml::Value =
        toml::from_str(include_str!("../../Cargo.toml")).expect("valid workspace manifest");
    let workspace_deps = workspace_manifest["workspace"]["dependencies"]
        .as_table()
        .expect("workspace dependencies table");

    let argon2 = workspace_deps
        .get("argon2")
        .and_then(toml::Value::as_table)
        .expect("argon2 uses explicit workspace dependency table");
    assert_eq!(
        argon2.get("version").and_then(toml::Value::as_str),
        Some("0.5.3")
    );
    assert_eq!(
        argon2
            .get("default-features")
            .and_then(toml::Value::as_bool),
        Some(false),
        "argon2 must disable default features (no PHC parser / std)"
    );
    let argon2_features = argon2
        .get("features")
        .and_then(toml::Value::as_array)
        .expect("argon2 feature policy is explicit")
        .iter()
        .map(|feature| feature.as_str().expect("feature is a string"))
        .collect::<BTreeSet<_>>();
    assert_eq!(argon2_features, BTreeSet::from(["alloc", "zeroize"]));

    // balloon-hash must be fully gone from the workspace dependency surface.
    assert!(
        workspace_deps.get("balloon-hash").is_none(),
        "balloon-hash was retired by the crypto-1 Argon2id migration"
    );

    let core_manifest: toml::Value =
        toml::from_str(include_str!("../Cargo.toml")).expect("valid core manifest");
    let core_deps = core_manifest["dependencies"]
        .as_table()
        .expect("core dependencies table");
    assert_eq!(
        core_deps["argon2"]["workspace"].as_bool(),
        Some(true),
        "dexios-core must inherit the workspace argon2 dependency policy"
    );
    // dexios-core no longer derives keys from blake3 (it was only balloon-hash's hash
    // primitive); content hashing lives in dexios-domain.
    assert!(
        core_deps.get("blake3").is_none(),
        "dexios-core must not depend on blake3 after the Argon2id migration"
    );
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
