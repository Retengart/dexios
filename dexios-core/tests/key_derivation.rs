use dexios_core::kdf::{
    BLAKE3_BALLOON_ALGORITHM_DELTA, BLAKE3_BALLOON_P_COST, BLAKE3_BALLOON_SPACE_COST,
    BLAKE3_BALLOON_TIME_COST, Kdf, Salt,
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
        .derive(Protected::new(vector.password.as_bytes().to_vec()), &salt)
        .expect("KDF hash");

    assert_eq!(key.expose(), &expected);
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
            "balloon" => {
                assert!(vector.metadata.contains_key("source_repo"));
                assert!(vector.metadata.contains_key("source_commit"));
                assert!(vector.metadata.contains_key("source_hash_primitive"));
                assert!(vector.metadata.contains_key("params_space_cost"));
                assert!(vector.metadata.contains_key("params_time_cost"));
                assert!(vector.metadata.contains_key("params_p_cost"));
                assert!(vector.metadata.contains_key("params_delta"));
            }
            other => panic!("unexpected KDF algorithm in testdata: {other}"),
        }
    }

    assert!(
        vectors.iter().all(|vector| vector.algorithm != "argon2id"),
        "Argon2id is a historical unsupported keyslot tag, not a normal KDF vector"
    );
    assert!(
        vectors
            .iter()
            .any(|vector| vector.algorithm == "balloon" && vector.case == "stable")
    );
}

#[test]
fn normal_kdf_selector_is_blake3_balloon_only() {
    let supported = [Kdf::Blake3Balloon];

    for selector in supported {
        match selector {
            Kdf::Blake3Balloon => {}
        }
    }
}

#[test]
fn blake3_balloon_derives_a_32_byte_key() {
    let derived = Kdf::Blake3Balloon
        .derive(Protected::new(b"password".to_vec()), &Salt::new([9; 16]))
        .unwrap();
    assert_eq!(derived.expose().len(), 32);
}

#[test]
fn blake3_balloon_vector_metadata_matches_frozen_contract() {
    let vectors = load_vectors();
    let vector = find_vector(&vectors, "balloon", "stable");

    assert_eq!(
        vector.metadata["params_space_cost"].as_integer(),
        Some(i64::from(BLAKE3_BALLOON_SPACE_COST))
    );
    assert_eq!(
        vector.metadata["params_time_cost"].as_integer(),
        Some(i64::from(BLAKE3_BALLOON_TIME_COST))
    );
    assert_eq!(
        vector.metadata["params_p_cost"].as_integer(),
        Some(i64::from(BLAKE3_BALLOON_P_COST))
    );
    assert_eq!(
        vector.metadata["params_delta"].as_integer(),
        Some(i64::from(BLAKE3_BALLOON_ALGORITHM_DELTA))
    );
}

#[test]
fn balloon_matches_stable_known_vector() {
    assert_vector(Kdf::Blake3Balloon, "balloon", "stable");
}
