use dexios_core::header::HeaderVersion;
use dexios_core::key::{argon2id_hash, balloon_hash};
use dexios_core::protected::Protected;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct VectorFile {
    vector: Vec<KdfVector>,
}

#[derive(Deserialize)]
struct KdfVector {
    algorithm: String,
    version: String,
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

fn find_vector<'a>(vectors: &'a [KdfVector], algorithm: &str, version: &str) -> &'a KdfVector {
    vectors
        .iter()
        .find(|vector| vector.algorithm == algorithm && vector.version == version)
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

#[test]
fn kdf_vector_file_contains_expected_cases() {
    let vectors = load_vectors();
    assert!(
        vectors
            .iter()
            .any(|vector| vector.algorithm == "argon2id" && vector.version == "V1")
    );
    assert!(
        vectors
            .iter()
            .any(|vector| vector.algorithm == "balloon" && vector.version == "V5")
    );

    for vector in &vectors {
        assert!(!vector.provenance.is_empty());
        assert!(vector.metadata.contains_key("source_kind"));
        assert!(vector.metadata.contains_key("source_name"));

        match vector.algorithm.as_str() {
            "argon2id" => {
                assert!(vector.metadata.contains_key("source_version"));
                assert!(vector.metadata.contains_key("source_entrypoint"));
                assert!(vector.metadata.contains_key("params_memory_kib"));
                assert!(vector.metadata.contains_key("params_time_cost"));
                assert!(vector.metadata.contains_key("params_parallelism"));
                assert!(vector.metadata.contains_key("params_hash_len"));
            }
            "balloon" => {
                assert!(vector.metadata.contains_key("source_repo"));
                assert!(vector.metadata.contains_key("source_commit"));
                assert!(vector.metadata.contains_key("source_hash_primitive"));
                assert!(vector.metadata.contains_key("params_space_cost"));
                assert!(vector.metadata.contains_key("params_time_cost"));
                assert!(vector.metadata.contains_key("params_delta"));
            }
            other => panic!("unexpected KDF algorithm in testdata: {other}"),
        }
    }
}

fn assert_argon2_vector(version: HeaderVersion, version_id: &str) {
    let vectors = load_vectors();
    let vector = find_vector(&vectors, "argon2id", version_id);
    let salt = decode_hex::<16>(&vector.salt_hex);
    let expected = decode_hex::<32>(&vector.expected_hex);
    let key = argon2id_hash(Protected::new(vector.password.as_bytes().to_vec()), &salt, &version)
        .expect("argon2 hash");

    assert_eq!(key.expose(), &expected);
}

fn assert_balloon_vector(version: HeaderVersion, version_id: &str) {
    let vectors = load_vectors();
    let vector = find_vector(&vectors, "balloon", version_id);
    let salt = decode_hex::<16>(&vector.salt_hex);
    let expected = decode_hex::<32>(&vector.expected_hex);
    let key = balloon_hash(Protected::new(vector.password.as_bytes().to_vec()), &salt, &version)
        .expect("balloon hash");

    assert_eq!(key.expose(), &expected);
}

#[test]
fn argon2id_v1_matches_known_vector() {
    assert_argon2_vector(HeaderVersion::V1, "V1");
}

#[test]
fn argon2id_v2_matches_known_vector() {
    assert_argon2_vector(HeaderVersion::V2, "V2");
}

#[test]
fn argon2id_v3_matches_known_vector() {
    assert_argon2_vector(HeaderVersion::V3, "V3");
}

#[test]
fn balloon_hash_v4_matches_known_vector() {
    assert_balloon_vector(HeaderVersion::V4, "V4");
}

#[test]
fn balloon_hash_v5_matches_known_vector() {
    assert_balloon_vector(HeaderVersion::V5, "V5");
}
