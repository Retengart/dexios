use dexios_core::header::HeaderVersion;
use dexios_core::key::{argon2id_hash, balloon_hash};
use dexios_core::protected::Protected;

fn assert_argon2_vector(version: HeaderVersion, salt: [u8; 16], expected: [u8; 32]) {
    let key = argon2id_hash(Protected::new(b"test-password".to_vec()), &salt, &version)
        .expect("argon2 hash");

    assert_eq!(key.expose(), &expected);
}

fn assert_balloon_vector(version: HeaderVersion, salt: [u8; 16], expected: [u8; 32]) {
    let key = balloon_hash(Protected::new(b"test-password".to_vec()), &salt, &version)
        .expect("balloon hash");

    assert_eq!(key.expose(), &expected);
}

#[test]
fn argon2id_v1_matches_known_vector() {
    assert_argon2_vector(
        HeaderVersion::V1,
        [1u8; 16],
        [
            235, 25, 229, 163, 131, 5, 207, 223, 87, 2, 224, 123, 68, 166, 74, 100, 210, 164, 130,
            29, 62, 86, 80, 221, 103, 49, 102, 222, 58, 208, 243, 103,
        ],
    );
}

#[test]
fn argon2id_v2_matches_known_vector() {
    assert_argon2_vector(
        HeaderVersion::V2,
        [2u8; 16],
        [
            86, 162, 141, 4, 76, 82, 19, 1, 104, 244, 232, 246, 80, 15, 247, 227, 223, 10, 152,
            127, 211, 55, 171, 77, 196, 178, 182, 115, 55, 222, 58, 40,
        ],
    );
}

#[test]
fn argon2id_v3_matches_known_vector() {
    assert_argon2_vector(
        HeaderVersion::V3,
        [3u8; 16],
        [
            212, 156, 207, 30, 87, 168, 212, 163, 138, 3, 154, 222, 198, 164, 143, 103, 102, 93,
            155, 50, 98, 229, 113, 166, 201, 91, 231, 100, 124, 241, 36, 139,
        ],
    );
}

#[test]
fn balloon_hash_v4_matches_known_vector() {
    assert_balloon_vector(
        HeaderVersion::V4,
        [4u8; 16],
        [
            246, 64, 48, 185, 149, 188, 20, 145, 61, 245, 232, 199, 212, 215, 91, 19, 108, 130,
            168, 222, 249, 203, 243, 198, 130, 66, 64, 218, 111, 189, 79, 11,
        ],
    );
}

#[test]
fn balloon_hash_v5_matches_known_vector() {
    assert_balloon_vector(
        HeaderVersion::V5,
        [5u8; 16],
        [
            176, 159, 223, 18, 174, 67, 221, 115, 122, 112, 7, 240, 222, 183, 195, 193, 105, 43,
            203, 36, 151, 245, 42, 132, 93, 123, 249, 213, 227, 241, 172, 35,
        ],
    );
}
