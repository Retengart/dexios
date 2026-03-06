use dexios_core::header::HeaderVersion;
use dexios_core::key::{argon2id_hash, balloon_hash};
use dexios_core::protected::Protected;

#[test]
fn argon2id_hash_is_deterministic_for_v3() {
    let salt = [3u8; 16];
    let one = argon2id_hash(
        Protected::new(b"test-password".to_vec()),
        &salt,
        &HeaderVersion::V3,
    )
    .expect("argon2 hash");
    let two = argon2id_hash(
        Protected::new(b"test-password".to_vec()),
        &salt,
        &HeaderVersion::V3,
    )
    .expect("argon2 hash");

    assert_eq!(one.expose(), two.expose());
    assert_eq!(one.expose().len(), 32);
}

#[test]
fn balloon_hash_is_deterministic_for_v5() {
    let salt = [7u8; 16];
    let one = balloon_hash(
        Protected::new(b"test-password".to_vec()),
        &salt,
        &HeaderVersion::V5,
    )
    .expect("balloon hash");
    let two = balloon_hash(
        Protected::new(b"test-password".to_vec()),
        &salt,
        &HeaderVersion::V5,
    )
    .expect("balloon hash");

    assert_eq!(one.expose(), two.expose());
    assert_eq!(one.expose().len(), 32);
}
