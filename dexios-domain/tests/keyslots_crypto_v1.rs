#[path = "support/keyslots_v1.rs"]
mod keyslots_support;

use keyslots_support::*;

#[test]
fn encrypt_writes_argon2id_keyslot() {
    let encrypted = encrypted_v1_fixture();

    assert_eq!(keyslot_kdfs(&encrypted), [KeyslotKdf::Argon2id]);
}
#[test]
fn argon2id_only_keyslot_returns_unsupported_kdf_for_verify() {
    let encrypted = encrypted_v1_fixture();
    mark_keyslot_unsupported_argon2id(&encrypted, 0);

    let verify = verify_fixture(&encrypted, b"old-pass");

    assert!(matches!(
        verify,
        Err(key::Error::UnsupportedKdf([0xDF, 0x02]))
    ));
}
#[test]
fn argon2id_only_keyslot_returns_unsupported_kdf_for_decrypt() {
    let encrypted = encrypted_v1_fixture();
    mark_keyslot_unsupported_argon2id(&encrypted, 0);

    let decrypt = decrypt_fixture(&encrypted, b"old-pass");

    assert!(matches!(
        decrypt,
        Err(decrypt::Error::UnsupportedKdf([0xDF, 0x02]))
    ));
}
#[test]
fn decrypt_v1_master_key_tries_later_supported_keyslot_without_raw_key_clone_contract() {
    let encrypted = encrypted_v1_fixture();

    append_synthetic_second_keyslot(&encrypted, b"old-pass", b"new-pass");

    let (_master_key, index) = key::decrypt_v1_master_key_with_index(
        &read_v1_header_from_cursor(&encrypted),
        Protected::new(b"new-pass".to_vec()),
    )
    .expect("later supported keyslot should decrypt");

    assert_eq!(
        index.get(),
        1,
        "wrong first keyslot should not prevent trying the later supported keyslot"
    );
}
#[test]
fn unsupported_kdf_wins_when_no_supported_keyslot_decrypts() {
    let encrypted = encrypted_v1_fixture();

    append_synthetic_second_keyslot(&encrypted, b"old-pass", b"new-pass");
    mark_keyslot_unsupported_argon2id(&encrypted, 0);

    let decrypt = key::decrypt_v1_master_key_with_index(
        &read_v1_header_from_cursor(&encrypted),
        Protected::new(b"wrong-pass".to_vec()),
    );

    assert!(matches!(
        decrypt,
        Err(key::Error::UnsupportedKdf([0xDF, 0x02]))
    ));
}
#[test]
fn domain_key_decrypt_source_avoids_raw_key_clone_and_unwrap_regressions() {
    let forbidden = ["raw_key_old.clone()", ".unwrap()"];

    for pattern in forbidden {
        assert!(
            !DOMAIN_KEY_SOURCE.contains(pattern),
            "`dexios-domain/src/key.rs` must not contain `{pattern}` in the keyslot decrypt path"
        );
    }
}
#[test]
fn domain_encrypt_add_change_sources_keep_borrowed_secret_contract() {
    let sources = [
        ("dexios-domain/src/encrypt.rs", DOMAIN_ENCRYPT_SOURCE),
        ("dexios-domain/src/key.rs", DOMAIN_KEY_SOURCE),
        ("dexios-domain/src/key/add.rs", DOMAIN_KEY_ADD_SOURCE),
        ("dexios-domain/src/key/change.rs", DOMAIN_KEY_CHANGE_SOURCE),
    ];
    let forbidden = [
        ".expose(",
        "raw_key.clone()",
        "raw_key_old.clone()",
        "raw_key_new.clone()",
    ];

    for (path, source) in sources {
        for pattern in forbidden {
            assert!(
                !source.contains(pattern),
                "`{path}` must not contain `{pattern}` after the borrowed secret API migration"
            );
        }
    }

    assert!(
        DOMAIN_ENCRYPT_SOURCE.contains(".derive(&raw_key,"),
        "`encrypt.rs` should borrow raw_key for KDF derivation"
    );
    assert!(
        DOMAIN_KEY_SOURCE.contains(".derive(&raw_key_old,"),
        "`key.rs` should borrow raw_key_old while trying keyslots"
    );
    assert!(
        DOMAIN_KEY_ADD_SOURCE.contains(".derive(&new_key_secret,"),
        "`key/add.rs` should borrow the new key secret for replacement keyslot derivation"
    );
    assert!(
        DOMAIN_KEY_CHANGE_SOURCE.contains(".derive(&raw_key_new,"),
        "`key/change.rs` should borrow raw_key_new for replacement keyslot derivation"
    );
}
#[test]
fn supported_keyslot_verifies_when_mixed_with_unsupported_argon2id() {
    let encrypted = encrypted_v1_fixture();

    append_synthetic_second_keyslot(&encrypted, b"old-pass", b"new-pass");
    mark_keyslot_unsupported_argon2id(&encrypted, 0);

    verify_fixture(&encrypted, b"new-pass").expect("supported keyslot should still verify");
}
#[test]
fn wrong_key_current_v1_fixture_rejects_verification_and_decrypt() {
    // Manifest fixture: wrong-key-current-v1.
    let encrypted = encrypted_v1_fixture();

    let wrong_verify = verify_fixture(&encrypted, b"wrong-pass");
    assert!(matches!(wrong_verify, Err(key::Error::IncorrectKey)));

    let wrong_decrypt = decrypt_fixture(&encrypted, b"wrong-pass");
    assert!(matches!(
        wrong_decrypt,
        Err(decrypt::Error::DecryptMasterKey)
    ));
}
#[test]
fn mutating_initial_keyslot_nonce_breaks_keyslot_unwrap_authentication() {
    let (_dir, encrypted_path) = encrypted_v1_file("slot-nonce-auth");

    mutate_slot_nonce_file(&encrypted_path, 0);

    assert!(matches!(
        verify_file(&encrypted_path, b"old-pass"),
        Err(key::Error::IncorrectKey)
    ));
    assert!(matches!(
        decrypt_file(&encrypted_path, b"old-pass"),
        Err(decrypt::Error::DecryptMasterKey)
    ));
}
#[test]
fn mutating_payload_nonce_breaks_payload_authentication_with_proven_master_key() {
    let (_dir, encrypted_path) = encrypted_v1_file("payload-nonce-auth");
    let original_header = read_v1_header_from_path(&encrypted_path);
    let (master_key, _) = key::decrypt_v1_master_key_with_index(
        &original_header,
        Protected::new(b"old-pass".to_vec()),
    )
    .expect("old key must unwrap original master key before payload nonce mutation");

    mutate_payload_nonce_file(&encrypted_path);
    let mutated = fs::read(&encrypted_path).expect("read mutated encrypted fixture");
    let mut reader = Cursor::new(mutated);
    let parsed = read_header(&mut reader).expect("mutated canonical header remains parseable");
    let ParsedHeader::V1(payload) = parsed;
    let mut plaintext = Vec::new();

    let result = V1PayloadStream::decrypt_file_uncommitted(
        master_key,
        &payload,
        &mut reader,
        &mut plaintext,
    );

    assert!(
        result.is_err(),
        "payload nonce participates in stream AAD/nonce authentication"
    );
    assert!(plaintext.is_empty());
}
