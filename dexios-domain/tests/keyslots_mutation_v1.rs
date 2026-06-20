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
#[path = "support/keyslots_v1.rs"]
mod keyslots_support;

use keyslots_support::*;

#[test]
fn key_del_rejects_final_keyslot_before_writing_header() {
    let (_dir, encrypted_path) = encrypted_v1_file("delete-final-before-write");
    let original = fs::read(&encrypted_path).expect("read original fixture");

    let intent = key::delete::DeleteIntent::new(&encrypted_path).expect("prepare delete intent");
    let deletion = key::delete::execute(intent, Protected::new(b"old-pass".to_vec()));

    assert!(
        deletion.is_err(),
        "deleting the final usable keyslot should be rejected before writing the header"
    );
    assert_eq!(
        fs::read(&encrypted_path).expect("read after final-slot delete"),
        original
    );

    let plaintext = decrypt_file(&encrypted_path, b"old-pass").expect("decrypt with original key");
    assert_eq!(plaintext, b"Hello world");
}
#[test]
fn key_add_commits_second_keyslot_without_breaking_existing_decrypt() {
    let encrypted = encrypted_v1_fixture();
    let (_temp_dir, temp_dir_path) = canonical_tempdir();
    let encrypted_path = temp_dir_path.join("plain.enc");
    fs::write(&encrypted_path, encrypted.borrow().get_ref()).expect("write encrypted fixture");
    let original = fs::read(&encrypted_path).expect("read original fixture");

    let intent = key::add::AddIntent::new(&encrypted_path).expect("prepare key add intent");
    let proven = intent
        .verify_old_key(Protected::new(b"old-pass".to_vec()))
        .expect("old key proof");
    key::add::execute(proven, Protected::new(b"new-pass".to_vec()), Kdf::Argon2id)
        .expect("add second keyslot");

    let changed = fs::read(&encrypted_path).expect("read after add");
    assert_eq!(
        &changed[HEADER_LEN..],
        &original[HEADER_LEN..],
        "key add must preserve payload bytes"
    );

    let plaintext = decrypt_file(&encrypted_path, b"old-pass").expect("decrypt with original key");
    assert_eq!(plaintext, b"Hello world");
    let plaintext = decrypt_file(&encrypted_path, b"new-pass").expect("decrypt with added key");
    assert_eq!(plaintext, b"Hello world");
}
#[test]
fn key_change_failure_preserves_original_header() {
    let encrypted = encrypted_v1_fixture();
    let (_temp_dir, temp_dir_path) = canonical_tempdir();
    let encrypted_path = temp_dir_path.join("plain.enc");
    fs::write(&encrypted_path, encrypted.borrow().get_ref()).expect("write encrypted fixture");
    let original = fs::read(&encrypted_path).expect("read original fixture");

    let intent = key::change::ChangeIntent::new(&encrypted_path).expect("prepare change intent");
    let result = intent.verify_old_key(Protected::new(b"wrong-pass".to_vec()));

    assert!(matches!(result, Err(key::Error::IncorrectKey)));
    let after = fs::read(&encrypted_path).expect("read preserved fixture");
    assert_eq!(&after[..HEADER_LEN], &original[..HEADER_LEN]);
    assert_eq!(after, original);
}
#[test]
fn key_change_rejects_target_changed_after_old_key_proof() {
    let (_dir, encrypted_path) = encrypted_v1_file("change-target-changed");
    let intent = key::change::ChangeIntent::new(&encrypted_path).expect("prepare change intent");
    let proven = intent
        .verify_old_key(Protected::new(b"old-pass".to_vec()))
        .expect("old key proof");
    fs::write(&encrypted_path, b"changed target").expect("mutate target after proof");

    let result = key::change::execute(proven, Protected::new(b"new-pass".to_vec()), Kdf::Argon2id);

    assert!(matches!(result, Err(key::Error::TargetChanged)));
    assert_eq!(fs::read(&encrypted_path).unwrap(), b"changed target");
}
#[test]
fn key_change_commits_replacement_header_that_only_new_key_can_use() {
    let (_dir, encrypted_path) = encrypted_v1_file("change-new-key");
    let original = fs::read(&encrypted_path).expect("read original fixture");
    let original_header = read_v1_header_from_path(&encrypted_path);
    let (old_master_key, old_index) = key::decrypt_v1_master_key_with_index(
        &original_header,
        Protected::new(b"old-pass".to_vec()),
    )
    .expect("old key must unwrap original master key");

    let intent = key::change::ChangeIntent::new(&encrypted_path).expect("prepare change intent");
    let proven = intent
        .verify_old_key(Protected::new(b"old-pass".to_vec()))
        .expect("old key proof");
    key::change::execute(proven, Protected::new(b"new-pass".to_vec()), Kdf::Argon2id)
        .expect("commit key change");

    let changed = fs::read(&encrypted_path).expect("read changed fixture");
    assert_eq!(
        &changed[HEADER_LEN..],
        &original[HEADER_LEN..],
        "key change must replace only header bytes and preserve payload bytes"
    );
    verify_file(&encrypted_path, b"new-pass").expect("new key should verify");
    assert!(matches!(
        verify_file(&encrypted_path, b"old-pass"),
        Err(key::Error::IncorrectKey)
    ));
    let plaintext = decrypt_file(&encrypted_path, b"new-pass").expect("decrypt with new key");
    assert_eq!(plaintext, b"Hello world");

    let changed_header = read_v1_header_from_path(&encrypted_path);
    assert_eq!(
        changed_header.payload_nonce(),
        original_header.payload_nonce(),
        "key change must preserve payload nonce"
    );
    let serialized = changed_header
        .serialize()
        .expect("serialize changed header");
    assert_eq!(serialized.len(), HEADER_LEN);
    let reparsed =
        V1Header::deserialize(&mut Cursor::new(serialized)).expect("reparse changed header");
    let (new_master_key, new_index) =
        key::decrypt_v1_master_key_with_index(&reparsed, Protected::new(b"new-pass".to_vec()))
            .expect("new key must unwrap replacement master key");
    assert_eq!(
        new_index.get(),
        old_index.get(),
        "key change must replace the old-key-proven slot"
    );
    assert!(
        old_master_key.same_secret_as(&new_master_key),
        "replacement keyslot must unwrap the same master key proven by the old key"
    );
}
#[test]
fn key_change_slot_one_keeps_physical_slot_and_persists_fresh_nonce() {
    let (_dir, encrypted_path) = two_keyslot_v1_file("change-slot-one", b"new-pass");
    let original = fs::read(&encrypted_path).expect("read original fixture");
    let original_header = read_v1_header_from_path(&encrypted_path);
    let (master_key_before, index_before) = key::decrypt_v1_master_key_with_index(
        &original_header,
        Protected::new(b"new-pass".to_vec()),
    )
    .expect("second key must prove physical slot 1");
    assert_eq!(index_before.get(), 1);
    let prior_slot_one_nonce = keyslot_nonce_bytes(&original, 1);

    change_key_file(&encrypted_path, b"new-pass", b"third-pass");

    let changed = fs::read(&encrypted_path).expect("read changed fixture");
    assert_eq!(
        &changed[HEADER_LEN..],
        &original[HEADER_LEN..],
        "key change must preserve payload bytes"
    );
    assert_eq!(
        keyslot_bytes(&changed, 0),
        keyslot_bytes(&original, 0),
        "changing physical slot 1 must not rewrite physical slot 0"
    );
    assert_ne!(
        keyslot_bytes(&changed, 1),
        keyslot_bytes(&original, 1),
        "changing physical slot 1 must rewrite only that slot record"
    );
    assert_eq!(keyslot_bytes(&changed, 2), keyslot_bytes(&original, 2));
    assert_eq!(keyslot_bytes(&changed, 3), keyslot_bytes(&original, 3));

    let changed_header = read_v1_header_from_path(&encrypted_path);
    let slot_one = changed_header
        .keyslots_collection()
        .get_physical(1)
        .expect("changed key must remain in physical slot 1");
    assert_eq!(slot_one.physical_index(), 1);
    assert_ne!(
        keyslot_nonce_bytes(&changed, 1),
        prior_slot_one_nonce,
        "key change must persist a fresh nonce for the replaced physical slot"
    );
    assert_eq!(
        slot_one.nonce().as_bytes(),
        &keyslot_nonce_bytes(&changed, 1),
        "reparsed physical slot 1 must expose the persisted nonce"
    );

    let (master_key_after, index_after) = key::decrypt_v1_master_key_with_index(
        &changed_header,
        Protected::new(b"third-pass".to_vec()),
    )
    .expect("replacement key must unwrap changed physical slot 1");
    assert_eq!(index_after.get(), 1);
    assert!(master_key_before.same_secret_as(&master_key_after));
    verify_file(&encrypted_path, b"old-pass").expect("unchanged slot 0 should still verify");
    assert!(matches!(
        verify_file(&encrypted_path, b"new-pass"),
        Err(key::Error::IncorrectKey)
    ));
}
#[test]
fn key_change_unsupported_kdf_preflight_preserves_original_bytes() {
    let (_dir, encrypted_path) = encrypted_v1_file("change-unsupported-kdf");
    mark_keyslot_unsupported_argon2id_file(&encrypted_path, 0);
    let original = fs::read(&encrypted_path).expect("read unsupported KDF fixture");

    let result = key::change::ChangeIntent::new(&encrypted_path);

    assert!(matches!(
        result,
        Err(key::Error::UnsupportedKdf([0xDF, 0x02]))
    ));
    assert_eq!(
        fs::read(&encrypted_path).expect("read after unsupported change"),
        original,
        "unsupported KDF preflight must not mutate header or payload bytes"
    );
}
#[test]
fn key_delete_failure_preserves_original_header() {
    let (_dir, encrypted_path) = encrypted_v1_file("delete-final-preserved");
    let original = fs::read(&encrypted_path).expect("read original fixture");

    let intent = key::delete::DeleteIntent::new(&encrypted_path).expect("prepare delete intent");
    let result = key::delete::execute(intent, Protected::new(b"old-pass".to_vec()));

    assert!(matches!(
        result,
        Err(key::Error::CannotRemoveFinalV1Keyslot)
    ));
    let after = fs::read(&encrypted_path).expect("read preserved fixture");
    assert_eq!(&after[..HEADER_LEN], &original[..HEADER_LEN]);
    assert_eq!(after, original);
}
#[test]
fn key_delete_rejects_target_changed_after_intent_construction() {
    let (_dir, encrypted_path) = encrypted_v1_file("delete-target-changed");
    add_key_file(&encrypted_path, b"old-pass", b"new-pass");
    let intent = key::delete::DeleteIntent::new(&encrypted_path).expect("prepare delete intent");
    fs::write(&encrypted_path, b"changed target").expect("mutate target after intent");

    let result = key::delete::execute(intent, Protected::new(b"old-pass".to_vec()));

    assert!(matches!(result, Err(key::Error::TargetChanged)));
    assert_eq!(fs::read(&encrypted_path).unwrap(), b"changed target");
}
#[test]
fn key_delete_removes_only_old_key_proven_slot_and_preserves_payload() {
    let (_dir, encrypted_path) = two_keyslot_v1_file("delete-proven-slot", b"new-pass");
    let original = fs::read(&encrypted_path).expect("read original fixture");
    let original_header = read_v1_header_from_path(&encrypted_path);
    let (_master_key, proven_index) = key::decrypt_v1_master_key_with_index(
        &original_header,
        Protected::new(b"old-pass".to_vec()),
    )
    .expect("old key must prove a slot before delete");

    let intent = key::delete::DeleteIntent::new(&encrypted_path).expect("prepare delete intent");
    key::delete::execute(intent, Protected::new(b"old-pass".to_vec()))
        .expect("delete old-key-proven slot");

    let changed = fs::read(&encrypted_path).expect("read changed fixture");
    assert_eq!(
        &changed[HEADER_LEN..],
        &original[HEADER_LEN..],
        "key delete must preserve payload bytes exactly"
    );
    assert!(matches!(
        verify_file(&encrypted_path, b"old-pass"),
        Err(key::Error::IncorrectKey)
    ));
    verify_file(&encrypted_path, b"new-pass").expect("remaining key should verify");
    let plaintext = decrypt_file(&encrypted_path, b"new-pass").expect("decrypt with remaining key");
    assert_eq!(plaintext, b"Hello world");

    let changed_header = read_v1_header_from_path(&encrypted_path);
    assert_eq!(
        changed_header.payload_nonce(),
        original_header.payload_nonce(),
        "key delete must preserve payload nonce"
    );
    let serialized = changed_header
        .serialize()
        .expect("serialize changed header");
    assert_eq!(serialized.len(), HEADER_LEN);
    let reparsed =
        V1Header::deserialize(&mut Cursor::new(serialized)).expect("reparse changed header");
    assert_eq!(reparsed.keyslots().len(), 1);
    assert_eq!(
        proven_index.get(),
        0,
        "test fixture must prove old key selected the removed slot"
    );
}
#[test]
fn key_delete_zeroes_only_physical_slot_zero_and_keeps_slot_one_index() {
    let (_dir, encrypted_path) = two_keyslot_v1_file("delete-fixed-physical-slot", b"new-pass");
    let original = fs::read(&encrypted_path).expect("read original fixture");

    delete_key_file(&encrypted_path, b"old-pass").expect("delete physical slot 0");

    let changed = fs::read(&encrypted_path).expect("read changed fixture");
    assert_eq!(
        &changed[HEADER_LEN..],
        &original[HEADER_LEN..],
        "key delete must preserve payload bytes"
    );
    assert_eq!(
        keyslot_bytes(&changed, 0),
        [0u8; KEYSLOT_LEN],
        "key delete must zero only the proven physical slot"
    );
    assert_eq!(
        keyslot_bytes(&changed, 1),
        keyslot_bytes(&original, 1),
        "key delete must not compact physical slot 1 into slot 0"
    );
    assert_eq!(keyslot_bytes(&changed, 2), keyslot_bytes(&original, 2));
    assert_eq!(keyslot_bytes(&changed, 3), keyslot_bytes(&original, 3));

    let changed_header = read_v1_header_from_path(&encrypted_path);
    assert!(
        changed_header
            .keyslots_collection()
            .get_physical(0)
            .is_none(),
        "deleted physical slot 0 must reparse as empty"
    );
    let remaining = changed_header
        .keyslots_collection()
        .get_physical(1)
        .expect("remaining key must stay at physical slot 1");
    assert_eq!(remaining.physical_index(), 1);
    verify_file(&encrypted_path, b"new-pass").expect("remaining physical slot 1 should verify");
}
#[test]
fn unsupported_keyslot_does_not_count_as_supported_recovery_key_for_delete() {
    let (_dir, encrypted_path) =
        two_keyslot_v1_file("delete-unsupported-does-not-count", b"new-pass");
    mark_keyslot_unsupported_argon2id_file(&encrypted_path, 0);
    let original = fs::read(&encrypted_path).expect("read mixed KDF fixture");

    let delete = delete_key_file(&encrypted_path, b"new-pass");

    assert!(matches!(
        delete,
        Err(key::Error::CannotRemoveFinalV1Keyslot)
    ));
    assert_eq!(
        fs::read(&encrypted_path).expect("read after rejected delete"),
        original,
        "unsupported keyslot metadata must not count as a supported recovery key"
    );
}
#[test]
fn key_delete_wrong_old_key_preserves_original_bytes() {
    let (_dir, encrypted_path) = two_keyslot_v1_file("delete-wrong-key", b"new-pass");
    let original = fs::read(&encrypted_path).expect("read original fixture");

    let intent = key::delete::DeleteIntent::new(&encrypted_path).expect("prepare delete intent");
    let result = key::delete::execute(intent, Protected::new(b"wrong-pass".to_vec()));

    assert!(matches!(result, Err(key::Error::IncorrectKey)));
    assert_eq!(
        fs::read(&encrypted_path).expect("read after wrong-key delete"),
        original,
        "wrong old key must not mutate header or payload bytes"
    );
}
#[test]
fn key_delete_unsupported_kdf_preflight_preserves_original_bytes() {
    let (_dir, encrypted_path) = encrypted_v1_file("delete-unsupported-kdf");
    mark_keyslot_unsupported_argon2id_file(&encrypted_path, 0);
    let original = fs::read(&encrypted_path).expect("read unsupported KDF fixture");

    let result = key::delete::DeleteIntent::new(&encrypted_path);

    assert!(matches!(
        result,
        Err(key::Error::UnsupportedKdf([0xDF, 0x02]))
    ));
    assert_eq!(
        fs::read(&encrypted_path).expect("read after unsupported delete"),
        original,
        "unsupported KDF preflight must not mutate header or payload bytes"
    );
}
#[test]
fn can_change_and_reject_final_delete_v1_keyslots() {
    // Manifest fixture: keyslot-mutation-two-keyslots.
    let (_dir, encrypted_path) = encrypted_v1_file("change-final-delete");

    verify_file(&encrypted_path, b"old-pass").expect("verify original key");

    let intent = key::change::ChangeIntent::new(&encrypted_path).expect("prepare change intent");
    let proven = intent
        .verify_old_key(Protected::new(b"old-pass".to_vec()))
        .expect("old key proof");
    key::change::execute(proven, Protected::new(b"new-pass".to_vec()), Kdf::Argon2id)
        .expect("change keyslot");

    let changed = RefCell::new(Cursor::new(
        fs::read(&encrypted_path).expect("read changed fixture"),
    ));
    assert_eq!(keyslot_kdfs(&changed), [KeyslotKdf::Argon2id]);

    verify_file(&encrypted_path, b"new-pass").expect("verify changed key");

    let intent = key::delete::DeleteIntent::new(&encrypted_path).expect("prepare delete intent");
    let delete = key::delete::execute(intent, Protected::new(b"new-pass".to_vec()));
    assert!(matches!(
        delete,
        Err(key::Error::CannotRemoveFinalV1Keyslot)
    ));

    let plaintext = decrypt_file(&encrypted_path, b"new-pass").expect("decrypt with changed key");
    assert_eq!(plaintext, b"Hello world");
}
