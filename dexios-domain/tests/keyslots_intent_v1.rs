#[path = "support/keyslots_v1.rs"]
mod keyslots_support;

use keyslots_support::*;

#[test]
fn key_add_intent_adds_supported_v1_without_mutating_payload() {
    let (_dir, encrypted_path) = encrypted_v1_file("add-supported-v1");
    let original = fs::read(&encrypted_path).expect("read original encrypted fixture");

    let intent = key::add::AddIntent::new(&encrypted_path).expect("prepare key add intent");
    let proven = intent
        .verify_old_key(Protected::new(b"old-pass".to_vec()))
        .expect("old key proof");
    key::add::execute(
        proven,
        Protected::new(b"new-pass".to_vec()),
        Kdf::Blake3Balloon,
    )
    .expect("add second keyslot");

    let changed = fs::read(&encrypted_path).expect("read after add");
    assert_eq!(
        &changed[HEADER_LEN..],
        &original[HEADER_LEN..],
        "key add must not mutate payload bytes"
    );
    verify_file(&encrypted_path, b"old-pass").expect("old key should still verify");
    verify_file(&encrypted_path, b"new-pass").expect("new key should verify");
}
#[test]
fn key_add_populates_empty_physical_slot_with_fresh_persisted_nonce() {
    let (_dir, encrypted_path) = encrypted_v1_file("add-fixed-physical-slot");
    let original = fs::read(&encrypted_path).expect("read original encrypted fixture");
    assert_eq!(keyslot_bytes(&original, 1), [0u8; KEYSLOT_LEN]);

    add_key_file(&encrypted_path, b"old-pass", b"new-pass");

    let changed = fs::read(&encrypted_path).expect("read added encrypted fixture");
    assert_eq!(
        &changed[HEADER_LEN..],
        &original[HEADER_LEN..],
        "key add must preserve payload bytes"
    );
    assert_eq!(
        keyslot_bytes(&changed, 0),
        keyslot_bytes(&original, 0),
        "key add must not rewrite the proven physical slot"
    );
    assert_ne!(
        keyslot_bytes(&changed, 1),
        [0u8; KEYSLOT_LEN],
        "key add must populate the first empty physical slot"
    );
    assert_eq!(keyslot_bytes(&changed, 2), [0u8; KEYSLOT_LEN]);
    assert_eq!(keyslot_bytes(&changed, 3), [0u8; KEYSLOT_LEN]);

    let changed_header = read_v1_header_from_path(&encrypted_path);
    let slot_one = changed_header
        .keyslots_collection()
        .get_physical(1)
        .expect("added key must stay in physical slot 1");
    assert_eq!(slot_one.physical_index(), 1);
    assert_eq!(
        slot_one.nonce().as_bytes(),
        &keyslot_nonce_bytes(&changed, 1),
        "persisted nonce bytes must match the reparsed physical slot"
    );
    assert_ne!(
        keyslot_nonce_bytes(&changed, 1),
        [0u8; 24],
        "key add must persist a fresh nonce in the target slot"
    );
    let (_master_key, index) = key::decrypt_v1_master_key_with_index(
        &changed_header,
        Protected::new(b"new-pass".to_vec()),
    )
    .expect("new key must unwrap from the added physical slot");
    assert_eq!(index.get(), 1);
}
#[test]
fn key_add_rejects_target_changed_after_old_key_proof() {
    let (_dir, encrypted_path) = encrypted_v1_file("add-target-changed");
    let intent = key::add::AddIntent::new(&encrypted_path).expect("prepare add intent");
    let proven = intent
        .verify_old_key(Protected::new(b"old-pass".to_vec()))
        .expect("old key proof");
    fs::write(&encrypted_path, b"changed target").expect("mutate target after proof");

    let result = key::add::execute(
        proven,
        Protected::new(b"new-pass".to_vec()),
        Kdf::Blake3Balloon,
    );

    assert!(matches!(result, Err(key::Error::TargetChanged)));
    assert_eq!(fs::read(&encrypted_path).unwrap(), b"changed target");
}
#[test]
#[cfg(unix)]
fn key_add_rejects_target_replacement_after_old_key_proof() {
    let (_dir, encrypted_path) = encrypted_v1_file("add-target-replaced");
    let replacement_path = encrypted_path.with_extension("replacement.enc");
    let original = fs::read(&encrypted_path).expect("read original fixture");
    let intent = key::add::AddIntent::new(&encrypted_path).expect("prepare add intent");
    let proven = intent
        .verify_old_key(Protected::new(b"old-pass".to_vec()))
        .expect("old key proof");
    fs::write(&replacement_path, &original).expect("write replacement fixture");

    fs::rename(&replacement_path, &encrypted_path).expect("replace target after proof");

    let result = key::add::execute(
        proven,
        Protected::new(b"new-pass".to_vec()),
        Kdf::Blake3Balloon,
    );

    assert!(matches!(result, Err(key::Error::TargetChanged)));
    assert_eq!(fs::read(&encrypted_path).unwrap(), original);
}
#[test]
fn key_add_intent_reports_unsupported_kdf_before_mutation_or_secret_use() {
    let (_dir, encrypted_path) = encrypted_v1_file("add-unsupported-kdf");
    mark_keyslot_unsupported_argon2id_file(&encrypted_path, 0);
    let original = fs::read(&encrypted_path).expect("read unsupported KDF fixture");

    let add = key::add::AddIntent::new(&encrypted_path);

    assert!(matches!(add, Err(key::Error::UnsupportedKdf([0xDF, 0x02]))));
    assert_eq!(
        fs::read(&encrypted_path).expect("read after unsupported KDF add"),
        original,
        "unsupported KDF preflight must be read-only"
    );
}
#[test]
fn key_verify_intent_returns_typed_read_only_outcomes() {
    let (_dir, encrypted_path) = encrypted_v1_file("verify-outcomes");

    let valid = key::verify::VerifyIntent::new(&encrypted_path).expect("prepare verify intent");
    key::verify::execute(valid, Protected::new(b"old-pass".to_vec())).expect("verify old key");

    let wrong_key = key::verify::VerifyIntent::new(&encrypted_path).expect("prepare verify intent");
    let wrong_key_result = key::verify::execute(wrong_key, Protected::new(b"wrong-pass".to_vec()));
    assert!(matches!(wrong_key_result, Err(key::Error::IncorrectKey)));

    let unsupported_path = encrypted_path.with_file_name("legacy-header.bin");
    write_unsupported_format_fixture(&unsupported_path);
    let unsupported = key::verify::VerifyIntent::new(&unsupported_path);
    assert!(matches!(
        unsupported,
        Err(key::Error::UnsupportedFormat([0xDE, 0x01]))
    ));

    let malformed_path = encrypted_path.with_file_name("malformed-v1.bin");
    write_malformed_v1_fixture(&malformed_path);
    let malformed = key::verify::VerifyIntent::new(&malformed_path);
    assert!(matches!(
        malformed,
        Err(key::Error::MalformedV1Header(
            HeaderReadError::NonZeroReservedBytes
        ))
    ));

    let missing = key::verify::VerifyIntent::new(encrypted_path.with_file_name("missing.enc"));
    assert!(matches!(missing, Err(key::Error::ReadIo)));
}
#[test]
fn key_intents_classify_retired_416_byte_v1_as_unsupported_format() {
    fn intent_error<T>(result: Result<T, key::Error>, case: &str) -> key::Error {
        match result {
            Ok(_) => panic!("{case} unexpectedly accepted retired 416-byte V1"),
            Err(error) => error,
        }
    }

    fn assert_retired_layout(error: key::Error) {
        assert!(matches!(error, key::Error::RetiredV1Layout));
        assert_eq!(
            error.workflow_class(),
            WorkflowErrorClass::UnsupportedFormat
        );
    }

    let dir = tempfile::tempdir().unwrap();
    let retired = dir.path().join("retired-current-v1.enc");
    write_retired_v1_fixture(&retired);

    assert_retired_layout(intent_error(
        key::add::AddIntent::new(&retired),
        "add intent",
    ));
    assert_retired_layout(intent_error(
        key::change::ChangeIntent::new(&retired),
        "change intent",
    ));
    assert_retired_layout(intent_error(
        key::delete::DeleteIntent::new(&retired),
        "delete intent",
    ));
    assert_retired_layout(intent_error(
        key::verify::VerifyIntent::new(&retired),
        "verify intent",
    ));
}
#[test]
fn key_verify_intent_reports_all_unsupported_keyslots_before_prompting() {
    let (_dir, encrypted_path) = encrypted_v1_file("verify-unsupported-kdf");
    mark_keyslot_unsupported_argon2id_file(&encrypted_path, 0);

    let verify = key::verify::VerifyIntent::new(&encrypted_path);

    assert!(matches!(
        verify,
        Err(key::Error::UnsupportedKdf([0xDF, 0x02]))
    ));
}
#[test]
fn key_verify_intent_does_not_read_or_authenticate_payload_stream() {
    let (_dir, encrypted_path) = encrypted_v1_file("verify-header-only");
    let mut bytes = fs::read(&encrypted_path).expect("read encrypted fixture");
    bytes.truncate(HEADER_LEN);
    fs::write(&encrypted_path, bytes).expect("write header-only fixture");

    let intent = key::verify::VerifyIntent::new(&encrypted_path).expect("prepare verify intent");
    key::verify::execute(intent, Protected::new(b"old-pass".to_vec()))
        .expect("key verify must not inspect payload stream bytes");
}
#[test]
fn key_verify_is_read_only_for_serialized_header_bytes() {
    let (_dir, encrypted_path) = two_keyslot_v1_file("verify-read-only", b"new-pass");
    let original = fs::read(&encrypted_path).expect("read original fixture");

    verify_file(&encrypted_path, b"new-pass").expect("verify later physical slot");

    assert_eq!(
        fs::read(&encrypted_path).expect("read after verify"),
        original,
        "key verify must not normalize, compact, or rewrite serialized header bytes"
    );
}
#[test]
fn key_add_verify_sources_do_not_expose_public_raw_request_state() {
    let sources = [
        ("dexios-domain/src/key/add.rs", DOMAIN_KEY_ADD_SOURCE),
        (
            "dexios-domain/src/key/verify.rs",
            include_str!("../src/key/verify.rs"),
        ),
    ];
    let forbidden = [
        "pub struct Request",
        "pub handle:",
        "RefCell",
        "pub raw_key",
        "raw_key_new",
    ];

    for (path, source) in sources {
        for pattern in forbidden {
            assert!(
                !source.contains(pattern),
                "`{path}` must not expose `{pattern}` in public add/verify contracts"
            );
        }
    }
}
