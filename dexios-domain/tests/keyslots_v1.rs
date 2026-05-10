use core::header::common::{HEADER_STATIC_LEN, KEYSLOT_LEN};
use core::header::v1::KeyslotKdf;
use core::header::{ParsedHeader, read_header};
use core::kdf::Kdf;
use core::protected::Protected;
use dexios_domain::{decrypt, encrypt, key};
use std::cell::RefCell;
use std::io::{Cursor, Seek};

const DOMAIN_KEY_SOURCE: &str = include_str!("../src/key.rs");
const DOMAIN_ENCRYPT_SOURCE: &str = include_str!("../src/encrypt.rs");
const DOMAIN_KEY_ADD_SOURCE: &str = include_str!("../src/key/add.rs");
const DOMAIN_KEY_CHANGE_SOURCE: &str = include_str!("../src/key/change.rs");

fn encrypted_v1_fixture() -> RefCell<Cursor<Vec<u8>>> {
    let input = RefCell::new(Cursor::new(b"Hello world".to_vec()));
    let output = RefCell::new(Cursor::new(Vec::new()));

    encrypt::execute(encrypt::Request {
        reader: &input,
        writer: &output,
        header_writer: None,
        raw_key: Protected::new(b"old-pass".to_vec()),
        kdf: Kdf::Blake3Balloon,
    })
    .expect("encrypt fixture");

    output.borrow_mut().rewind().expect("rewind fixture");
    output
}

fn mark_keyslot_unsupported_argon2id(encrypted: &RefCell<Cursor<Vec<u8>>>, index: usize) {
    let mut handle = encrypted.borrow_mut();
    let offset = HEADER_STATIC_LEN + (index * KEYSLOT_LEN);
    handle.get_mut()[offset..offset + 2].copy_from_slice(&[0xDF, 0x02]);
    handle.rewind().expect("rewind after KDF tag mutation");
}

fn keyslot_kdfs(encrypted: &RefCell<Cursor<Vec<u8>>>) -> Vec<KeyslotKdf> {
    let mut handle = encrypted.borrow_mut();
    handle.rewind().expect("rewind before header read");
    let parsed = read_header(&mut *handle).expect("read V1 header");
    let ParsedHeader::V1(payload) = parsed;
    payload
        .header()
        .keyslots()
        .iter()
        .map(|keyslot| keyslot.kdf())
        .collect()
}

fn keyslots(encrypted: &RefCell<Cursor<Vec<u8>>>) -> core::header::v1::V1Keyslots {
    let mut handle = encrypted.borrow_mut();
    handle.rewind().expect("rewind before header read");
    let parsed = read_header(&mut *handle).expect("read V1 header");
    let ParsedHeader::V1(payload) = parsed;
    payload.header().keyslots_collection().clone()
}

fn decrypt_fixture(
    encrypted: &RefCell<Cursor<Vec<u8>>>,
    raw_key: &[u8],
) -> Result<Vec<u8>, decrypt::Error> {
    encrypted.borrow_mut().rewind().expect("rewind encrypted");
    let output = RefCell::new(Cursor::new(Vec::new()));

    decrypt::execute(decrypt::Request {
        header_reader: None,
        reader: encrypted,
        writer: &output,
        raw_key: Protected::new(raw_key.to_vec()),
        on_decrypted_header: None,
    })?;

    Ok(output.into_inner().into_inner())
}

#[test]
fn encrypt_writes_blake3_balloon_keyslot() {
    let encrypted = encrypted_v1_fixture();

    assert_eq!(keyslot_kdfs(&encrypted), [KeyslotKdf::Blake3Balloon]);
}

#[test]
fn argon2id_only_keyslot_returns_unsupported_kdf_for_verify() {
    let encrypted = encrypted_v1_fixture();
    mark_keyslot_unsupported_argon2id(&encrypted, 0);

    let verify = key::verify::execute(key::verify::Request {
        handle: &encrypted,
        raw_key: Protected::new(b"old-pass".to_vec()),
    });

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

    key::add::execute(key::add::Request {
        handle: &encrypted,
        raw_key_old: Protected::new(b"old-pass".to_vec()),
        raw_key_new: Protected::new(b"new-pass".to_vec()),
        kdf: Kdf::Blake3Balloon,
    })
    .expect("add second supported keyslot");

    let keyslots = keyslots(&encrypted);
    let (_master_key, index) =
        key::decrypt_v1_master_key_with_index(&keyslots, Protected::new(b"new-pass".to_vec()))
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

    key::add::execute(key::add::Request {
        handle: &encrypted,
        raw_key_old: Protected::new(b"old-pass".to_vec()),
        raw_key_new: Protected::new(b"new-pass".to_vec()),
        kdf: Kdf::Blake3Balloon,
    })
    .expect("add second supported keyslot");
    mark_keyslot_unsupported_argon2id(&encrypted, 0);

    let keyslots = keyslots(&encrypted);
    let decrypt =
        key::decrypt_v1_master_key_with_index(&keyslots, Protected::new(b"wrong-pass".to_vec()));

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
        DOMAIN_KEY_ADD_SOURCE.contains(".derive(&raw_key_new,"),
        "`key/add.rs` should borrow raw_key_new for new keyslot derivation"
    );
    assert!(
        DOMAIN_KEY_CHANGE_SOURCE.contains(".derive(&raw_key_new,"),
        "`key/change.rs` should borrow raw_key_new for replacement keyslot derivation"
    );
}

#[test]
fn supported_keyslot_verifies_when_mixed_with_unsupported_argon2id() {
    let encrypted = encrypted_v1_fixture();

    key::add::execute(key::add::Request {
        handle: &encrypted,
        raw_key_old: Protected::new(b"old-pass".to_vec()),
        raw_key_new: Protected::new(b"new-pass".to_vec()),
        kdf: Kdf::Blake3Balloon,
    })
    .expect("add supported keyslot");
    mark_keyslot_unsupported_argon2id(&encrypted, 0);

    key::verify::execute(key::verify::Request {
        handle: &encrypted,
        raw_key: Protected::new(b"new-pass".to_vec()),
    })
    .expect("supported keyslot should still verify");
}

#[test]
fn key_del_rejects_final_keyslot_before_writing_header() {
    let encrypted = encrypted_v1_fixture();

    let deletion = key::delete::execute(key::delete::Request {
        handle: &encrypted,
        raw_key_old: Protected::new(b"old-pass".to_vec()),
    });

    assert!(
        deletion.is_err(),
        "deleting the final usable keyslot should be rejected before writing the header"
    );

    let plaintext = decrypt_fixture(&encrypted, b"old-pass").expect("decrypt with original key");
    assert_eq!(plaintext, b"Hello world");
}

#[test]
fn wrong_key_current_v1_fixture_rejects_verification_and_decrypt() {
    // Manifest fixture: wrong-key-current-v1.
    let encrypted = encrypted_v1_fixture();

    let wrong_verify = key::verify::execute(key::verify::Request {
        handle: &encrypted,
        raw_key: Protected::new(b"wrong-pass".to_vec()),
    });
    assert!(matches!(wrong_verify, Err(key::Error::IncorrectKey)));

    let wrong_decrypt = decrypt_fixture(&encrypted, b"wrong-pass");
    assert!(matches!(
        wrong_decrypt,
        Err(decrypt::Error::DecryptMasterKey)
    ));
}

#[test]
fn can_add_verify_change_and_delete_v1_keyslots() {
    // Manifest fixture: keyslot-mutation-two-keyslots.
    let encrypted = encrypted_v1_fixture();

    key::verify::execute(key::verify::Request {
        handle: &encrypted,
        raw_key: Protected::new(b"old-pass".to_vec()),
    })
    .expect("verify original key");

    encrypted.borrow_mut().rewind().expect("rewind before add");
    key::add::execute(key::add::Request {
        handle: &encrypted,
        raw_key_old: Protected::new(b"old-pass".to_vec()),
        raw_key_new: Protected::new(b"new-pass".to_vec()),
        kdf: Kdf::Blake3Balloon,
    })
    .expect("add keyslot");
    assert_eq!(
        keyslot_kdfs(&encrypted),
        [KeyslotKdf::Blake3Balloon, KeyslotKdf::Blake3Balloon]
    );

    encrypted
        .borrow_mut()
        .rewind()
        .expect("rewind before verify");
    key::verify::execute(key::verify::Request {
        handle: &encrypted,
        raw_key: Protected::new(b"new-pass".to_vec()),
    })
    .expect("verify added key");

    encrypted
        .borrow_mut()
        .rewind()
        .expect("rewind before change");
    key::change::execute(key::change::Request {
        handle: &encrypted,
        raw_key_old: Protected::new(b"new-pass".to_vec()),
        raw_key_new: Protected::new(b"third-pass".to_vec()),
        kdf: Kdf::Blake3Balloon,
    })
    .expect("change keyslot");
    assert_eq!(
        keyslot_kdfs(&encrypted),
        [KeyslotKdf::Blake3Balloon, KeyslotKdf::Blake3Balloon]
    );

    encrypted
        .borrow_mut()
        .rewind()
        .expect("rewind before verify");
    key::verify::execute(key::verify::Request {
        handle: &encrypted,
        raw_key: Protected::new(b"third-pass".to_vec()),
    })
    .expect("verify changed key");

    encrypted
        .borrow_mut()
        .rewind()
        .expect("rewind before delete");
    key::delete::execute(key::delete::Request {
        handle: &encrypted,
        raw_key_old: Protected::new(b"third-pass".to_vec()),
    })
    .expect("delete keyslot");

    encrypted
        .borrow_mut()
        .rewind()
        .expect("rewind before final verify");
    let deleted_verify = key::verify::execute(key::verify::Request {
        handle: &encrypted,
        raw_key: Protected::new(b"third-pass".to_vec()),
    });
    assert!(matches!(deleted_verify, Err(key::Error::IncorrectKey)));

    let plaintext = decrypt_fixture(&encrypted, b"old-pass").expect("decrypt with original key");
    assert_eq!(plaintext, b"Hello world");
}
