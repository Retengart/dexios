use core::kdf::Kdf;
use core::protected::Protected;
use dexios_domain::{decrypt, encrypt, key};
use std::cell::RefCell;
use std::io::{Cursor, Seek};

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
        kdf: Kdf::Argon2id,
    })
    .expect("add keyslot");

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
