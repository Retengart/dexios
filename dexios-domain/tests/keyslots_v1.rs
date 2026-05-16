use core::header::common::{
    CANONICAL_V1_DISCRIMINATOR, HEADER_LEN, HEADER_STATIC_LEN, KEYSLOT_LEN,
    RETIRED_CURRENT_V1_HEADER_LEN, Salt,
};
use core::header::v1::{KeyslotKdf, V1Header, V1Keyslot};
use core::header::{HeaderReadError, ParsedHeader, read_header};
use core::kdf::Kdf;
use core::primitives::{WrappingKey, gen_keyslot_nonce, gen_salt};
use core::protected::Protected;
use core::stream::V1PayloadStream;
use dexios_domain::workflow_error::WorkflowErrorClass;
use dexios_domain::{decrypt, encrypt, key};
use std::cell::RefCell;
use std::fs::{self, File};
use std::io::{Cursor, Seek};
use std::path::{Path, PathBuf};

const DOMAIN_KEY_SOURCE: &str = include_str!("../src/key.rs");
const DOMAIN_ENCRYPT_SOURCE: &str = include_str!("../src/encrypt.rs");
const DOMAIN_KEY_ADD_SOURCE: &str = include_str!("../src/key/add.rs");
const DOMAIN_KEY_CHANGE_SOURCE: &str = include_str!("../src/key/change.rs");
const DOMAIN_KEY_DELETE_SOURCE: &str = include_str!("../src/key/delete.rs");
const CANONICAL_KEYSLOT_KDF_TAG_OFFSET: usize = 2;
const HISTORICAL_ARGON2ID_KEY_TAG: [u8; 2] = [0xDF, 0x02];

fn encrypted_v1_fixture() -> RefCell<Cursor<Vec<u8>>> {
    let dir = tempfile::tempdir().unwrap();
    let input_path = dir.path().join("plain.txt");
    let output_path = dir.path().join("plain.enc");
    fs::write(&input_path, b"Hello world").unwrap();

    let intent = encrypt::EncryptIntent::new(
        &input_path,
        &output_path,
        dexios_domain::storage::identity::OverwritePolicy::CreateNew,
        None,
        Protected::new(b"old-pass".to_vec()),
        Kdf::Blake3Balloon,
    )
    .expect("build encrypt intent");
    encrypt::execute(intent).expect("encrypt fixture");

    RefCell::new(Cursor::new(fs::read(output_path).unwrap()))
}

fn encrypted_v1_file(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let input_path = dir.path().join(format!("{name}.txt"));
    let output_path = dir.path().join(format!("{name}.enc"));
    fs::write(&input_path, b"Hello world").unwrap();

    let intent = encrypt::EncryptIntent::new(
        &input_path,
        &output_path,
        dexios_domain::storage::identity::OverwritePolicy::CreateNew,
        None,
        Protected::new(b"old-pass".to_vec()),
        Kdf::Blake3Balloon,
    )
    .expect("build encrypt intent");
    encrypt::execute(intent).expect("encrypt fixture");

    (dir, output_path)
}

fn two_keyslot_v1_file(name: &str, second_key: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let (dir, encrypted_path) = encrypted_v1_file(name);
    let encrypted = RefCell::new(Cursor::new(
        fs::read(&encrypted_path).expect("read encrypted fixture"),
    ));
    append_synthetic_second_keyslot(&encrypted, b"old-pass", second_key);
    fs::write(&encrypted_path, encrypted.into_inner().into_inner())
        .expect("write two-keyslot fixture");

    (dir, encrypted_path)
}

fn mark_keyslot_unsupported_argon2id(encrypted: &RefCell<Cursor<Vec<u8>>>, index: usize) {
    let mut handle = encrypted.borrow_mut();
    let offset = HEADER_STATIC_LEN + (index * KEYSLOT_LEN) + CANONICAL_KEYSLOT_KDF_TAG_OFFSET;
    handle.get_mut()[offset..offset + 2].copy_from_slice(&HISTORICAL_ARGON2ID_KEY_TAG);
    handle.rewind().expect("rewind after KDF tag mutation");
}

fn mark_keyslot_unsupported_argon2id_file(path: &Path, index: usize) {
    let mut bytes = fs::read(path).expect("read encrypted fixture");
    let offset = HEADER_STATIC_LEN + (index * KEYSLOT_LEN) + CANONICAL_KEYSLOT_KDF_TAG_OFFSET;
    bytes[offset..offset + 2].copy_from_slice(&HISTORICAL_ARGON2ID_KEY_TAG);
    fs::write(path, bytes).expect("write unsupported KDF fixture");
}

fn mutate_slot_nonce_file(path: &Path, index: usize) {
    let mut bytes = fs::read(path).expect("read encrypted fixture");
    let offset = HEADER_STATIC_LEN + (index * KEYSLOT_LEN) + 20;
    bytes[offset] ^= 0x01;
    fs::write(path, bytes).expect("write mutated keyslot nonce fixture");
}

fn mutate_payload_nonce_file(path: &Path) {
    let mut bytes = fs::read(path).expect("read encrypted fixture");
    bytes[16] ^= 0x01;
    fs::write(path, bytes).expect("write mutated payload nonce fixture");
}

fn write_unsupported_format_fixture(path: &Path) {
    fs::write(path, [0xDE, 0x01, 0, 0, 0, 0, 0, 0, 0, 0])
        .expect("write unsupported format fixture");
}

fn write_malformed_v1_fixture(path: &Path) {
    let mut bytes = [0u8; HEADER_LEN];
    bytes[0..4].copy_from_slice(b"DXIO");
    bytes[4..6].copy_from_slice(&[0x00, 0x01]);
    bytes[6..10].copy_from_slice(&CANONICAL_V1_DISCRIMINATOR);
    bytes[10] = 0x01;
    bytes[11] = 0x01;
    bytes[12] = 0x01;
    bytes[13] = 0x01;
    bytes[14] = 0x04;
    bytes[15] = 1;
    fs::write(path, bytes).expect("write malformed V1 fixture");
}

fn decode_hex_fixture(path: &Path) -> Vec<u8> {
    let fixture = std::fs::read_to_string(path).expect("read hex fixture");
    let nibbles: Vec<u8> = fixture
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .map(|ch| {
            ch.to_digit(16)
                .unwrap_or_else(|| panic!("invalid hex digit {ch:?} in {}", path.display()))
                as u8
        })
        .collect();

    assert!(
        nibbles.len().is_multiple_of(2),
        "hex fixture {} must have an even number of digits",
        path.display()
    );

    nibbles
        .chunks_exact(2)
        .map(|pair| (pair[0] << 4) | pair[1])
        .collect()
}

fn retired_v1_fixture_bytes() -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("dexios-core")
        .join("tests")
        .join("testdata")
        .join("v1_valid_single_keyslot.hex");
    let bytes = decode_hex_fixture(&path);
    assert_eq!(bytes.len(), RETIRED_CURRENT_V1_HEADER_LEN);
    bytes
}

fn write_retired_v1_fixture(path: &Path) {
    fs::write(path, retired_v1_fixture_bytes()).expect("write retired V1 fixture");
}

fn read_v1_header_from_path(path: &Path) -> V1Header {
    let mut file = File::open(path).expect("open encrypted fixture");
    let parsed = read_header(&mut file).expect("read V1 header");
    let ParsedHeader::V1(payload) = parsed;
    payload.header().clone()
}

fn read_v1_header_from_cursor(encrypted: &RefCell<Cursor<Vec<u8>>>) -> V1Header {
    let mut handle = encrypted.borrow_mut();
    handle.rewind().expect("rewind before header read");
    let parsed = read_header(&mut *handle).expect("read V1 header");
    let ParsedHeader::V1(payload) = parsed;
    payload.header().clone()
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

fn keyslot_range(index: usize) -> std::ops::Range<usize> {
    let start = HEADER_STATIC_LEN + (index * KEYSLOT_LEN);
    start..start + KEYSLOT_LEN
}

fn keyslot_bytes(bytes: &[u8], index: usize) -> &[u8] {
    &bytes[keyslot_range(index)]
}

fn keyslot_nonce_bytes(bytes: &[u8], index: usize) -> [u8; 24] {
    let offset = HEADER_STATIC_LEN + (index * KEYSLOT_LEN) + 20;
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&bytes[offset..offset + 24]);
    nonce
}

fn add_key_file(path: &Path, old_key: &[u8], new_key: &[u8]) {
    let intent = key::add::AddIntent::new(path).expect("prepare key add intent");
    let proven = intent
        .verify_old_key(Protected::new(old_key.to_vec()))
        .expect("old key proof");
    key::add::execute(proven, Protected::new(new_key.to_vec()), Kdf::Blake3Balloon)
        .expect("add second keyslot");
}

fn change_key_file(path: &Path, old_key: &[u8], new_key: &[u8]) {
    let intent = key::change::ChangeIntent::new(path).expect("prepare key change intent");
    let proven = intent
        .verify_old_key(Protected::new(old_key.to_vec()))
        .expect("old key proof");
    key::change::execute(proven, Protected::new(new_key.to_vec()), Kdf::Blake3Balloon)
        .expect("change keyslot");
}

fn delete_key_file(path: &Path, key: &[u8]) -> Result<(), key::Error> {
    let intent = key::delete::DeleteIntent::new(path)?;
    key::delete::execute(intent, Protected::new(key.to_vec())).map(|_| ())
}

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

fn append_synthetic_second_keyslot(
    encrypted: &RefCell<Cursor<Vec<u8>>>,
    old_key: &[u8],
    new_key: &[u8],
) {
    let mut handle = encrypted.borrow_mut();
    handle.rewind().expect("rewind before synthetic keyslot");
    let parsed = read_header(&mut *handle).expect("read V1 header");
    let ParsedHeader::V1(payload) = parsed;
    let header = payload.header();
    let mut keyslots = header.keyslots_collection().clone();

    let (master_key, _) =
        key::decrypt_v1_master_key_with_index(header, Protected::new(old_key.to_vec()))
            .expect("decrypt existing master key");
    let salt = Salt::new(gen_salt());
    let nonce = gen_keyslot_nonce();
    let wrapping_key = Kdf::Blake3Balloon
        .derive(&Protected::new(new_key.to_vec()), &salt.to_kdf_salt())
        .expect("derive synthetic wrapping key");
    let physical_index = keyslots.len();
    let placeholder_keyslot = V1Keyslot::new(Kdf::Blake3Balloon, [0u8; 48], nonce, salt);
    let slot_wrapping_aad = header
        .slot_wrapping_aad(physical_index, &placeholder_keyslot)
        .expect("synthetic slot wrapping aad");
    let encrypted_master_key = core::cipher::wrap_v1_master_key(
        WrappingKey::from(wrapping_key),
        &master_key,
        &nonce,
        &slot_wrapping_aad,
    )
    .expect("wrap synthetic master key");
    keyslots
        .push(V1Keyslot::new(
            Kdf::Blake3Balloon,
            *encrypted_master_key.as_bytes(),
            nonce,
            salt,
        ))
        .expect("append synthetic keyslot");

    let synthetic_header =
        V1Header::new(*header.payload_nonce(), keyslots).expect("build synthetic header");
    handle.rewind().expect("rewind before synthetic write");
    synthetic_header
        .write(&mut *handle)
        .expect("write synthetic header");
    handle
        .seek(std::io::SeekFrom::Start(HEADER_LEN as u64))
        .expect("seek after synthetic header");
}

fn decrypt_fixture(
    encrypted: &RefCell<Cursor<Vec<u8>>>,
    raw_key: &[u8],
) -> Result<Vec<u8>, decrypt::Error> {
    encrypted.borrow_mut().rewind().expect("rewind encrypted");
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let encrypted_path = temp_dir.path().join("plain.enc");
    let output_path = temp_dir.path().join("plain.out");
    fs::write(&encrypted_path, encrypted.borrow().get_ref()).expect("write encrypted fixture");

    let intent = decrypt::DecryptIntent::new(
        &encrypted_path,
        &output_path,
        dexios_domain::storage::identity::OverwritePolicy::CreateNew,
        None::<&std::path::Path>,
        Protected::new(raw_key.to_vec()),
        None,
    )?;
    decrypt::execute(intent)?;

    Ok(fs::read(output_path).expect("read decrypted fixture"))
}

fn decrypt_file(path: &Path, raw_key: &[u8]) -> Result<Vec<u8>, decrypt::Error> {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let output_path = temp_dir.path().join("plain.out");

    let intent = decrypt::DecryptIntent::new(
        path,
        &output_path,
        dexios_domain::storage::identity::OverwritePolicy::CreateNew,
        None::<&std::path::Path>,
        Protected::new(raw_key.to_vec()),
        None,
    )?;
    decrypt::execute(intent)?;

    Ok(fs::read(output_path).expect("read decrypted fixture"))
}

fn verify_fixture(encrypted: &RefCell<Cursor<Vec<u8>>>, raw_key: &[u8]) -> Result<(), key::Error> {
    encrypted.borrow_mut().rewind().expect("rewind encrypted");
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let encrypted_path = temp_dir.path().join("plain.enc");
    fs::write(&encrypted_path, encrypted.borrow().get_ref()).expect("write encrypted fixture");

    let intent = key::verify::VerifyIntent::new(&encrypted_path)?;
    key::verify::execute(intent, Protected::new(raw_key.to_vec()))
}

fn verify_file(path: &Path, raw_key: &[u8]) -> Result<(), key::Error> {
    let intent = key::verify::VerifyIntent::new(path)?;
    key::verify::execute(intent, Protected::new(raw_key.to_vec()))
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
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let encrypted_path = temp_dir.path().join("plain.enc");
    fs::write(&encrypted_path, encrypted.borrow().get_ref()).expect("write encrypted fixture");
    let original = fs::read(&encrypted_path).expect("read original fixture");

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
        "key add must preserve payload bytes"
    );

    let plaintext = decrypt_file(&encrypted_path, b"old-pass").expect("decrypt with original key");
    assert_eq!(plaintext, b"Hello world");
    let plaintext = decrypt_file(&encrypted_path, b"new-pass").expect("decrypt with added key");
    assert_eq!(plaintext, b"Hello world");
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

    let result = V1PayloadStream::decrypt_file(master_key, &payload, &mut reader, &mut plaintext);

    assert!(
        result.is_err(),
        "payload nonce participates in stream AAD/nonce authentication"
    );
    assert!(plaintext.is_empty());
}

#[test]
fn key_change_failure_preserves_original_header() {
    let encrypted = encrypted_v1_fixture();
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let encrypted_path = temp_dir.path().join("plain.enc");
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
    key::change::execute(
        proven,
        Protected::new(b"new-pass".to_vec()),
        Kdf::Blake3Balloon,
    )
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
fn key_change_source_does_not_expose_public_raw_request_state() {
    let forbidden = [
        "pub struct Request",
        "pub handle:",
        "RefCell",
        "pub raw_key_old",
        "pub raw_key_new",
    ];

    for pattern in forbidden {
        assert!(
            !DOMAIN_KEY_CHANGE_SOURCE.contains(pattern),
            "`dexios-domain/src/key/change.rs` must not expose `{pattern}` in public change contracts"
        );
    }
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
fn key_delete_source_does_not_expose_public_raw_request_state_or_remaining_key_prompt() {
    let forbidden = [
        "pub struct Request",
        "pub handle:",
        "RefCell",
        "pub raw_key_old",
        "remaining_key",
        "remaining verification",
    ];

    for pattern in forbidden {
        assert!(
            !DOMAIN_KEY_DELETE_SOURCE.contains(pattern),
            "`dexios-domain/src/key/delete.rs` must not expose `{pattern}` in public delete contracts"
        );
    }
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
    key::change::execute(
        proven,
        Protected::new(b"new-pass".to_vec()),
        Kdf::Blake3Balloon,
    )
    .expect("change keyslot");

    let changed = RefCell::new(Cursor::new(
        fs::read(&encrypted_path).expect("read changed fixture"),
    ));
    assert_eq!(keyslot_kdfs(&changed), [KeyslotKdf::Blake3Balloon]);

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
