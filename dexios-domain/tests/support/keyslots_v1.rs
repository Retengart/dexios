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
        clippy::allow_attributes,
        clippy::redundant_pub_crate,
        reason = "shared test-support helpers assert exact behavior and may panic on failure"
    )
)]
#![allow(
    dead_code,
    unused_imports,
    reason = "shared keyslot helpers are imported selectively across test crates"
)]

#[path = "tempdir.rs"]
#[expect(dead_code, reason = "shared tempdir test helper")]
mod tempdir;

pub(super) use core::header::common::{
    CANONICAL_V1_DISCRIMINATOR, HEADER_LEN, HEADER_STATIC_LEN, KEYSLOT_LEN,
    RETIRED_CURRENT_V1_HEADER_LEN, Salt,
};
pub(super) use core::header::v1::{KeyslotKdf, V1Header, V1Keyslot, V1KeyslotIndex};
pub(super) use core::header::{HeaderReadError, ParsedHeader, read_header};
pub(super) use core::kdf::Kdf;
pub(super) use core::primitives::{WrappingKey, gen_keyslot_nonce, gen_salt};
pub(super) use core::protected::Protected;
pub(super) use core::stream::V1PayloadStream;
pub(super) use dexios_domain::workflow_error::WorkflowErrorClass;
pub(super) use dexios_domain::{decrypt, encrypt, key};
pub(super) use std::cell::RefCell;
pub(super) use std::fs::{self, File};
pub(super) use std::io::{Cursor, Seek};
pub(super) use std::path::{Path, PathBuf};
pub(super) use tempdir::canonical_tempdir;

pub(super) const CANONICAL_KEYSLOT_KDF_TAG_OFFSET: usize = 2;
pub(super) const HISTORICAL_ARGON2ID_KEY_TAG: [u8; 2] = [0xDF, 0x02];

pub(super) fn encrypted_v1_fixture() -> RefCell<Cursor<Vec<u8>>> {
    let (_dir, dir_path) = canonical_tempdir();
    let input_path = dir_path.join("plain.txt");
    let output_path = dir_path.join("plain.enc");
    fs::write(&input_path, b"Hello world").unwrap();

    let intent = encrypt::EncryptIntent::new(
        &input_path,
        &output_path,
        dexios_domain::storage::identity::OverwritePolicy::CreateNew,
        None,
        Protected::new(b"old-pass".to_vec()),
        Kdf::Argon2id,
    )
    .expect("build encrypt intent");
    encrypt::execute(intent).expect("encrypt fixture");

    RefCell::new(Cursor::new(fs::read(output_path).unwrap()))
}

pub(super) fn encrypted_v1_file(name: &str) -> (tempfile::TempDir, PathBuf) {
    let (dir, dir_path) = canonical_tempdir();
    let input_path = dir_path.join(format!("{name}.txt"));
    let output_path = dir_path.join(format!("{name}.enc"));
    fs::write(&input_path, b"Hello world").unwrap();

    let intent = encrypt::EncryptIntent::new(
        &input_path,
        &output_path,
        dexios_domain::storage::identity::OverwritePolicy::CreateNew,
        None,
        Protected::new(b"old-pass".to_vec()),
        Kdf::Argon2id,
    )
    .expect("build encrypt intent");
    encrypt::execute(intent).expect("encrypt fixture");

    (dir, output_path)
}

pub(super) fn two_keyslot_v1_file(name: &str, second_key: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let (dir, encrypted_path) = encrypted_v1_file(name);
    let encrypted = RefCell::new(Cursor::new(
        fs::read(&encrypted_path).expect("read encrypted fixture"),
    ));
    append_synthetic_second_keyslot(&encrypted, b"old-pass", second_key);
    fs::write(&encrypted_path, encrypted.into_inner().into_inner())
        .expect("write two-keyslot fixture");

    (dir, encrypted_path)
}

pub(super) fn mark_keyslot_unsupported_argon2id(
    encrypted: &RefCell<Cursor<Vec<u8>>>,
    index: usize,
) {
    let mut handle = encrypted.borrow_mut();
    let offset = HEADER_STATIC_LEN + (index * KEYSLOT_LEN) + CANONICAL_KEYSLOT_KDF_TAG_OFFSET;
    handle.get_mut()[offset..offset + 2].copy_from_slice(&HISTORICAL_ARGON2ID_KEY_TAG);
    handle.rewind().expect("rewind after KDF tag mutation");
}

pub(super) fn mark_keyslot_unsupported_argon2id_file(path: &Path, index: usize) {
    let mut bytes = fs::read(path).expect("read encrypted fixture");
    let offset = HEADER_STATIC_LEN + (index * KEYSLOT_LEN) + CANONICAL_KEYSLOT_KDF_TAG_OFFSET;
    bytes[offset..offset + 2].copy_from_slice(&HISTORICAL_ARGON2ID_KEY_TAG);
    fs::write(path, bytes).expect("write unsupported KDF fixture");
}

pub(super) fn mutate_slot_nonce_file(path: &Path, index: usize) {
    let mut bytes = fs::read(path).expect("read encrypted fixture");
    let offset = HEADER_STATIC_LEN + (index * KEYSLOT_LEN) + 20;
    bytes[offset] ^= 0x01;
    fs::write(path, bytes).expect("write mutated keyslot nonce fixture");
}

pub(super) fn mutate_payload_nonce_file(path: &Path) {
    let mut bytes = fs::read(path).expect("read encrypted fixture");
    bytes[16] ^= 0x01;
    fs::write(path, bytes).expect("write mutated payload nonce fixture");
}

pub(super) fn write_unsupported_format_fixture(path: &Path) {
    fs::write(path, [0xDE, 0x01, 0, 0, 0, 0, 0, 0, 0, 0])
        .expect("write unsupported format fixture");
}

pub(super) fn write_malformed_v1_fixture(path: &Path) {
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

pub(super) fn decode_hex_fixture(path: &Path) -> Vec<u8> {
    let fixture = fs::read_to_string(path).expect("read hex fixture");
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

pub(super) fn retired_v1_fixture_bytes() -> Vec<u8> {
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

pub(super) fn write_retired_v1_fixture(path: &Path) {
    fs::write(path, retired_v1_fixture_bytes()).expect("write retired V1 fixture");
}

pub(super) fn read_v1_header_from_path(path: &Path) -> V1Header {
    let mut file = File::open(path).expect("open encrypted fixture");
    let parsed = read_header(&mut file).expect("read V1 header");
    let ParsedHeader::V1(payload) = parsed;
    payload.header().clone()
}

pub(super) fn read_v1_header_from_cursor(encrypted: &RefCell<Cursor<Vec<u8>>>) -> V1Header {
    let mut handle = encrypted.borrow_mut();
    handle.rewind().expect("rewind before header read");
    let parsed = read_header(&mut *handle).expect("read V1 header");
    let ParsedHeader::V1(payload) = parsed;
    payload.header().clone()
}

pub(super) fn keyslot_kdfs(encrypted: &RefCell<Cursor<Vec<u8>>>) -> Vec<KeyslotKdf> {
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

pub(super) fn keyslot_range(index: usize) -> std::ops::Range<usize> {
    let start = HEADER_STATIC_LEN + (index * KEYSLOT_LEN);
    start..start + KEYSLOT_LEN
}

pub(super) fn keyslot_bytes(bytes: &[u8], index: usize) -> &[u8] {
    &bytes[keyslot_range(index)]
}

pub(super) fn keyslot_nonce_bytes(bytes: &[u8], index: usize) -> [u8; 24] {
    let offset = HEADER_STATIC_LEN + (index * KEYSLOT_LEN) + 20;
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&bytes[offset..offset + 24]);
    nonce
}

pub(super) fn add_key_file(path: &Path, old_key: &[u8], new_key: &[u8]) {
    let intent = key::add::AddIntent::new(path).expect("prepare key add intent");
    let proven = intent
        .verify_old_key(Protected::new(old_key.to_vec()))
        .expect("old key proof");
    key::add::execute(proven, Protected::new(new_key.to_vec()), Kdf::Argon2id)
        .expect("add second keyslot");
}

pub(super) fn change_key_file(path: &Path, old_key: &[u8], new_key: &[u8]) {
    let intent = key::change::ChangeIntent::new(path).expect("prepare key change intent");
    let proven = intent
        .verify_old_key(Protected::new(old_key.to_vec()))
        .expect("old key proof");
    key::change::execute(proven, Protected::new(new_key.to_vec()), Kdf::Argon2id)
        .expect("change keyslot");
}

pub(super) fn delete_key_file(path: &Path, key: &[u8]) -> Result<(), key::Error> {
    let intent = key::delete::DeleteIntent::new(path)?;
    key::delete::execute(intent, Protected::new(key.to_vec())).map(|_| ())
}

pub(super) fn append_synthetic_second_keyslot(
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
    let wrapping_key = Kdf::Argon2id
        .derive(&Protected::new(new_key.to_vec()), &salt.to_kdf_salt())
        .expect("derive synthetic wrapping key");
    let mut placeholder_keyslots = keyslots.clone();
    placeholder_keyslots
        .push(V1Keyslot::new(Kdf::Argon2id, [0u8; 48], nonce, salt))
        .expect("append placeholder keyslot");
    let placeholder_header = header
        .with_keyslots(placeholder_keyslots)
        .expect("build placeholder header");
    let slot_wrapping_aad = placeholder_header
        .slot_wrapping_aad_for_physical_slot(
            V1KeyslotIndex::try_from_physical_index(1).expect("slot one index"),
        )
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
            Kdf::Argon2id,
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

pub(super) fn decrypt_fixture(
    encrypted: &RefCell<Cursor<Vec<u8>>>,
    raw_key: &[u8],
) -> Result<Vec<u8>, decrypt::Error> {
    encrypted.borrow_mut().rewind().expect("rewind encrypted");
    let (_temp_dir, temp_dir_path) = canonical_tempdir();
    let encrypted_path = temp_dir_path.join("plain.enc");
    let output_path = temp_dir_path.join("plain.out");
    fs::write(&encrypted_path, encrypted.borrow().get_ref()).expect("write encrypted fixture");

    let intent = decrypt::DecryptIntent::new(
        &encrypted_path,
        &output_path,
        dexios_domain::storage::identity::OverwritePolicy::CreateNew,
        None::<&Path>,
        Protected::new(raw_key.to_vec()),
        None,
    )?;
    decrypt::execute(intent)?;

    Ok(fs::read(output_path).expect("read decrypted fixture"))
}

pub(super) fn decrypt_file(path: &Path, raw_key: &[u8]) -> Result<Vec<u8>, decrypt::Error> {
    let (_temp_dir, temp_dir_path) = canonical_tempdir();
    let output_path = temp_dir_path.join("plain.out");

    let intent = decrypt::DecryptIntent::new(
        path,
        &output_path,
        dexios_domain::storage::identity::OverwritePolicy::CreateNew,
        None::<&Path>,
        Protected::new(raw_key.to_vec()),
        None,
    )?;
    decrypt::execute(intent)?;

    Ok(fs::read(output_path).expect("read decrypted fixture"))
}

pub(super) fn verify_fixture(
    encrypted: &RefCell<Cursor<Vec<u8>>>,
    raw_key: &[u8],
) -> Result<(), key::Error> {
    encrypted.borrow_mut().rewind().expect("rewind encrypted");
    let (_temp_dir, temp_dir_path) = canonical_tempdir();
    let encrypted_path = temp_dir_path.join("plain.enc");
    fs::write(&encrypted_path, encrypted.borrow().get_ref()).expect("write encrypted fixture");

    let intent = key::verify::VerifyIntent::new(&encrypted_path)?;
    key::verify::execute(intent, Protected::new(raw_key.to_vec()))
}

pub(super) fn verify_file(path: &Path, raw_key: &[u8]) -> Result<(), key::Error> {
    let intent = key::verify::VerifyIntent::new(path)?;
    key::verify::execute(intent, Protected::new(raw_key.to_vec()))
}
