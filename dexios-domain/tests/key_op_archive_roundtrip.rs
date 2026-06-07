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
use std::fs;
use std::path::Path;

use core::kdf::Kdf;
use core::protected::Protected;
use dexios_domain::archive::ArchivePolicy;
use dexios_domain::decrypt;
use dexios_domain::encrypt;
use dexios_domain::key;
use dexios_domain::pack::{self, DetachedHeaderTarget, PackIntent};
use dexios_domain::storage::identity::OverwritePolicy;
use dexios_domain::unpack;

const PASSWORD: &[u8; 8] = b"12345678";
const NEW_KEY: &[u8; 8] = b"new-pass";

fn create_source_dir(root: &Path) -> std::path::PathBuf {
    let source_dir = root.join("source");
    fs::create_dir_all(source_dir.join("nested")).unwrap();
    fs::write(source_dir.join("hello.txt"), b"hello").unwrap();
    fs::write(source_dir.join("nested/world.txt"), b"world").unwrap();
    source_dir
}

fn pack_intent(
    source_paths: Vec<std::path::PathBuf>,
    output_path: &Path,
    detached_header_path: Option<&Path>,
) -> Result<PackIntent, pack::Error> {
    PackIntent::new(
        source_paths,
        output_path,
        OverwritePolicy::CreateNew,
        detached_header_path
            .map(|path| DetachedHeaderTarget::new(path, OverwritePolicy::CreateNew)),
        Protected::new(PASSWORD.to_vec()),
        Kdf::Argon2id,
        ArchivePolicy::default(),
        true,
        None,
    )
}

fn add_key_file(path: &Path, old_key: &[u8], new_key: &[u8]) {
    let intent = key::add::AddIntent::new(path).expect("prepare key add intent");
    let proven = intent
        .verify_old_key(Protected::new(old_key.to_vec()))
        .expect("old key proof");
    key::add::execute(proven, Protected::new(new_key.to_vec()), Kdf::Argon2id)
        .expect("add second keyslot");
}

fn change_key_file(path: &Path, old_key: &[u8], new_key: &[u8]) {
    let intent = key::change::ChangeIntent::new(path).expect("prepare key change intent");
    let proven = intent
        .verify_old_key(Protected::new(old_key.to_vec()))
        .expect("old key proof");
    key::change::execute(proven, Protected::new(new_key.to_vec()), Kdf::Argon2id)
        .expect("change keyslot");
}

fn delete_key_file(path: &Path, key: &[u8]) -> Result<(), key::Error> {
    let intent = key::delete::DeleteIntent::new(path)?;
    key::delete::execute(intent, Protected::new(key.to_vec())).map(|_| ())
}

fn unpack_archive_with_key(
    encrypted_archive: &Path,
    output_dir: &Path,
    key: &[u8],
) -> Result<dexios_domain::storage::transaction::CommitReceipt, unpack::Error> {
    let intent = unpack::UnpackIntent::new(
        encrypted_archive,
        None,
        output_dir,
        Protected::new(key.to_vec()),
        None,
        None,
        None,
    )?;
    unpack::execute(intent)
}

#[test]
fn pack_key_add_unpack_preserves_manifest_archive_aad() {
    let root = tempfile::tempdir().unwrap();
    let root_path = fs::canonicalize(root.path()).unwrap();
    let source_dir = create_source_dir(&root_path);
    let archive_path = root_path.join("archive.enc");
    let output_dir = root_path.join("out");

    pack::execute_transactional(pack_intent(vec![source_dir], &archive_path, None).unwrap())
        .unwrap();

    add_key_file(&archive_path, PASSWORD, NEW_KEY);

    fs::create_dir_all(&output_dir).unwrap();
    unpack_archive_with_key(&archive_path, &output_dir, PASSWORD)
        .expect("AINT-02: pack->key add->unpack must succeed for ManifestArchive");

    assert_eq!(
        fs::read(output_dir.join("source/hello.txt")).unwrap(),
        b"hello"
    );
}

#[test]
fn pack_key_change_unpack_preserves_manifest_archive_aad() {
    let root = tempfile::tempdir().unwrap();
    let root_path = fs::canonicalize(root.path()).unwrap();
    let source_dir = create_source_dir(&root_path);
    let archive_path = root_path.join("archive.enc");
    let output_dir = root_path.join("out");

    pack::execute_transactional(pack_intent(vec![source_dir], &archive_path, None).unwrap())
        .unwrap();

    change_key_file(&archive_path, PASSWORD, NEW_KEY);

    fs::create_dir_all(&output_dir).unwrap();
    unpack_archive_with_key(&archive_path, &output_dir, NEW_KEY)
        .expect("AINT-03: pack->key change->unpack must succeed for ManifestArchive");

    assert_eq!(
        fs::read(output_dir.join("source/hello.txt")).unwrap(),
        b"hello"
    );
}

#[test]
fn pack_key_add_key_delete_unpack_preserves_manifest_archive_aad() {
    let root = tempfile::tempdir().unwrap();
    let root_path = fs::canonicalize(root.path()).unwrap();
    let source_dir = create_source_dir(&root_path);
    let archive_path = root_path.join("archive.enc");
    let output_dir = root_path.join("out");

    pack::execute_transactional(pack_intent(vec![source_dir], &archive_path, None).unwrap())
        .unwrap();

    add_key_file(&archive_path, PASSWORD, NEW_KEY); // slot 0: PASSWORD, slot 1: NEW_KEY
    delete_key_file(&archive_path, NEW_KEY).unwrap(); // delete slot 1; slot 0 remains

    fs::create_dir_all(&output_dir).unwrap();
    unpack_archive_with_key(&archive_path, &output_dir, PASSWORD)
        .expect("AINT-04: pack->key add->key delete->unpack must succeed for ManifestArchive");

    assert_eq!(
        fs::read(output_dir.join("source/hello.txt")).unwrap(),
        b"hello"
    );
}

#[test]
fn encrypt_key_add_decrypt_preserves_rawfile_payload() {
    let dir = tempfile::tempdir().unwrap();
    let dir_path = fs::canonicalize(dir.path()).unwrap();
    let input_path = dir_path.join("plain.txt");
    let enc_path = dir_path.join("plain.enc");
    let dec_path = dir_path.join("plain.dec");
    fs::write(&input_path, b"hello rawfile").unwrap();

    encrypt::execute(
        encrypt::EncryptIntent::new(
            &input_path,
            &enc_path,
            OverwritePolicy::CreateNew,
            None,
            Protected::new(PASSWORD.to_vec()),
            Kdf::Argon2id,
        )
        .unwrap(),
    )
    .unwrap();

    add_key_file(&enc_path, PASSWORD, NEW_KEY);

    decrypt::execute(
        decrypt::DecryptIntent::new(
            &enc_path,
            &dec_path,
            OverwritePolicy::CreateNew,
            None::<&Path>,
            Protected::new(PASSWORD.to_vec()),
            None,
        )
        .unwrap(),
    )
    .expect("AINT-06: encrypt->key add->decrypt must succeed for RawFile");

    assert_eq!(fs::read(&dec_path).unwrap(), b"hello rawfile");
}
