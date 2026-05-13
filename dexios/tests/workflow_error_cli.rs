use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use core::header::common::{HEADER_LEN, HEADER_STATIC_LEN, KEYSLOT_LEN};
use core::kdf::Kdf;
use core::protected::Protected;
use domain::encrypt;
use domain::storage::identity::OverwritePolicy;
use zip::write::SimpleFileOptions;

const CORRECT_PASSWORD: &str = "correct-password";
const WRONG_PASSWORD: &str = "wrong-password";
const ERRORS_SOURCE: &str = include_str!("../src/subcommands/errors.rs");
const SUBCOMMANDS_SOURCE: &str = include_str!("../src/subcommands.rs");
const ENCRYPT_SOURCE: &str = include_str!("../src/subcommands/encrypt.rs");
const DECRYPT_SOURCE: &str = include_str!("../src/subcommands/decrypt.rs");
const HEADER_SOURCE: &str = include_str!("../src/subcommands/header.rs");
const KEY_SOURCE: &str = include_str!("../src/subcommands/key.rs");
const PACK_SOURCE: &str = include_str!("../src/subcommands/pack.rs");
const UNPACK_SOURCE: &str = include_str!("../src/subcommands/unpack.rs");
static NEXT_TEST_DIR: AtomicUsize = AtomicUsize::new(0);

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(prefix: &str) -> Self {
        let seq = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "dexios-{prefix}-{}-{seq}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        let path = fs::canonicalize(path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run_cli(current_dir: &Path, key: &str, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dexios"));
    command
        .current_dir(current_dir)
        .env("DEXIOS_KEY", key)
        .args(args)
        .output()
        .unwrap()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_no_default_source_chain(stderr: &str) {
    for forbidden in [
        "Caused by:",
        "caused by:",
        "source chain",
        "Stack backtrace",
    ] {
        assert!(
            !stderr.contains(forbidden),
            "normal CLI stderr must stay terse and omit source-chain text: {stderr}"
        );
    }
}

fn encrypt_fixture(test_dir: &TestDir) {
    fs::write(test_dir.path().join("plain.txt"), b"top secret").unwrap();
    let output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["encrypt", "--force", "plain.txt", "plain.enc"],
    );

    assert!(
        output.status.success(),
        "encrypt fixture failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        stderr(&output)
    );
}

fn write_zip_with_entries(path: &Path, entries: &[(&str, &[u8])]) {
    let file = fs::File::create(path).unwrap();
    let mut zip_writer = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .large_file(true)
        .unix_permissions(0o755);

    for (name, body) in entries {
        zip_writer.start_file(*name, options).unwrap();
        zip_writer.write_all(body).unwrap();
    }

    zip_writer.finish().unwrap();
}

fn encrypt_archive(input_path: &Path, output_path: &Path) {
    let intent = encrypt::EncryptIntent::new(
        input_path,
        output_path,
        OverwritePolicy::CreateNew,
        None,
        Protected::new(CORRECT_PASSWORD.as_bytes().to_vec()),
        Kdf::Blake3Balloon,
    )
    .unwrap();
    encrypt::execute(intent).unwrap();
}

fn write_legacy_header(path: &Path) {
    let mut file = fs::File::create(path).unwrap();
    file.write_all(&[0xDE, 0x05]).unwrap();
    file.write_all(&[7u8; 126]).unwrap();
    file.flush().unwrap();
}

fn write_malformed_v1_header(path: &Path) {
    let mut bytes = [0u8; 416];
    bytes[0..4].copy_from_slice(b"DXIO");
    bytes[4..6].copy_from_slice(&[0x00, 0x01]);
    bytes[7] = 1;
    fs::write(path, bytes).unwrap();
}

fn mark_keyslot_unsupported_argon2id(path: &Path, index: usize) {
    let mut bytes = fs::read(path).unwrap();
    let offset = HEADER_STATIC_LEN + (index * KEYSLOT_LEN);
    bytes[offset..offset + 2].copy_from_slice(&[0xDF, 0x02]);
    fs::write(path, bytes).unwrap();
}

#[test]
fn cli_workflow_errors_are_routed_through_mapping_helpers() {
    assert!(SUBCOMMANDS_SOURCE.contains("pub mod errors;"));
    assert!(ERRORS_SOURCE.contains("map_encrypt_error"));
    assert!(ERRORS_SOURCE.contains("map_decrypt_error"));
    assert!(ERRORS_SOURCE.contains("map_pack_error"));
    assert!(ERRORS_SOURCE.contains("map_unpack_error"));
    assert!(ERRORS_SOURCE.contains("Not enough temporary or output storage while packing archive"));
    assert!(
        ERRORS_SOURCE.contains("Not enough temporary or output storage while unpacking archive")
    );
    assert!(ERRORS_SOURCE.contains("error.is_resource_pressure()"));
    assert!(ERRORS_SOURCE.contains("map_header_error"));
    assert!(ERRORS_SOURCE.contains("map_key_error"));
    assert!(ERRORS_SOURCE.contains("WorkflowErrorClass::TransactionCommitFailure"));
    assert!(ENCRYPT_SOURCE.contains("map_encrypt_error"));
    assert!(DECRYPT_SOURCE.contains("map_decrypt_error"));
    assert!(PACK_SOURCE.contains("map_pack_error"));
    assert!(UNPACK_SOURCE.contains("map_unpack_error"));
    assert!(HEADER_SOURCE.contains("map_header_error"));
    assert!(KEY_SOURCE.contains("map_key_error"));
    assert!(!ERRORS_SOURCE.contains("to_string()"));
    assert!(!ERRORS_SOURCE.contains("contains("));
}

#[test]
fn malformed_and_unsupported_headers_use_typed_cli_mapping() {
    let test_dir = TestDir::new("workflow-error-header");
    let malformed = test_dir.path().join("malformed.enc");
    let legacy = test_dir.path().join("legacy.hdr");
    write_malformed_v1_header(&malformed);
    write_legacy_header(&legacy);

    let malformed_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["header", "details", "malformed.enc"],
    );
    assert!(!malformed_output.status.success());
    let malformed_stderr = stderr(&malformed_output);
    assert!(
        malformed_stderr.contains("Malformed Dexios V1 header"),
        "stderr did not expose the malformed header class: {malformed_stderr}"
    );

    let legacy_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["header", "details", "legacy.hdr"],
    );
    assert!(!legacy_output.status.success());
    let legacy_stderr = stderr(&legacy_output);
    assert!(
        legacy_stderr.contains("Unsupported Dexios format"),
        "stderr did not expose the unsupported format class: {legacy_stderr}"
    );
}

#[test]
fn unsafe_path_and_transaction_errors_use_typed_cli_mapping() {
    let test_dir = TestDir::new("workflow-error-path-transaction");
    fs::write(test_dir.path().join("plain.txt"), b"do not truncate").unwrap();

    let alias_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["encrypt", "--force", "plain.txt", "./plain.txt"],
    );
    assert!(!alias_output.status.success());
    let alias_stderr = stderr(&alias_output);
    assert!(
        alias_stderr.contains("Unsafe path"),
        "stderr did not expose the unsafe path class: {alias_stderr}"
    );
    assert_eq!(
        fs::read(test_dir.path().join("plain.txt")).unwrap(),
        b"do not truncate"
    );

    fs::create_dir(test_dir.path().join("out-dir")).unwrap();
    let transaction_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["encrypt", "--force", "plain.txt", "out-dir"],
    );
    assert!(!transaction_output.status.success());
    let transaction_stderr = stderr(&transaction_output);
    assert!(
        transaction_stderr.contains("commit"),
        "stderr did not expose the transaction failure class: {transaction_stderr}"
    );
}

#[test]
fn archive_pack_errors_use_typed_cli_mapping() {
    let test_dir = TestDir::new("workflow-error-pack");
    let source_dir = test_dir.path().join("source");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("hello.txt"), b"hello").unwrap();

    let alias_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["pack", "--force", "source", "source/archive.enc"],
    );
    assert!(!alias_output.status.success());
    let alias_stderr = stderr(&alias_output);
    assert!(
        alias_stderr.contains("Unsafe path"),
        "pack alias did not expose typed unsafe path class: {alias_stderr}"
    );
}

#[test]
fn archive_unpack_errors_use_typed_cli_mapping() {
    let test_dir = TestDir::new("workflow-error-unpack");
    let unsafe_zip = test_dir.path().join("unsafe.zip");
    let unsafe_archive = test_dir.path().join("unsafe.enc");
    write_zip_with_entries(&unsafe_zip, &[("../escape.txt", b"escape")]);
    encrypt_archive(&unsafe_zip, &unsafe_archive);

    let unsafe_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["unpack", "--force", "unsafe.enc", "out"],
    );
    assert!(!unsafe_output.status.success());
    let unsafe_stderr = stderr(&unsafe_output);
    assert!(
        unsafe_stderr.contains("Unsafe archive path"),
        "unsafe unpack did not expose typed unsafe path class: {unsafe_stderr}"
    );
    assert_no_default_source_chain(&unsafe_stderr);
    assert!(!test_dir.path().join("escape.txt").exists());

    let collision_zip = test_dir.path().join("collision.zip");
    let collision_archive = test_dir.path().join("collision.enc");
    write_zip_with_entries(&collision_zip, &[("a", b"file"), ("a/b", b"child")]);
    encrypt_archive(&collision_zip, &collision_archive);

    let collision_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["unpack", "--force", "collision.enc", "collision-out"],
    );
    assert!(!collision_output.status.success());
    let collision_stderr = stderr(&collision_output);
    assert!(
        collision_stderr.contains("Unsafe archive path"),
        "collision unpack did not expose typed unsafe path class: {collision_stderr}"
    );

    fs::create_dir_all(test_dir.path().join("packed-source")).unwrap();
    fs::write(
        test_dir.path().join("packed-source/plain.txt"),
        b"top secret",
    )
    .unwrap();
    let pack_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["pack", "--force", "packed-source", "packed.enc"],
    );
    assert!(
        pack_output.status.success(),
        "pack fixture failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&pack_output.stdout),
        stderr(&pack_output)
    );

    let wrong_key_output = run_cli(
        test_dir.path(),
        WRONG_PASSWORD,
        &["unpack", "--force", "packed.enc", "wrong-key-out"],
    );
    assert!(!wrong_key_output.status.success());
    let wrong_key_stderr = stderr(&wrong_key_output);
    assert!(
        wrong_key_stderr.contains("Authentication failed"),
        "wrong-key unpack did not expose terse auth class: {wrong_key_stderr}"
    );
    assert!(!wrong_key_stderr.contains(WRONG_PASSWORD));
    assert!(!wrong_key_stderr.contains("keyslot"));
    assert!(!wrong_key_stderr.contains("master key"));
    assert_no_default_source_chain(&wrong_key_stderr);
}

#[test]
fn incorrect_key_and_unsupported_workflow_messages_stay_terse() {
    let test_dir = TestDir::new("workflow-error-key");
    encrypt_fixture(&test_dir);

    let wrong_key_output = run_cli(
        test_dir.path(),
        WRONG_PASSWORD,
        &["decrypt", "--force", "plain.enc", "plain.out"],
    );
    assert!(!wrong_key_output.status.success());
    let wrong_key_stderr = stderr(&wrong_key_output);
    assert!(
        wrong_key_stderr.contains("Authentication failed"),
        "stderr did not expose the terse authentication class: {wrong_key_stderr}"
    );
    assert!(!wrong_key_stderr.contains(WRONG_PASSWORD));
    assert!(!wrong_key_stderr.contains("keyslot"));
    assert!(!wrong_key_stderr.contains("master key"));
    assert_no_default_source_chain(&wrong_key_stderr);

    fs::write(test_dir.path().join("old.key"), CORRECT_PASSWORD).unwrap();
    let add_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["key", "add", "--keyfile-old", "old.key", "plain.enc"],
    );
    assert!(!add_output.status.success());
    let add_stderr = stderr(&add_output);
    assert!(
        add_stderr.contains("Cannot add a V1 keyslot"),
        "stderr did not expose the unsupported workflow class: {add_stderr}"
    );
    assert!(!add_stderr.contains(CORRECT_PASSWORD));
}

#[test]
fn key_verify_wrong_key_and_unsupported_kdf_use_typed_mapping() {
    let test_dir = TestDir::new("workflow-error-key-verify");
    encrypt_fixture(&test_dir);

    let wrong_key_output = run_cli(
        test_dir.path(),
        WRONG_PASSWORD,
        &["key", "verify", "plain.enc"],
    );
    assert!(!wrong_key_output.status.success());
    let wrong_key_stderr = stderr(&wrong_key_output);
    assert!(
        wrong_key_stderr.contains("Incorrect key"),
        "stderr did not expose the terse incorrect-key class: {wrong_key_stderr}"
    );
    assert!(!wrong_key_stderr.contains(WRONG_PASSWORD));
    assert!(!wrong_key_stderr.contains(CORRECT_PASSWORD));
    assert!(!wrong_key_stderr.contains("keyslot"));
    assert!(!wrong_key_stderr.contains("master key"));
    assert_no_default_source_chain(&wrong_key_stderr);

    mark_keyslot_unsupported_argon2id(&test_dir.path().join("plain.enc"), 0);
    let unsupported_kdf_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["key", "verify", "plain.enc"],
    );
    assert!(!unsupported_kdf_output.status.success());
    let unsupported_kdf_stderr = stderr(&unsupported_kdf_output);
    assert!(
        unsupported_kdf_stderr.contains("Unsupported keyslot KDF tag"),
        "stderr did not expose the typed unsupported-KDF class: {unsupported_kdf_stderr}"
    );
    assert!(!unsupported_kdf_stderr.contains(CORRECT_PASSWORD));
}

#[test]
fn header_exact_failures_use_typed_cli_mapping() {
    let test_dir = TestDir::new("workflow-error-header-exact");
    encrypt_fixture(&test_dir);

    let dump_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["header", "dump", "plain.enc", "plain.hdr"],
    );
    assert!(
        dump_output.status.success(),
        "header dump fixture failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&dump_output.stdout),
        stderr(&dump_output)
    );

    let header_only_dump = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["header", "dump", "--force", "plain.hdr", "second.hdr"],
    );
    assert!(!header_only_dump.status.success());
    let header_only_stderr = stderr(&header_only_dump);
    assert!(
        header_only_stderr.contains("missing payload"),
        "header-only dump did not expose the missing-payload class: {header_only_stderr}"
    );
    assert!(!test_dir.path().join("second.hdr").exists());

    let header_bytes = fs::read(test_dir.path().join("plain.hdr")).unwrap();
    let encrypted_bytes = fs::read(test_dir.path().join("plain.enc")).unwrap();
    let mut stripped_bytes = vec![0u8; HEADER_LEN];
    stripped_bytes.extend_from_slice(&encrypted_bytes[HEADER_LEN..]);

    fs::write(
        test_dir.path().join("short.hdr"),
        &header_bytes[..HEADER_LEN - 1],
    )
    .unwrap();
    fs::write(test_dir.path().join("short-target.enc"), &stripped_bytes).unwrap();
    let short_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["header", "restore", "short.hdr", "short-target.enc"],
    );
    assert!(!short_output.status.success());
    let short_stderr = stderr(&short_output);
    assert!(
        short_stderr.contains("too short"),
        "short detached header did not expose the exact-length class: {short_stderr}"
    );
    assert_eq!(
        fs::read(test_dir.path().join("short-target.enc")).unwrap(),
        stripped_bytes
    );

    let mut trailing = header_bytes.clone();
    trailing.push(0xAA);
    fs::write(test_dir.path().join("trailing.hdr"), trailing).unwrap();
    fs::write(test_dir.path().join("trailing-target.enc"), &stripped_bytes).unwrap();
    let trailing_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["header", "restore", "trailing.hdr", "trailing-target.enc"],
    );
    assert!(!trailing_output.status.success());
    let trailing_stderr = stderr(&trailing_output);
    assert!(
        trailing_stderr.contains("trailing bytes"),
        "trailing detached header did not expose the exact-length class: {trailing_stderr}"
    );

    let not_stripped_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["header", "restore", "plain.hdr", "plain.enc"],
    );
    assert!(!not_stripped_output.status.success());
    let not_stripped_stderr = stderr(&not_stripped_output);
    assert!(
        not_stripped_stderr.contains("not stripped"),
        "restore into a non-stripped target did not expose the target-state class: {not_stripped_stderr}"
    );
    assert_eq!(
        fs::read(test_dir.path().join("plain.enc")).unwrap(),
        encrypted_bytes
    );
}

#[test]
fn io_and_overwrite_classes_are_explicitly_mapped() {
    assert!(ERRORS_SOURCE.contains("WorkflowErrorClass::IoFailure"));
    assert!(ERRORS_SOURCE.contains("WorkflowErrorClass::OverwriteDenied"));
    assert!(ERRORS_SOURCE.contains("Output already exists"));

    let test_dir = TestDir::new("workflow-error-io");
    let missing_header_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["header", "dump", "missing.enc", "missing.hdr"],
    );
    assert!(!missing_header_output.status.success());
    let missing_header_stderr = stderr(&missing_header_output);
    assert!(
        missing_header_stderr.contains("I/O failure"),
        "missing header input did not expose the typed IO class: {missing_header_stderr}"
    );

    let missing_key_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["key", "verify", "missing.enc"],
    );
    assert!(!missing_key_output.status.success());
    let missing_key_stderr = stderr(&missing_key_output);
    assert!(
        missing_key_stderr.contains("I/O failure while reading key workflow target"),
        "missing key target did not expose the typed IO class: {missing_key_stderr}"
    );
}
