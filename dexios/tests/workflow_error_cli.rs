use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use core::header::common::{HEADER_LEN, HEADER_STATIC_LEN, KEYSLOT_LEN};

const CORRECT_PASSWORD: &str = "correct-password";
const WRONG_PASSWORD: &str = "wrong-password";
const ERRORS_SOURCE: &str = include_str!("../src/subcommands/errors.rs");
const SUBCOMMANDS_SOURCE: &str = include_str!("../src/subcommands.rs");
const ENCRYPT_SOURCE: &str = include_str!("../src/subcommands/encrypt.rs");
const DECRYPT_SOURCE: &str = include_str!("../src/subcommands/decrypt.rs");
const HEADER_SOURCE: &str = include_str!("../src/subcommands/header.rs");
const KEY_SOURCE: &str = include_str!("../src/subcommands/key.rs");
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
    assert!(ERRORS_SOURCE.contains("map_header_error"));
    assert!(ERRORS_SOURCE.contains("map_key_error"));
    assert!(ERRORS_SOURCE.contains("WorkflowErrorClass::TransactionCommitFailure"));
    assert!(ENCRYPT_SOURCE.contains("map_encrypt_error"));
    assert!(DECRYPT_SOURCE.contains("map_decrypt_error"));
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
