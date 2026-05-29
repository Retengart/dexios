#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::unreachable, clippy::string_slice, clippy::too_many_lines, clippy::cast_possible_truncation, clippy::cast_possible_wrap, clippy::cast_sign_loss, clippy::cast_precision_loss, clippy::match_same_arms, clippy::items_after_statements, clippy::redundant_closure_for_method_calls, clippy::needless_collect, clippy::manual_let_else, clippy::format_collect, clippy::case_sensitive_file_extension_comparisons, clippy::struct_excessive_bools, reason = "integration tests assert exact behavior and may panic on failure"))]
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use core::header::common::HEADER_LEN;

const PASSWORD: &str = "12345678";
const DEXIOS_SUBCOMMANDS_RS: &str = include_str!("../src/subcommands.rs");
const DEXIOS_SUBCOMMAND_ERRORS_RS: &str = include_str!("../src/subcommands/errors.rs");
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

fn run_cli(current_dir: &Path, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dexios"));
    command
        .current_dir(current_dir)
        .env("DEXIOS_KEY", PASSWORD)
        .args(args)
        .output()
        .unwrap()
}

fn assert_source_contains(source_name: &str, source: &str, needle: &str) {
    assert!(
        source.contains(needle),
        "{source_name} must contain {needle:?}"
    );
}

#[test]
fn storage_transaction_cli_harness_runs_in_disposable_real_fs_dir() {
    let test_dir = TestDir::new("storage-transactions-cli");
    let fixture = test_dir.path().join("fixture.txt");
    fs::write(&fixture, b"cli fixture").unwrap();

    let output = run_cli(test_dir.path(), &["--help"]);

    assert!(
        output.status.success(),
        "dexios --help failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(fixture.exists());
}

#[test]
fn encrypt_force_replaces_existing_output_after_success() {
    let test_dir = TestDir::new("encrypt-force-transaction");
    let plain = test_dir.path().join("plain.txt");
    let output_path = test_dir.path().join("plain.enc");
    fs::write(&plain, b"transactional plaintext").unwrap();
    fs::write(&output_path, b"existing encrypted output").unwrap();

    let output = run_cli(
        test_dir.path(),
        &["encrypt", "--force", "plain.txt", "plain.enc"],
    );

    assert!(
        output.status.success(),
        "encrypt failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&plain).unwrap(), b"transactional plaintext");
    assert_ne!(
        fs::read(&output_path).unwrap(),
        b"existing encrypted output"
    );
}

#[test]
fn decrypt_wrong_key_failure_preserves_existing_output() {
    let test_dir = TestDir::new("decrypt-wrong-key-transaction");
    let plain = test_dir.path().join("plain.txt");
    let encrypted = test_dir.path().join("plain.enc");
    let output_path = test_dir.path().join("plain.out");
    fs::write(&plain, b"top secret").unwrap();

    let encrypt_output = run_cli(
        test_dir.path(),
        &["encrypt", "--force", "plain.txt", "plain.enc"],
    );
    assert!(
        encrypt_output.status.success(),
        "encrypt fixture failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&encrypt_output.stdout),
        String::from_utf8_lossy(&encrypt_output.stderr)
    );
    assert!(encrypted.exists());

    fs::write(&output_path, b"existing output").unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_dexios"));
    let decrypt_output = command
        .current_dir(test_dir.path())
        .env("DEXIOS_KEY", "wrong-password")
        .args(["decrypt", "--force", "plain.enc", "plain.out"])
        .output()
        .unwrap();

    assert!(
        !decrypt_output.status.success(),
        "decrypt unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&decrypt_output.stdout),
        String::from_utf8_lossy(&decrypt_output.stderr)
    );
    assert_eq!(fs::read(&output_path).unwrap(), b"existing output");
}

#[test]
fn header_dump_failure_preserves_existing_output() {
    let test_dir = TestDir::new("header-dump-failure-transaction");
    let invalid_input = test_dir.path().join("plain.txt");
    let dumped_header = test_dir.path().join("plain.hdr");
    fs::write(&invalid_input, b"not a dexios file").unwrap();
    fs::write(&dumped_header, b"existing header").unwrap();

    let output = run_cli(
        test_dir.path(),
        &["header", "dump", "--force", "plain.txt", "plain.hdr"],
    );

    assert!(
        !output.status.success(),
        "header dump unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&dumped_header).unwrap(), b"existing header");
}

#[test]
fn header_dump_force_replaces_only_after_commit() {
    let test_dir = TestDir::new("header-dump-force-transaction");
    let plain = test_dir.path().join("plain.txt");
    let encrypted = test_dir.path().join("plain.enc");
    let dumped_header = test_dir.path().join("plain.hdr");
    fs::write(&plain, b"header dump plaintext").unwrap();
    fs::write(&dumped_header, b"existing header").unwrap();

    let encrypt_output = run_cli(
        test_dir.path(),
        &["encrypt", "--force", "plain.txt", "plain.enc"],
    );
    assert!(
        encrypt_output.status.success(),
        "encrypt fixture failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&encrypt_output.stdout),
        String::from_utf8_lossy(&encrypt_output.stderr)
    );
    assert!(encrypted.exists());

    let output = run_cli(
        test_dir.path(),
        &["header", "dump", "--force", "plain.enc", "plain.hdr"],
    );

    assert!(
        output.status.success(),
        "header dump failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let dumped = fs::read(&dumped_header).unwrap();
    assert_ne!(dumped, b"existing header");
    assert_eq!(dumped.len(), HEADER_LEN);
}

#[test]
fn header_strip_failure_preserves_original_file() {
    let test_dir = TestDir::new("header-strip-failure-transaction");
    let invalid_input = test_dir.path().join("plain.txt");
    let original = b"not a dexios encrypted file";
    fs::write(&invalid_input, original).unwrap();

    let output = run_cli(
        test_dir.path(),
        &["header", "strip", "--force", "plain.txt"],
    );

    assert!(
        !output.status.success(),
        "header strip unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&invalid_input).unwrap(), original);
}

#[test]
fn header_restore_failure_preserves_original_file() {
    let test_dir = TestDir::new("header-restore-failure-transaction");
    let plain = test_dir.path().join("plain.txt");
    let encrypted = test_dir.path().join("plain.enc");
    fs::write(&plain, b"header restore plaintext").unwrap();

    let encrypt_output = run_cli(
        test_dir.path(),
        &["encrypt", "--force", "plain.txt", "plain.enc"],
    );
    assert!(
        encrypt_output.status.success(),
        "encrypt fixture failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&encrypt_output.stdout),
        String::from_utf8_lossy(&encrypt_output.stderr)
    );

    let dump_output = run_cli(
        test_dir.path(),
        &["header", "dump", "plain.enc", "plain.hdr"],
    );
    assert!(
        dump_output.status.success(),
        "header dump fixture failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&dump_output.stdout),
        String::from_utf8_lossy(&dump_output.stderr)
    );
    let original = fs::read(&encrypted).unwrap();

    let output = run_cli(
        test_dir.path(),
        &["header", "restore", "--force", "plain.hdr", "plain.enc"],
    );

    assert!(
        !output.status.success(),
        "header restore unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&encrypted).unwrap(), original);
}

#[test]
fn key_change_failure_preserves_original_header() {
    let test_dir = TestDir::new("key-change-failure-transaction");
    let plain = test_dir.path().join("plain.txt");
    let encrypted = test_dir.path().join("plain.enc");
    let wrong_key = test_dir.path().join("wrong.key");
    let new_key = test_dir.path().join("new.key");
    fs::write(&plain, b"key change plaintext").unwrap();
    fs::write(&wrong_key, b"wrong-password").unwrap();
    fs::write(&new_key, b"new-password").unwrap();

    let encrypt_output = run_cli(
        test_dir.path(),
        &["encrypt", "--force", "plain.txt", "plain.enc"],
    );
    assert!(
        encrypt_output.status.success(),
        "encrypt fixture failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&encrypt_output.stdout),
        String::from_utf8_lossy(&encrypt_output.stderr)
    );
    let original = fs::read(&encrypted).unwrap();

    let output = run_cli(
        test_dir.path(),
        &[
            "key",
            "change",
            "--keyfile-old",
            "wrong.key",
            "--keyfile-new",
            "new.key",
            "plain.enc",
        ],
    );

    assert!(
        !output.status.success(),
        "key change unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let after = fs::read(&encrypted).unwrap();
    assert_eq!(&after[..HEADER_LEN], &original[..HEADER_LEN]);
    assert_eq!(after, original);
}

#[test]
fn key_delete_failure_preserves_original_header() {
    let test_dir = TestDir::new("key-delete-failure-transaction");
    let plain = test_dir.path().join("plain.txt");
    let encrypted = test_dir.path().join("plain.enc");
    let keyfile = test_dir.path().join("old.key");
    fs::write(&plain, b"key delete plaintext").unwrap();
    fs::write(&keyfile, PASSWORD).unwrap();

    let encrypt_output = run_cli(
        test_dir.path(),
        &["encrypt", "--force", "plain.txt", "plain.enc"],
    );
    assert!(
        encrypt_output.status.success(),
        "encrypt fixture failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&encrypt_output.stdout),
        String::from_utf8_lossy(&encrypt_output.stderr)
    );
    let original = fs::read(&encrypted).unwrap();

    let output = run_cli(
        test_dir.path(),
        &["key", "del", "--keyfile", "old.key", "plain.enc"],
    );

    assert!(
        !output.status.success(),
        "key delete unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let after = fs::read(&encrypted).unwrap();
    assert_eq!(&after[..HEADER_LEN], &original[..HEADER_LEN]);
    assert_eq!(after, original);
}

#[test]
fn unpack_delete_input_keeps_input_after_extraction_commit_failure() {
    let test_dir = TestDir::new("unpack-delete-input-commit-failure");
    let source_dir = test_dir.path().join("source");
    let nested = source_dir.join("payload");
    let encrypted = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let conflicting_dir = output_dir
        .join("source")
        .join("payload")
        .join("payload.txt");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("payload.txt"), b"payload").unwrap();
    fs::create_dir_all(&conflicting_dir).unwrap();

    let pack_output = run_cli(
        test_dir.path(),
        &["pack", "--force", "source", "archive.enc"],
    );
    assert!(
        pack_output.status.success(),
        "pack fixture failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&pack_output.stdout),
        String::from_utf8_lossy(&pack_output.stderr)
    );
    assert!(encrypted.exists());

    let unpack_output = run_cli(
        test_dir.path(),
        &["unpack", "--force", "--delete-input", "archive.enc", "out"],
    );

    assert!(
        !unpack_output.status.success(),
        "unpack unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&unpack_output.stdout),
        String::from_utf8_lossy(&unpack_output.stderr)
    );
    assert!(encrypted.exists());
}

#[test]
fn cli_delete_after_success_is_source_gated_against_failed_hash() {
    for required in [
        "HashVerification::Failed",
        "requested hash did not succeed",
        "cleanup_after_commit",
    ] {
        let source = format!("{DEXIOS_SUBCOMMANDS_RS}\n{DEXIOS_SUBCOMMAND_ERRORS_RS}");
        assert_source_contains("dexios CLI transaction cleanup corpus", &source, required);
    }
}
