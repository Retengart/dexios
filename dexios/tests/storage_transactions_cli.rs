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
#[path = "support/keyfile_cli.rs"]
mod keyfile_cli;
#[expect(dead_code, reason = "shared tempdir test helper")]
#[path = "support/tempdir.rs"]
mod tempdir;

use std::fs;
use std::path::Path;
use std::process::Command;

use core::header::common::HEADER_LEN;
use tempdir::TestDir;

const PASSWORD: &str = "12345678";

fn run_cli(current_dir: &Path, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dexios"));
    command.current_dir(current_dir);
    keyfile_cli::append_keyed_args(&mut command, current_dir, PASSWORD, args);
    command.output().unwrap()
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
    command.current_dir(test_dir.path());
    keyfile_cli::append_keyed_args(
        &mut command,
        test_dir.path(),
        "wrong-password",
        &["decrypt", "--force", "plain.enc", "plain.out"],
    );
    let decrypt_output = command.output().unwrap();

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
    let encrypted_for_header = test_dir.path().join("fixture.enc");
    let original = b"not a dexios encrypted file";
    fs::write(&invalid_input, original).unwrap();
    fs::write(
        test_dir.path().join("fixture.txt"),
        b"header strip backup fixture",
    )
    .unwrap();

    let encrypt_output = run_cli(
        test_dir.path(),
        &["encrypt", "--force", "fixture.txt", "fixture.enc"],
    );
    assert!(
        encrypt_output.status.success(),
        "encrypt fixture failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&encrypt_output.stdout),
        String::from_utf8_lossy(&encrypt_output.stderr)
    );
    let dump_output = run_cli(
        test_dir.path(),
        &["header", "dump", "--force", "fixture.enc", "fixture.hdr"],
    );
    assert!(
        dump_output.status.success(),
        "header dump fixture failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&dump_output.stdout),
        String::from_utf8_lossy(&dump_output.stderr)
    );

    let output = run_cli(
        test_dir.path(),
        &[
            "header",
            "strip",
            "--force",
            "--header",
            "fixture.hdr",
            "plain.txt",
        ],
    );

    assert!(
        !output.status.success(),
        "header strip unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(&invalid_input).unwrap(), original);
    assert!(encrypted_for_header.exists());
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
