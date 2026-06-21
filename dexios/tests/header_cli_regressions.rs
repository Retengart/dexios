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
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use core::header::common::HEADER_LEN;
use tempdir::TestDir;

const PASSWORD: &str = "correct-password";

fn run_cli(current_dir: &Path, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dexios"));
    command.current_dir(current_dir);
    keyfile_cli::append_keyed_args(&mut command, current_dir, PASSWORD, args);
    command.output().unwrap()
}

fn run_cli_with_stdin(current_dir: &Path, args: &[&str], stdin: &[u8]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dexios"));
    command.current_dir(current_dir);
    keyfile_cli::append_keyed_args(&mut command, current_dir, PASSWORD, args);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

fn assert_success(output: &std::process::Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure(output: &std::process::Output, label: &str) {
    assert!(
        !output.status.success(),
        "{label} unexpectedly succeeded: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn encrypt_fixture(test_dir: &TestDir, name: &str, plaintext: &[u8]) -> PathBuf {
    let plain = test_dir.path().join(format!("{name}.txt"));
    let encrypted = test_dir.path().join(format!("{name}.enc"));
    fs::write(&plain, plaintext).unwrap();

    let output = run_cli(
        test_dir.path(),
        &[
            "encrypt",
            "--force",
            plain.file_name().unwrap().to_str().unwrap(),
            encrypted.file_name().unwrap().to_str().unwrap(),
        ],
    );
    assert_success(&output, "encrypt fixture");

    encrypted
}

fn dump_header(test_dir: &TestDir, encrypted_name: &str, header_name: &str) -> PathBuf {
    let output = run_cli(
        test_dir.path(),
        &["header", "dump", encrypted_name, header_name],
    );
    assert_success(&output, "header dump fixture");
    test_dir.path().join(header_name)
}

#[test]
fn header_dump_rejects_header_only_input_and_writes_exact_detached_header() {
    let test_dir = TestDir::new("header-dump-exact");
    let encrypted = encrypt_fixture(&test_dir, "plain", b"payload bytes");

    let dump_output = run_cli(
        test_dir.path(),
        &["header", "dump", "plain.enc", "plain.hdr"],
    );
    assert_success(&dump_output, "header dump");

    let dumped = fs::read(test_dir.path().join("plain.hdr")).unwrap();
    assert_eq!(dumped.len(), HEADER_LEN);

    let header_only_output = run_cli(
        test_dir.path(),
        &["header", "dump", "plain.hdr", "second.hdr"],
    );
    assert_failure(&header_only_output, "header dump from header-only input");
    assert!(!test_dir.path().join("second.hdr").exists());
    assert!(fs::read(encrypted).unwrap().len() > HEADER_LEN);
}

#[test]
fn header_restore_rejects_inexact_headers_and_invalid_targets_without_mutation() {
    let test_dir = TestDir::new("header-restore-exact");
    let encrypted = encrypt_fixture(&test_dir, "plain", b"payload bytes");
    let header = dump_header(&test_dir, "plain.enc", "plain.hdr");
    let header_bytes = fs::read(&header).unwrap();
    let original = fs::read(&encrypted).unwrap();
    let payload = original[HEADER_LEN..].to_vec();

    let short_header = test_dir.path().join("short.hdr");
    fs::write(&short_header, &header_bytes[..HEADER_LEN - 1]).unwrap();
    let stripped_for_short = test_dir.path().join("stripped-short.enc");
    let mut stripped_bytes = vec![0u8; HEADER_LEN];
    stripped_bytes.extend_from_slice(&payload);
    fs::write(&stripped_for_short, &stripped_bytes).unwrap();
    let output = run_cli(
        test_dir.path(),
        &[
            "header",
            "restore",
            "--force",
            "short.hdr",
            "stripped-short.enc",
        ],
    );
    assert_failure(&output, "restore with short detached header");
    assert_eq!(fs::read(&stripped_for_short).unwrap(), stripped_bytes);

    let trailing_header = test_dir.path().join("trailing.hdr");
    let mut trailing = header_bytes;
    trailing.push(0xAA);
    fs::write(&trailing_header, trailing).unwrap();
    let stripped_for_trailing = test_dir.path().join("stripped-trailing.enc");
    fs::write(&stripped_for_trailing, &stripped_bytes).unwrap();
    let output = run_cli(
        test_dir.path(),
        &[
            "header",
            "restore",
            "--force",
            "trailing.hdr",
            "stripped-trailing.enc",
        ],
    );
    assert_failure(&output, "restore with trailing detached header");
    assert_eq!(fs::read(&stripped_for_trailing).unwrap(), stripped_bytes);

    let short_target = test_dir.path().join("short-target.enc");
    let short_target_bytes = vec![0u8; HEADER_LEN - 1];
    fs::write(&short_target, &short_target_bytes).unwrap();
    let output = run_cli(
        test_dir.path(),
        &[
            "header",
            "restore",
            "--force",
            "plain.hdr",
            "short-target.enc",
        ],
    );
    assert_failure(&output, "restore into short target");
    assert_eq!(fs::read(&short_target).unwrap(), short_target_bytes);

    let header_only_target = test_dir.path().join("header-only-target.enc");
    let header_only_bytes = vec![0u8; HEADER_LEN];
    fs::write(&header_only_target, &header_only_bytes).unwrap();
    let output = run_cli(
        test_dir.path(),
        &[
            "header",
            "restore",
            "--force",
            "plain.hdr",
            "header-only-target.enc",
        ],
    );
    assert_failure(&output, "restore into header-only target");
    assert_eq!(fs::read(&header_only_target).unwrap(), header_only_bytes);

    let non_zero_target = test_dir.path().join("non-zero-target.enc");
    fs::write(&non_zero_target, &original).unwrap();
    let output = run_cli(
        test_dir.path(),
        &[
            "header",
            "restore",
            "--force",
            "plain.hdr",
            "non-zero-target.enc",
        ],
    );
    assert_failure(&output, "restore into non-stripped target");
    assert_eq!(fs::read(&non_zero_target).unwrap(), original);
}

#[test]
fn header_strip_requires_matching_header_backup_and_preserves_payload_bytes() {
    let test_dir = TestDir::new("header-strip-exact");
    let encrypted = encrypt_fixture(&test_dir, "plain", b"payload bytes");
    dump_header(&test_dir, "plain.enc", "plain.hdr");
    let original = fs::read(&encrypted).unwrap();
    let payload = original[HEADER_LEN..].to_vec();

    let decline_output = run_cli_with_stdin(
        test_dir.path(),
        &["header", "strip", "--header", "plain.hdr", "plain.enc"],
        b"n\n",
    );
    assert_success(&decline_output, "declined header strip");
    assert_eq!(
        fs::read(&encrypted).unwrap(),
        original,
        "declining header strip confirmation must leave the target unchanged"
    );

    let output = run_cli(
        test_dir.path(),
        &[
            "header",
            "strip",
            "--force",
            "--header",
            "plain.hdr",
            "plain.enc",
        ],
    );
    assert_success(&output, "header strip");

    let stripped = fs::read(&encrypted).unwrap();
    assert_eq!(stripped.len(), original.len());
    assert_eq!(&stripped[..HEADER_LEN], vec![0u8; HEADER_LEN].as_slice());
    assert_eq!(&stripped[HEADER_LEN..], payload.as_slice());

    let header_only = test_dir.path().join("header-only.enc");
    fs::write(&header_only, &original[..HEADER_LEN]).unwrap();
    let header_only_before = fs::read(&header_only).unwrap();
    let output = run_cli(
        test_dir.path(),
        &[
            "header",
            "strip",
            "--force",
            "--header",
            "plain.hdr",
            "header-only.enc",
        ],
    );
    assert_failure(&output, "header strip header-only input");
    assert_eq!(fs::read(header_only).unwrap(), header_only_before);
}

#[test]
fn header_strip_rejects_wrong_header_backup_without_mutation() {
    let test_dir = TestDir::new("header-strip-wrong-backup");
    let encrypted = encrypt_fixture(&test_dir, "plain", b"payload bytes");
    // A second encrypted file gives us a structurally valid but unrelated header backup.
    encrypt_fixture(&test_dir, "other", b"other payload");
    dump_header(&test_dir, "other.enc", "wrong.hdr");
    let original = fs::read(&encrypted).unwrap();

    let output = run_cli(
        test_dir.path(),
        &[
            "header",
            "strip",
            "--force",
            "--header",
            "wrong.hdr",
            "plain.enc",
        ],
    );
    assert_failure(&output, "header strip with wrong detached header backup");
    assert_eq!(
        fs::read(&encrypted).unwrap(),
        original,
        "a mismatched detached header backup must leave the embedded header byte-unchanged"
    );

    // A truncated (wrong-size) backup is likewise refused without mutation.
    let short = test_dir.path().join("short.hdr");
    fs::write(&short, &original[..HEADER_LEN - 1]).unwrap();
    let output = run_cli(
        test_dir.path(),
        &[
            "header",
            "strip",
            "--force",
            "--header",
            "short.hdr",
            "plain.enc",
        ],
    );
    assert_failure(
        &output,
        "header strip with wrong-size detached header backup",
    );
    assert_eq!(fs::read(&encrypted).unwrap(), original);
}

#[test]
fn header_strip_requires_detached_header_backup_argument() {
    let test_dir = TestDir::new("header-strip-missing-backup");
    encrypt_fixture(&test_dir, "plain", b"payload bytes");

    let output = run_cli(
        test_dir.path(),
        &["header", "strip", "--force", "plain.enc"],
    );
    assert_failure(&output, "header strip without --header backup");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--header"),
        "missing --header must produce a clap usage error mentioning the argument"
    );
}

#[test]
fn header_restore_requires_confirmation_without_force() {
    let test_dir = TestDir::new("header-restore-confirmation");
    let encrypted = encrypt_fixture(&test_dir, "plain", b"payload bytes");
    let header = dump_header(&test_dir, "plain.enc", "plain.hdr");
    let original = fs::read(&encrypted).unwrap();
    let payload = original[HEADER_LEN..].to_vec();
    let stripped = test_dir.path().join("stripped.enc");
    let mut stripped_bytes = vec![0u8; HEADER_LEN];
    stripped_bytes.extend_from_slice(&payload);
    fs::write(&stripped, &stripped_bytes).unwrap();

    let output = run_cli_with_stdin(
        test_dir.path(),
        &["header", "restore", "plain.hdr", "stripped.enc"],
        b"n\n",
    );

    assert_success(&output, "declined header restore");
    assert_eq!(
        fs::read(&stripped).unwrap(),
        stripped_bytes,
        "declining header restore confirmation must leave the target unchanged"
    );

    let output = run_cli(
        test_dir.path(),
        &[
            "header",
            "restore",
            "--force",
            header.to_str().unwrap(),
            "stripped.enc",
        ],
    );
    assert_success(&output, "forced header restore");
    assert_eq!(fs::read(&stripped).unwrap(), original);
}
