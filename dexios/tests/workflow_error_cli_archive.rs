#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::unreachable, clippy::string_slice, clippy::too_many_lines, clippy::cast_possible_truncation, clippy::cast_possible_wrap, clippy::cast_sign_loss, clippy::cast_precision_loss, clippy::match_same_arms, clippy::items_after_statements, clippy::redundant_closure_for_method_calls, clippy::needless_collect, clippy::manual_let_else, clippy::format_collect, clippy::case_sensitive_file_extension_comparisons, clippy::struct_excessive_bools, reason = "integration tests assert exact behavior and may panic on failure"))]
use std::fs;

#[path = "support/workflow_error_cli.rs"]
mod workflow_error_cli_support;

use workflow_error_cli_support::{
    CORRECT_PASSWORD, TestDir, WRONG_PASSWORD, assert_no_default_debug_rendering,
    assert_no_default_source_chain, run_cli, stderr, write_manifest_archive_with_entries,
};

const ERRORS_SOURCE: &str = include_str!("../src/subcommands/errors.rs");

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

    assert!(
        ERRORS_SOURCE.contains(
            "WorkflowErrorClass::TransactionCommitFailure => {\n            anyhow!(\"Unable to commit encrypted output\")"
        ),
        "encrypt transaction commit failures must keep their explicit CLI mapping"
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
        transaction_stderr.contains("I/O failure while encrypting data"),
        "directory target preflight failure did not stay in the encrypt I/O class: {transaction_stderr}"
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
    let unsafe_archive = test_dir.path().join("unsafe.enc");
    write_manifest_archive_with_entries(&unsafe_archive, &[("../escape.txt", b"escape")]);

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
    assert_no_default_debug_rendering(&unsafe_stderr);
    assert!(!test_dir.path().join("escape.txt").exists());

    let collision_archive = test_dir.path().join("collision.enc");
    write_manifest_archive_with_entries(&collision_archive, &[("a", b"file"), ("a/b", b"child")]);

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
    assert_no_default_source_chain(&collision_stderr);
    assert_no_default_debug_rendering(&collision_stderr);

    fs::write(
        test_dir.path().join("legacy.zip"),
        b"PK\x03\x04legacy zip bytes",
    )
    .unwrap();
    let legacy_encrypt_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["encrypt", "--force", "legacy.zip", "legacy.enc"],
    );
    assert!(
        legacy_encrypt_output.status.success(),
        "legacy raw archive fixture failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&legacy_encrypt_output.stdout),
        stderr(&legacy_encrypt_output)
    );
    let legacy_unpack_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["unpack", "--force", "legacy.enc", "legacy-out"],
    );
    assert!(!legacy_unpack_output.status.success());
    let legacy_stderr = stderr(&legacy_unpack_output);
    assert!(
        legacy_stderr.contains("Malformed archive data")
            || legacy_stderr.contains("Unsupported archive format"),
        "legacy raw archive payload must fail as a terse archive class: {legacy_stderr}"
    );
    assert_no_default_source_chain(&legacy_stderr);
    assert_no_default_debug_rendering(&legacy_stderr);
    assert!(!test_dir.path().join("legacy-out").exists());

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
    assert_no_default_debug_rendering(&wrong_key_stderr);
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
