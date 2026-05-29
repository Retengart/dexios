#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::unreachable, clippy::string_slice, clippy::too_many_lines, clippy::cast_possible_truncation, clippy::cast_possible_wrap, clippy::cast_sign_loss, clippy::cast_precision_loss, clippy::match_same_arms, clippy::items_after_statements, clippy::redundant_closure_for_method_calls, clippy::needless_collect, clippy::manual_let_else, clippy::format_collect, clippy::case_sensitive_file_extension_comparisons, clippy::struct_excessive_bools, reason = "integration tests assert exact behavior and may panic on failure"))]
use std::fs;

use core::header::common::HEADER_LEN;

#[path = "support/workflow_error_cli.rs"]
mod workflow_error_cli_support;

use workflow_error_cli_support::{
    CORRECT_PASSWORD, TestDir, WRONG_PASSWORD, assert_no_default_source_chain, encrypt_fixture,
    mark_keyslot_unsupported_argon2id, run_cli, stderr, write_legacy_header,
    write_malformed_v1_header, write_retired_v1_fixture,
};

#[test]
fn malformed_and_unsupported_headers_use_typed_cli_mapping() {
    let test_dir = TestDir::new("workflow-error-header");
    let malformed = test_dir.path().join("malformed.enc");
    let legacy = test_dir.path().join("legacy.hdr");
    let retired = test_dir.path().join("retired-current-v1.enc");
    write_malformed_v1_header(&malformed);
    write_legacy_header(&legacy);
    write_retired_v1_fixture(&retired);

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
    assert!(
        malformed_stderr.contains("non-zero reserved bytes in V1 header"),
        "header details should preserve safe V1 parse classes: {malformed_stderr}"
    );

    let dump_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &[
            "header",
            "dump",
            "--force",
            "malformed.enc",
            "malformed.hdr",
        ],
    );
    assert!(!dump_output.status.success());
    let dump_stderr = stderr(&dump_output);
    assert!(
        dump_stderr.contains("Malformed Dexios V1 header"),
        "header dump did not expose the malformed header class: {dump_stderr}"
    );
    assert!(
        !dump_stderr.contains("non-zero reserved bytes in V1 header"),
        "header dump must keep malformed parser details terse: {dump_stderr}"
    );
    assert!(!test_dir.path().join("malformed.hdr").exists());

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

    let retired_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["header", "details", "retired-current-v1.enc"],
    );
    assert!(!retired_output.status.success());
    let retired_stderr = stderr(&retired_output);
    assert!(
        retired_stderr.contains("Unsupported Dexios format"),
        "retired 416-byte V1 did not expose the unsupported format class: {retired_stderr}"
    );
    assert!(
        !retired_stderr.contains("Malformed Dexios V1 header"),
        "retired 416-byte V1 was misclassified as malformed: {retired_stderr}"
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
    assert_no_default_source_chain(&wrong_key_stderr);

    fs::write(test_dir.path().join("old.key"), CORRECT_PASSWORD).unwrap();
    let delete_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["key", "del", "--force", "--keyfile", "old.key", "plain.enc"],
    );
    assert!(!delete_output.status.success());
    let delete_stderr = stderr(&delete_output);
    assert!(
        delete_stderr.contains("Cannot remove the final V1 keyslot"),
        "stderr did not expose the unsupported workflow class: {delete_stderr}"
    );
    assert!(!delete_stderr.contains(CORRECT_PASSWORD));
    assert_no_default_source_chain(&delete_stderr);
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

    write_retired_v1_fixture(&test_dir.path().join("retired-current-v1.enc"));
    let retired_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &["key", "verify", "retired-current-v1.enc"],
    );
    assert!(!retired_output.status.success());
    let retired_stderr = stderr(&retired_output);
    assert!(
        retired_stderr.contains("Unsupported Dexios format"),
        "retired 416-byte V1 did not expose key unsupported-format class: {retired_stderr}"
    );
    assert!(
        !retired_stderr.contains("Malformed Dexios V1 header"),
        "key verify misclassified retired 416-byte V1 as malformed: {retired_stderr}"
    );
    assert_no_default_source_chain(&retired_stderr);
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
        &[
            "header",
            "restore",
            "--force",
            "short.hdr",
            "short-target.enc",
        ],
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

    let mut trailing = header_bytes;
    trailing.push(0xAA);
    fs::write(test_dir.path().join("trailing.hdr"), trailing).unwrap();
    fs::write(test_dir.path().join("trailing-target.enc"), &stripped_bytes).unwrap();
    let trailing_output = run_cli(
        test_dir.path(),
        CORRECT_PASSWORD,
        &[
            "header",
            "restore",
            "--force",
            "trailing.hdr",
            "trailing-target.enc",
        ],
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
        &["header", "restore", "--force", "plain.hdr", "plain.enc"],
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
