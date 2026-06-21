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
use domain::workflow_error::WorkflowErrorClass;

#[expect(
    dead_code,
    reason = "the included CLI error-mapper module exposes more mappers than this boundary test exercises"
)]
#[path = "../src/subcommands/errors.rs"]
mod cli_error_mappers;

#[path = "support/workflow_error_cli.rs"]
mod workflow_error_cli_support;

use workflow_error_cli_support::{
    CORRECT_PASSWORD, TestDir, WRONG_PASSWORD, assert_no_default_debug_rendering,
    assert_no_default_source_chain, encrypt_fixture, partial_commit_error, run_cli, stderr,
};

#[test]
fn partial_commit_keeps_commit_failure_cli_mapping() {
    let pack_error = domain::pack::Error::Transaction(partial_commit_error());
    assert_eq!(
        pack_error.workflow_class(),
        WorkflowErrorClass::TransactionCommitFailure
    );

    let mapped = cli_error_mappers::map_pack_error(pack_error).to_string();
    assert_eq!(mapped, "Unable to commit packed archive");
    assert!(
        !mapped.contains("Not enough temporary or output storage"),
        "partial commit evidence must not collapse into resource-pressure wording: {mapped}"
    );

    let unpack_error = domain::unpack::Error::Transaction(partial_commit_error());
    assert_eq!(
        unpack_error.workflow_class(),
        WorkflowErrorClass::TransactionCommitFailure
    );

    let mapped = cli_error_mappers::map_unpack_error(unpack_error).to_string();
    assert_eq!(mapped, "Unable to commit unpacked output");
    assert!(
        !mapped.contains("Not enough temporary or output storage"),
        "partial commit evidence must not collapse into resource-pressure wording: {mapped}"
    );
}

#[test]
fn detached_encrypt_partial_publication_names_committed_and_failed_artifacts() {
    let encrypt_error = domain::encrypt::Error::DetachedPublication(partial_commit_error());
    assert_eq!(
        encrypt_error.workflow_class(),
        WorkflowErrorClass::TransactionCommitFailure
    );

    let mapped = cli_error_mappers::map_encrypt_error(encrypt_error).to_string();
    assert_eq!(
        mapped,
        "Detached publication incomplete: payload committed, header failed; source cleanup was not authorized"
    );
    assert!(
        !mapped.contains("Unable to commit encrypted output"),
        "detached partial publication must not collapse into generic commit wording: {mapped}"
    );
}

#[test]
fn detached_pack_partial_publication_names_committed_and_failed_artifacts() {
    let pack_error = domain::pack::Error::DetachedPublication(partial_commit_error());
    assert_eq!(
        pack_error.workflow_class(),
        WorkflowErrorClass::TransactionCommitFailure
    );

    let mapped = cli_error_mappers::map_pack_error(pack_error).to_string();
    assert_eq!(
        mapped,
        "Detached publication incomplete: payload committed, header failed; source cleanup was not authorized"
    );
    assert!(
        !mapped.contains("Unable to commit packed archive"),
        "detached partial publication must not collapse into generic commit wording: {mapped}"
    );
}

#[test]
fn wrong_key_decrypt_default_stderr_is_display_only() {
    let test_dir = TestDir::new("workflow-error-display-only");
    encrypt_fixture(&test_dir);

    let wrong_key_output = run_cli(
        test_dir.path(),
        WRONG_PASSWORD,
        &["decrypt", "--force", "plain.enc", "plain.out"],
    );
    assert!(!wrong_key_output.status.success());
    let wrong_key_stderr = stderr(&wrong_key_output);
    let error_lines = wrong_key_stderr
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    assert_eq!(
        error_lines,
        ["Authentication failed"],
        "default workflow stderr should be the sanitized Display message only: {wrong_key_stderr}"
    );
    assert_no_default_source_chain(&wrong_key_stderr);
    assert_no_default_debug_rendering(&wrong_key_stderr);
    assert!(!wrong_key_stderr.contains(WRONG_PASSWORD));
    assert!(!wrong_key_stderr.contains(CORRECT_PASSWORD));
    assert!(!wrong_key_stderr.contains("keyslot"));
    assert!(!wrong_key_stderr.contains("master key"));
}
