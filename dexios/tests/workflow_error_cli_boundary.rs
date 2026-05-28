use domain::workflow_error::WorkflowErrorClass;

#[allow(dead_code)]
#[path = "../src/subcommands/errors.rs"]
mod cli_error_mappers;

#[path = "support/workflow_error_cli.rs"]
mod workflow_error_cli_support;

use workflow_error_cli_support::{
    CORRECT_PASSWORD, TestDir, WRONG_PASSWORD, assert_no_default_debug_rendering,
    assert_no_default_source_chain, encrypt_fixture, partial_commit_error, run_cli, stderr,
};

const MAIN_SOURCE: &str = include_str!("../src/main.rs");
const ERRORS_SOURCE: &str = include_str!("../src/subcommands/errors.rs");
const SUBCOMMANDS_SOURCE: &str = include_str!("../src/subcommands.rs");
const ENCRYPT_SOURCE: &str = include_str!("../src/subcommands/encrypt.rs");
const DECRYPT_SOURCE: &str = include_str!("../src/subcommands/decrypt.rs");
const HEADER_SOURCE: &str = include_str!("../src/subcommands/header.rs");
const KEY_SOURCE: &str = include_str!("../src/subcommands/key.rs");
const PACK_SOURCE: &str = include_str!("../src/subcommands/pack.rs");
const UNPACK_SOURCE: &str = include_str!("../src/subcommands/unpack.rs");

fn production_mapper_source() -> &'static str {
    ERRORS_SOURCE
        .split("#[cfg(test)]")
        .next()
        .expect("production mapper source")
}

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
fn cli_workflow_errors_are_routed_through_mapping_helpers() {
    assert!(SUBCOMMANDS_SOURCE.contains("pub mod errors;"));
    let mapper_source = production_mapper_source();
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
    assert!(ERRORS_SOURCE.contains("WorkflowErrorClass::CleanupFailure"));
    assert!(ERRORS_SOURCE.contains("WorkflowErrorClass::ResourcePressure"));
    assert_eq!(
        mapper_source
            .matches("match error.workflow_class()")
            .count(),
        6,
        "all six CLI workflow mappers should route by typed WorkflowErrorClass"
    );
    assert!(ENCRYPT_SOURCE.contains("map_encrypt_error"));
    assert!(DECRYPT_SOURCE.contains("map_decrypt_error"));
    assert!(PACK_SOURCE.contains("map_pack_error"));
    assert!(UNPACK_SOURCE.contains("map_unpack_error"));
    assert!(HEADER_SOURCE.contains("map_header_error"));
    assert!(KEY_SOURCE.contains("map_key_error"));
    for forbidden in [
        "clap::Error",
        "Command::error",
        ".to_string().contains(",
        "format!(",
        ".contains(",
        ".chain()",
        ".source()",
        "{error:#}",
        "{error:?}",
    ] {
        assert!(
            !mapper_source.contains(forbidden),
            "production workflow mappers must not use {forbidden} for post-parse error rendering"
        );
    }
}

#[test]
fn main_uses_display_only_error_boundary_for_workflow_failures() {
    assert!(
        MAIN_SOURCE.contains("fn run() -> Result<()>"),
        "main.rs should keep dispatch in a private run() that returns Result"
    );
    assert!(
        MAIN_SOURCE.contains("eprintln!(\"{error}\")"),
        "main.rs should render normal workflow errors with Display only"
    );
    assert!(
        MAIN_SOURCE.contains("std::process::exit(1)"),
        "main.rs should exit non-zero after rendering Display-only stderr"
    );
    assert!(
        !MAIN_SOURCE.contains("fn main() -> Result<()>"),
        "main() must not return Result because default error reporting is outside CLI control"
    );
    assert!(!MAIN_SOURCE.contains("{error:#}"));
    assert!(!MAIN_SOURCE.contains("{error:?}"));
    assert!(!MAIN_SOURCE.contains(".chain()"));
    assert!(!MAIN_SOURCE.contains(".source()"));
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
    assert_eq!(
        wrong_key_stderr, "Authentication failed\n",
        "default workflow stderr should be the sanitized Display message only"
    );
    assert_no_default_source_chain(&wrong_key_stderr);
    assert_no_default_debug_rendering(&wrong_key_stderr);
    assert!(!wrong_key_stderr.contains(WRONG_PASSWORD));
    assert!(!wrong_key_stderr.contains(CORRECT_PASSWORD));
    assert!(!wrong_key_stderr.contains("keyslot"));
    assert!(!wrong_key_stderr.contains("master key"));
}
