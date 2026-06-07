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
        clippy::allow_attributes,
        clippy::redundant_pub_crate,
        reason = "shared test-support helpers assert exact behavior and may panic on failure"
    )
)]
#![allow(
    dead_code,
    unused_imports,
    reason = "shared transaction helpers are imported selectively across test crates"
)]

use std::error::Error as _;

pub(super) use std::fs;
pub(super) use std::io;
pub(super) use std::path::{Path, PathBuf};

pub(super) use dexios_domain::storage::NamedStagedOutput;
pub(super) use dexios_domain::storage::identity::{
    OverwritePolicy, PathIdentityGraph, PathRole, ResolvedTarget,
};
#[cfg(feature = "test-support")]
pub(super) use dexios_domain::storage::test_support::{FailureHooks, FailurePoint};
#[cfg(feature = "test-support")]
pub(super) use dexios_domain::storage::transaction::DetachedPairReceipt;
pub(super) use dexios_domain::storage::transaction::{
    CleanupAuthorizedReceipt, CommittedArtifact, DetachedPublicationFailure,
    LinkedOutputTransaction, PartialCommitReceipt, StagedOutputTransaction, TransactionError,
};
#[expect(dead_code, reason = "shared tempdir test helper")]
#[path = "tempdir.rs"]
mod tempdir;
pub(super) use tempdir::DomainTestDir as TestDir;

pub(super) const EXISTING_OUTPUT: &[u8] = b"existing output";
pub(super) const CANDIDATE_OUTPUT: &[u8] = b"candidate output";
pub(super) const STORAGE_TEMP_RS: &str = include_str!("../../src/storage/temp.rs");

pub(super) fn resolved_output(path: &Path, overwrite_policy: OverwritePolicy) -> ResolvedTarget {
    resolved_artifact(path, PathRole::Output, overwrite_policy)
}

pub(super) fn resolved_artifact(
    path: &Path,
    role: PathRole,
    overwrite_policy: OverwritePolicy,
) -> ResolvedTarget {
    let mut graph = PathIdentityGraph::new();
    graph.add_output(path, role, overwrite_policy).unwrap()
}

pub(super) fn write_existing_target(path: &Path) {
    fs::write(path, EXISTING_OUTPUT).unwrap();
}

pub(super) fn assert_existing_target_preserved(path: &Path) {
    assert_eq!(fs::read(path).unwrap(), EXISTING_OUTPUT);
}

pub(super) fn assert_has_source(error: &TransactionError, label: &str) {
    assert!(
        error.source().is_some(),
        "{label} must preserve its IO source"
    );
}

#[cfg(feature = "test-support")]
pub(super) fn assert_no_source(error: &TransactionError, label: &str) {
    assert!(
        error.source().is_none(),
        "{label} must remain source-free for synthetic failure hooks"
    );
}

#[cfg(feature = "test-support")]
pub(super) fn write_existing_linked_targets(output_path: &Path, header_path: &Path) {
    fs::write(output_path, b"existing linked output").unwrap();
    fs::write(header_path, b"existing linked header").unwrap();
}

#[cfg(feature = "test-support")]
pub(super) fn assert_existing_linked_targets_preserved(output_path: &Path, header_path: &Path) {
    assert_eq!(fs::read(output_path).unwrap(), b"existing linked output");
    assert_eq!(fs::read(header_path).unwrap(), b"existing linked header");
}

#[cfg(unix)]
pub(super) fn symlink_dir_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::unix::fs::symlink(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping transaction symlink test: symlinks unsupported here: {err}");
            false
        }
    }
}

#[cfg(windows)]
pub(super) fn symlink_dir_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::windows::fs::symlink_dir(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping transaction symlink test: symlinks unsupported here: {err}");
            false
        }
    }
}

pub(super) fn cleanup_authorized_artifacts(
    receipt: &impl CleanupAuthorizedReceipt,
) -> &[CommittedArtifact] {
    receipt.committed_artifacts()
}

#[cfg(feature = "test-support")]
pub(super) fn linked_transaction_with_failure_hook(
    point: FailurePoint,
    output_path: &Path,
    header_path: &Path,
) -> LinkedOutputTransaction {
    let mut transaction = LinkedOutputTransaction::with_failure_hooks(FailureHooks::fail_on(point));
    transaction
        .stage(resolved_artifact(
            output_path,
            PathRole::Output,
            OverwritePolicy::ReplaceAtCommit,
        ))
        .unwrap();
    transaction
        .stage(resolved_artifact(
            header_path,
            PathRole::DetachedHeader,
            OverwritePolicy::ReplaceAtCommit,
        ))
        .unwrap();
    transaction
}
