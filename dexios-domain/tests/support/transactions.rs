#![allow(dead_code, unused_imports)]

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

pub(super) const EXISTING_OUTPUT: &[u8] = b"existing output";
pub(super) const CANDIDATE_OUTPUT: &[u8] = b"candidate output";
pub(super) const STORAGE_TEMP_RS: &str = include_str!("../../src/storage/temp.rs");

pub(super) struct TestDir {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl TestDir {
    pub(super) fn new(prefix: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix(&format!("dexios-{prefix}-"))
            .tempdir()
            .unwrap();
        let path = fs::canonicalize(dir.path()).unwrap();
        Self { _dir: dir, path }
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

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
