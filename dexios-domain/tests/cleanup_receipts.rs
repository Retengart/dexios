use std::fs;
#[cfg(feature = "test-support")]
use std::io;
use std::path::{Path, PathBuf};

#[cfg(feature = "test-support")]
use dexios_domain::storage::cleanup::CleanupTarget;
use dexios_domain::storage::cleanup::{
    CleanupGateError, CleanupReceipt, HashVerification, PostCommitSuccess,
};
use dexios_domain::storage::identity::PathRole;
#[cfg(feature = "test-support")]
use dexios_domain::storage::test_support::{FailureHooks, FailurePoint};
use dexios_domain::storage::transaction::{CommitReceipt, CommittedArtifact};

struct TestDir {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl TestDir {
    fn new(prefix: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix(&format!("dexios-{prefix}-"))
            .tempdir()
            .unwrap();
        let path = fs::canonicalize(dir.path()).unwrap();
        Self { _dir: dir, path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn committed_output(path: PathBuf) -> CommitReceipt {
    CommitReceipt {
        artifacts: vec![CommittedArtifact {
            role: PathRole::Output,
            path,
        }],
    }
}

fn post_commit_success(path: PathBuf) -> PostCommitSuccess {
    let receipt = committed_output(path);
    PostCommitSuccess::from_commit_and_hash(&receipt, HashVerification::NotRequested).unwrap()
}

#[test]
fn cleanup_receipt_harness_uses_disposable_targets() {
    let test_dir = TestDir::new("cleanup-receipts");
    let committed_output = test_dir.path().join("committed.dexios");
    let cleanup_target = test_dir.path().join("source.txt");

    fs::write(&committed_output, b"committed output").unwrap();
    fs::write(&cleanup_target, b"cleanup target").unwrap();
    fs::remove_file(&cleanup_target).unwrap();

    // D-17 requires delete-after-success tests to use real cleanup targets.
    assert_eq!(fs::read(&committed_output).unwrap(), b"committed output");
    assert!(!cleanup_target.exists());
}

#[test]
fn cleanup_receipt_deletes_all_targets_after_post_commit_success() {
    let test_dir = TestDir::new("cleanup-receipt-delete-all");
    let committed = test_dir.path().join("committed.dexios");
    let file = test_dir.path().join("source.txt");
    let dir = test_dir.path().join("source-dir");
    let nested = dir.join("nested.txt");
    fs::write(&committed, b"committed output").unwrap();
    fs::write(&file, b"source file").unwrap();
    fs::create_dir(&dir).unwrap();
    fs::write(&nested, b"nested source").unwrap();

    let cleanup_receipt = CleanupReceipt::from_paths([file.as_path(), dir.as_path()]).unwrap();
    let proof = post_commit_success(committed);

    let result = cleanup_receipt.run(&proof);

    assert!(result.is_success(), "cleanup failures: {result:?}");
    assert_eq!(result.deleted.len(), 2);
    assert!(!file.exists());
    assert!(!dir.exists());
}

#[test]
#[cfg(feature = "test-support")]
fn cleanup_receipt_reports_partial_failure() {
    let test_dir = TestDir::new("cleanup-receipt-partial-failure");
    let committed = test_dir.path().join("committed.dexios");
    let injected_failure = test_dir.path().join("still-present.txt");
    let deleted = test_dir.path().join("deleted.txt");
    fs::write(&committed, b"committed output").unwrap();
    fs::write(&injected_failure, b"source one").unwrap();
    fs::write(&deleted, b"source two").unwrap();

    let cleanup_receipt = CleanupReceipt::new(vec![
        CleanupTarget::file(&injected_failure),
        CleanupTarget::file(&deleted),
    ]);
    let proof = post_commit_success(committed);

    let result = cleanup_receipt
        .run_with_failure_hooks(&proof, FailureHooks::fail_on(FailurePoint::Cleanup));

    assert!(!result.is_success());
    assert_eq!(result.deleted.len(), 1);
    assert_eq!(result.deleted[0].path, deleted);
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].target.path, injected_failure);
    assert_eq!(result.failures[0].error, io::ErrorKind::Other);
    assert!(injected_failure.exists());
    assert!(!deleted.exists());
}

#[test]
fn cleanup_receipt_requires_hash_success_before_delete() {
    let test_dir = TestDir::new("cleanup-receipt-hash-gate");
    let committed = test_dir.path().join("committed.dexios");
    let target = test_dir.path().join("source.txt");
    fs::write(&committed, b"committed output").unwrap();
    fs::write(&target, b"source file").unwrap();
    let cleanup_receipt = CleanupReceipt::from_paths([target.as_path()]).unwrap();
    let commit_receipt = committed_output(committed);

    let proof = PostCommitSuccess::from_commit_and_hash(&commit_receipt, HashVerification::Failed);

    assert_eq!(proof, Err(CleanupGateError::HashNotVerified));
    assert!(target.exists());
    assert_eq!(cleanup_receipt.targets.len(), 1);
}

#[test]
#[cfg(feature = "test-support")]
fn failure_hooks_select_cleanup_failure_point() {
    let hooks = FailureHooks::fail_on(FailurePoint::Cleanup);

    for point in [
        FailurePoint::Write,
        FailurePoint::Flush,
        FailurePoint::Sync,
        FailurePoint::Persist,
    ] {
        assert!(hooks.check(point).is_ok(), "non-cleanup point should pass");
    }

    let error = hooks
        .check(FailurePoint::Cleanup)
        .expect_err("cleanup point should fail");
    assert_eq!(error.point(), FailurePoint::Cleanup);
}
