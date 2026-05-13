use std::fs;
use std::path::{Path, PathBuf};

use dexios_domain::storage::NamedStagedOutput;
use dexios_domain::storage::identity::{
    OverwritePolicy, PathIdentityGraph, PathRole, ResolvedTarget,
};
#[cfg(feature = "test-support")]
use dexios_domain::storage::test_support::{FailureHooks, FailurePoint};
use dexios_domain::storage::transaction::{
    LinkedOutputTransaction, StagedOutputTransaction, TransactionError,
};

const EXISTING_OUTPUT: &[u8] = b"existing output";
const CANDIDATE_OUTPUT: &[u8] = b"candidate output";

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

#[test]
fn transaction_harness_creates_final_and_staged_paths() {
    let test_dir = TestDir::new("transactions");
    let final_output = test_dir.path().join("output.dexios");
    let staged_output = test_dir.path().join("output.dexios.staged");

    fs::write(&final_output, b"existing output").unwrap();
    fs::write(&staged_output, b"candidate output").unwrap();

    // D-17 requires overwrite-preservation tests to use real filesystem paths.
    assert_eq!(fs::read(&final_output).unwrap(), b"existing output");
    assert_eq!(fs::read(&staged_output).unwrap(), b"candidate output");
}

#[test]
#[cfg(feature = "test-support")]
fn failure_hooks_select_transaction_failure_points() {
    let points = [
        FailurePoint::Write,
        FailurePoint::Flush,
        FailurePoint::Sync,
        FailurePoint::Persist,
    ];

    for selected in points {
        let hooks = FailureHooks::fail_on(selected);

        for point in points {
            let result = hooks.check(point);
            if point == selected {
                let error = result.expect_err("selected point should fail");
                assert_eq!(error.point(), selected);
            } else {
                assert!(result.is_ok(), "non-selected point should pass");
            }
        }
    }

    let hooks = FailureHooks::none();
    for point in points {
        assert!(hooks.check(point).is_ok());
    }
}

fn resolved_output(path: &Path, overwrite_policy: OverwritePolicy) -> ResolvedTarget {
    resolved_artifact(path, PathRole::Output, overwrite_policy)
}

fn resolved_artifact(
    path: &Path,
    role: PathRole,
    overwrite_policy: OverwritePolicy,
) -> ResolvedTarget {
    let mut graph = PathIdentityGraph::new();
    graph.add_output(path, role, overwrite_policy).unwrap()
}

fn write_existing_target(path: &Path) {
    fs::write(path, EXISTING_OUTPUT).unwrap();
}

fn assert_existing_target_preserved(path: &Path) {
    assert_eq!(fs::read(path).unwrap(), EXISTING_OUTPUT);
}

#[test]
fn staged_output_commits_replacement_after_flush_sync_persist() {
    let test_dir = TestDir::new("staged-output-commit");
    let target_path = test_dir.path().join("output.dexios");
    write_existing_target(&target_path);

    let target = resolved_output(&target_path, OverwritePolicy::ReplaceAtCommit);
    let mut transaction = StagedOutputTransaction::new(target).unwrap();
    transaction.write_all(CANDIDATE_OUTPUT).unwrap();

    let receipt = transaction.commit().unwrap();

    assert_eq!(fs::read(&target_path).unwrap(), CANDIDATE_OUTPUT);
    assert_eq!(receipt.artifacts.len(), 1);
    assert_eq!(receipt.artifacts[0].role, PathRole::Output);
    assert_eq!(receipt.artifacts[0].path, target_path);
}

#[test]
#[cfg(feature = "test-support")]
fn staged_output_write_failure_preserves_existing_target() {
    let test_dir = TestDir::new("staged-output-write");
    let target_path = test_dir.path().join("output.dexios");
    write_existing_target(&target_path);

    let target = resolved_output(&target_path, OverwritePolicy::ReplaceAtCommit);
    let mut staged =
        NamedStagedOutput::with_failure_hooks(target, FailureHooks::fail_on(FailurePoint::Write))
            .unwrap();

    let error = staged.write_all(CANDIDATE_OUTPUT).unwrap_err();

    assert!(matches!(error, TransactionError::Write { .. }));
    assert_existing_target_preserved(&target_path);
}

#[test]
#[cfg(feature = "test-support")]
fn staged_output_flush_failure_preserves_existing_target() {
    let test_dir = TestDir::new("staged-output-flush");
    let target_path = test_dir.path().join("output.dexios");
    write_existing_target(&target_path);

    let target = resolved_output(&target_path, OverwritePolicy::ReplaceAtCommit);
    let mut staged =
        NamedStagedOutput::with_failure_hooks(target, FailureHooks::fail_on(FailurePoint::Flush))
            .unwrap();
    staged.write_all(CANDIDATE_OUTPUT).unwrap();

    let error = staged.flush().unwrap_err();

    assert!(matches!(error, TransactionError::Flush { .. }));
    assert_existing_target_preserved(&target_path);
}

#[test]
#[cfg(feature = "test-support")]
fn staged_output_sync_failure_preserves_existing_target() {
    let test_dir = TestDir::new("staged-output-sync");
    let target_path = test_dir.path().join("output.dexios");
    write_existing_target(&target_path);

    let target = resolved_output(&target_path, OverwritePolicy::ReplaceAtCommit);
    let mut staged =
        NamedStagedOutput::with_failure_hooks(target, FailureHooks::fail_on(FailurePoint::Sync))
            .unwrap();
    staged.write_all(CANDIDATE_OUTPUT).unwrap();
    staged.flush().unwrap();

    let error = staged.sync_all().unwrap_err();

    assert!(matches!(error, TransactionError::Sync { .. }));
    assert_existing_target_preserved(&target_path);
}

#[test]
#[cfg(feature = "test-support")]
fn staged_output_persist_failure_preserves_existing_target() {
    let test_dir = TestDir::new("staged-output-persist");
    let target_path = test_dir.path().join("output.dexios");
    write_existing_target(&target_path);

    let target = resolved_output(&target_path, OverwritePolicy::ReplaceAtCommit);
    let mut staged =
        NamedStagedOutput::with_failure_hooks(target, FailureHooks::fail_on(FailurePoint::Persist))
            .unwrap();
    staged.write_all(CANDIDATE_OUTPUT).unwrap();

    let error = staged.persist_replace_at_commit().unwrap_err();

    assert!(matches!(error, TransactionError::Persist { .. }));
    assert_existing_target_preserved(&target_path);
}

#[test]
fn staged_output_create_new_uses_no_clobber_persist() {
    let test_dir = TestDir::new("staged-output-noclobber");
    let target_path = test_dir.path().join("output.dexios");
    write_existing_target(&target_path);

    let target = resolved_output(&target_path, OverwritePolicy::CreateNew);
    let mut staged = NamedStagedOutput::new(target).unwrap();
    staged.write_all(CANDIDATE_OUTPUT).unwrap();

    let error = staged.persist_replace_at_commit().unwrap_err();

    assert!(matches!(error, TransactionError::Persist { .. }));
    assert_existing_target_preserved(&target_path);
}

#[test]
fn linked_transaction_commits_output_and_header_together() {
    let test_dir = TestDir::new("linked-transaction-commit");
    let output_path = test_dir.path().join("output.dexios");
    let header_path = test_dir.path().join("output.dexios.hdr");

    let mut transaction = LinkedOutputTransaction::new();
    let output = transaction
        .stage(resolved_artifact(
            &output_path,
            PathRole::Output,
            OverwritePolicy::CreateNew,
        ))
        .unwrap();
    let header = transaction
        .stage(resolved_artifact(
            &header_path,
            PathRole::DetachedHeader,
            OverwritePolicy::CreateNew,
        ))
        .unwrap();
    transaction
        .staged_output_mut(output)
        .unwrap()
        .write_all(b"ciphertext")
        .unwrap();
    transaction
        .staged_output_mut(header)
        .unwrap()
        .write_all(b"detached header")
        .unwrap();

    let receipt = transaction.commit_all().unwrap();

    assert_eq!(fs::read(&output_path).unwrap(), b"ciphertext");
    assert_eq!(fs::read(&header_path).unwrap(), b"detached header");
    assert_eq!(receipt.artifacts.len(), 2);
    assert_eq!(receipt.artifacts[0].role, PathRole::Output);
    assert_eq!(receipt.artifacts[0].path, output_path);
    assert_eq!(receipt.artifacts[1].role, PathRole::DetachedHeader);
    assert_eq!(receipt.artifacts[1].path, header_path);
}

#[test]
fn linked_transaction_blocks_cleanup_after_partial_commit() {
    let test_dir = TestDir::new("linked-transaction-partial");
    let output_path = test_dir.path().join("output.dexios");
    let header_path = test_dir.path().join("output.dexios.hdr");
    fs::write(&header_path, b"existing header").unwrap();

    let mut transaction = LinkedOutputTransaction::new();
    let output = transaction
        .stage(resolved_artifact(
            &output_path,
            PathRole::Output,
            OverwritePolicy::CreateNew,
        ))
        .unwrap();
    let header = transaction
        .stage(resolved_artifact(
            &header_path,
            PathRole::DetachedHeader,
            OverwritePolicy::CreateNew,
        ))
        .unwrap();
    transaction
        .staged_output_mut(output)
        .unwrap()
        .write_all(b"ciphertext")
        .unwrap();
    transaction
        .staged_output_mut(header)
        .unwrap()
        .write_all(b"new header")
        .unwrap();

    let error = transaction.commit_all().unwrap_err();

    match error {
        TransactionError::PartialCommit { receipt, failed } => {
            assert_eq!(receipt.artifacts.len(), 1);
            assert_eq!(receipt.artifacts[0].role, PathRole::Output);
            assert_eq!(receipt.artifacts[0].path, output_path);
            assert_eq!(failed.role, PathRole::DetachedHeader);
            assert_eq!(failed.path, header_path);
        }
        other => panic!("expected partial commit error, got {other:?}"),
    }
    assert_eq!(
        fs::read(test_dir.path().join("output.dexios")).unwrap(),
        b"ciphertext"
    );
    assert_eq!(
        fs::read(test_dir.path().join("output.dexios.hdr")).unwrap(),
        b"existing header"
    );
}

#[test]
#[cfg(feature = "test-support")]
fn transaction_failure_hook_write_preserves_existing_target() {
    let test_dir = TestDir::new("failure-hook-write");
    let target_path = test_dir.path().join("output.dexios");
    write_existing_target(&target_path);

    let target = resolved_output(&target_path, OverwritePolicy::ReplaceAtCommit);
    let mut transaction = StagedOutputTransaction::with_failure_hooks(
        target,
        FailureHooks::fail_on(FailurePoint::Write),
    )
    .unwrap();

    let error = transaction.write_all(CANDIDATE_OUTPUT).unwrap_err();

    assert!(matches!(error, TransactionError::Write { .. }));
    assert_existing_target_preserved(&target_path);
}

#[test]
#[cfg(feature = "test-support")]
fn transaction_failure_hook_flush_preserves_existing_target() {
    let test_dir = TestDir::new("failure-hook-flush");
    let target_path = test_dir.path().join("output.dexios");
    write_existing_target(&target_path);

    let target = resolved_output(&target_path, OverwritePolicy::ReplaceAtCommit);
    let mut transaction = StagedOutputTransaction::with_failure_hooks(
        target,
        FailureHooks::fail_on(FailurePoint::Flush),
    )
    .unwrap();
    transaction.write_all(CANDIDATE_OUTPUT).unwrap();

    let error = transaction.commit().unwrap_err();

    assert!(matches!(error, TransactionError::Flush { .. }));
    assert_existing_target_preserved(&target_path);
}

#[test]
#[cfg(feature = "test-support")]
fn transaction_failure_hook_sync_preserves_existing_target() {
    let test_dir = TestDir::new("failure-hook-sync");
    let target_path = test_dir.path().join("output.dexios");
    write_existing_target(&target_path);

    let target = resolved_output(&target_path, OverwritePolicy::ReplaceAtCommit);
    let mut transaction = StagedOutputTransaction::with_failure_hooks(
        target,
        FailureHooks::fail_on(FailurePoint::Sync),
    )
    .unwrap();
    transaction.write_all(CANDIDATE_OUTPUT).unwrap();

    let error = transaction.commit().unwrap_err();

    assert!(matches!(error, TransactionError::Sync { .. }));
    assert_existing_target_preserved(&target_path);
}

#[test]
#[cfg(feature = "test-support")]
fn transaction_failure_hook_persist_preserves_existing_target() {
    let test_dir = TestDir::new("failure-hook-persist");
    let target_path = test_dir.path().join("output.dexios");
    write_existing_target(&target_path);

    let target = resolved_output(&target_path, OverwritePolicy::ReplaceAtCommit);
    let mut transaction = StagedOutputTransaction::with_failure_hooks(
        target,
        FailureHooks::fail_on(FailurePoint::Persist),
    )
    .unwrap();
    transaction.write_all(CANDIDATE_OUTPUT).unwrap();

    let error = transaction.commit().unwrap_err();

    assert!(matches!(error, TransactionError::Persist { .. }));
    assert_existing_target_preserved(&target_path);
}
