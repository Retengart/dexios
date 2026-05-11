use std::fs;
use std::path::{Path, PathBuf};

use dexios_domain::storage::NamedStagedOutput;
use dexios_domain::storage::identity::{
    OverwritePolicy, PathIdentityGraph, PathRole, ResolvedTarget,
};
use dexios_domain::storage::test_support::{FailureHooks, FailurePoint};
use dexios_domain::storage::transaction::{StagedOutputTransaction, TransactionError};

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
    let mut graph = PathIdentityGraph::new();
    graph
        .add_output(path, PathRole::Output, overwrite_policy)
        .unwrap()
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
