use std::error::Error as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use dexios_domain::storage::NamedStagedOutput;
use dexios_domain::storage::identity::{
    OverwritePolicy, PathIdentityGraph, PathRole, ResolvedTarget,
};
#[cfg(feature = "test-support")]
use dexios_domain::storage::test_support::{FailureHooks, FailurePoint};
#[cfg(feature = "test-support")]
use dexios_domain::storage::transaction::DetachedPairReceipt;
use dexios_domain::storage::transaction::{
    CleanupAuthorizedReceipt, CommittedArtifact, DetachedPublicationFailure,
    LinkedOutputTransaction, PartialCommitReceipt, StagedOutputTransaction, TransactionError,
};

const EXISTING_OUTPUT: &[u8] = b"existing output";
const CANDIDATE_OUTPUT: &[u8] = b"candidate output";
const STORAGE_TEMP_RS: &str = include_str!("../src/storage/temp.rs");

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
#[cfg(unix)]
fn storage_persist_uses_fd_relative_unix_finalization() {
    assert!(
        STORAGE_TEMP_RS.contains("renameat("),
        "unix staged persist must finalize relative to opened directory fds"
    );
    assert!(
        STORAGE_TEMP_RS.contains("linkat("),
        "unix create-new staged persist must use an atomic no-clobber fd-relative link"
    );
    assert!(
        !STORAGE_TEMP_RS.contains(".persist(") && !STORAGE_TEMP_RS.contains(".persist_noclobber("),
        "unix staged persist must not fall back to path-based tempfile persist APIs"
    );
    assert!(
        !STORAGE_TEMP_RS.contains("create_dir_all"),
        "target parent creation must not follow symlinks through path-based create_dir_all"
    );
}

#[test]
#[cfg(feature = "test-support")]
fn failure_hooks_select_transaction_failure_points() {
    let points = [
        FailurePoint::Write,
        FailurePoint::Flush,
        FailurePoint::Sync,
        FailurePoint::Persist,
        FailurePoint::PostCommitSync,
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

fn assert_has_source(error: &TransactionError, label: &str) {
    assert!(
        error.source().is_some(),
        "{label} must preserve its IO source"
    );
}

#[cfg(feature = "test-support")]
fn assert_no_source(error: &TransactionError, label: &str) {
    assert!(
        error.source().is_none(),
        "{label} must remain source-free for synthetic failure hooks"
    );
}

#[cfg(feature = "test-support")]
fn write_existing_linked_targets(output_path: &Path, header_path: &Path) {
    fs::write(output_path, b"existing linked output").unwrap();
    fs::write(header_path, b"existing linked header").unwrap();
}

#[cfg(feature = "test-support")]
fn assert_existing_linked_targets_preserved(output_path: &Path, header_path: &Path) {
    assert_eq!(fs::read(output_path).unwrap(), b"existing linked output");
    assert_eq!(fs::read(header_path).unwrap(), b"existing linked header");
}

#[cfg(unix)]
fn symlink_dir_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::unix::fs::symlink(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping transaction symlink test: symlinks unsupported here: {err}");
            false
        }
    }
}

#[cfg(windows)]
fn symlink_dir_or_skip(src: &Path, dst: &Path) -> bool {
    match std::os::windows::fs::symlink_dir(src, dst) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("skipping transaction symlink test: symlinks unsupported here: {err}");
            false
        }
    }
}

fn cleanup_authorized_artifacts(receipt: &impl CleanupAuthorizedReceipt) -> &[CommittedArtifact] {
    receipt.committed_artifacts()
}

#[cfg(feature = "test-support")]
fn linked_transaction_with_failure_hook(
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
    assert_eq!(receipt.committed_artifacts().len(), 1);
    assert_eq!(receipt.committed_artifacts()[0].role(), PathRole::Output);
    assert_eq!(receipt.committed_artifacts()[0].path(), target_path);
}

#[test]
fn staged_output_write_error_preserves_io_source() {
    let test_dir = TestDir::new("staged-output-write-source");
    let target_path = test_dir.path().join("output.dexios");
    write_existing_target(&target_path);

    let target = resolved_output(&target_path, OverwritePolicy::ReplaceAtCommit);
    let mut staged = NamedStagedOutput::new(target).unwrap();

    let error = staged
        .with_writer(|_| Err::<(), io::Error>(io::Error::from(io::ErrorKind::BrokenPipe)))
        .unwrap_err();

    match &error {
        TransactionError::Write { path, .. } => assert_eq!(path, &target_path),
        other => panic!("expected write error, got {other:?}"),
    }
    assert_has_source(&error, "staged output write error");
    assert_existing_target_preserved(&target_path);
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
    assert_no_source(&error, "synthetic staged output write failure");
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
    assert_no_source(&error, "synthetic staged output flush failure");
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
    assert_no_source(&error, "synthetic staged output sync failure");
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
    assert_no_source(&error, "synthetic staged output persist failure");
    assert_existing_target_preserved(&target_path);
}

#[test]
#[cfg(all(unix, feature = "test-support"))]
fn staged_output_post_commit_sync_failure_reports_visible_artifact() {
    let test_dir = TestDir::new("staged-output-post-commit-sync");
    let target_path = test_dir.path().join("output.dexios");

    let target = resolved_output(&target_path, OverwritePolicy::CreateNew);
    let mut staged = NamedStagedOutput::with_failure_hooks(
        target,
        FailureHooks::fail_on(FailurePoint::PostCommitSync),
    )
    .unwrap();
    staged.write_all(CANDIDATE_OUTPUT).unwrap();

    let error = staged.persist_replace_at_commit().unwrap_err();

    let TransactionError::PostCommitSync { receipt, .. } = &error else {
        panic!("expected post-commit sync failure, got {error:?}");
    };
    assert_has_source(&error, "synthetic post-commit sync failure");
    assert_eq!(receipt.committed_artifacts().len(), 1);
    assert_eq!(receipt.committed_artifacts()[0].path(), target_path);
    assert_eq!(fs::read(&target_path).unwrap(), CANDIDATE_OUTPUT);
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
    assert_has_source(&error, "staged output no-clobber persist failure");
    assert_existing_target_preserved(&target_path);
}

#[test]
#[cfg(any(unix, windows))]
fn staged_output_rejects_missing_parent_symlink_created_after_validation() {
    let test_dir = TestDir::new("staged-output-missing-parent-symlink");
    let target_path = test_dir.path().join("missing").join("output.dexios");
    let outside_dir = test_dir.path().join("outside");
    fs::create_dir(&outside_dir).unwrap();

    let target = resolved_output(&target_path, OverwritePolicy::CreateNew);
    let mut transaction = StagedOutputTransaction::new(target).unwrap();
    transaction.write_all(CANDIDATE_OUTPUT).unwrap();
    if !symlink_dir_or_skip(&outside_dir, &test_dir.path().join("missing")) {
        return;
    }

    let error = transaction.commit().unwrap_err();

    assert!(
        matches!(error, TransactionError::Persist { .. }),
        "expected persist failure for post-validation symlinked missing parent, got {error:?}"
    );
    assert!(
        !outside_dir.join("output.dexios").exists(),
        "candidate output must not be redirected through a symlinked missing parent"
    );
}

#[test]
#[cfg(unix)]
fn staged_output_rejects_parent_directory_replacement_after_validation() {
    let test_dir = TestDir::new("staged-output-parent-replacement");
    let parent = test_dir.path().join("parent");
    let moved_parent = test_dir.path().join("moved-parent");
    fs::create_dir(&parent).unwrap();
    let target_path = parent.join("output.dexios");

    let target = resolved_output(&target_path, OverwritePolicy::CreateNew);
    let mut transaction = StagedOutputTransaction::new(target).unwrap();
    transaction.write_all(CANDIDATE_OUTPUT).unwrap();
    fs::rename(&parent, &moved_parent).unwrap();
    fs::create_dir(&parent).unwrap();

    let error = transaction.commit().unwrap_err();

    assert!(
        matches!(error, TransactionError::Persist { .. }),
        "expected persist failure for replaced parent directory, got {error:?}"
    );
    assert!(
        !parent.join("output.dexios").exists(),
        "candidate output must not be committed into a replaced parent directory"
    );
    assert!(
        !moved_parent.join("output.dexios").exists(),
        "candidate output must not be committed after parent identity changes"
    );
}

#[test]
#[cfg(unix)]
fn staged_output_rejects_target_leaf_replacement_after_validation() {
    let test_dir = TestDir::new("staged-output-leaf-replacement");
    let target_path = test_dir.path().join("output.dexios");
    let replacement_path = test_dir.path().join("replacement.dexios");
    write_existing_target(&target_path);

    let target = resolved_output(&target_path, OverwritePolicy::ReplaceAtCommit);
    let mut transaction = StagedOutputTransaction::new(target).unwrap();
    transaction.write_all(CANDIDATE_OUTPUT).unwrap();
    fs::write(&replacement_path, EXISTING_OUTPUT).unwrap();
    fs::rename(&replacement_path, &target_path).unwrap();

    let error = transaction.commit().unwrap_err();

    assert!(
        matches!(error, TransactionError::Persist { .. }),
        "expected persist failure for replaced target leaf, got {error:?}"
    );
    assert_eq!(
        fs::read(&target_path).unwrap(),
        EXISTING_OUTPUT,
        "candidate output must not replace a target whose leaf identity changed"
    );
}

#[test]
#[cfg(unix)]
fn staged_output_rejects_replaced_staged_temp_path_before_persist() {
    let test_dir = TestDir::new("staged-output-source-replacement");
    let target_path = test_dir.path().join("output.dexios");

    let target = resolved_output(&target_path, OverwritePolicy::CreateNew);
    let mut transaction = StagedOutputTransaction::new(target).unwrap();
    transaction.write_all(CANDIDATE_OUTPUT).unwrap();
    let staged_path = transaction
        .target()
        .target_parent()
        .read_dir()
        .unwrap()
        .find_map(|entry| {
            let entry = entry.unwrap();
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".tmp")
                .then(|| entry.path())
        })
        .expect("staged temp path");
    fs::remove_file(&staged_path).unwrap();
    fs::write(&staged_path, b"attacker bytes").unwrap();

    let error = transaction.commit().unwrap_err();

    assert!(
        matches!(error, TransactionError::Persist { .. }),
        "expected persist failure for replaced staged source, got {error:?}"
    );
    assert!(
        !target_path.exists(),
        "target must not receive attacker-controlled staged bytes"
    );
}

#[test]
fn staged_output_rejects_existing_directory_target_before_staging() {
    let test_dir = TestDir::new("staged-output-directory-target");
    let target_dir = test_dir.path().join("output-dir");
    fs::create_dir(&target_dir).unwrap();

    let error = match StagedOutputTransaction::new(resolved_output(
        &target_dir,
        OverwritePolicy::ReplaceAtCommit,
    )) {
        Ok(_) => panic!("directory target staging must fail"),
        Err(error) => error,
    };

    assert!(
        matches!(error, TransactionError::Write { .. }),
        "expected write preflight failure for directory target, got {error:?}"
    );
}

#[test]
#[cfg(any(unix, windows))]
fn linked_stage_in_rejects_missing_parent_symlink_before_parent_creation() {
    let test_dir = TestDir::new("linked-stage-in-missing-parent-symlink");
    let target_path = test_dir
        .path()
        .join("missing")
        .join("nested")
        .join("output.dexios");
    let outside_dir = test_dir.path().join("outside");
    fs::create_dir(&outside_dir).unwrap();

    let mut transaction = LinkedOutputTransaction::new();
    let output = transaction
        .stage_in(
            resolved_output(&target_path, OverwritePolicy::CreateNew),
            test_dir.path(),
        )
        .unwrap();
    transaction
        .staged_output_mut(output)
        .unwrap()
        .write_all(CANDIDATE_OUTPUT)
        .unwrap();
    if !symlink_dir_or_skip(&outside_dir, &test_dir.path().join("missing")) {
        return;
    }

    let error = transaction.commit_all().unwrap_err();

    assert!(
        matches!(error, TransactionError::Persist { .. }),
        "expected persist failure before creating parents through a symlink, got {error:?}"
    );
    assert!(
        !outside_dir.join("nested").exists(),
        "parent creation must not be redirected through a symlinked missing component"
    );
    assert!(
        !outside_dir.join("nested/output.dexios").exists(),
        "candidate output must not be redirected through a symlinked missing component"
    );
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
    assert_eq!(receipt.committed_artifacts().len(), 2);
    assert_eq!(receipt.committed_artifacts()[0].role(), PathRole::Output);
    assert_eq!(receipt.committed_artifacts()[0].path(), output_path);
    assert_eq!(
        receipt.committed_artifacts()[1].role(),
        PathRole::DetachedHeader
    );
    assert_eq!(receipt.committed_artifacts()[1].path(), header_path);
}

#[test]
#[cfg(feature = "test-support")]
fn linked_transaction_complete_detached_pair_receipt_names_payload_and_header() {
    let test_dir = TestDir::new("detached-pair-complete-receipt");
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
    let detached_pair = DetachedPairReceipt::from_commit_receipt_for_test(receipt);

    assert_eq!(detached_pair.committed_artifacts().len(), 2);
    assert_eq!(
        detached_pair.committed_artifacts()[0].role(),
        PathRole::Output
    );
    assert_eq!(detached_pair.committed_artifacts()[0].path(), output_path);
    assert_eq!(
        detached_pair.committed_artifacts()[1].role(),
        PathRole::DetachedHeader
    );
    assert_eq!(detached_pair.committed_artifacts()[1].path(), header_path);
}

#[test]
fn complete_commit_receipt_is_cleanup_authorized_public_evidence() {
    let test_dir = TestDir::new("complete-receipt-cleanup-proof");
    let output_path = test_dir.path().join("output.dexios");
    let target = resolved_output(&output_path, OverwritePolicy::CreateNew);
    let mut transaction = StagedOutputTransaction::new(target).unwrap();
    transaction.write_all(CANDIDATE_OUTPUT).unwrap();
    let receipt = transaction.commit().unwrap();

    let artifacts = cleanup_authorized_artifacts(&receipt);

    assert_eq!(artifacts.len(), 1);
    assert_eq!(artifacts[0].role(), PathRole::Output);
    assert_eq!(artifacts[0].path(), output_path);
}

#[test]
#[cfg(feature = "test-support")]
fn linked_transaction_pre_commit_failure_write_preserves_all_existing_targets() {
    let test_dir = TestDir::new("linked-transaction-write-failure");
    let output_path = test_dir.path().join("output.dexios");
    let header_path = test_dir.path().join("output.dexios.hdr");
    write_existing_linked_targets(&output_path, &header_path);

    let mut transaction =
        linked_transaction_with_failure_hook(FailurePoint::Write, &output_path, &header_path);
    let error = transaction
        .staged_output_mut(0)
        .unwrap()
        .write_all(b"new ciphertext")
        .unwrap_err();

    assert!(matches!(error, TransactionError::Write { .. }));
    assert_no_source(&error, "linked transaction pre-commit write failure");
    assert_existing_linked_targets_preserved(&output_path, &header_path);
}

#[test]
#[cfg(feature = "test-support")]
fn linked_transaction_pre_commit_failure_flush_preserves_all_existing_targets() {
    let test_dir = TestDir::new("linked-transaction-flush-failure");
    let output_path = test_dir.path().join("output.dexios");
    let header_path = test_dir.path().join("output.dexios.hdr");
    write_existing_linked_targets(&output_path, &header_path);

    let mut transaction =
        linked_transaction_with_failure_hook(FailurePoint::Flush, &output_path, &header_path);
    transaction
        .staged_output_mut(0)
        .unwrap()
        .write_all(b"new ciphertext")
        .unwrap();
    transaction
        .staged_output_mut(1)
        .unwrap()
        .write_all(b"new detached header")
        .unwrap();

    let error = transaction.commit_all().unwrap_err();

    assert!(matches!(error, TransactionError::Flush { .. }));
    assert_no_source(&error, "linked transaction pre-commit flush failure");
    assert_existing_linked_targets_preserved(&output_path, &header_path);
}

#[test]
#[cfg(feature = "test-support")]
fn linked_transaction_pre_commit_failure_sync_preserves_all_existing_targets() {
    let test_dir = TestDir::new("linked-transaction-sync-failure");
    let output_path = test_dir.path().join("output.dexios");
    let header_path = test_dir.path().join("output.dexios.hdr");
    write_existing_linked_targets(&output_path, &header_path);

    let mut transaction =
        linked_transaction_with_failure_hook(FailurePoint::Sync, &output_path, &header_path);
    transaction
        .staged_output_mut(0)
        .unwrap()
        .write_all(b"new ciphertext")
        .unwrap();
    transaction
        .staged_output_mut(1)
        .unwrap()
        .write_all(b"new detached header")
        .unwrap();

    let error = transaction.commit_all().unwrap_err();

    assert!(matches!(error, TransactionError::Sync { .. }));
    assert_no_source(&error, "linked transaction pre-commit sync failure");
    assert_existing_linked_targets_preserved(&output_path, &header_path);
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

    match &error {
        TransactionError::PartialCommit {
            receipt, failed, ..
        } => {
            let _: &PartialCommitReceipt = receipt;
            assert_eq!(receipt.committed_artifacts().len(), 1);
            assert_eq!(receipt.committed_artifacts()[0].role(), PathRole::Output);
            assert_eq!(receipt.committed_artifacts()[0].path(), output_path);
            assert_eq!(failed.role(), PathRole::DetachedHeader);
            assert_eq!(failed.path(), header_path);
        }
        other => panic!("expected partial commit error, got {other:?}"),
    }
    assert_has_source(&error, "linked transaction partial commit failure");
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
fn linked_transaction_partial_detached_publication_receipt_names_committed_and_failed_artifacts() {
    let test_dir = TestDir::new("detached-pair-partial-receipt");
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
    let TransactionError::PartialCommit { .. } = &error else {
        panic!("expected partial commit error, got {error:?}");
    };

    let partial = error
        .detached_publication_failure()
        .expect("partial detached publication evidence");
    let DetachedPublicationFailure::Partial(partial) = partial else {
        panic!("expected partial detached publication evidence");
    };

    assert_eq!(partial.committed_artifacts().len(), 1);
    assert_eq!(partial.committed_artifacts()[0].role(), PathRole::Output);
    assert_eq!(partial.committed_artifacts()[0].path(), output_path);
    assert_eq!(partial.failed_artifact().role(), PathRole::DetachedHeader);
    assert_eq!(partial.failed_artifact().path(), header_path);
}

#[test]
#[cfg(feature = "test-support")]
fn post_commit_sync_detached_publication_failure_is_not_clean_success() {
    let receipt = PartialCommitReceipt::unchecked_new_for_test(vec![
        CommittedArtifact::unchecked_new_for_test(PathRole::Output, PathBuf::from("payload.enc")),
        CommittedArtifact::unchecked_new_for_test(
            PathRole::DetachedHeader,
            PathBuf::from("payload.hdr"),
        ),
    ]);
    let error = TransactionError::PostCommitSync {
        receipt,
        source: None,
    };

    let Some(DetachedPublicationFailure::PostCommitSync(evidence)) =
        error.detached_publication_failure()
    else {
        panic!("post-commit sync must be detached publication failure evidence");
    };
    assert_eq!(evidence.committed_artifacts().len(), 2);
    assert_eq!(evidence.committed_artifacts()[0].role(), PathRole::Output);
    assert_eq!(
        evidence.committed_artifacts()[1].role(),
        PathRole::DetachedHeader
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
    assert_no_source(&error, "synthetic transaction write hook");
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
    assert_no_source(&error, "synthetic transaction flush hook");
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
    assert_no_source(&error, "synthetic transaction sync hook");
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
    assert_no_source(&error, "synthetic transaction persist hook");
    assert_existing_target_preserved(&target_path);
}
