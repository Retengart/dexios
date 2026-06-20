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
#[cfg(feature = "test-support")]
use std::error::Error as _;
use std::fs;
#[cfg(feature = "test-support")]
use std::io;
use std::path::PathBuf;

#[cfg(feature = "test-support")]
use dexios_domain::storage::cleanup::{
    CleanupGateError, CleanupReceipt, CleanupTarget, CleanupTargetIdentity, HashVerification,
    PostCommitSuccess,
};
#[cfg(feature = "test-support")]
use dexios_domain::storage::identity::{OverwritePolicy, PathIdentityGraph, PathRole};
#[cfg(feature = "test-support")]
use dexios_domain::storage::test_support::{FailureError, FailureHooks, FailurePoint};
#[cfg(feature = "test-support")]
use dexios_domain::storage::transaction::{CommitReceipt, StagedOutputTransaction};
#[expect(dead_code, reason = "shared tempdir test helper")]
#[path = "support/tempdir.rs"]
mod tempdir;
use tempdir::DomainTestDir as TestDir;

#[cfg(feature = "test-support")]
fn committed_output(path: PathBuf) -> CommitReceipt {
    let mut graph = PathIdentityGraph::new();
    let target = graph
        .add_output(&path, PathRole::Output, OverwritePolicy::ReplaceAtCommit)
        .expect("resolve committed output");
    let mut transaction = StagedOutputTransaction::new(target).expect("stage committed output");
    transaction
        .write_all(b"committed output")
        .expect("write committed output proof");
    transaction.commit().expect("commit proof output")
}

#[cfg(feature = "test-support")]
fn post_commit_success(path: PathBuf) -> PostCommitSuccess {
    let receipt = committed_output(path);
    PostCommitSuccess::from_commit_and_hash(&receipt, HashVerification::NotRequested).unwrap()
}

#[test]
#[cfg(feature = "test-support")]
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

    let cleanup_receipt =
        CleanupReceipt::from_paths_for_test([file.as_path(), dir.as_path()]).unwrap();
    let proof = post_commit_success(committed);

    let result = cleanup_receipt.run(&proof);

    assert!(
        matches!(
            cleanup_receipt.targets()[0].identity(),
            CleanupTargetIdentity::Verified { .. }
        ),
        "CleanupReceipt::from_paths_for_test must capture target identity evidence"
    );
    assert!(result.is_success(), "cleanup failures: {result:?}");
    assert_eq!(result.deleted.len(), 2);
    assert!(!file.exists());
    assert!(!dir.exists());
}

#[test]
#[cfg(feature = "test-support")]
fn cleanup_receipt_changed_target_identity_is_reported_and_replacement_file_is_not_deleted() {
    let test_dir = TestDir::new("cleanup-receipt-changed-identity");
    let committed = test_dir.path().join("committed.dexios");
    let target = test_dir.path().join("source.txt");
    fs::write(&committed, b"committed output").unwrap();
    fs::write(&target, b"original source").unwrap();

    let cleanup_receipt = CleanupReceipt::from_paths_for_test([target.as_path()]).unwrap();
    let proof = post_commit_success(committed.clone());
    fs::remove_file(&target).unwrap();
    fs::write(&target, b"replacement source").unwrap();

    let result = cleanup_receipt.run(&proof);

    assert!(
        !result.is_success(),
        "cleanup must fail closed when a recorded target identity changes; result={result:?}"
    );
    assert_eq!(fs::read(&committed).unwrap(), b"committed output");
    assert_eq!(fs::read(&target).unwrap(), b"replacement source");
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].target.path(), target.as_path());
    assert!(
        result.failures[0].source().is_some(),
        "changed cleanup identity must retain diagnostic source evidence"
    );
}

#[test]
#[cfg(feature = "test-support")]
fn cleanup_receipt_changed_target_kind_is_reported_and_replacement_directory_is_not_deleted() {
    let test_dir = TestDir::new("cleanup-receipt-changed-kind");
    let committed = test_dir.path().join("committed.dexios");
    let target = test_dir.path().join("source");
    fs::write(&committed, b"committed output").unwrap();
    fs::write(&target, b"original source file").unwrap();

    let cleanup_receipt = CleanupReceipt::from_paths_for_test([target.as_path()]).unwrap();
    let proof = post_commit_success(committed.clone());
    fs::remove_file(&target).unwrap();
    fs::create_dir(&target).unwrap();
    fs::write(target.join("replacement.txt"), b"replacement directory").unwrap();

    let result = cleanup_receipt.run(&proof);

    assert!(
        !result.is_success(),
        "cleanup must fail closed when a recorded file target becomes a directory"
    );
    assert_eq!(fs::read(&committed).unwrap(), b"committed output");
    assert_eq!(
        fs::read(target.join("replacement.txt")).unwrap(),
        b"replacement directory"
    );
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].target.path(), target.as_path());
    assert!(
        result.failures[0].source().is_some(),
        "changed cleanup kind must retain diagnostic source evidence"
    );
}

#[test]
#[cfg(feature = "test-support")]
fn cleanup_receipt_changed_directory_kind_is_reported_and_replacement_file_is_not_deleted() {
    let test_dir = TestDir::new("cleanup-receipt-changed-dir-kind");
    let committed = test_dir.path().join("committed.dexios");
    let target = test_dir.path().join("source-dir");
    fs::write(&committed, b"committed output").unwrap();
    fs::create_dir(&target).unwrap();
    fs::write(target.join("original.txt"), b"original directory").unwrap();

    let cleanup_receipt = CleanupReceipt::from_paths_for_test([target.as_path()]).unwrap();
    let proof = post_commit_success(committed.clone());
    fs::remove_dir_all(&target).unwrap();
    fs::write(&target, b"replacement file").unwrap();

    let result = cleanup_receipt.run(&proof);

    assert!(
        !result.is_success(),
        "cleanup must fail closed when a recorded directory target becomes a file"
    );
    assert_eq!(fs::read(&committed).unwrap(), b"committed output");
    assert_eq!(fs::read(&target).unwrap(), b"replacement file");
}

#[test]
#[cfg(feature = "test-support")]
fn cleanup_receipt_from_processed_source_refuses_replaced_file() {
    let test_dir = TestDir::new("cleanup-receipt-processed-source");
    let committed = test_dir.path().join("committed.dexios");
    let target = test_dir.path().join("source.txt");
    fs::write(&committed, b"committed output").unwrap();
    fs::write(&target, b"original source").unwrap();

    let mut graph = PathIdentityGraph::new();
    let processed_source = graph
        .add_existing(&target, PathRole::ProcessedSource)
        .expect("capture processed source");
    let cleanup_receipt = CleanupReceipt::from_processed_sources_for_test([&processed_source])
        .expect("cleanup receipt");
    let proof = post_commit_success(committed.clone());
    fs::remove_file(&target).unwrap();
    fs::write(&target, b"replacement source").unwrap();

    let result = cleanup_receipt.run(&proof);

    assert!(
        !result.is_success(),
        "processed-source cleanup must fail closed when the processed file is replaced"
    );
    assert_eq!(fs::read(&committed).unwrap(), b"committed output");
    assert_eq!(fs::read(&target).unwrap(), b"replacement source");
}

#[test]
#[cfg(feature = "test-support")]
fn cleanup_receipt_from_processed_source_refuses_same_inode_rewrite() {
    let test_dir = TestDir::new("cleanup-receipt-processed-rewrite");
    let committed = test_dir.path().join("committed.dexios");
    let target = test_dir.path().join("source.txt");
    fs::write(&committed, b"committed output").unwrap();
    fs::write(&target, b"original source").unwrap();

    let mut graph = PathIdentityGraph::new();
    let processed_source = graph
        .add_existing(&target, PathRole::ProcessedSource)
        .expect("capture processed source");
    let cleanup_receipt = CleanupReceipt::from_processed_sources_for_test([&processed_source])
        .expect("cleanup receipt");
    let proof = post_commit_success(committed.clone());
    fs::write(&target, b"changed source").unwrap();

    let result = cleanup_receipt.run(&proof);

    assert!(
        !result.is_success(),
        "processed-source cleanup must fail closed when the same source file is rewritten"
    );
    assert_eq!(fs::read(&committed).unwrap(), b"committed output");
    assert_eq!(fs::read(&target).unwrap(), b"changed source");
}

#[test]
#[cfg(feature = "test-support")]
fn cleanup_receipt_from_processed_source_tree_refuses_changed_directory_tree() {
    let test_dir = TestDir::new("cleanup-receipt-processed-tree");
    let committed = test_dir.path().join("committed.dexios");
    let target = test_dir.path().join("source-dir");
    fs::write(&committed, b"committed output").unwrap();
    fs::create_dir(&target).unwrap();
    fs::write(target.join("original.txt"), b"original directory").unwrap();

    let mut graph = PathIdentityGraph::new();
    let processed_source = graph
        .add_existing(&target, PathRole::ProcessedSource)
        .expect("capture processed source directory");
    let cleanup_receipt = CleanupReceipt::from_processed_source_trees_for_test([&processed_source])
        .expect("cleanup receipt");
    let proof = post_commit_success(committed.clone());
    fs::write(target.join("replacement.txt"), b"new user data").unwrap();

    let result = cleanup_receipt.run(&proof);

    assert!(
        !result.is_success(),
        "processed-source cleanup must fail closed when a processed directory tree changes"
    );
    assert_eq!(fs::read(&committed).unwrap(), b"committed output");
    assert_eq!(
        fs::read(target.join("replacement.txt")).unwrap(),
        b"new user data"
    );
}

#[test]
#[cfg(feature = "test-support")]
fn cleanup_receipt_from_processed_source_tree_refuses_same_inode_file_rewrite() {
    let test_dir = TestDir::new("cleanup-receipt-processed-tree-rewrite");
    let committed = test_dir.path().join("committed.dexios");
    let target = test_dir.path().join("source-dir");
    let file = target.join("original.txt");
    fs::write(&committed, b"committed output").unwrap();
    fs::create_dir(&target).unwrap();
    fs::write(&file, b"original directory").unwrap();

    let mut graph = PathIdentityGraph::new();
    let processed_source = graph
        .add_existing(&target, PathRole::ProcessedSource)
        .expect("capture processed source directory");
    let cleanup_receipt = CleanupReceipt::from_processed_source_trees_for_test([&processed_source])
        .expect("cleanup receipt");
    let proof = post_commit_success(committed.clone());
    fs::write(&file, b"rewritten user data").unwrap();

    let result = cleanup_receipt.run(&proof);

    assert!(
        !result.is_success(),
        "processed-source cleanup must fail closed when a processed directory file is rewritten"
    );
    assert_eq!(fs::read(&committed).unwrap(), b"committed output");
    assert_eq!(fs::read(&file).unwrap(), b"rewritten user data");
}

#[cfg(unix)]
#[test]
#[cfg(feature = "test-support")]
fn cleanup_receipt_changed_target_symlink_is_reported_and_symlink_is_not_deleted() {
    use std::os::unix::fs::symlink;

    let test_dir = TestDir::new("cleanup-receipt-changed-symlink");
    let committed = test_dir.path().join("committed.dexios");
    let target = test_dir.path().join("source.txt");
    let linked_target = test_dir.path().join("replacement-target.txt");
    fs::write(&committed, b"committed output").unwrap();
    fs::write(&target, b"original source").unwrap();
    fs::write(&linked_target, b"replacement target").unwrap();

    let cleanup_receipt = CleanupReceipt::from_paths_for_test([target.as_path()]).unwrap();
    let proof = post_commit_success(committed.clone());
    fs::remove_file(&target).unwrap();
    symlink(&linked_target, &target).unwrap();

    let result = cleanup_receipt.run(&proof);

    assert!(
        !result.is_success(),
        "cleanup must fail closed when a recorded file target becomes a symlink"
    );
    assert_eq!(fs::read(&committed).unwrap(), b"committed output");
    assert!(
        fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&linked_target).unwrap(), b"replacement target");
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

    let cleanup_receipt = CleanupReceipt::unchecked_new_for_test(vec![
        CleanupTarget::unchecked_file_for_test(&injected_failure),
        CleanupTarget::unchecked_file_for_test(&deleted),
    ]);
    assert!(
        cleanup_receipt.targets()[0]
            .identity()
            .source()
            .contains("unchecked CleanupTarget::file constructor"),
        "unchecked test constructor must make weaker cleanup identity status explicit"
    );
    let proof = post_commit_success(committed);

    let result = cleanup_receipt
        .run_with_failure_hooks(&proof, FailureHooks::fail_on(FailurePoint::Cleanup));

    assert!(!result.is_success());
    assert_eq!(result.deleted.len(), 1);
    assert_eq!(result.deleted[0].path(), deleted.as_path());
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].target.path(), injected_failure.as_path());
    assert_eq!(result.failures[0].error, io::ErrorKind::Other);
    let hook_source = result.failures[0]
        .source()
        .and_then(|source| source.downcast_ref::<FailureError>())
        .expect("cleanup failure source must retain the typed failure hook");
    assert_eq!(result.failures[0].error, io::ErrorKind::Other);
    assert_eq!(hook_source.point(), FailurePoint::Cleanup);
    assert!(injected_failure.exists());
    assert!(!deleted.exists());
}

#[test]
#[cfg(feature = "test-support")]
fn cleanup_receipt_requires_hash_success_before_delete() {
    let test_dir = TestDir::new("cleanup-receipt-hash-gate");
    let committed = test_dir.path().join("committed.dexios");
    let target = test_dir.path().join("source.txt");
    fs::write(&committed, b"committed output").unwrap();
    fs::write(&target, b"source file").unwrap();
    let cleanup_receipt = CleanupReceipt::from_paths_for_test([target.as_path()]).unwrap();
    let commit_receipt = committed_output(committed);

    let proof = PostCommitSuccess::from_commit_and_hash(&commit_receipt, HashVerification::Failed);

    assert_eq!(proof, Err(CleanupGateError::HashNotVerified));
    assert!(target.exists());
    assert_eq!(cleanup_receipt.targets().len(), 1);
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
        FailurePoint::PostCommitSync,
    ] {
        assert!(hooks.check(point).is_ok(), "non-cleanup point should pass");
    }

    let error = hooks
        .check(FailurePoint::Cleanup)
        .expect_err("cleanup point should fail");
    assert_eq!(error.point(), FailurePoint::Cleanup);
}
