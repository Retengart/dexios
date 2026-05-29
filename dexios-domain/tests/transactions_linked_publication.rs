#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::unreachable, clippy::string_slice, clippy::too_many_lines, clippy::cast_possible_truncation, clippy::cast_possible_wrap, clippy::cast_sign_loss, clippy::cast_precision_loss, clippy::match_same_arms, clippy::items_after_statements, clippy::redundant_closure_for_method_calls, clippy::needless_collect, clippy::manual_let_else, clippy::format_collect, clippy::case_sensitive_file_extension_comparisons, clippy::struct_excessive_bools, reason = "integration tests assert exact behavior and may panic on failure"))]
#[path = "support/transactions.rs"]
mod transactions_support;

use transactions_support::*;

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
