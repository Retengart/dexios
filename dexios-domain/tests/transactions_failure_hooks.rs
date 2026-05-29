#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::unreachable, clippy::string_slice, clippy::too_many_lines, clippy::cast_possible_truncation, clippy::cast_possible_wrap, clippy::cast_sign_loss, clippy::cast_precision_loss, clippy::match_same_arms, clippy::items_after_statements, clippy::redundant_closure_for_method_calls, clippy::needless_collect, clippy::manual_let_else, clippy::format_collect, clippy::case_sensitive_file_extension_comparisons, clippy::struct_excessive_bools, reason = "integration tests assert exact behavior and may panic on failure"))]
#[path = "support/transactions.rs"]
mod transactions_support;

use transactions_support::*;

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
