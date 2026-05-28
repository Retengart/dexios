#[path = "support/transactions.rs"]
mod transactions_support;

use transactions_support::*;

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
