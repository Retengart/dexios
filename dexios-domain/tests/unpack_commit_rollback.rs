#[path = "support/unpack_v1.rs"]
mod unpack_support;

use unpack_support::*;

#[cfg(feature = "test-support")]
#[test]
fn unpack_commit_failure_removes_created_selected_directories() {
    let test_dir = TestDir::new("unpack-rollback-created-dir");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[("created-dir/", b""), ("payload.txt", b"payload")],
    );

    let result = unpack_archive_with_failure_hooks(
        &encrypted_archive,
        &output_dir,
        FailureHooks::fail_on(FailurePoint::Persist),
    );

    assert_first_persist_failure(result);
    assert!(
        !output_dir.join("created-dir").exists(),
        "current-run selected directory must be removed after first-file commit failure"
    );
}
#[cfg(feature = "test-support")]
#[test]
fn unpack_commit_failure_preserves_preexisting_selected_directories() {
    let test_dir = TestDir::new("unpack-rollback-preexisting-dir");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let preexisting_dir = output_dir.join("preexisting");
    let sentinel = preexisting_dir.join("sentinel.txt");

    fs::create_dir_all(&preexisting_dir).unwrap();
    fs::write(&sentinel, b"keep me").unwrap();
    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[("preexisting/", b""), ("payload.txt", b"payload")],
    );

    let result = unpack_archive_with_failure_hooks(
        &encrypted_archive,
        &output_dir,
        FailureHooks::fail_on(FailurePoint::Persist),
    );

    assert_first_persist_failure(result);
    assert!(
        preexisting_dir.is_dir(),
        "pre-existing selected directory must survive rollback"
    );
    assert_eq!(fs::read(&sentinel).unwrap(), b"keep me");
}
#[cfg(feature = "test-support")]
#[test]
fn unpack_commit_failure_removes_nested_intermediates_in_reverse_order() {
    let test_dir = TestDir::new("unpack-rollback-nested-dir");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[("nested/created/", b""), ("payload.txt", b"payload")],
    );

    let result = unpack_archive_with_failure_hooks(
        &encrypted_archive,
        &output_dir,
        FailureHooks::fail_on(FailurePoint::Persist),
    );

    assert_first_persist_failure(result);
    assert!(
        !output_dir.join("nested/created").exists(),
        "created nested selected directory must be removed"
    );
    assert!(
        !output_dir.join("nested").exists(),
        "intermediate directory created by create_unpack_dir_all must be removed"
    );
}
#[test]
fn unpack_corrupted_stream_never_extracts_outputs() {
    let test_dir = TestDir::new("unpack-corrupted-stream");

    for (label, corrupt) in [
        ("final-tamper", tamper_final_stream_chunk as fn(&Path)),
        ("one-byte-truncation", truncate_stream as fn(&Path)),
    ] {
        let encrypted_archive = test_dir.path().join(format!("{label}.enc"));
        let output_dir = test_dir.path().join(format!("{label}-out"));
        let payload = vec![0xA5; BLOCK_SIZE + 37];

        write_manifest_archive_with_entries(
            &encrypted_archive,
            &[("safe.txt", payload.as_slice())],
        );
        corrupt(&encrypted_archive);

        let result = unpack_archive(&encrypted_archive, &output_dir, None);

        assert!(
            matches!(
                result,
                Err(unpack::Error::Decrypt(decrypt::Error::DecryptData))
            ),
            "{label}: expected corrupted encrypted archive to fail authentication, got {result:?}"
        );
        assert!(
            !output_dir.join("safe.txt").exists(),
            "{label}: corrupted archive must not extract safe entries"
        );
    }
}
#[test]
fn unpack_archive_final_auth_failure_preserves_final_outputs() {
    let test_dir = TestDir::new("unpack-final-auth-no-commit");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let existing_file = output_dir.join("safe.txt");
    let sentinel = b"existing archive final output";
    let payload = vec![0xA5; BLOCK_SIZE + 37];

    fs::create_dir_all(&output_dir).unwrap();
    fs::write(&existing_file, sentinel).unwrap();
    write_manifest_archive_with_entries(&encrypted_archive, &[("safe.txt", payload.as_slice())]);
    tamper_final_stream_chunk(&encrypted_archive);

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(
            result,
            Err(unpack::Error::Decrypt(decrypt::Error::DecryptData))
        ),
        "archive final-auth failure must be reported before extraction commit, got {result:?}"
    );
    assert_eq!(
        fs::read(&existing_file).unwrap(),
        sentinel.as_slice(),
        "unpack final output must remain unchanged until stream final auth succeeds"
    );
}
#[test]
fn unpack_preserves_existing_file_when_later_extraction_fails() {
    let test_dir = TestDir::new("unpack-staged-preserve");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let existing_file = output_dir.join("existing.txt");
    let blocked_target = output_dir.join("blocked");

    fs::create_dir_all(&blocked_target).unwrap();
    fs::write(&existing_file, b"original contents").unwrap();
    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[
            ("existing.txt", b"candidate replacement"),
            ("blocked", b"cannot replace directory"),
        ],
    );

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(
            result,
            Err(unpack::Error::UnsafeOutputPath(ref path)) if path == &blocked_target
        ),
        "expected unsafe output path error, got {result:?}"
    );
    assert_eq!(fs::read(&existing_file).unwrap(), b"original contents");
    assert!(blocked_target.is_dir());
}
