#[path = "support/unpack_v1.rs"]
mod unpack_support;

use unpack_support::*;

#[test]
fn unpack_rejects_entry_that_aliases_encrypted_input_archive() {
    let test_dir = TestDir::new("unpack-input-alias");
    let encrypted_archive = test_dir.path().join("archive.enc");

    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[
            ("archive.enc", b"plaintext replacement"),
            ("safe.txt", b"safe"),
        ],
    );
    let original_archive = fs::read(&encrypted_archive).unwrap();

    let result = unpack_archive(&encrypted_archive, test_dir.path(), None);

    assert!(
        matches!(
            result,
            Err(unpack::Error::PathIdentity(
                IdentityError::AliasedPath { .. }
            ))
        ),
        "expected input archive alias rejection, got {result:?}"
    );
    assert_eq!(fs::read(&encrypted_archive).unwrap(), original_archive);
    assert!(!test_dir.path().join("safe.txt").exists());
}
#[test]
fn unpack_rejects_entry_that_aliases_detached_header() {
    let test_dir = TestDir::new("unpack-header-alias");
    let encrypted_archive = test_dir.path().join("archive-detached.enc");
    let detached_header = test_dir.path().join("archive.hdr");

    write_detached_manifest_archive_with_entries(
        &encrypted_archive,
        &detached_header,
        &[
            ("archive.hdr", b"detached header replacement"),
            ("safe.txt", b"safe"),
        ],
    );
    let original_header = fs::read(&detached_header).unwrap();

    let result =
        unpack_archive_with_detached_header(&encrypted_archive, &detached_header, test_dir.path());

    assert!(
        matches!(
            result,
            Err(unpack::Error::PathIdentity(
                IdentityError::AliasedPath { .. }
            ))
        ),
        "expected detached header alias rejection, got {result:?}"
    );
    assert_eq!(fs::read(&detached_header).unwrap(), original_header);
    assert!(!test_dir.path().join("safe.txt").exists());
}
#[test]
fn unpack_rejects_unsafe_entry_without_extracting_safe_sibling() {
    let test_dir = TestDir::new("unpack-unsafe-sibling");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[("../escape.txt", b"escape"), ("safe.txt", b"safe")],
    );

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(result, Err(unpack::Error::UnsafeOutputPath(_))),
        "expected unsafe output path error, got {result:?}"
    );
    assert!(!output_dir.join("safe.txt").exists());
    assert!(!test_dir.path().join("escape.txt").exists());
}
#[test]
fn unpack_arch_04_d16_temp_cleanup_on_validation_failure_commits_no_outputs() {
    let test_dir = TestDir::new("unpack-temp-cleanup-validation");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[("../escape.txt", b"escape"), ("safe.txt", b"safe")],
    );

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(matches!(result, Err(unpack::Error::UnsafeOutputPath(_))));
    assert!(!output_dir.join("safe.txt").exists());
    assert!(!test_dir.path().join("escape.txt").exists());
}
#[test]
fn unpack_rejects_unsafe_archive_before_overwrite_callback() {
    let test_dir = TestDir::new("unpack-unsafe-no-prompt");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let callback_count = Arc::new(AtomicUsize::new(0));

    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[("../escape.txt", b"escape"), ("safe.txt", b"safe")],
    );

    let callback_count_for_closure = Arc::clone(&callback_count);
    let result = unpack_archive(
        &encrypted_archive,
        &output_dir,
        Some(Box::new(move |_| {
            callback_count_for_closure.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        })),
    );

    assert!(
        matches!(result, Err(unpack::Error::UnsafeOutputPath(_))),
        "expected unsafe output path error, got {result:?}"
    );
    assert_eq!(callback_count.load(Ordering::SeqCst), 0);
    assert!(!output_dir.join("safe.txt").exists());
}
#[test]
fn unpack_rejects_file_prefix_collision_before_extraction() {
    let test_dir = TestDir::new("unpack-prefix-collision");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_manifest_archive_with_entries(&encrypted_archive, &[("a", b"file"), ("a/b", b"child")]);

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(result, Err(unpack::Error::DuplicateOutputPath(_))),
        "expected duplicate output path error, got {result:?}"
    );
    assert!(!output_dir.join("a").exists());
    assert!(!output_dir.join("a/b").exists());
}
#[test]
fn unpack_declined_safe_overwrite_is_skipped_after_validation() {
    let test_dir = TestDir::new("unpack-declined-overwrite");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let existing_file = output_dir.join("existing.txt");

    fs::create_dir_all(&output_dir).unwrap();
    fs::write(&existing_file, b"original contents").unwrap();
    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[
            ("existing.txt", b"candidate replacement"),
            ("new.txt", b"new contents"),
        ],
    );

    let receipt = unpack_archive(
        &encrypted_archive,
        &output_dir,
        Some(Box::new({
            let existing_file = existing_file.clone();
            move |path| Ok(path != existing_file)
        })),
    )
    .unwrap();

    assert_eq!(fs::read(&existing_file).unwrap(), b"original contents");
    assert_eq!(
        fs::read_to_string(output_dir.join("new.txt")).unwrap(),
        "new contents"
    );
    assert_eq!(receipt.committed_artifacts().len(), 1);
}
#[test]
fn unpack_rejects_duplicate_targets_after_path_normalization() {
    let test_dir = TestDir::new("unpack-duplicate-targets");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[("collision.txt", b"first"), ("collision.txt", b"second")],
    );

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(
            result,
            Err(unpack::Error::DuplicateOutputPath(ref path))
                if path == Path::new("collision.txt")
        ),
        "expected duplicate output path error, got {result:?}"
    );
    assert!(!output_dir.join("collision.txt").exists());
}
