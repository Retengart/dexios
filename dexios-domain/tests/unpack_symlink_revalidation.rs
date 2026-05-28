#[path = "support/unpack_v1.rs"]
mod unpack_support;

use unpack_support::*;

#[cfg(any(unix, windows))]
#[test]
fn unpack_revalidates_symlinked_prefix_created_after_validation() {
    let test_dir = TestDir::new("unpack-toctou-symlink");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let outside_dir = test_dir.path().join("outside");
    let output_dir = test_dir.path().join("out");

    fs::create_dir_all(&outside_dir).unwrap();
    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[("payload/secret.txt", b"top secret")],
    );

    let result = unpack_archive(
        &encrypted_archive,
        &output_dir,
        Some(Box::new({
            let output_dir = output_dir.clone();
            let outside_dir = outside_dir.clone();
            move |path| {
                if path.ends_with("payload/secret.txt") {
                    symlink_dir(&outside_dir, &output_dir.join("payload"));
                }
                Ok(true)
            }
        })),
    );

    assert!(
        matches!(result, Err(unpack::Error::UnsafeOutputPath(_))),
        "expected unsafe output path error, got {result:?}"
    );
    assert!(!outside_dir.join("secret.txt").exists());
}
#[cfg(any(unix, windows))]
#[test]
fn unpack_revalidation_failure_preserves_existing_outputs() {
    let test_dir = TestDir::new("unpack-toctou-preserve");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let outside_dir = test_dir.path().join("outside");
    let output_dir = test_dir.path().join("out");
    let existing_file = output_dir.join("existing.txt");

    fs::create_dir_all(&outside_dir).unwrap();
    fs::create_dir_all(&output_dir).unwrap();
    fs::write(&existing_file, b"original contents").unwrap();
    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[
            ("existing.txt", b"candidate replacement"),
            ("payload/secret.txt", b"top secret"),
        ],
    );

    let result = unpack_archive(
        &encrypted_archive,
        &output_dir,
        Some(Box::new({
            let output_dir = output_dir.clone();
            let outside_dir = outside_dir.clone();
            move |path| {
                if path.ends_with("payload/secret.txt") {
                    symlink_dir(&outside_dir, &output_dir.join("payload"));
                }
                Ok(true)
            }
        })),
    );

    assert!(
        matches!(result, Err(unpack::Error::UnsafeOutputPath(_))),
        "expected unsafe output path error, got {result:?}"
    );
    assert_eq!(fs::read(&existing_file).unwrap(), b"original contents");
    assert!(!outside_dir.join("secret.txt").exists());
}
#[cfg(any(unix, windows))]
#[test]
fn unpack_revalidation_failure_does_not_create_new_nested_output_parent() {
    let test_dir = TestDir::new("unpack-toctou-no-new-parent");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let outside_dir = test_dir.path().join("outside");
    let output_dir = test_dir.path().join("out");

    fs::create_dir_all(&outside_dir).unwrap();
    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[
            ("safe/nested.txt", b"candidate"),
            ("payload/secret.txt", b"top secret"),
        ],
    );

    let result = unpack_archive(
        &encrypted_archive,
        &output_dir,
        Some(Box::new({
            let output_dir = output_dir.clone();
            let outside_dir = outside_dir.clone();
            move |path| {
                if path.ends_with("payload/secret.txt") {
                    symlink_dir(&outside_dir, &output_dir.join("payload"));
                }
                Ok(true)
            }
        })),
    );

    assert!(
        matches!(result, Err(unpack::Error::UnsafeOutputPath(_))),
        "expected unsafe output path error, got {result:?}"
    );
    assert!(
        !output_dir.join("safe").exists(),
        "new nested output parent must not become visible before extraction commit"
    );
    assert!(!outside_dir.join("secret.txt").exists());
}
#[cfg(any(unix, windows))]
#[test]
fn unpack_revalidation_failure_does_not_create_selected_directory_entries() {
    let test_dir = TestDir::new("unpack-toctou-no-selected-dir");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let outside_dir = test_dir.path().join("outside");
    let output_dir = test_dir.path().join("out");

    fs::create_dir_all(&outside_dir).unwrap();
    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[
            ("selected-dir/", b""),
            ("payload/secret.txt", b"top secret"),
        ],
    );

    let result = unpack_archive(
        &encrypted_archive,
        &output_dir,
        Some(Box::new({
            let output_dir = output_dir.clone();
            let outside_dir = outside_dir.clone();
            move |path| {
                if path.ends_with("payload/secret.txt") {
                    symlink_dir(&outside_dir, &output_dir.join("payload"));
                }
                Ok(true)
            }
        })),
    );

    assert!(
        matches!(result, Err(unpack::Error::UnsafeOutputPath(_))),
        "expected unsafe output path error, got {result:?}"
    );
    assert!(
        !output_dir.join("selected-dir").exists(),
        "selected directory entries must not become visible before final revalidation"
    );
    assert!(!outside_dir.join("secret.txt").exists());
}
#[cfg(any(unix, windows))]
#[test]
fn unpack_revalidates_directory_entry_prefix_created_after_validation() {
    let test_dir = TestDir::new("unpack-toctou-dir-entry");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let outside_dir = test_dir.path().join("outside");
    let output_dir = test_dir.path().join("out");

    fs::create_dir_all(&outside_dir).unwrap();
    write_manifest_archive_with_entries(&encrypted_archive, &[("payload/created/", b"")]);

    let result = unpack_archive(
        &encrypted_archive,
        &output_dir,
        Some(Box::new({
            let output_dir = output_dir.clone();
            let outside_dir = outside_dir.clone();
            move |path| {
                if path.ends_with("payload/created") {
                    symlink_dir(&outside_dir, &output_dir.join("payload"));
                }
                Ok(true)
            }
        })),
    );

    assert!(
        matches!(result, Err(unpack::Error::UnsafeOutputPath(_))),
        "expected unsafe output path error, got {result:?}"
    );
    assert!(!outside_dir.join("created").exists());
}
#[cfg(any(unix, windows))]
#[test]
fn unpack_intent_rejects_final_symlink_archive_input_before_parsing() {
    let test_dir = TestDir::new("unpack-input-final-symlink");
    let archive_target = test_dir.path().join("not-an-archive.enc");
    let archive_link = test_dir.path().join("archive-link.enc");
    let output_dir = test_dir.path().join("out");

    fs::write(&archive_target, b"not a dexios archive").unwrap();
    if !symlink_file_or_skip(&archive_target, &archive_link) {
        return;
    }

    let result = unpack::UnpackIntent::new(
        &archive_link,
        None,
        &output_dir,
        Protected::new(PASSWORD.to_vec()),
        None,
        None,
        None,
    );

    assert_unpack_intent_rejects_unsafe_path(result);
    assert!(!output_dir.exists());
}
#[cfg(any(unix, windows))]
#[test]
fn unpack_intent_rejects_final_symlink_detached_header_before_parsing() {
    let test_dir = TestDir::new("unpack-header-final-symlink");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let header_target = test_dir.path().join("not-a-header.hdr");
    let header_link = test_dir.path().join("header-link.hdr");
    let output_dir = test_dir.path().join("out");

    fs::write(&encrypted_archive, b"not a dexios archive").unwrap();
    fs::write(&header_target, b"not a dexios header").unwrap();
    if !symlink_file_or_skip(&header_target, &header_link) {
        return;
    }

    let result = unpack::UnpackIntent::new(
        &encrypted_archive,
        Some(header_link.as_path()),
        &output_dir,
        Protected::new(PASSWORD.to_vec()),
        None,
        None,
        None,
    );

    assert_unpack_intent_rejects_unsafe_path(result);
    assert!(!output_dir.exists());
}
#[cfg(any(unix, windows))]
#[test]
fn unpack_intent_rejects_archive_input_with_symlinked_parent_before_parsing() {
    let test_dir = TestDir::new("unpack-input-parent-symlink");
    let outside_dir = test_dir.path().join("outside");
    let parent_link = test_dir.path().join("archive-parent-link");
    let output_dir = test_dir.path().join("out");

    fs::create_dir(&outside_dir).unwrap();
    fs::write(outside_dir.join("archive.enc"), b"not a dexios archive").unwrap();
    if !symlink_dir_or_skip(&outside_dir, &parent_link) {
        return;
    }

    let result = unpack::UnpackIntent::new(
        parent_link.join("archive.enc"),
        None,
        &output_dir,
        Protected::new(PASSWORD.to_vec()),
        None,
        None,
        None,
    );

    assert_unpack_intent_rejects_unsafe_path(result);
    assert!(!output_dir.exists());
}
#[cfg(any(unix, windows))]
#[test]
fn unpack_rejects_symlinked_intermediate_output_paths() {
    let test_dir = TestDir::new("unpack-symlink-escape");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let outside_dir = test_dir.path().join("outside");
    let output_dir = test_dir.path().join("out");

    fs::create_dir_all(&outside_dir).unwrap();
    fs::create_dir_all(&output_dir).unwrap();
    symlink_dir(&outside_dir, &output_dir.join("payload"));

    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[("payload/secret.txt", b"top secret")],
    );

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(
            result,
            Err(unpack::Error::UnsafeOutputPath(ref path))
                if path.ends_with("payload/secret.txt")
        ),
        "expected unsafe output path error, got {result:?}"
    );
    assert!(!outside_dir.join("secret.txt").exists());
}
#[cfg(any(unix, windows))]
#[test]
fn unpack_rejects_symlinked_output_directory_prefix() {
    let test_dir = TestDir::new("unpack-symlink-output-prefix");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let outside_dir = test_dir.path().join("outside");
    let output_prefix = test_dir.path().join("out-link");
    let output_dir = output_prefix.join("nested");

    fs::create_dir_all(&outside_dir).unwrap();
    symlink_dir(&outside_dir, &output_prefix);

    write_manifest_archive_with_entries(&encrypted_archive, &[("secret.txt", b"top secret")]);

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(result, Err(unpack::Error::UnsafeOutputPath(_))),
        "expected unsafe output path error, got {result:?}"
    );
    assert!(!outside_dir.join("nested/secret.txt").exists());
}
