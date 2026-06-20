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
#[path = "support/unpack_v1.rs"]
mod unpack_support;

use dexios_domain::workflow_error::WorkflowErrorClass;
#[cfg(unix)]
use std::error::Error as _;
use unpack_support::*;

fn assert_manifest_archive_path_error(error: &unpack::Error, label: &str) {
    assert_eq!(
        error.workflow_class(),
        WorkflowErrorClass::UnsafePath,
        "{label} must be classified as unsafe path; got {error:?}"
    );
    assert!(
        error.to_string().contains("Archive path error"),
        "{label} must report an archive path error; got {error:?}"
    );
}

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

    let error = result.unwrap_err();
    assert_manifest_archive_path_error(&error, "unsafe sibling archive path");
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

    let error = result.unwrap_err();
    assert_manifest_archive_path_error(&error, "pre-callback archive path");
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

#[cfg(unix)]
#[test]
fn unpack_rejects_output_root_replaced_before_selected_file_staging() {
    let test_dir = TestDir::new("unpack-root-replaced-before-staging");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let original_root = test_dir.path().join("original-out");
    let existing_file = output_dir.join("existing.txt");
    let selected_file = output_dir.join("selected.txt");
    let selected_body = b"selected body";

    fs::create_dir_all(&output_dir).unwrap();
    fs::write(&existing_file, b"original pre-existing output").unwrap();
    write_manifest_archive_with_entries(&encrypted_archive, &[("selected.txt", selected_body)]);

    let result = unpack_archive(
        &encrypted_archive,
        &output_dir,
        Some(Box::new({
            let output_dir = output_dir.clone();
            let original_root = original_root.clone();
            move |path| {
                assert_eq!(
                    path, selected_file,
                    "test archive should select the single file body"
                );
                fs::rename(&output_dir, &original_root).unwrap();
                fs::create_dir_all(&output_dir).unwrap();
                fs::write(
                    output_dir.join("replacement-marker.txt"),
                    b"replacement root",
                )
                .unwrap();
                Ok(true)
            }
        })),
    );

    assert_eq!(
        fs::read(original_root.join("existing.txt")).unwrap(),
        b"original pre-existing output",
        "pre-existing outputs in the original root must be preserved"
    );
    assert!(
        !original_root.join("selected.txt").exists(),
        "selected output must not be committed into the preserved original root"
    );
    assert!(
        !output_dir.join("selected.txt").exists(),
        "selected output must not be committed through the replacement root; result was {result:?}"
    );
    assert_no_plaintext_under(&output_dir, selected_body);

    let error = result.expect_err("replaced output root must fail before selected body staging");
    assert_replacement_path_workflow_error(&error, "replaced output root");
    assert!(
        !matches!(error, unpack::Error::Transaction(_)),
        "replaced output root must be rejected before transaction staging/commit, got {error:?}"
    );
}

#[cfg(all(unix, feature = "test-support"))]
#[test]
fn unpack_rejects_output_root_replaced_after_final_auth_before_selected_directory_creation() {
    let test_dir = TestDir::new("unpack-root-replaced-after-final-auth");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let original_root = test_dir.path().join("original-out");
    let existing_file = output_dir.join("existing.txt");

    fs::create_dir_all(&output_dir).unwrap();
    fs::write(&existing_file, b"original pre-existing output").unwrap();
    write_manifest_archive_with_entries(&encrypted_archive, &[("selected-dir/", b"")]);

    let final_auth_observer_count = Arc::new(AtomicUsize::new(0));
    let intent = unpack::UnpackIntent::new(
        &encrypted_archive,
        None,
        &output_dir,
        Protected::new(PASSWORD.to_vec()),
        None,
        None,
        None,
    )
    .unwrap()
    .with_after_final_auth_observer(Box::new({
        let output_dir = output_dir.clone();
        let original_root = original_root.clone();
        let final_auth_observer_count = Arc::clone(&final_auth_observer_count);
        move || {
            final_auth_observer_count.fetch_add(1, Ordering::SeqCst);
            fs::rename(&output_dir, &original_root).unwrap();
            fs::create_dir_all(&output_dir).unwrap();
            fs::write(
                output_dir.join("replacement-marker.txt"),
                b"replacement root",
            )
            .unwrap();
        }
    }));

    let result = unpack::execute(intent);

    assert_eq!(
        final_auth_observer_count.load(Ordering::SeqCst),
        1,
        "regression must replace the output root after final authentication"
    );
    assert_eq!(
        fs::read(original_root.join("existing.txt")).unwrap(),
        b"original pre-existing output",
        "pre-existing outputs in the original root must be preserved"
    );
    assert!(
        !original_root.join("selected-dir").exists(),
        "selected directory must not be created in the preserved original root"
    );
    assert!(
        !output_dir.join("selected-dir").exists(),
        "selected directory must not be created through the replacement root; result was {result:?}"
    );

    let error =
        result.expect_err("replaced output root must fail before selected directory creation");
    assert_replacement_path_workflow_error(&error, "post-auth replaced output root");
    assert!(
        !matches!(error, unpack::Error::Transaction(_)),
        "post-auth output-root replacement must be rejected before transaction commit, got {error:?}"
    );
}

#[cfg(unix)]
fn assert_replacement_path_workflow_error(error: &unpack::Error, label: &str) {
    let class = error.workflow_class();
    assert!(
        matches!(
            class,
            WorkflowErrorClass::UnsafePath | WorkflowErrorClass::IoFailure
        ),
        "{label} must fail as unsafe path or IO failure, not malformed archive, crypto, or callback error; got {class:?} from {error:?}"
    );
    assert!(
        !matches!(
            class,
            WorkflowErrorClass::MalformedFormat
                | WorkflowErrorClass::KdfFailure
                | WorkflowErrorClass::AuthenticationFailure
                | WorkflowErrorClass::Other
        ),
        "{label} replacement-path failure must not be hidden as unrelated workflow class {class:?}"
    );
    assert!(
        !matches!(error, unpack::Error::ArchiveFileCallback(_)),
        "{label} replacement-path failure must not be reported as a callback error"
    );
    if matches!(class, WorkflowErrorClass::IoFailure) {
        assert!(
            error.source().is_some(),
            "{label} IO-class replacement failure must preserve its storage/source error"
        );
    }
}

#[cfg(unix)]
fn assert_no_plaintext_under(root: &Path, forbidden: &[u8]) {
    if !root.exists() {
        return;
    }

    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            assert_no_plaintext_under(&path, forbidden);
        } else {
            assert_ne!(
                fs::read(&path).unwrap(),
                forbidden,
                "plaintext body must not appear under replacement root at {}",
                path.display()
            );
        }
    }
}
