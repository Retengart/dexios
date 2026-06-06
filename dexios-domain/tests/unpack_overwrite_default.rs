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

use unpack_support::*;

// fs-4: unpack with no overwrite-consent callback must default existing-file targets to
// CreateNew (refuse to clobber) instead of silently replacing them.
#[test]
fn unpack_without_consent_callback_refuses_to_clobber_existing_file() {
    let test_dir = TestDir::new("unpack-overwrite-default");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let existing = output_dir.join("existing.txt");

    fs::create_dir_all(&output_dir).unwrap();
    fs::write(&existing, b"original contents").unwrap();
    write_manifest_archive_with_entries(&encrypted_archive, &[("existing.txt", b"replacement")]);

    // No consent callback => non-clobber default.
    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        result.is_err(),
        "unpack without a consent callback must refuse to clobber an existing file, got {result:?}"
    );
    assert_eq!(
        fs::read(&existing).unwrap(),
        b"original contents",
        "existing file must be preserved when overwrite is refused"
    );
}
