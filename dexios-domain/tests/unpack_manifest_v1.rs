#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::unreachable, clippy::string_slice, clippy::too_many_lines, clippy::cast_possible_truncation, clippy::cast_possible_wrap, clippy::cast_sign_loss, clippy::cast_precision_loss, clippy::match_same_arms, clippy::items_after_statements, clippy::redundant_closure_for_method_calls, clippy::needless_collect, clippy::manual_let_else, clippy::format_collect, clippy::case_sensitive_file_extension_comparisons, clippy::struct_excessive_bools, reason = "integration tests assert exact behavior and may panic on failure"))]
#[path = "support/unpack_v1.rs"]
mod unpack_support;

use unpack_support::*;

#[test]
fn test_dir_uses_system_temp_root() {
    let dir = TestDir::new("unpack-temp-root");

    let temp_root = fs::canonicalize(std::env::temp_dir()).unwrap();
    assert!(dir.path().starts_with(&temp_root));
    assert!(!dir.path().starts_with(Path::new("target/test-artifacts")));
}
#[test]
fn should_unpack_archive_without_explicit_directory_entries() {
    let test_dir = TestDir::new("unpack-no-dirs");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_manifest_archive_without_directory_entries(&encrypted_archive);

    unpack_archive(&encrypted_archive, &output_dir, None).unwrap();

    let restored = fs::read_to_string(output_dir.join("nested/inner/file.txt")).unwrap();
    assert_eq!(restored, "nested hello");
}
#[test]
fn unpack_directory_only_archive_returns_directory_commit_receipt() {
    let test_dir = TestDir::new("unpack-directory-only");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_manifest_archive_with_entries(&encrypted_archive, &[("empty-dir/", b"")]);

    let receipt = unpack_archive(&encrypted_archive, &output_dir, None).unwrap();

    assert!(output_dir.join("empty-dir").is_dir());
    assert_eq!(receipt.committed_artifacts().len(), 1);
    assert_eq!(
        receipt.committed_artifacts()[0].path(),
        output_dir.join("empty-dir")
    );
}
#[test]
fn should_unpack_exact_block_manifest_payload() {
    let test_dir = TestDir::new("unpack-exact-block");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let payload = vec![0x7Au8; BLOCK_SIZE];

    write_manifest_archive_with_entries(&encrypted_archive, &[("exact.bin", payload.as_slice())]);

    unpack_archive(&encrypted_archive, &output_dir, None).unwrap();

    assert_eq!(fs::read(output_dir.join("exact.bin")).unwrap(), payload);
}
#[test]
fn unpack_rejects_archive_path_deeper_than_structural_limit() {
    let test_dir = TestDir::new("unpack-depth-limit");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let too_deep_path = archive_path_with_depth(65);

    write_manifest_archive_with_entries(
        &encrypted_archive,
        &[(too_deep_path.as_str(), b"too deep")],
    );

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(result, Err(unpack::Error::ArchiveLimit(_))),
        "expected archive depth limit failure, got {result:?}"
    );
    assert!(!output_dir.join("dir0").exists());
}
#[test]
fn unpack_rejects_archive_path_longer_than_structural_limit() {
    let test_dir = TestDir::new("unpack-path-bytes-limit");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let too_long_path = archive_path_with_wide_components(64, 70);

    write_malformed_manifest_archive_payload(
        &encrypted_archive,
        raw_manifest_payload_with_file(too_long_path.as_str(), b"too long"),
    );

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(
            result,
            Err(unpack::Error::ArchivePayload(
                PayloadError::NormalizedPathLimitExceeded { .. }
            ))
        ),
        "expected archive path byte payload limit failure, got {result:?}"
    );
    assert!(!output_dir.exists());
}
#[test]
fn unpack_rejects_manifest_payload_with_trailing_bytes() {
    let test_dir = TestDir::new("unpack-trailing-payload");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let mut payload = raw_manifest_payload_with_file("safe.txt", b"safe");
    payload.extend_from_slice(b"trailing");

    write_malformed_manifest_archive_payload(&encrypted_archive, payload);

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(
            result,
            Err(unpack::Error::ArchivePayload(PayloadError::TrailingBytes(
                8
            )))
        ),
        "expected trailing payload bytes, got {result:?}"
    );
    assert!(!output_dir.join("safe.txt").exists());
}
#[test]
fn unpack_rejects_manifest_payload_with_missing_body_frame() {
    let test_dir = TestDir::new("unpack-missing-frame");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");

    write_malformed_manifest_archive_payload(
        &encrypted_archive,
        raw_manifest_payload(&[("safe.txt", 4)]),
    );

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(
            result,
            Err(unpack::Error::ArchivePayload(
                PayloadError::MissingBodyFrame(0)
            ))
        ),
        "expected missing body frame, got {result:?}"
    );
    assert!(!output_dir.join("safe.txt").exists());
}
#[test]
fn unpack_rejects_manifest_payload_with_body_length_mismatch() {
    let test_dir = TestDir::new("unpack-length-mismatch");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let mut payload = raw_manifest_payload(&[("safe.txt", 4)]);
    append_raw_body_frame(&mut payload, 0, 5, b"abcde");

    write_malformed_manifest_archive_payload(&encrypted_archive, payload);

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(
            result,
            Err(unpack::Error::ArchivePayload(
                PayloadError::BodyFrameLengthMismatch {
                    expected: 4,
                    actual: 5
                }
            ))
        ),
        "expected body length mismatch, got {result:?}"
    );
    assert!(!output_dir.join("safe.txt").exists());
}
#[test]
fn unpack_rejects_manifest_payload_with_body_frame_order_mismatch() {
    let test_dir = TestDir::new("unpack-order-mismatch");
    let encrypted_archive = test_dir.path().join("archive.enc");
    let output_dir = test_dir.path().join("out");
    let mut payload = raw_manifest_payload(&[("first.txt", 5), ("second.txt", 6)]);
    append_raw_body_frame(&mut payload, 1, 6, b"second");
    append_raw_body_frame(&mut payload, 0, 5, b"first");

    write_malformed_manifest_archive_payload(&encrypted_archive, payload);

    let result = unpack_archive(&encrypted_archive, &output_dir, None);

    assert!(
        matches!(
            result,
            Err(unpack::Error::ArchivePayload(
                PayloadError::BodyFrameOrderMismatch {
                    expected: 0,
                    actual: 1
                }
            ))
        ),
        "expected body frame order mismatch, got {result:?}"
    );
    assert!(!output_dir.join("first.txt").exists());
    assert!(!output_dir.join("second.txt").exists());
}
