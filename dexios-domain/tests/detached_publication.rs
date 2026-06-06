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
use std::fs;

use core::kdf::Kdf;
use core::protected::Protected;
use dexios_domain::archive::ArchivePolicy;
use dexios_domain::pack;
use dexios_domain::storage::identity::{OverwritePolicy, PathRole};
use dexios_domain::storage::transaction::{DetachedPublicationFailure, TransactionError};
use dexios_domain::{encrypt, pack::PackIntent};

const PASSWORD: &[u8; 8] = b"12345678";

fn key() -> Protected<Vec<u8>> {
    Protected::new(PASSWORD.to_vec())
}

#[test]
fn encrypt_detached_partial_publication_reports_committed_payload_and_failed_header() {
    let root = tempfile::tempdir().unwrap();
    let input_path = root.path().join("plain.txt");
    let output_path = root.path().join("plain.enc");
    let header_path = root.path().join("plain.hdr");
    fs::write(&input_path, b"top secret").unwrap();
    fs::write(&header_path, b"existing header").unwrap();

    let intent = encrypt::EncryptIntent::new(
        &input_path,
        &output_path,
        OverwritePolicy::ReplaceAtCommit,
        Some(encrypt::DetachedHeaderTarget::new(
            &header_path,
            OverwritePolicy::CreateNew,
        )),
        key(),
        Kdf::Argon2id,
    )
    .unwrap();

    let error = encrypt::execute_transactional_with_cleanup(intent).unwrap_err();

    let encrypt::Error::DetachedPublication(TransactionError::PartialCommit { .. }) = &error else {
        panic!("expected detached partial publication, got {error:?}");
    };
    let DetachedPublicationFailure::Partial(publication) = error
        .detached_publication_failure()
        .expect("detached publication evidence")
    else {
        panic!("expected partial detached publication evidence");
    };
    assert_eq!(publication.committed_artifacts().len(), 1);
    assert_eq!(
        publication.committed_artifacts()[0].role(),
        PathRole::Output
    );
    assert_eq!(publication.committed_artifacts()[0].path(), output_path);
    assert_eq!(
        publication.failed_artifact().role(),
        PathRole::DetachedHeader
    );
    assert_eq!(publication.failed_artifact().path(), header_path);
    assert!(output_path.exists());
    assert_eq!(fs::read(&header_path).unwrap(), b"existing header");
    assert_eq!(fs::read(&input_path).unwrap(), b"top secret");
}

#[test]
fn pack_detached_partial_publication_reports_committed_payload_and_failed_header() {
    let root = tempfile::tempdir().unwrap();
    let source_dir = root.path().join("source");
    let output_path = root.path().join("archive.enc");
    let header_path = root.path().join("archive.hdr");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("plain.txt"), b"top secret").unwrap();
    fs::write(&header_path, b"existing header").unwrap();

    let intent = PackIntent::new(
        vec![&source_dir],
        &output_path,
        OverwritePolicy::ReplaceAtCommit,
        Some(pack::DetachedHeaderTarget::new(
            &header_path,
            OverwritePolicy::CreateNew,
        )),
        key(),
        Kdf::Argon2id,
        ArchivePolicy::default(),
        true,
        None,
    )
    .unwrap();

    let error = pack::execute_transactional_with_cleanup(intent).unwrap_err();

    let pack::Error::DetachedPublication(TransactionError::PartialCommit { .. }) = &error else {
        panic!("expected detached partial publication, got {error:?}");
    };
    let DetachedPublicationFailure::Partial(publication) = error
        .detached_publication_failure()
        .expect("detached publication evidence")
    else {
        panic!("expected partial detached publication evidence");
    };
    assert_eq!(publication.committed_artifacts().len(), 1);
    assert_eq!(
        publication.committed_artifacts()[0].role(),
        PathRole::GeneratedOutput
    );
    assert_eq!(publication.committed_artifacts()[0].path(), output_path);
    assert_eq!(
        publication.failed_artifact().role(),
        PathRole::GeneratedDetachedHeader
    );
    assert_eq!(publication.failed_artifact().path(), header_path);
    assert!(output_path.exists());
    assert_eq!(fs::read(&header_path).unwrap(), b"existing header");
    assert_eq!(
        fs::read(source_dir.join("plain.txt")).unwrap(),
        b"top secret"
    );
}
